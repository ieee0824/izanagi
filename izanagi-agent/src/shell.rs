//! PTY forwarding and bounded child-process cleanup.
use crate::connection::{recv_message, send_message};
use izanagi::protocol::Message;

/// Owns the shell until it has been reaped, including on task cancellation.
pub(crate) struct ShellChild {
    pid: libc::pid_t,
    reaped: bool,
}

impl ShellChild {
    pub(crate) fn new(pid: libc::pid_t) -> Self {
        Self { pid, reaped: false }
    }

    fn signal(&self, signal: libc::c_int) {
        if !self.reaped {
            unsafe {
                libc::kill(-self.pid, signal);
                // Also cover a child that has not yet established its session.
                libc::kill(self.pid, signal);
            }
        }
    }

    fn try_reap(&mut self) -> std::io::Result<Option<i32>> {
        // Peek without reaping so the PID/process-group ID cannot be reused
        // before we kill any surviving group members (the shell may exit first).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.reaped = true;
            }
            return if error.raw_os_error() == Some(libc::EINTR) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == self.pid {
            self.reaped = true;
            return Ok(Some(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            }));
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.reaped = true;
            }
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
        Ok(None)
    }

    async fn cleanup(&mut self) -> anyhow::Result<i32> {
        // Terminate remaining group members even if PTY hangup already exited the shell.
        self.signal(libc::SIGTERM);
        // Preserve the exit status of a shell that has already exited.
        if let Some(code) = self.try_reap()? {
            return Ok(code);
        }
        for signal in [None, Some(libc::SIGKILL)] {
            if let Some(signal) = signal {
                self.signal(signal);
            }
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                if let Some(code) = self.try_reap()? {
                    return Ok(code);
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        anyhow::bail!("timed out reaping shell child {}", self.pid)
    }
}

impl Drop for ShellChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.signal(libc::SIGKILL);
            // Cancellation must not leave a zombie or block a Tokio worker.
            let pid = self.pid;
            std::thread::spawn(move || {
                let mut child = ShellChild::new(pid);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while matches!(child.try_reap(), Ok(None)) {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                // Do not recursively spawn another reaper on timeout/error.
                child.reaped = true;
            });
        }
    }
}

pub(crate) async fn relay_shell<R, W>(
    reader: &mut R,
    writer: &mut W,
    auth_key: Option<&[u8]>,
    send_seq: &mut u64,
    recv_seq: &mut u64,
    master: std::fs::File,
    mut child: ShellChild,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::os::fd::AsRawFd;
    // Capture every error, including setup errors, before common cleanup.
    let result: anyhow::Result<()> = async {
        let master_fd = master.as_raw_fd();
        let flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let master_async = tokio::io::unix::AsyncFd::new(master)?;
        loop {
            tokio::select! {
                // PTY → ホスト (stdout)
                readable = master_async.readable() => {
                    match readable {
                        Ok(mut guard) => {
                            match guard.try_io(|inner| {
                                use std::io::Read;
                                let mut buf = vec![0u8; 4096];
                                let n = inner.get_ref().read(&mut buf)?;
                                buf.truncate(n);
                                Ok(buf)
                            }) {
                                Ok(Ok(data)) if !data.is_empty() => {
                                    send_message(
                                        writer,
                                        &Message::ShellData { stream: 1, data },
                                        auth_key,
                                        send_seq,
                                    ).await?;
                                }
                                Ok(Ok(_)) => {
                                    // EOF — シェル終了
                                    break;
                                }
                                Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    continue;
                                }
                                Ok(Err(_)) => {
                                    break;
                                }
                                Err(_would_block) => {
                                    continue;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                // ホスト → PTY (stdin) / リサイズ / クローズ
                result = recv_message(reader, auth_key, recv_seq) => {
                    match result? {
                        Some(Message::ShellData { stream: 0, data }) => {
                            // stdin をPTY に書き込み
                            match master_async.writable().await {
                                Ok(mut guard) => {
                                    let _ = guard.try_io(|inner| {
                                        use std::io::Write;
                                        inner.get_ref().write_all(&data)
                                    });
                                }
                                Err(_) => break,
                            }
                        }
                        Some(Message::ShellResize { rows, cols }) => {
                            let ws = libc::winsize {
                                ws_row: rows,
                                ws_col: cols,
                                ws_xpixel: 0,
                                ws_ypixel: 0,
                            };
                            unsafe {
                                libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
                            }
                        }
                        Some(Message::Stop) | None => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
    .await;
    // The transfer future has dropped the PTY master before signalling/waiting.
    let cleanup = child.cleanup().await;
    if let Err(error) = &cleanup {
        eprintln!("shell cleanup failed: {error}");
    }
    result?;
    let exit_code = cleanup?;
    // A stalled peer must not retain the connection task after child cleanup.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        send_message(
            writer,
            &Message::ShellClose { exit_code },
            auth_key,
            send_seq,
        ),
    )
    .await??;
    eprintln!("shell closed with exit code {}", exit_code);
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod shell_cleanup {
    use super::{ShellChild, relay_shell};
    use izanagi::protocol::{self, Message};
    use std::os::fd::FromRawFd;
    use tokio::io::AsyncWriteExt;

    fn shell(command: &str) -> (std::fs::File, ShellChild, libc::pid_t) {
        let executable = std::ffi::CString::new("/bin/sh").unwrap();
        let option = std::ffi::CString::new("-c").unwrap();
        let command = std::ffi::CString::new(command).unwrap();
        let argv = [
            executable.as_ptr(),
            option.as_ptr(),
            command.as_ptr(),
            std::ptr::null(),
        ];
        let mut fd = -1;
        let pid = unsafe {
            libc::forkpty(
                &mut fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::execv(executable.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
        }
        (
            unsafe { std::fs::File::from_raw_fd(fd) },
            ShellChild::new(pid),
            pid,
        )
    }

    async fn read_message<R: tokio::io::AsyncRead + Unpin>(
        reader: &mut R,
        auth_key: &[u8],
        sequence: &mut u64,
    ) -> anyhow::Result<Option<Message>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            protocol::read_message_authenticated(reader, auth_key, sequence),
        )
        .await?
    }

    fn assert_reaped(pid: libc::pid_t) {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_shell_cleanup_on_normal_exit_disconnect_stop_and_protocol_error() {
        for mode in ["exit", "disconnect", "stop", "protocol-error"] {
            // Ignore graceful signals so abnormal cases exercise SIGKILL escalation.
            let command = if mode == "exit" {
                "printf ready; exit 7"
            } else {
                "trap '' HUP TERM; printf ready; while :; do sleep 1; done"
            };
            let (master, child, pid) = shell(command);
            let auth_key = rand::random::<[u8; 32]>();
            let (host, agent) = tokio::io::duplex(8192);
            let (mut host_reader, mut host_writer) = tokio::io::split(host);
            let (mut reader, mut writer) = tokio::io::split(agent);
            let task = tokio::spawn(async move {
                relay_shell(
                    &mut reader,
                    &mut writer,
                    Some(&auth_key),
                    &mut 0,
                    &mut 0,
                    master,
                    child,
                )
                .await
            });
            let mut sequence = 0;
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_message(&mut host_reader, &auth_key, &mut sequence),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            assert!(matches!(output, Message::ShellData { .. }));
            match mode {
                "disconnect" => {
                    drop(host_reader);
                    drop(host_writer);
                }
                "protocol-error" => {
                    host_writer.write_all(&[0]).await.unwrap();
                }
                "stop" => {
                    protocol::write_message_authenticated(
                        &mut host_writer,
                        &Message::Stop,
                        &auth_key,
                        &mut 0,
                    )
                    .await
                    .unwrap();
                    let close = read_message(&mut host_reader, &auth_key, &mut sequence)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(matches!(close, Message::ShellClose { .. }));
                }
                "exit" => {
                    let close = read_message(&mut host_reader, &auth_key, &mut sequence)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(close, Message::ShellClose { exit_code: 7 });
                }
                _ => unreachable!(),
            }
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap();
            if mode == "protocol-error" {
                assert!(result.is_err());
            }
            if mode == "exit" || mode == "stop" {
                result.unwrap();
            }
            assert_reaped(pid);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_kills_group_members_after_shell_has_exited() {
        let (master, child, pid) = shell("trap '' HUP TERM; sleep 60 & printf '%s' \"$!\"; exit 0");
        let (mut host, agent) = tokio::io::duplex(8192);
        let (mut reader, mut writer) = tokio::io::split(agent);
        let task = tokio::spawn(async move {
            relay_shell(
                &mut reader,
                &mut writer,
                None,
                &mut 0,
                &mut 0,
                master,
                child,
            )
            .await
        });
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            protocol::read_message(&mut host),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let Message::ShellData { data, .. } = output else {
            panic!("expected descendant PID");
        };
        let descendant: libc::pid_t = std::str::from_utf8(&data).unwrap().parse().unwrap();
        // Give the leader time to exit while its signal-resistant descendant holds the PTY.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        protocol::write_message(&mut host, &Message::Stop)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_reaped(pid);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match std::fs::read_to_string(format!("/proc/{descendant}/stat")) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Ok(stat) if stat.split_once(") ").unwrap().1.starts_with('Z') => break,
                    _ => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_shell_task_reaps_child() {
        let (master, child, pid) =
            shell("trap '' HUP TERM; printf ready; while :; do sleep 1; done");
        let (mut host, mut agent) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(&mut agent);
            relay_shell(
                &mut reader,
                &mut writer,
                None,
                &mut 0,
                &mut 0,
                master,
                child,
            )
            .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            protocol::read_message(&mut host),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while unsafe { libc::kill(pid, 0) } == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_reaped(pid);
    }

    struct BrokenWriter;
    impl tokio::io::AsyncWrite for BrokenWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shell_send_error_reaps_child() {
        let (master, child, pid) =
            shell("trap '' HUP TERM; printf ready; while :; do sleep 1; done");
        let (_host, mut reader) = tokio::io::duplex(64);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_shell(
                &mut reader,
                &mut BrokenWriter,
                None,
                &mut 0,
                &mut 0,
                master,
                child,
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert_reaped(pid);
    }
}
