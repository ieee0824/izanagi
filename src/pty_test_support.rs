//! Subprocess regression harness: leave PTY input open and idle until the child exits.
use izanagi::{protocol::Message, protocol_client::ProtocolClient};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;

pub(crate) fn exercise(probe: &str, mode: &'static str) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let auth_key = hex::encode(rand::random::<[u8; 32]>()).into_bytes();
    let key_path = std::env::temp_dir().join(format!("izanagi-pty-test-{}", rand::random::<u64>()));
    // Key files are private and contain freshly generated test-only material.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut key_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap();
    key_file.write_all(&auth_key).unwrap();
    let server = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let (reader, writer) = stream.into_split();
            let mut peer = ProtocolClient::new(reader, writer, Some(auth_key));
            peer.recv_message().await.unwrap();
            peer.send_message(&Message::Hello {
                authenticated: true,
                token: None,
            })
            .await
            .unwrap();
            peer.send_message(&Message::Ready).await.unwrap();
            assert!(matches!(
                peer.recv_message().await.unwrap(),
                Some(Message::Shell { .. })
            ));
            // Ensure the host has started an idle terminal read before close/disconnect/error.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            match mode {
                "close" => peer
                    .send_message(&Message::ShellClose { exit_code: 0 })
                    .await
                    .unwrap(),
                "error" => peer
                    .send_message(&Message::Error("shell test error".into()))
                    .await
                    .unwrap(),
                "disconnect" => {}
                "cancel" => {
                    assert!(peer.recv_message().await.unwrap().is_none());
                }
                _ => unreachable!(),
            }
        });
    });
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    unsafe {
        libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
    }
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut original) },
        0
    );
    #[cfg(target_os = "linux")]
    let stdin_flags = unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) };
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", probe, "--nocapture"])
        .env("IZANAGI_PTY_TEST_PORT", port.to_string())
        .env("IZANAGI_PTY_TEST_MODE", mode)
        .env("IZANAGI_SECRET_FILE", &key_path)
        .env_remove("IZANAGI_SHARED_SECRET")
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave.try_clone().unwrap());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut output = Vec::new();
    let mut saw_raw_mode = false;
    let status = loop {
        // Drain output without ever sending input/EOF. macOS PTY close can wait
        // for pending output even when the application itself has finished.
        use std::io::Read;
        let mut bytes = [0; 4096];
        while let Ok(n) = master.read(&mut bytes) {
            if n == 0 {
                break;
            }
            output.extend_from_slice(&bytes[..n]);
        }
        let mut current: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut current) } == 0 {
            saw_raw_mode |= current.c_lflag & (libc::ICANON | libc::ECHO) == 0;
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            drop(master);
            let _ = child.wait();
            panic!(
                "shell child did not exit with idle PTY input ({mode}): {}",
                String::from_utf8_lossy(&output)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "shell probe failed ({mode}): {}",
        String::from_utf8_lossy(&output)
    );
    assert!(saw_raw_mode, "probe must have actually entered raw mode");
    // macOS revokes the slave on session-leader exit. The child asserts exact
    // termios restoration before exiting; Linux can additionally inspect it here.
    #[cfg(target_os = "linux")]
    {
        let mut restored: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut restored) },
            0
        );
        assert_termios_equal(&original, &restored);
    }
    #[cfg(target_os = "linux")]
    assert_eq!(
        unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) },
        stdin_flags,
        "stdin flags must stay unchanged"
    );
    drop(master);
    server.join().unwrap();
    std::fs::remove_file(key_path).unwrap();
}

pub(crate) fn terminal_snapshot() -> (libc::termios, libc::c_int) {
    let mut mode = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut mode) }, 0);
    (mode, unsafe {
        libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL)
    })
}

pub(crate) fn assert_terminal_restored(original: &(libc::termios, libc::c_int)) {
    let restored = terminal_snapshot();
    assert_termios_equal(&original.0, &restored.0);
    assert_eq!(original.1, restored.1, "stdin flags must stay unchanged");
}

fn assert_termios_equal(original: &libc::termios, restored: &libc::termios) {
    assert_eq!(
        (
            restored.c_iflag,
            restored.c_oflag,
            restored.c_cflag,
            restored.c_lflag,
            restored.c_cc
        ),
        (
            original.c_iflag,
            original.c_oflag,
            original.c_cflag,
            original.c_lflag,
            original.c_cc
        )
    );
}
