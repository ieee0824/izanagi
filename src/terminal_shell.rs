//! Interactive shell I/O with cancellable terminal reads and RAII mode restoration.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use crate::protocol::Message;
use crate::protocol_client::ProtocolClient;

struct Terminal {
    fd: File,
    original: libc::termios,
}

impl Terminal {
    fn open() -> anyhow::Result<Self> {
        // Open a separate file description: dup(stdin) would share O_NONBLOCK flags.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/tty")?;
        let fd = file;
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut original) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut raw = original;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSAFLUSH, &raw) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { fd, original })
    }

    async fn read(&self, bytes: &mut [u8]) -> std::io::Result<usize> {
        // kqueue cannot register some /dev/tty devices on macOS. A zero-timeout
        // poll plus an async timer works on both macOS and Linux, without a
        // blocking task or any syscall that waits for terminal input.
        loop {
            let mut descriptor = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            } else if ready > 0 {
                match (&self.fd).read(bytes) {
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::Interrupted => {}
                    result => return result,
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        loop {
            // Restore and discard pending guest input, including on cancellation.
            if unsafe { libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.original) } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                eprintln!("terminal mode restoration failed: {error}");
                break;
            }
        }
    }
}

fn terminal_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0
        && ws.ws_row > 0
        && ws.ws_col > 0
    {
        (ws.ws_row, ws.ws_col)
    } else {
        (24, 80)
    }
}

/// Shared by a newly started QEMU sandbox and an existing up session.
/// Dropping this future cancels terminal readiness without leaving a blocking stdin task.
pub async fn interactive_shell<R, W>(client: &mut ProtocolClient<R, W>) -> anyhow::Result<i32>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let terminal = Terminal::open()?;
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let (rows, cols) = terminal_size();
    client.send_message(&Message::Shell { rows, cols }).await?;
    let mut bytes = [0; 1024];
    loop {
        tokio::select! {
            n = terminal.read(&mut bytes) => {
                let n = n?;
                if n == 0 {
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), client.send_message(&Message::Stop)).await;
                    anyhow::bail!("terminal input closed");
                }
                client.send_message(&Message::ShellData { stream: 0, data: bytes[..n].to_vec() }).await?;
            }
            message = client.recv_message() => match message? {
                Some(Message::ShellData { data, .. }) => {
                    std::io::stdout().write_all(&data)?;
                    std::io::stdout().flush()?;
                }
                Some(Message::ShellClose { exit_code }) => return Ok(exit_code),
                Some(Message::Error(error)) => anyhow::bail!("agent error: {error}"),
                None => anyhow::bail!("agent disconnected during shell"),
                other => anyhow::bail!("unexpected shell response: {other:?}"),
            },
            _ = sigwinch.recv() => {
                let (rows, cols) = terminal_size();
                client.send_message(&Message::ShellResize { rows, cols }).await?;
            }
        }
    }
}
