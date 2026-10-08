use anyhow::Context;
use izanagi::config::Config;
use izanagi::protocol::{Message, load_shared_secret_from_env};
use izanagi::session::{self, Session, SessionBackend};
use tokio::io::AsyncReadExt;

use super::{acquire_instance_lock, izanagi_dir, start_engine, stop_engine};

pub async fn cmd_shell(config: &Config) -> anyhow::Result<u8> {
    // up 中のセッションがあればそこに接続
    if let Some(sess) = session::load_session(&izanagi_dir())?
        && session::is_session_alive(&sess)
    {
        return shell_on_session(&sess).await;
    }

    // セッションがなければ単発起動
    let _lock = acquire_instance_lock()?;

    let (engine, log_storage) = start_engine(config, None).await?;

    let shell_result = engine.sandbox().shell().await;

    stop_engine(engine, &log_storage).await;

    // "shell exited with code N" エラーから終了コードを抽出
    match shell_result {
        Ok(()) => Ok(0),
        Err(e) => {
            let msg = e.to_string();
            if let Some(code_str) = msg.strip_prefix("shell exited with code ")
                && let Ok(code) = code_str.trim().parse::<u8>()
            {
                return Ok(code);
            }
            Err(e)
        }
    }
}

/// up 中のセッションに接続してシェルを起動する。
async fn shell_on_session(sess: &Session) -> anyhow::Result<u8> {
    match &sess.backend {
        SessionBackend::AppleContainer {
            container_name,
            mount_point,
            ..
        } => {
            let args =
                izanagi::apple_container_sandbox::build_shell_args(container_name, mount_point);

            let status = tokio::process::Command::new("container")
                .args(&args)
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .status()
                .await
                .context("container exec -it の実行に失敗")?;

            Ok(status
                .code()
                .and_then(|c| u8::try_from(c).ok())
                .unwrap_or(1))
        }
        SessionBackend::Qemu {
            host_port,
            token_hash,
        } => qemu_interactive_shell(*host_port, token_hash.as_deref()).await,
    }
}

/// QEMU セッションに接続して対話的シェルを実行する。
async fn qemu_interactive_shell(host_port: u16, token_hash: Option<&str>) -> anyhow::Result<u8> {
    use tokio::net::TcpStream;

    let addr = format!("127.0.0.1:{}", host_port);
    let stream = TcpStream::connect(&addr)
        .await
        .context("agent への接続に失敗")?;
    let (reader, writer) = tokio::io::split(stream);

    let secret = load_shared_secret_from_env()?;
    let mut client = izanagi::protocol_client::ProtocolClient::new(reader, writer, secret);

    // Hello ハンドシェイク + Ready 待ち
    client
        .handshake_and_wait_ready(token_hash.map(|s| s.to_string()))
        .await?;

    // ターミナルサイズ取得
    let (rows, cols) = get_terminal_size();

    // Shell メッセージ送信
    client.send_message(&Message::Shell { rows, cols }).await?;

    // raw mode
    let _raw_guard = RawModeGuard::enable()?;

    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = vec![0u8; 1024];
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;

    let mut exit_code: u8 = 0;

    loop {
        tokio::select! {
            n = stdin.read(&mut stdin_buf) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        let msg = Message::ShellData {
                            stream: 0,
                            data: stdin_buf[..n].to_vec(),
                        };
                        client.send_message(&msg).await?;
                    }
                    Err(_) => break,
                }
            }
            result = client.recv_message() => {
                match result? {
                    Some(Message::ShellData { data, .. }) => {
                        use std::io::Write;
                        std::io::stdout().write_all(&data)?;
                        std::io::stdout().flush()?;
                    }
                    Some(Message::ShellClose { exit_code: code }) => {
                        exit_code = code.try_into().unwrap_or(1);
                        break;
                    }
                    Some(Message::Error(e)) => {
                        anyhow::bail!("agent error: {}", e);
                    }
                    None => break,
                    _ => {}
                }
            }
            _ = sigwinch.recv() => {
                let (rows, cols) = get_terminal_size();
                client.send_message(&Message::ShellResize { rows, cols }).await?;
            }
        }
    }

    Ok(exit_code)
}

/// ターミナルサイズを取得する。
fn get_terminal_size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
            && ws.ws_row > 0
            && ws.ws_col > 0
        {
            (ws.ws_row, ws.ws_col)
        } else {
            (24, 80)
        }
    }
}

/// RAII でターミナルを raw mode に設定し、ドロップ時に復元する。
struct RawModeGuard {
    original: libc::termios,
}

impl RawModeGuard {
    fn enable() -> anyhow::Result<Self> {
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut original) != 0 {
                anyhow::bail!("tcgetattr failed: {}", std::io::Error::last_os_error());
            }
            let mut raw = original;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw) != 0 {
                anyhow::bail!("tcsetattr failed: {}", std::io::Error::last_os_error());
            }
            Ok(Self { original })
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &self.original);
        }
    }
}
