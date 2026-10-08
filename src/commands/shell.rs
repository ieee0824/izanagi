use anyhow::Context;
use izanagi::config::Config;
use izanagi::protocol::load_shared_secret_from_env;
use izanagi::session::{self, Session, SessionBackend};

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

    let shell_result = engine.shell().await;

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

    let code = izanagi::terminal_shell::interactive_shell(&mut client).await?;
    Ok(code.try_into().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    #[test]
    fn existing_session_shell_exits_and_restores_terminal_without_input() {
        for mode in ["close", "disconnect", "error", "cancel"] {
            crate::pty_test_support::exercise("commands::shell::tests::shell_runtime_probe", mode);
        }
    }

    #[test]
    fn shell_runtime_probe() {
        let Ok(port) = std::env::var("IZANAGI_PTY_TEST_PORT") else {
            return;
        };
        let mode = std::env::var("IZANAGI_PTY_TEST_MODE").unwrap();
        let original = crate::pty_test_support::terminal_snapshot();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let shell = super::qemu_interactive_shell(port.parse().unwrap(), None);
            if mode == "cancel" {
                tokio::time::timeout(std::time::Duration::from_millis(200), shell)
                    .await
                    .map_err(anyhow::Error::from)?
            } else {
                shell.await
            }
        });
        match mode.as_str() {
            "close" => assert_eq!(result.unwrap(), 0),
            "disconnect" => assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("agent disconnected during shell")
            ),
            "error" => assert!(result.unwrap_err().to_string().contains("shell test error")),
            "cancel" => assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("deadline has elapsed")
            ),
            _ => unreachable!(),
        }
        // Runtime destruction is part of the test: a blocking stdin task used to hang here.
        drop(runtime);
        crate::pty_test_support::assert_terminal_restored(&original);
    }
}
