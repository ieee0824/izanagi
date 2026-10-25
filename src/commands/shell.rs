use izanagi::config::Config;
use izanagi::session::{self, Session};

use super::{acquire_instance_lock, build_sandbox_env, izanagi_dir, start_engine, stop_engine};

pub async fn cmd_shell(config: &Config) -> anyhow::Result<u8> {
    // up 中のセッションがあればそこに接続
    if let Some(sess) = session::load_session(&izanagi_dir())?
        && session::is_session_alive(&sess)
    {
        return shell_on_session(config, &sess).await;
    }

    // セッションがなければ単発起動
    let _lock = acquire_instance_lock()?;

    let (engine, log_storage) = start_engine(config, None).await?;

    let policy = &config.sandbox.environment;
    let shell_result = if policy.set.is_empty() && policy.inherit.is_empty() {
        engine.shell().await
    } else {
        let (env, inherit) = build_sandbox_env(Some(config));
        engine.shell_with_environment(&env, &inherit).await
    };

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
async fn shell_on_session(config: &Config, sess: &Session) -> anyhow::Result<u8> {
    let mut client = sess.backend.connect_agent().await?;
    let policy = &config.sandbox.environment;
    let code = if policy.set.is_empty() && policy.inherit.is_empty() {
        izanagi::terminal_shell::interactive_shell(&mut client).await?
    } else {
        let (env, inherit) = build_sandbox_env(Some(config));
        izanagi::terminal_shell::interactive_shell_with_environment(&mut client, &env, &inherit)
            .await?
    };
    Ok(code.try_into().unwrap_or(1))
}

#[cfg(test)]
async fn qemu_interactive_shell(host_port: u16, token_hash: Option<&str>) -> anyhow::Result<u8> {
    let sess = Session {
        backend: izanagi::session::SessionBackend::Qemu {
            host_port,
            token_hash: token_hash.map(str::to_string),
        },
        pid: 0,
        started_at: 0,
    };
    let config = Config::default();
    shell_on_session(&config, &sess).await
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
    fn existing_session_shell_survives_fragmented_output_and_resize() {
        crate::pty_test_support::exercise(
            "commands::shell::tests::shell_runtime_probe",
            "fragment-resize",
        );
    }

    #[test]
    fn existing_session_shell_roundtrip_resize_exit_status_and_invalid_response() {
        for mode in ["roundtrip", "nonzero", "unexpected"] {
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
            "close" | "fragment-resize" | "roundtrip" => assert_eq!(result.unwrap(), 0),
            "nonzero" => assert_eq!(result.unwrap(), 42),
            "unexpected" => assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("unexpected shell response")
            ),
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
