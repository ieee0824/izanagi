use std::collections::HashMap;

use izanagi::config::Config;
use izanagi::session::{self, Session};

use super::{acquire_instance_lock, build_sandbox_env, izanagi_dir, start_engine, stop_engine};

pub async fn cmd_exec(config: &Config, cmd: &[String]) -> anyhow::Result<u8> {
    if cmd.is_empty() {
        anyhow::bail!("実行するコマンドを指定してください");
    }

    // up 中のセッションがあればそこに接続
    if let Some(sess) = session::load_session(&izanagi_dir())?
        && session::is_session_alive(&sess)
    {
        return exec_on_session(config, &sess, cmd).await;
    }

    // セッションがなければ単発起動
    let _lock = acquire_instance_lock()?;

    let (engine, log_storage) = start_engine(config, None).await?;

    let exec_result = {
        let (env, inherit) = build_sandbox_env(Some(config));

        tokio::select! {
            result = async {
                if inherit.is_empty() {
                    engine.exec(cmd, &env).await
                } else {
                    engine.exec_with_environment(cmd, &env, &inherit).await
                }
            } => {
                match result {
                    Ok(output) => {
                        if !output.stdout.is_empty() {
                            print!("{}", String::from_utf8_lossy(&output.stdout));
                        }
                        if !output.stderr.is_empty() {
                            eprint!("{}", String::from_utf8_lossy(&output.stderr));
                        }
                        Ok::<u8, anyhow::Error>(u8::try_from(output.exit_code).unwrap_or(1))
                    }
                    Err(e) => Err(e),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n中断されました。クリーンアップ中...");
                Ok(130) // 128 + SIGINT(2)
            }
        }
    };

    stop_engine(engine, &log_storage).await;

    exec_result
}

/// up 中のセッションに接続してコマンドを実行する。
pub(crate) async fn exec_on_session(
    config: &Config,
    sess: &Session,
    cmd: &[String],
) -> anyhow::Result<u8> {
    let (env, inherit) = build_sandbox_env(Some(config));

    let output = if inherit.is_empty() {
        exec_on_session_raw(sess, cmd, &env).await?
    } else {
        exec_on_session_raw_with_environment(sess, cmd, &env, &inherit).await?
    };
    if !output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(u8::try_from(output.exit_code).unwrap_or(1))
}

/// CLI/MCP share the same authenticated connection and agent execution path.
pub(crate) async fn exec_on_session_raw(
    sess: &Session,
    cmd: &[String],
    env: &HashMap<String, String>,
) -> anyhow::Result<izanagi::sandbox::ExecOutput> {
    let mut client = sess.backend.connect_agent().await?;
    izanagi::agent_session::execute(&mut client, cmd, env).await
}

pub(crate) async fn exec_on_session_raw_with_environment(
    sess: &Session,
    cmd: &[String],
    env: &HashMap<String, String>,
    inherit: &[String],
) -> anyhow::Result<izanagi::sandbox::ExecOutput> {
    let mut client = sess.backend.connect_agent().await?;
    izanagi::agent_session::execute_with_environment(&mut client, cmd, env, inherit).await
}
