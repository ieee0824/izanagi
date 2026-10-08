use std::collections::HashMap;

use anyhow::Context;
use izanagi::config::Config;
use izanagi::session::{self, Session, SessionBackend};

use super::{acquire_instance_lock, build_sandbox_env, izanagi_dir, start_engine, stop_engine};

pub async fn cmd_exec(config: &Config, cmd: &[String]) -> anyhow::Result<u8> {
    if cmd.is_empty() {
        anyhow::bail!("実行するコマンドを指定してください");
    }

    // up 中のセッションがあればそこに接続
    if let Some(sess) = session::load_session(&izanagi_dir())?
        && session::is_session_alive(&sess)
    {
        return exec_on_session(&sess, cmd).await;
    }

    // セッションがなければ単発起動
    let _lock = acquire_instance_lock()?;

    let (engine, log_storage) = start_engine(config, None).await?;

    let exec_result = {
        let env = build_sandbox_env();

        tokio::select! {
            result = engine.exec(cmd, &env) => {
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
pub(crate) async fn exec_on_session(sess: &Session, cmd: &[String]) -> anyhow::Result<u8> {
    let env = build_sandbox_env();

    match &sess.backend {
        SessionBackend::AppleContainer {
            container_name,
            mount_point,
            ..
        } => {
            let args = izanagi::apple_container_sandbox::build_exec_args(
                container_name,
                cmd,
                &env,
                mount_point,
            );

            let output = tokio::process::Command::new("container")
                .args(&args)
                .output()
                .await
                .context("container exec の実行に失敗")?;

            if !output.stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
            }
            Ok(output
                .status
                .code()
                .and_then(|c| u8::try_from(c).ok())
                .unwrap_or(1))
        }
        SessionBackend::Qemu {
            host_port,
            token_hash,
        } => exec_on_qemu_session(*host_port, token_hash.clone(), cmd, &env).await,
    }
}

/// QEMU agent に接続してコマンドを実行し、生の結果を返す共通ヘルパー。
/// exec.rs と exec_capture.rs の両方から利用される。
pub(crate) async fn exec_on_qemu_raw(
    host_port: u16,
    token_hash: Option<String>,
    cmd: &[String],
    env: &HashMap<String, String>,
) -> anyhow::Result<(i32, Vec<u8>, Vec<u8>)> {
    let addr = format!("127.0.0.1:{}", host_port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| format!("agent への接続に失敗: {}", addr))?;
    let (reader, writer) = tokio::io::split(stream);

    let secret = izanagi::protocol::load_shared_secret_from_env()?;
    let mut client = izanagi::protocol_client::ProtocolClient::new(reader, writer, secret);

    client.handshake_and_wait_ready(token_hash).await?;

    let exec_msg = izanagi::protocol::Message::Exec {
        cmd: cmd.to_vec(),
        env: env.clone(),
    };
    client.send_message(&exec_msg).await?;

    match client.recv_message().await? {
        Some(izanagi::protocol::Message::ExecResult {
            exit_code,
            stdout,
            stderr,
        }) => Ok((exit_code, stdout, stderr)),
        Some(izanagi::protocol::Message::Error(e)) => {
            anyhow::bail!("exec error: {}", e);
        }
        other => anyhow::bail!("unexpected response: {:?}", other),
    }
}

async fn exec_on_qemu_session(
    host_port: u16,
    token_hash: Option<String>,
    cmd: &[String],
    env: &HashMap<String, String>,
) -> anyhow::Result<u8> {
    let (exit_code, stdout, stderr) = exec_on_qemu_raw(host_port, token_hash, cmd, env).await?;
    if !stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&stdout));
    }
    if !stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&stderr));
    }
    Ok(u8::try_from(exit_code).unwrap_or(1))
}
