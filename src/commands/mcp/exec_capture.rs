use std::collections::HashMap;
use std::process::Stdio;

use anyhow::Context;
use izanagi::session;
use tokio::io::AsyncReadExt;

use izanagi::exec_output::{MAX_OUTPUT_SIZE, truncate_output};

/// drain の上限 (64 MB)。超過分は読み捨てず子プロセスをブロックさせる。
const MAX_DRAIN_SIZE: u64 = 64 * 1024 * 1024;

/// Apple Container exec のコマンド実行タイムアウト (300秒)。agent 側と同じ制限。
const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// コマンド実行結果を保持する構造体。
pub(super) struct ExecOutput {
    pub(super) exit_code: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

/// セッションに接続してコマンドを実行し、結果をキャプチャして返す。
///
/// exec.rs の `exec_on_session` は stdout/stderr を直接 print するため MCP には使えない。
/// この関数は出力を文字列としてキャプチャする。
pub(super) async fn exec_on_session_capture(
    sess: &session::Session,
    cmd: &[String],
) -> anyhow::Result<ExecOutput> {
    let env = super::build_sandbox_env();

    match &sess.backend {
        session::SessionBackend::AppleContainer {
            container_name,
            mount_point,
            ..
        } => exec_on_container_session_capture(container_name, mount_point, cmd, &env).await,
        session::SessionBackend::Qemu {
            host_port,
            token_hash,
        } => exec_on_qemu_session_capture(*host_port, token_hash.clone(), cmd, &env).await,
    }
}

async fn exec_on_container_session_capture(
    container_name: &str,
    mount_point: &str,
    cmd: &[String],
    env: &HashMap<String, String>,
) -> anyhow::Result<ExecOutput> {
    let args =
        izanagi::apple_container_sandbox::build_exec_args(container_name, cmd, env, mount_point);

    let mut child = tokio::process::Command::new("container")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("container exec の実行に失敗")?;

    let child_stdout = child.stdout.take().expect("stdout must be piped");
    let child_stderr = child.stderr.take().expect("stderr must be piped");
    let exec_fut = async {
        tokio::try_join!(
            capture_pipe(child_stdout),
            capture_pipe(child_stderr),
            child.wait()
        )
    };

    match tokio::time::timeout(EXEC_TIMEOUT, exec_fut).await {
        Ok(Ok((stdout_raw, stderr_raw, status))) => Ok(ExecOutput {
            exit_code: status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&truncate_output(stdout_raw)).into_owned(),
            stderr: String::from_utf8_lossy(&truncate_output(stderr_raw)).into_owned(),
        }),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            anyhow::bail!(
                "container exec がタイムアウトしました ({}秒)",
                EXEC_TIMEOUT.as_secs()
            );
        }
    }
}

async fn capture_pipe(mut pipe: impl tokio::io::AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64 * 1024);
    let read_limit = (MAX_OUTPUT_SIZE + 1) as u64;
    let mut limited = (&mut pipe).take(read_limit);
    limited.read_to_end(&mut buf).await?;
    // Drain with the same cap; dropping the pipe closes it if the cap is reached.
    let drained = tokio::io::copy(
        &mut (&mut pipe).take(MAX_DRAIN_SIZE),
        &mut tokio::io::sink(),
    )
    .await?;
    if drained >= MAX_DRAIN_SIZE {
        drop(pipe);
    }
    Ok(buf)
}

/// QEMU バックエンド向けキャプチャ版 exec。共通ヘルパーを利用。タイムアウト付き。
async fn exec_on_qemu_session_capture(
    host_port: u16,
    token_hash: Option<String>,
    cmd: &[String],
    env: &HashMap<String, String>,
) -> anyhow::Result<ExecOutput> {
    let raw_fut = crate::commands::exec::exec_on_qemu_raw(host_port, token_hash, cmd, env);
    let (exit_code, stdout, stderr) =
        tokio::time::timeout(EXEC_TIMEOUT, raw_fut)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "QEMU exec がタイムアウトしました ({}秒)",
                    EXEC_TIMEOUT.as_secs()
                )
            })??;
    Ok(ExecOutput {
        exit_code,
        stdout: String::from_utf8_lossy(&truncate_output(stdout)).into_owned(),
        stderr: String::from_utf8_lossy(&truncate_output(stderr)).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capture_retains_only_output_prefix_and_drains_both_pipes() {
        let (mut stdout_writer, stdout) = tokio::io::duplex(128);
        let (mut stderr_writer, stderr) = tokio::io::duplex(128);
        let size = (MAX_OUTPUT_SIZE + 4096) as u64;
        let writers = async {
            let mut stdout_bytes = tokio::io::repeat(b'o').take(size);
            let mut stderr_bytes = tokio::io::repeat(b'e').take(size);
            tokio::try_join!(
                tokio::io::copy(&mut stdout_bytes, &mut stdout_writer),
                tokio::io::copy(&mut stderr_bytes, &mut stderr_writer),
            )
            .unwrap();
            drop((stdout_writer, stderr_writer));
        };
        let capture = async { tokio::try_join!(capture_pipe(stdout), capture_pipe(stderr)) };
        let (_, result) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(writers, capture)
        })
        .await
        .unwrap();
        let (stdout, stderr) = result.unwrap();
        assert_eq!(stdout, vec![b'o'; MAX_OUTPUT_SIZE + 1]);
        assert_eq!(stderr, vec![b'e'; MAX_OUTPUT_SIZE + 1]);
    }

    #[test]
    fn truncate_output_under_limit() {
        let data = vec![0u8; 100];
        let result = truncate_output(data.clone());
        assert_eq!(result, data);
    }

    #[test]
    fn truncate_output_at_limit() {
        let data = vec![0u8; MAX_OUTPUT_SIZE];
        let result = truncate_output(data.clone());
        assert_eq!(result, data);
    }

    #[test]
    fn truncate_output_over_limit() {
        let data = vec![0u8; MAX_OUTPUT_SIZE + 1000];
        let result = truncate_output(data);
        assert_eq!(result.len(), MAX_OUTPUT_SIZE + b"\n[truncated]".len());
        assert!(result.ends_with(b"\n[truncated]"));
    }
}
