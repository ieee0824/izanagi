use izanagi::exec_output::truncate_output;
use izanagi::session;

const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub(super) struct ExecOutput {
    pub(super) exit_code: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

/// Both backends execute through the authenticated agent, including its output limits.
pub(super) async fn exec_on_session_capture(
    sess: &session::Session,
    cmd: &[String],
) -> anyhow::Result<ExecOutput> {
    let (env, _) = super::build_sandbox_env(None);
    let output = tokio::time::timeout(
        EXEC_TIMEOUT,
        crate::commands::exec::exec_on_session_raw(sess, cmd, &env),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "agent exec がタイムアウトしました ({}秒)",
            EXEC_TIMEOUT.as_secs()
        )
    })??;
    Ok(ExecOutput {
        exit_code: output.exit_code,
        stdout: String::from_utf8_lossy(&truncate_output(output.stdout)).into_owned(),
        stderr: String::from_utf8_lossy(&truncate_output(output.stderr)).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use izanagi::exec_output::MAX_OUTPUT_SIZE;

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
