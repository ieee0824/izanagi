use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::Result;
use tokio::io::AsyncReadExt;

use crate::security::{EXEC_ERROR_PREFIX, sanitize_env, sanitize_exec_error, shell_escape};

/// 非特権ユーザー名。コマンド実行はこのユーザーで行う。
pub(crate) const EXEC_USER: &str = "izanagi";

/// コマンド実行のタイムアウト（秒）。デフォルト 300秒。
const EXEC_TIMEOUT_SECS: u64 = 300;

use izanagi::exec_output::{MAX_OUTPUT_SIZE, truncate_output};

/// EXEC_USER の存在チェック結果をキャッシュする。
/// VM 内でユーザーが動的に追加・削除されることはないため、起動後1回だけチェックすれば十分。
static EXEC_USER_EXISTS: OnceLock<bool> = OnceLock::new();

/// EXEC_USER が存在するか確認し、結果をキャッシュする。
async fn check_exec_user_exists() -> bool {
    if let Some(&cached) = EXEC_USER_EXISTS.get() {
        return cached;
    }
    let exists = tokio::process::Command::new("id")
        .arg(EXEC_USER)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = EXEC_USER_EXISTS.set(exists);
    exists
}

/// VM 内でコマンドを非特権ユーザーとして実行する。
/// agent 自体は root で動作するが（eBPF に必要）、
/// ユーザーから依頼されたコマンドは `EXEC_USER` に降格して実行する。
pub(crate) async fn execute_command(
    cmd: &[String],
    env: &HashMap<String, String>,
) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    if cmd.is_empty() {
        anyhow::bail!("{}: not found", EXEC_ERROR_PREFIX);
    }

    // コマンド allowlist の検証
    check_command_allowlist(&cmd[0])?;

    // 危険な環境変数を除外
    let env = sanitize_env(env);

    // EXEC_USER が存在するか確認（結果はキャッシュされる）
    let use_su = check_exec_user_exists().await;

    let mut child = spawn_exec(cmd, &env, use_su)?;
    collect_exec_output(&mut child, EXEC_TIMEOUT_SECS).await
}

fn spawn_exec(
    cmd: &[String],
    env: &HashMap<String, String>,
    user_exists: bool,
) -> Result<tokio::process::Child> {
    if !user_exists {
        anyhow::bail!(
            "execution user '{}' not found. Refusing to execute as root.",
            EXEC_USER
        );
    }
    // 非特権ユーザーとしてコマンドを実行。
    // su を使わず pre_exec 内で直接 setgid/setuid + prctl を行うことで、
    // exec 後も PR_SET_DUMPABLE=0 が維持され /proc/self/environ が保護される。
    // (su 経由だと su の exec 時に dumpable がリセットされる問題を回避)
    let cmd_str = cmd
        .iter()
        .map(|s| shell_escape(s))
        .collect::<Vec<_>>()
        .join(" ");

    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", &cmd_str])
        .env_clear()
        .envs(env)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", format!("/home/{}", EXEC_USER))
        .env("USER", EXEC_USER)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    configure_exec_credentials(&mut command);
    command.spawn().map_err(|e| sanitize_exec_error(&e))
}

fn configure_exec_credentials(command: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        #[allow(unused_imports)]
        use std::os::unix::process::CommandExt;
        let exec_user = EXEC_USER.to_string();
        unsafe {
            command.pre_exec(move || drop_exec_privileges(&exec_user));
        }
    }
}

#[cfg(unix)]
fn drop_exec_privileges(exec_user: &str) -> std::io::Result<()> {
    // Preserve the child setup order: session, group, user, then dumpability.
    unsafe {
        // 新しいプロセスグループを作成（タイムアウト時に孫プロセスも含めて kill するため）
        if libc::setsid() == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // 非特権ユーザーに権限降格
        let c_user = std::ffi::CString::new(exec_user)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
        }
        if libc::setgid((*pw).pw_gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setuid((*pw).pw_uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // /proc/self/environ のパーミッションを制限。
        // setuid 後かつ exec 前に設定するため、exec される /bin/sh と
        // その子プロセス (node 等) でも dumpable=0 が維持される。
        #[cfg(target_os = "linux")]
        if libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

async fn read_exec_pipe<R: tokio::io::AsyncRead + Unpin>(
    pipe: Option<R>,
) -> std::io::Result<Vec<u8>> {
    let read_limit = (MAX_OUTPUT_SIZE + 1) as u64;
    let mut buf = Vec::with_capacity(read_limit as usize);
    if let Some(mut pipe) = pipe {
        let mut limited = (&mut pipe).take(read_limit);
        tokio::io::AsyncReadExt::read_to_end(&mut limited, &mut buf).await?;
        // Drain beyond the retained cap to prevent pipe backpressure deadlocks.
        tokio::io::copy(&mut pipe, &mut tokio::io::sink()).await?;
    }
    Ok(buf)
}

async fn collect_exec_output(
    child: &mut tokio::process::Child,
    timeout_secs: u64,
) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    // Own both pipes before concurrently waiting and reading.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let wait_fut = async {
        let (status, stdout, stderr) =
            tokio::join!(child.wait(), read_exec_pipe(stdout), read_exec_pipe(stderr));
        Ok::<_, anyhow::Error>((status?, stdout?, stderr?))
    };
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), wait_fut).await {
        Ok(Ok((status, stdout_buf, stderr_buf))) => {
            let stdout = truncate_output(stdout_buf);
            let stderr = truncate_output(stderr_buf);
            Ok((status.code().unwrap_or(-1), stdout, stderr))
        }
        Ok(Err(e)) => {
            // 内部エラーの詳細をログに出して、抽象化されたメッセージを返す
            let _ = e;
            eprintln!("exec internal error");
            anyhow::bail!(EXEC_ERROR_PREFIX);
        }
        Err(_) => {
            kill_exec_group(child).await;
            eprintln!(
                "WARNING: command timed out after {} seconds, killed process group",
                timeout_secs
            );
            Ok((-1, Vec::new(), b"timeout".to_vec()))
        }
    }
}

async fn kill_exec_group(child: &mut tokio::process::Child) {
    // タイムアウト: プロセスグループ全体を kill して孫プロセスも含めて停止する
    #[cfg(unix)]
    if let Some(pid) = child.id()
        && let Ok(pid_i32) = i32::try_from(pid)
    {
        // 負の PID でプロセスグループ全体に SIGKILL を送信
        unsafe {
            libc::kill(-pid_i32, libc::SIGKILL);
        }
        // i32 変換失敗時は child.kill() にフォールバック
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

/// 環境変数 `IZANAGI_ALLOWED_COMMANDS` によるコマンド allowlist を検証する。
/// 未設定時はデフォルトで全コマンドを拒否（fail-closed）。
/// `IZANAGI_ALLOW_ALL_COMMANDS=1` を明示的に設定した場合のみ全許可。
/// allowlist はフルパスまたはファイル名で照合する。
fn check_command_allowlist(cmd: &str) -> Result<()> {
    let allowed = match std::env::var("IZANAGI_ALLOWED_COMMANDS") {
        Ok(val) if !val.is_empty() => val,
        _ => {
            // allowlist 未設定: 明示的なオプトインがなければ拒否
            if std::env::var("IZANAGI_ALLOW_ALL_COMMANDS").unwrap_or_default() == "1" {
                return Ok(());
            }
            eprintln!("WARNING: IZANAGI_ALLOWED_COMMANDS not set, rejecting command (fail-closed)");
            anyhow::bail!("{}: no allowlist configured", EXEC_ERROR_PREFIX);
        }
    };

    let cmd_path = std::path::Path::new(cmd);
    let cmd_name = cmd_path.file_name().and_then(|n| n.to_str()).unwrap_or(cmd);

    let allowlist: Vec<&str> = allowed.split(',').map(|s| s.trim()).collect();

    // フルパスで一致するか、ファイル名で一致するか
    let allowed = allowlist.iter().any(|entry| {
        let entry_path = std::path::Path::new(entry);
        if entry_path.is_absolute() {
            // allowlist にフルパスが指定されている場合、フルパスで比較
            *entry == cmd
        } else {
            // allowlist にファイル名が指定されている場合、ファイル名で比較
            *entry == cmd_name
        }
    });

    if allowed {
        Ok(())
    } else {
        eprintln!("WARNING: command not in allowlist");
        anyhow::bail!("{}: not allowed", EXEC_ERROR_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn large_output_is_drained_and_both_streams_are_truncated() {
        let size = MAX_OUTPUT_SIZE + 1024;
        let mut child = tokio::process::Command::new("/bin/sh")
            .args([
                "-c",
                &format!("head -c {size} /dev/zero; head -c {size} /dev/zero >&2"),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let (code, stdout, stderr) = super::collect_exec_output(&mut child, 5).await.unwrap();
        assert_eq!(code, 0);
        for output in [stdout, stderr] {
            assert_eq!(output.len(), MAX_OUTPUT_SIZE + b"\n[truncated]".len());
            assert!(output.ends_with(b"\n[truncated]"));
        }
        assert!(child.id().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_out_command_is_killed_and_reaped() {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exec sleep 60"])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let result = super::collect_exec_output(&mut child, 0).await.unwrap();
        assert_eq!(result, (-1, Vec::new(), b"timeout".to_vec()));
        assert!(child.id().is_none());
    }

    use super::*;

    /// 環境変数を操作するテストの排他制御用。テストの並行実行で競合を防ぐ。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 環境変数を RAII で管理するガード。Drop 時に確実にクリーンアップする。
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        vars: Vec<&'static str>,
    }

    impl EnvGuard {
        fn new(vars: &[(&'static str, Option<&str>)]) -> Self {
            let lock = ENV_LOCK.lock().unwrap();
            for &(key, val) in vars {
                unsafe {
                    match val {
                        Some(v) => std::env::set_var(key, v),
                        None => std::env::remove_var(key),
                    }
                }
            }
            Self {
                _lock: lock,
                vars: vars.iter().map(|&(k, _)| k).collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in &self.vars {
                unsafe { std::env::remove_var(key) };
            }
        }
    }

    #[test]
    fn truncate_output_within_limit() {
        let data = vec![0u8; 100];
        let result = truncate_output(data);
        assert_eq!(result.len(), 100);
    }

    #[test]
    fn truncate_output_exceeds_limit() {
        let data = vec![0u8; MAX_OUTPUT_SIZE + 100];
        let result = truncate_output(data);
        // MAX_OUTPUT_SIZE に切り詰め + "\n[truncated]" が付加される
        assert_eq!(result.len(), MAX_OUTPUT_SIZE + b"\n[truncated]".len());
        assert!(result.ends_with(b"\n[truncated]"));
    }

    // --- Task 353: command allowlist tests ---
    //
    // 環境変数を操作するテストは EnvGuard で排他制御 + パニック時もクリーンアップする。

    #[test]
    fn allowlist_rejects_when_not_configured() {
        let _g = EnvGuard::new(&[
            ("IZANAGI_ALLOWED_COMMANDS", None),
            ("IZANAGI_ALLOW_ALL_COMMANDS", None),
        ]);
        assert!(check_command_allowlist("echo").is_err());
    }

    #[test]
    fn allowlist_allows_matching_command_name() {
        let _g = EnvGuard::new(&[
            ("IZANAGI_ALLOWED_COMMANDS", Some("echo,ls,cat")),
            ("IZANAGI_ALLOW_ALL_COMMANDS", None),
        ]);
        assert!(check_command_allowlist("echo").is_ok());
        assert!(check_command_allowlist("ls").is_ok());
        assert!(check_command_allowlist("cat").is_ok());
    }

    #[test]
    fn allowlist_rejects_non_matching_command() {
        let _g = EnvGuard::new(&[
            ("IZANAGI_ALLOWED_COMMANDS", Some("echo,ls")),
            ("IZANAGI_ALLOW_ALL_COMMANDS", None),
        ]);
        assert!(check_command_allowlist("rm").is_err());
    }

    #[test]
    fn allowlist_matches_full_path() {
        let _g = EnvGuard::new(&[
            ("IZANAGI_ALLOWED_COMMANDS", Some("/usr/bin/echo")),
            ("IZANAGI_ALLOW_ALL_COMMANDS", None),
        ]);
        assert!(check_command_allowlist("/usr/bin/echo").is_ok());
        assert!(check_command_allowlist("echo").is_err());
    }

    #[test]
    fn allowlist_basename_match_for_full_path_command() {
        let _g = EnvGuard::new(&[
            ("IZANAGI_ALLOWED_COMMANDS", Some("echo")),
            ("IZANAGI_ALLOW_ALL_COMMANDS", None),
        ]);
        assert!(check_command_allowlist("/usr/bin/echo").is_ok());
    }

    #[test]
    fn allow_all_commands_bypasses_allowlist() {
        let _g = EnvGuard::new(&[
            ("IZANAGI_ALLOWED_COMMANDS", None),
            ("IZANAGI_ALLOW_ALL_COMMANDS", Some("1")),
        ]);
        assert!(check_command_allowlist("anything").is_ok());
    }

    // --- Task 354: execute_command edge cases ---

    #[tokio::test]
    async fn execute_command_empty_cmd_fails() {
        let result = execute_command(&[], &Default::default()).await;
        assert!(result.is_err());
    }
}
