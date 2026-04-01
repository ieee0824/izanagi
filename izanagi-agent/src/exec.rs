use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::Result;
use tokio::io::AsyncReadExt;

use crate::security::{sanitize_env, sanitize_exec_error, shell_escape, EXEC_ERROR_PREFIX};

/// 非特権ユーザー名。コマンド実行はこのユーザーで行う。
pub(crate) const EXEC_USER: &str = "izanagi";

/// コマンド実行のタイムアウト（秒）。デフォルト 300秒。
const EXEC_TIMEOUT_SECS: u64 = 300;

/// 出力サイズの上限 (512KB)。
const MAX_OUTPUT_SIZE: usize = 512 * 1024;

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

    let mut child = if use_su {
        // 非特権ユーザーとしてコマンドを実行。
        // su を使わず pre_exec 内で直接 setgid/setuid + prctl を行うことで、
        // exec 後も PR_SET_DUMPABLE=0 が維持され /proc/self/environ が保護される。
        // (su 経由だと su の exec 時に dumpable がリセットされる問題を回避)
        let cmd_str = cmd
            .iter()
            .map(|s| shell_escape(s))
            .collect::<Vec<_>>()
            .join(" ");

        let exec_user = EXEC_USER.to_string();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", &cmd_str])
            .env_clear()
            .envs(&env)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", format!("/home/{}", EXEC_USER))
            .env("USER", EXEC_USER)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        {
            #[allow(unused_imports)]
            use std::os::unix::process::CommandExt;
            unsafe {
                command.pre_exec(move || {
                    // 新しいプロセスグループを作成（タイムアウト時に孫プロセスも含めて kill するため）
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    // 非特権ユーザーに権限降格
                    let c_user = std::ffi::CString::new(exec_user.as_str())
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
                });
            }
        }
        command.spawn().map_err(|e| sanitize_exec_error(&e))?
    } else {
        anyhow::bail!(
            "execution user '{}' not found. Refusing to execute as root.",
            EXEC_USER
        );
    };

    // stdout/stderr のハンドルを取り出す（wait と並行読み取りするため所有権を分離）
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // タイムアウト付きで子プロセスの完了を待つ
    let timeout_secs = EXEC_TIMEOUT_SECS;
    let timeout_duration = std::time::Duration::from_secs(timeout_secs);

    // stdout/stderr の読み取りと wait を並行実行（デッドロック防止）
    //
    // take(MAX_OUTPUT_SIZE + 1) でメモリ使用量を制限する (#190)。
    // +1 バイトで truncation を検出し、後段の truncate_output() で正確に切り詰める。
    // take() 後も残りのストリームを drain して、子プロセスがパイプ詰まりで
    // ハングするのを防止する。
    let read_limit = (MAX_OUTPUT_SIZE + 1) as u64;
    let wait_fut = async {
        let stdout_fut = async {
            let mut buf = Vec::with_capacity(read_limit as usize);
            if let Some(mut out) = child_stdout {
                let mut limited = (&mut out).take(read_limit);
                tokio::io::AsyncReadExt::read_to_end(&mut limited, &mut buf).await?;
                // 残りを読み捨ててパイプ詰まりを防止
                tokio::io::copy(&mut out, &mut tokio::io::sink()).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };
        let stderr_fut = async {
            let mut buf = Vec::with_capacity(read_limit as usize);
            if let Some(mut err) = child_stderr {
                let mut limited = (&mut err).take(read_limit);
                tokio::io::AsyncReadExt::read_to_end(&mut limited, &mut buf).await?;
                // 残りを読み捨ててパイプ詰まりを防止
                tokio::io::copy(&mut err, &mut tokio::io::sink()).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };

        let (status, stdout_result, stderr_result) =
            tokio::join!(child.wait(), stdout_fut, stderr_fut);
        let status = status?;
        let stdout_buf = stdout_result?;
        let stderr_buf = stderr_result?;
        Ok::<_, anyhow::Error>((status, stdout_buf, stderr_buf))
    };

    match tokio::time::timeout(timeout_duration, wait_fut).await {
        Ok(Ok((status, stdout_buf, stderr_buf))) => {
            let stdout = truncate_output(stdout_buf);
            let stderr = truncate_output(stderr_buf);
            Ok((status.code().unwrap_or(-1), stdout, stderr))
        }
        Ok(Err(e)) => {
            // 内部エラーの詳細をログに出して、抽象化されたメッセージを返す
            eprintln!("exec internal error: {}", e);
            anyhow::bail!(EXEC_ERROR_PREFIX);
        }
        Err(_) => {
            // タイムアウト: プロセスグループ全体を kill して孫プロセスも含めて停止する
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                if let Ok(pid_i32) = i32::try_from(pid) {
                    // 負の PID でプロセスグループ全体に SIGKILL を送信
                    unsafe {
                        libc::kill(-pid_i32, libc::SIGKILL);
                    }
                }
                // i32 変換失敗時は child.kill() にフォールバック
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            eprintln!(
                "WARNING: command timed out after {} seconds, killed process group",
                timeout_secs
            );
            Ok((-1, Vec::new(), b"timeout".to_vec()))
        }
    }
}

/// 出力が `MAX_OUTPUT_SIZE` を超えた場合に切り詰め、末尾に `\n[truncated]` を付加する。
fn truncate_output(mut data: Vec<u8>) -> Vec<u8> {
    if data.len() > MAX_OUTPUT_SIZE {
        data.truncate(MAX_OUTPUT_SIZE);
        data.extend_from_slice(b"\n[truncated]");
    }
    data
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
        eprintln!("WARNING: command '{}' not in allowlist", cmd_name);
        anyhow::bail!("{}: not allowed", EXEC_ERROR_PREFIX)
    }
}

#[cfg(test)]
mod tests {
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
