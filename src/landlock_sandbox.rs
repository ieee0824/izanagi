//! Linux Landlock ベースの軽量サンドボックス実装。
//!
//! `ShareConfig` から Landlock ルールセットを構築し、
//! `self_restrict` 後に子プロセスを起動する。
//! カーネル 5.13+ (Landlock ABI v1+) が必要。

use std::collections::HashMap;

use crate::sandbox::{ExecOutput, Sandbox, SandboxConfig, SandboxStatus, ShareConfig};

// ============================================================
// Linux + landlock feature: 実機実装
// ============================================================

#[cfg(all(target_os = "linux", feature = "landlock"))]
mod inner {
    use super::*;
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetError, RulesetStatus,
    };
    use std::os::unix::process::CommandExt;

    // apply_ruleset_inner 内の async-signal-safe な write(2) と ENOSYS 用
    use libc;

    /// 利用可能な Landlock ABI バージョンを検出する。
    /// `landlock_create_ruleset(2)` の VERSION クエリを使用し、
    /// カーネルが Landlock 非対応または無効な場合は `None` を返す。
    ///
    /// この実装がルール構築で対応している最新ABIはV3なので、より新しい
    /// カーネルではV3へ丸める。
    pub fn detect_abi() -> Option<ABI> {
        const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
        let version = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        match version {
            v if v >= 3 => Some(ABI::V3),
            2 => Some(ABI::V2),
            1 => Some(ABI::V1),
            _ => None,
        }
    }

    /// `ShareConfig` から Landlock ルールセットを構築する（`restrict_self` はまだ呼ばない）。
    ///
    /// ルールセット構築は heap allocation を伴うため、`pre_exec` 内ではなく
    /// fork 前に行い、`pre_exec` 内では `restrict_self()` のみ呼ぶ。
    pub fn build_ruleset(
        share: &ShareConfig,
        abi: ABI,
    ) -> anyhow::Result<landlock::RulesetCreated> {
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .create()?;

        // host_paths は読み書き可能
        for path in &share.host_paths {
            let fd = PathFd::new(path)?;
            ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))?;
        }

        // NOTE: share.mount_point はゲスト側パス（例: "/workspace"）であり、
        // Landlock はホスト側カーネルで適用されるためルールに含めない。
        // ホスト側のパスは host_paths で指定される。

        // /tmp は読み書きのみに制限（シンボリックリンク作成や Refer 等は除外）
        {
            let tmp_access = AccessFs::ReadFile
                | AccessFs::WriteFile
                | AccessFs::ReadDir
                | AccessFs::RemoveFile
                | AccessFs::MakeReg;
            let fd = PathFd::new("/tmp")?;
            ruleset = ruleset.add_rule(PathBeneath::new(fd, tmp_access))?;
        }

        ruleset = allow_runtime_directories(ruleset)?;

        ruleset = allow_system_configuration(ruleset)?;

        ruleset = allow_process_metadata(ruleset)?;

        // /sys: デフォルト deny のまま。明示的な許可は行わない。
        // /proc, /sys 全体はルールに含まれないため Landlock の deny-by-default で制限される。

        Ok(ruleset)
    }

    fn allow_runtime_directories(
        mut ruleset: landlock::RulesetCreated,
    ) -> anyhow::Result<landlock::RulesetCreated> {
        // 基本的な読み取り・実行専用パス（ディレクトリ単位）。
        // Execute がないと Landlock 適用後に /bin/bash や /usr/bin/* を
        // execve(2) できないため、書き込み権限とは分離して明示的に許可する。
        let readonly_dirs = ["/usr", "/lib", "/lib64", "/bin", "/sbin"];
        let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
        let read_execute_access = read_access | AccessFs::Execute;
        for p in &readonly_dirs {
            let path = std::path::Path::new(p);
            if path.exists() {
                let fd = PathFd::new(path)?;
                ruleset = ruleset.add_rule(PathBeneath::new(fd, read_execute_access))?;
            }
        }

        Ok(ruleset)
    }

    fn allow_system_configuration(
        mut ruleset: landlock::RulesetCreated,
    ) -> anyhow::Result<landlock::RulesetCreated> {
        let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
        // /etc は全体を許可せず、必要最小限のファイル/ディレクトリのみ読み取り許可
        // /etc/shadow 等の機密ファイルへのアクセスを防ぐため
        let readonly_etc_paths = [
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/ld.so.cache",
            "/etc/ssl/certs",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
        ];
        for p in &readonly_etc_paths {
            let path = std::path::Path::new(p);
            if path.exists() {
                let fd = PathFd::new(path)?;
                let access = if path.is_dir() {
                    read_access
                } else {
                    AccessFs::ReadFile.into()
                };
                ruleset = ruleset.add_rule(PathBeneath::new(fd, access))?;
            }
        }

        Ok(ruleset)
    }

    fn allow_process_metadata(
        mut ruleset: landlock::RulesetCreated,
    ) -> anyhow::Result<landlock::RulesetCreated> {
        // /proc: デフォルト deny。一部プログラムが必要とする最小限のエントリのみ許可。
        // /proc/self/environ は明示的に許可しない（環境変数窃取の防止）。
        let readonly_proc_paths = ["/proc/self/status", "/proc/self/maps", "/proc/self/exe"];
        for p in &readonly_proc_paths {
            let path = std::path::Path::new(p);
            if path.exists() {
                let fd = PathFd::new(path)?;
                ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::ReadFile))?;
            }
        }

        Ok(ruleset)
    }

    fn exec_with_ruleset(
        share: &ShareConfig,
        abi: ABI,
        cmd: &[String],
        env: &HashMap<String, String>,
    ) -> std::io::Result<std::process::Output> {
        use std::process::{Command, Stdio};

        // ルールセット構築は fork 前に完了（heap allocation を伴う）
        let mut ruleset = Some(build_ruleset(share, abi).map_err(std::io::Error::other)?);

        // Safety: pre_exec 内では restrict_self() のみ呼ぶ（async-signal-safe）
        // apply_ruleset は std::io::Result を返し、ヒープアロケーションを行わない
        unsafe {
            Command::new(&cmd[0])
                .args(&cmd[1..])
                .env_clear()
                .envs(env)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .pre_exec(move || match ruleset.take() {
                    Some(ruleset) => apply_ruleset(ruleset),
                    None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                })
                .output()
        }
    }

    /// 構築済みルールセットを現在のプロセスに適用する。
    ///
    /// **この関数は `pre_exec` 内から呼ばれることを想定しており、
    /// ヒープアロケーションを一切行わない。**
    /// 返り値は `std::io::Result<()>` で、エラー時も静的文字列のみ使用する。
    /// `restrict_self()` は Landlock syscall のみで async-signal-safe。
    /// ルールセット構築は `build_ruleset()` で fork 前に完了しておくこと。
    ///
    /// `PartiallyEnforced` はデフォルトでエラー（fail-closed）。
    /// 部分適用を許可する場合は `apply_ruleset_allow_partial()` を使用する。
    pub fn apply_ruleset(ruleset: landlock::RulesetCreated) -> std::io::Result<()> {
        apply_ruleset_inner(ruleset, false)
    }

    /// `PartiallyEnforced` を許可するバリアント。
    /// カーネルが古い環境で明示的にオプトインする場合に使用する。
    #[allow(dead_code)]
    pub fn apply_ruleset_allow_partial(ruleset: landlock::RulesetCreated) -> std::io::Result<()> {
        apply_ruleset_inner(ruleset, true)
    }

    /// `RulesetError` から元の OS エラーコードを抽出する。
    /// ヒープアロケーションなしで `std::io::Error` に変換する。
    fn ruleset_error_to_io(e: RulesetError) -> std::io::Error {
        use std::error::Error;
        // source チェーンを辿って io::Error の raw_os_error を取得
        let mut source: Option<&(dyn Error + 'static)> = Some(&e);
        while let Some(err) = source {
            if let Some(io_err) = err.downcast_ref::<std::io::Error>()
                && let Some(code) = io_err.raw_os_error()
            {
                return std::io::Error::from_raw_os_error(code);
            }
            source = err.source();
        }
        // OS エラーコードが取得できない場合のフォールバック
        std::io::Error::from_raw_os_error(libc::ENOSYS)
    }

    /// `apply_ruleset` の内部実装。ヒープアロケーションを一切行わない。
    fn apply_ruleset_inner(
        ruleset: landlock::RulesetCreated,
        allow_partial: bool,
    ) -> std::io::Result<()> {
        let status = ruleset.restrict_self().map_err(ruleset_error_to_io)?;
        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(()),
            RulesetStatus::PartiallyEnforced if allow_partial => {
                let msg = b"WARNING: Landlock ruleset is only partially enforced.\n";
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                }
                Ok(())
            }
            RulesetStatus::PartiallyEnforced => {
                let msg = b"FATAL: Landlock ruleset only partially enforced. Aborting.\n";
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                }
                Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
            }
            RulesetStatus::NotEnforced => {
                let msg = b"FATAL: Landlock ruleset was not enforced by the kernel.\n";
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                }
                Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
            }
        }
    }

    /// `ShareConfig` から Landlock ルールセットを構築して self_restrict する。
    /// テストや単純な呼び出し用の便利関数。
    #[allow(dead_code)]
    pub fn apply_landlock(share: &ShareConfig, abi: ABI) -> anyhow::Result<()> {
        let ruleset = build_ruleset(share, abi)?;
        apply_ruleset(ruleset)?;
        Ok(())
    }

    pub struct LandlockSandbox {
        pub(crate) status: SandboxStatus,
        pub(crate) share: Option<ShareConfig>,
        pub(crate) abi: Option<ABI>,
    }

    impl Default for LandlockSandbox {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LandlockSandbox {
        pub fn new() -> Self {
            Self {
                status: SandboxStatus::Stopped,
                share: None,
                abi: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl Sandbox for LandlockSandbox {
        async fn up(&mut self, config: &SandboxConfig) -> anyhow::Result<()> {
            if self.status != SandboxStatus::Stopped {
                anyhow::bail!(
                    "Sandbox is not in Stopped state (current: {:?})",
                    self.status
                );
            }

            self.status = SandboxStatus::Starting;

            let share = match config {
                SandboxConfig::Landlock { share } => share.clone(),
                _ => {
                    self.status = SandboxStatus::Stopped;
                    anyhow::bail!("LandlockSandbox requires SandboxConfig::Landlock");
                }
            };

            let abi = detect_abi().ok_or_else(|| {
                self.status = SandboxStatus::Stopped;
                anyhow::anyhow!("Landlock is not supported on this kernel")
            })?;

            self.share = Some(share);
            self.abi = Some(abi);
            self.status = SandboxStatus::Running;

            Ok(())
        }

        async fn exec(
            &self,
            cmd: &[String],
            env: &HashMap<String, String>,
        ) -> anyhow::Result<ExecOutput> {
            if self.status != SandboxStatus::Running {
                anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
            }

            if cmd.is_empty() {
                anyhow::bail!("Command must not be empty");
            }

            let share = self
                .share
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("ShareConfig not set"))?;
            let abi = self
                .abi
                .ok_or_else(|| anyhow::anyhow!("ABI not detected"))?;

            // 子プロセスを fork し、子側で Landlock を適用してから exec する。
            // Landlock の restrict_self() は呼び出したスレッドとその子に適用されるため、
            // 安全に fork + restrict + exec のパターンを使う。
            let share_clone = share.clone();
            let env_clone = env.clone();
            let cmd_clone: Vec<String> = cmd.to_vec();

            let output = tokio::task::spawn_blocking(move || {
                exec_with_ruleset(&share_clone, abi, &cmd_clone, &env_clone)
            })
            .await??;

            Ok(ExecOutput {
                exit_code: output.status.code().unwrap_or(-1),
                stdout: output.stdout,
                stderr: output.stderr,
            })
        }

        async fn shell(&self) -> anyhow::Result<()> {
            if self.status != SandboxStatus::Running {
                anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
            }

            let share = self
                .share
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("ShareConfig not set"))?;
            let abi = self
                .abi
                .ok_or_else(|| anyhow::anyhow!("ABI not detected"))?;

            let share_clone = share.clone();

            let status = tokio::task::spawn_blocking(move || {
                use std::process::{Command, Stdio};

                // ルールセット構築は fork 前に完了（heap allocation を伴う）
                let mut ruleset =
                    Some(build_ruleset(&share_clone, abi).map_err(std::io::Error::other)?);

                // Safety: pre_exec 内では restrict_self() のみ呼ぶ（async-signal-safe）
                // apply_ruleset は std::io::Result を返し、ヒープアロケーションを行わない
                unsafe {
                    Command::new("/bin/bash")
                        .env_clear()
                        .env("HOME", std::env::var("HOME").unwrap_or_default())
                        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                        .env("TERM", std::env::var("TERM").unwrap_or_default())
                        .stdin(Stdio::inherit())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .pre_exec(move || match ruleset.take() {
                            Some(ruleset) => apply_ruleset(ruleset),
                            None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                        })
                        .status()
                }
            })
            .await??;

            if !status.success() {
                anyhow::bail!("Shell exited with status: {}", status);
            }

            Ok(())
        }

        async fn down(&mut self) -> anyhow::Result<()> {
            if self.status != SandboxStatus::Running {
                anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
            }

            self.status = SandboxStatus::Stopping;
            self.share = None;
            self.abi = None;
            self.status = SandboxStatus::Stopped;

            Ok(())
        }

        fn status(&self) -> SandboxStatus {
            self.status
        }
    }
}

// ============================================================
// Linux 以外 (macOS 含む) または landlock feature なし: スタブ実装
// ============================================================

#[cfg(not(all(target_os = "linux", feature = "landlock")))]
mod inner {
    use super::*;

    pub struct LandlockSandbox {
        pub(crate) status: SandboxStatus,
    }

    impl Default for LandlockSandbox {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LandlockSandbox {
        pub fn new() -> Self {
            Self {
                status: SandboxStatus::Stopped,
            }
        }
    }

    #[async_trait::async_trait]
    impl Sandbox for LandlockSandbox {
        async fn up(&mut self, _config: &SandboxConfig) -> anyhow::Result<()> {
            anyhow::bail!("Landlock sandbox is only available on Linux with landlock feature")
        }

        async fn exec(
            &self,
            _cmd: &[String],
            _env: &HashMap<String, String>,
        ) -> anyhow::Result<ExecOutput> {
            anyhow::bail!("Landlock sandbox is only available on Linux with landlock feature")
        }

        async fn shell(&self) -> anyhow::Result<()> {
            anyhow::bail!("Landlock sandbox is only available on Linux with landlock feature")
        }

        async fn down(&mut self) -> anyhow::Result<()> {
            anyhow::bail!("Landlock sandbox is only available on Linux with landlock feature")
        }

        fn status(&self) -> SandboxStatus {
            self.status
        }
    }
}

pub use inner::LandlockSandbox;

/// `ShareConfig` からルールセット構成の概要を文字列で返す（デバッグ・テスト用）。
/// プラットフォーム非依存で動作する。
pub fn describe_ruleset(share: &ShareConfig) -> String {
    let mut desc = String::new();
    desc.push_str("Landlock Ruleset:\n");

    desc.push_str("  Writable paths:\n");
    for p in &share.host_paths {
        desc.push_str(&format!("    - {} (read/write)\n", p.display()));
    }
    // NOTE: mount_point はゲスト側パスのため Landlock ルールには含めない
    desc.push_str("    - /tmp (read/write)\n");

    desc.push_str("  Read/execute-only paths:\n");
    for p in &["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
        desc.push_str(&format!("    - {} (read/execute-only)\n", p));
    }
    // /etc は全体ではなく必要なファイルのみ
    for p in &[
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/ld.so.cache",
        "/etc/ssl/certs",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
    ] {
        desc.push_str(&format!("    - {} (read-only)\n", p));
    }

    // /proc は必要最小限のエントリのみ許可
    desc.push_str("  /proc (minimal read-only):\n");
    for p in &["/proc/self/status", "/proc/self/maps", "/proc/self/exe"] {
        desc.push_str(&format!("    - {} (read-only)\n", p));
    }
    desc.push_str("  /sys: denied (no exceptions)\n");

    desc.push_str("  All other paths: denied\n");
    desc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_describe_ruleset_basic() {
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/home/user/project")],
            mount_point: PathBuf::from("/workspace"),
        };
        let desc = describe_ruleset(&share);

        assert!(desc.contains("Landlock Ruleset:"));
        assert!(desc.contains("/home/user/project (read/write)"));
        // mount_point はゲスト側パスのため含まれない
        assert!(!desc.contains("/workspace (mount_point, read/write)"));
        assert!(desc.contains("/tmp (read/write)"));
        assert!(desc.contains("/usr (read/execute-only)"));
        assert!(desc.contains("/etc/resolv.conf (read-only)"));
        // /proc は最小限のエントリのみ許可
        assert!(desc.contains("/proc (minimal read-only)"));
        assert!(desc.contains("/proc/self/status (read-only)"));
        assert!(desc.contains("/proc/self/maps (read-only)"));
        assert!(desc.contains("/proc/self/exe (read-only)"));
        // /proc/self/environ は含まれない（環境変数窃取の防止）
        assert!(!desc.contains("/proc/self/environ"));
        // /sys は完全 deny
        assert!(desc.contains("/sys: denied"));
        assert!(desc.contains("All other paths: denied"));
    }

    #[test]
    fn test_describe_ruleset_multiple_paths() {
        let share = ShareConfig {
            host_paths: vec![
                PathBuf::from("/home/user/project1"),
                PathBuf::from("/home/user/project2"),
            ],
            mount_point: PathBuf::from("/workspace"),
        };
        let desc = describe_ruleset(&share);

        assert!(desc.contains("/home/user/project1 (read/write)"));
        assert!(desc.contains("/home/user/project2 (read/write)"));
    }

    #[test]
    fn test_describe_ruleset_no_host_paths() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let desc = describe_ruleset(&share);

        assert!(desc.contains("Landlock Ruleset:"));
        // mount_point はゲスト側パスのため含まれない
        assert!(!desc.contains("/workspace (mount_point, read/write)"));
        assert!(desc.contains("/tmp (read/write)"));
    }

    #[test]
    fn test_landlock_sandbox_new() {
        let sb = LandlockSandbox::new();
        assert_eq!(sb.status, SandboxStatus::Stopped);
    }

    #[cfg(not(all(target_os = "linux", feature = "landlock")))]
    #[tokio::test]
    async fn test_landlock_stub_up_fails() {
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/tmp")],
            mount_point: PathBuf::from("/workspace"),
        };
        let config = SandboxConfig::Landlock { share };

        let mut sb = LandlockSandbox::new();
        let result = sb.up(&config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only available on Linux")
        );
    }

    #[cfg(not(all(target_os = "linux", feature = "landlock")))]
    #[tokio::test]
    async fn test_landlock_stub_exec_fails() {
        let sb = LandlockSandbox::new();
        let env = HashMap::new();
        let result = sb.exec(&["echo".to_string()], &env).await;
        assert!(result.is_err());
    }

    #[cfg(not(all(target_os = "linux", feature = "landlock")))]
    #[tokio::test]
    async fn test_landlock_stub_shell_fails() {
        let sb = LandlockSandbox::new();
        let result = sb.shell().await;
        assert!(result.is_err());
    }

    #[cfg(not(all(target_os = "linux", feature = "landlock")))]
    #[tokio::test]
    async fn test_landlock_stub_down_fails() {
        let mut sb = LandlockSandbox::new();
        let result = sb.down().await;
        assert!(result.is_err());
    }

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    #[tokio::test]
    async fn test_landlock_lifecycle() {
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/tmp")],
            mount_point: PathBuf::from("/workspace"),
        };
        let config = SandboxConfig::Landlock { share };

        let mut sb = LandlockSandbox::new();
        assert_eq!(sb.status(), SandboxStatus::Stopped);

        // up が成功するかはカーネルサポートに依存
        if sb.up(&config).await.is_ok() {
            assert_eq!(sb.status(), SandboxStatus::Running);
            sb.down().await.expect("down should succeed");
            assert_eq!(sb.status(), SandboxStatus::Stopped);
        }
    }

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    #[tokio::test]
    async fn test_landlock_executes_system_binary() {
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/tmp")],
            mount_point: PathBuf::from("/workspace"),
        };
        let config = SandboxConfig::Landlock { share };
        let mut sb = LandlockSandbox::new();

        // Landlock非対応または無効なカーネルでは実機テストをスキップする。
        if sb.up(&config).await.is_err() {
            return;
        }

        let output = sb
            .exec(&["/bin/true".to_string()], &HashMap::new())
            .await
            .expect("a system binary should be executable under Landlock");
        assert_eq!(output.exit_code, 0);

        sb.down().await.expect("down should succeed");
    }

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    #[tokio::test]
    async fn test_landlock_rejects_binary_outside_allowed_paths() {
        use std::os::unix::fs::PermissionsExt;

        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/tmp")],
            mount_point: PathBuf::from("/workspace"),
        };
        let config = SandboxConfig::Landlock { share };
        let mut sb = LandlockSandbox::new();

        // Landlock非対応または無効なカーネルでは実機テストをスキップする。
        if sb.up(&config).await.is_err() {
            return;
        }

        let executable = PathBuf::from(format!(
            "/dev/shm/izanagi-landlock-denied-{}",
            std::process::id()
        ));
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("create test executable");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("mark test file executable");

        let result = sb
            .exec(
                &[executable.to_string_lossy().into_owned()],
                &HashMap::new(),
            )
            .await;

        let _ = std::fs::remove_file(&executable);
        sb.down().await.expect("down should succeed");
        assert!(
            result.is_err(),
            "a binary outside the allowed paths must not be executable"
        );
    }

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    #[tokio::test]
    async fn test_landlock_limits_etc_to_explicitly_allowed_files() {
        let config = SandboxConfig::Landlock {
            share: ShareConfig {
                host_paths: vec![PathBuf::from("/tmp")],
                mount_point: PathBuf::from("/workspace"),
            },
        };
        let mut sb = LandlockSandbox::new();
        if sb.up(&config).await.is_err() {
            return;
        }
        std::fs::read("/etc/hostname").expect("denied fixture must be readable without Landlock");
        let allowed = sb
            .exec(&["/bin/cat".into(), "/etc/passwd".into()], &HashMap::new())
            .await
            .unwrap();
        let denied = sb
            .exec(
                &["/bin/cat".into(), "/etc/hostname".into()],
                &HashMap::new(),
            )
            .await
            .unwrap();
        sb.down().await.unwrap();
        assert_eq!(allowed.exit_code, 0);
        assert!(!allowed.stdout.is_empty());
        assert_ne!(denied.exit_code, 0);
        assert!(denied.stdout.is_empty());
    }

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    #[tokio::test]
    async fn test_landlock_wrong_config() {
        let config = SandboxConfig::AppleContainer {
            image: String::new(),
            share: ShareConfig {
                host_paths: vec![],
                mount_point: PathBuf::from("/workspace"),
            },
            dns_proxy: None,
            network: None,
        };

        let mut sb = LandlockSandbox::new();
        let result = sb.up(&config).await;
        assert!(result.is_err());
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }
}
