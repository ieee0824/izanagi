//! Apple Container ベースのサンドボックス実装 (macOS only)。
//!
//! `container` CLI (Apple Container) を使用してコンテナを管理する。
//! Docker 互換の CLI: `container run`, `container stop`, `container exec`, `container rm`

use crate::util::find_available_port;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::Command;

use crate::sandbox::{ExecOutput, Sandbox, SandboxConfig, SandboxStatus, ShareConfig};

/// env-file の RAII ガード。Drop 時にファイルを確実に削除する。
/// パニック時やエラーパスでのクリーンアップ漏れを防止する。
struct EnvFileGuard {
    path: Option<PathBuf>,
}

impl EnvFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }
}

impl Drop for EnvFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path
            && let Err(e) = std::fs::remove_file(path)
        {
            // ファイルが既に削除されている場合は無視
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("警告: env-file の削除に失敗: {}: {}", path.display(), e);
            }
        }
    }
}

/// シークレットを一時ファイルに書き出し、そのパスを返す。
/// Unix ではファイルは 0600 パーミッションでアトミックに作成される。
/// 非 Unix ではデフォルトパーミッションで作成される（Windows 未サポート）。
fn write_secret_env_file(secret: &str) -> anyhow::Result<EnvFileGuard> {
    // シークレットに制御文字（改行等）が含まれると env-file インジェクションになるため拒否
    if secret.chars().any(|c| c.is_control()) {
        anyhow::bail!("シークレットに制御文字を含むことはできません");
    }

    let random_suffix: String = (0..8)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    let path = std::env::temp_dir().join(format!("izanagi-envfile-{}.tmp", random_suffix));
    let content = format!("IZANAGI_SHARED_SECRET={}\n", secret);

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(content.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, &content)?;
    }

    Ok(EnvFileGuard::new(path))
}

/// `container` CLI のデフォルトバイナリ名。
const DEFAULT_CONTAINER_BINARY: &str = "container";

/// Agent が Listen するコンテナ内部のポート。
const AGENT_PORT: u16 = 9001;

/// コンテナ起動待ちのデフォルトタイムアウト (秒)。
const START_TIMEOUT_SECS: u64 = 60;

/// `container image list` の出力からイメージの存在を確認する。
pub async fn check_image_exists(image: &str) -> anyhow::Result<()> {
    check_image_exists_with(image, DEFAULT_CONTAINER_BINARY).await
}

/// 指定したコンテナランタイムでイメージの存在を確認する。
async fn check_image_exists_with(image: &str, binary: &str) -> anyhow::Result<()> {
    let output = Command::new(binary)
        .args(["image", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "container コマンドの実行に失敗しました。Apple Container がインストールされているか確認してください: {}",
                e
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("container image list の実行に失敗しました: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !image_exists_in_output(&stdout, image) {
        anyhow::bail!(
            "コンテナイメージ \"{}\" が見つかりません。\n\
             以下のコマンドでイメージをビルドしてください:\n\
             \n\
             $ ./image/build.sh",
            image
        );
    }

    Ok(())
}

/// `container image list` の出力にイメージが含まれるか判定する。
///
/// 出力の各行にイメージ名が含まれるかを確認する。
pub fn image_exists_in_output(output: &str, image: &str) -> bool {
    output.lines().any(|line| {
        // 行をフィールドに分割し、最初のフィールド(またはいずれかのフィールド)がイメージ名に一致するか確認
        line.split_whitespace().any(|field| field == image)
    })
}

/// `container run` コマンドの引数を構築する。
///
/// `env_file` が指定された場合、`--env-file <path>` でシークレットを渡す。
/// `-e` による直接渡しは行わない。
pub fn build_run_args(
    container_name: &str,
    image: &str,
    host_port: u16,
    share: &ShareConfig,
    env_file: Option<&str>,
    dns_proxy: Option<&str>,
    network: Option<crate::config::ContainerNetworkMode>,
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        container_name.to_string(),
    ];

    // ポートフォワード: --network none と非互換。
    // Config::validate() でガードされているが、防御的にここでもチェックする。
    if network.is_none() {
        // 127.0.0.1 にバインドし、ホスト外部からの接続を防ぐ
        args.extend_from_slice(&[
            "-p".to_string(),
            format!("127.0.0.1:{}:{}", host_port, AGENT_PORT),
        ]);
    }

    // コンテナ環境には fw_cfg がないため、トークン認証をスキップする。
    // コマンド実行はホスト側で HMAC 認証済みのため、agent 側は全コマンドを許可する。
    // ポートは 127.0.0.1 にバインドされるため、外部からの接続は不可。
    args.extend_from_slice(&[
        "-e".to_string(),
        "IZANAGI_ALLOW_NO_TOKEN=1".to_string(),
        "-e".to_string(),
        "IZANAGI_ALLOW_ALL_COMMANDS=1".to_string(),
    ]);

    // シークレットは --env-file 経由で渡す
    if let Some(path) = env_file {
        args.extend_from_slice(&["--env-file".to_string(), path.to_string()]);
    }

    // ボリュームマウント（最初のパスのみマウント）
    if let Some(host_path) = share.host_paths.first() {
        let path_str = host_path.to_string_lossy();
        let abs_path = if path_str.starts_with('~') {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(path_str.replacen('~', &home, 1))
        } else if host_path.is_relative() {
            std::env::current_dir().unwrap_or_default().join(host_path)
        } else {
            host_path.clone()
        };
        args.extend_from_slice(&[
            "--volume".to_string(),
            format!("{}:{}", abs_path.display(), share.mount_point.display()),
        ]);
    }

    // DNS プロキシ
    if let Some(dns_ip) = dns_proxy {
        args.extend_from_slice(&["--dns".to_string(), dns_ip.to_string()]);
    }

    // ネットワークモード
    if let Some(mode) = network {
        let mode_str = match mode {
            crate::config::ContainerNetworkMode::None => "none",
        };
        args.extend_from_slice(&["--network".to_string(), mode_str.to_string()]);
    }

    // イメージ名
    args.push(image.to_string());

    args
}

/// `container exec` コマンドの引数を構築する。
pub fn build_exec_args(
    container_name: &str,
    cmd: &[String],
    env: &HashMap<String, String>,
    mount_point: &str,
) -> Vec<String> {
    let mut args = vec!["exec".to_string()];

    // 非特権ユーザーで実行 + ワーキングディレクトリを mount_point に
    args.extend_from_slice(&[
        "-u".to_string(),
        "izanagi".to_string(),
        "-w".to_string(),
        mount_point.to_string(),
    ]);

    // 環境変数
    for (key, value) in env {
        args.extend_from_slice(&["-e".to_string(), format!("{}={}", key, value)]);
    }

    args.push(container_name.to_string());
    args.extend_from_slice(cmd);

    args
}

/// `container exec -it` コマンドの引数を構築する (shell 用)。
pub fn build_shell_args(container_name: &str, mount_point: &str) -> Vec<String> {
    vec![
        "exec".to_string(),
        "-it".to_string(),
        "-u".to_string(),
        "izanagi".to_string(),
        "-w".to_string(),
        mount_point.to_string(),
        container_name.to_string(),
        "/bin/sh".to_string(),
    ]
}

/// コンテナ名を生成する。`izanagi-<timestamp>-<pid>` 形式。
fn generate_container_name() -> String {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S%3f");
    let pid = std::process::id();
    format!("izanagi-{}-{}", ts, pid)
}

/// Apple Container ベースのサンドボックス。
pub struct AppleContainerSandbox {
    status: SandboxStatus,
    container_name: Option<String>,
    host_port: u16,
    image: Option<String>,
    mount_point: Option<String>,
    /// コンテナランタイムのバイナリ名 ("container" or "docker")。
    container_binary: String,
}

impl AppleContainerSandbox {
    /// デフォルトのコンテナランタイム ("container") で作成する。
    pub fn new() -> Self {
        // デフォルトは許可リストに含まれるため unwrap は安全
        Self::with_runtime(DEFAULT_CONTAINER_BINARY).expect("default runtime is always valid")
    }

    /// 指定したコンテナランタイムで作成する (#249)。
    ///
    /// 許可されるランタイム: "container", "docker", "podman"。
    /// それ以外はエラーを返す（設定ミスの黙殺を防止）。
    pub(crate) fn with_runtime(binary: &str) -> anyhow::Result<Self> {
        // 許可リストで制限し、任意バイナリの実行を防止
        match binary {
            "container" | "docker" | "podman" => {}
            _ => {
                anyhow::bail!(
                    "unknown container runtime '{}'. Allowed values: container, docker, podman",
                    binary
                );
            }
        }
        Ok(Self {
            status: SandboxStatus::Stopped,
            container_name: None,
            host_port: 0,
            image: None,
            mount_point: None,
            container_binary: binary.to_string(),
        })
    }

    /// Agent の Ready を待つ。TCP 接続でヘルスチェックを行う。
    async fn wait_for_ready(&self) -> anyhow::Result<()> {
        let timeout = tokio::time::Duration::from_secs(START_TIMEOUT_SECS);
        let addr = format!("127.0.0.1:{}", self.host_port);

        tokio::time::timeout(timeout, async {
            loop {
                match tokio::net::TcpStream::connect(&addr).await {
                    Ok(_) => return Ok(()),
                    Err(_) => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "コンテナの Agent が Ready になるまでにタイムアウトしました ({}秒)",
                START_TIMEOUT_SECS
            )
        })?
    }
}

impl Default for AppleContainerSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Sandbox for AppleContainerSandbox {
    async fn up(&mut self, config: &SandboxConfig) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Stopped {
            anyhow::bail!(
                "Sandbox is not in Stopped state (current: {:?})",
                self.status
            );
        }

        self.status = SandboxStatus::Starting;

        let (image, share, dns_proxy, network) = match config {
            SandboxConfig::AppleContainer {
                image,
                share,
                dns_proxy,
                network,
            } => (image.clone(), share.clone(), dns_proxy.clone(), *network),
            _ => {
                self.status = SandboxStatus::Stopped;
                anyhow::bail!("AppleContainerSandbox requires SandboxConfig::AppleContainer");
            }
        };

        // イメージの存在確認
        if let Err(e) = check_image_exists_with(&image, &self.container_binary).await {
            self.status = SandboxStatus::Stopped;
            return Err(e);
        }

        // 空きポートを取得
        self.host_port = find_available_port().await?;

        // コンテナ名を生成
        let container_name = generate_container_name();

        // シークレットを load_shared_secret_from_env で取得し、env-file に書き出す
        // EnvFileGuard により、成功・失敗・パニック問わず env-file は確実に削除される
        let shared_secret = crate::protocol::load_shared_secret_from_env()?
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string());
        let env_file_guard = if let Some(ref secret) = shared_secret {
            Some(write_secret_env_file(secret).map_err(|e| {
                self.status = SandboxStatus::Stopped;
                anyhow::anyhow!("Failed to write env-file: {}", e)
            })?)
        } else {
            None
        };

        // 複数 host_paths 指定時は警告（build_run_args は純関数なので呼び出し元で警告）
        if share.host_paths.len() > 1 {
            eprintln!(
                "警告: 複数の host_paths が指定されていますが、同一マウントポイントには最初のパスのみマウントされます。"
            );
        }

        // container run コマンドを実行
        let env_file_str = env_file_guard
            .as_ref()
            .and_then(|g| g.path())
            .and_then(|p| p.to_str());
        let args = build_run_args(
            &container_name,
            &image,
            self.host_port,
            &share,
            env_file_str,
            dns_proxy.as_deref(),
            network,
        );

        let output = Command::new(&self.container_binary)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                // env_file_guard の Drop で env-file は自動削除される
                self.status = SandboxStatus::Stopped;
                anyhow::anyhow!("Failed to start container: {}", e)
            })?;

        if !output.status.success() {
            // env_file_guard の Drop で env-file は自動削除される
            self.status = SandboxStatus::Stopped;
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("container run failed: {}", stderr);
        }

        self.container_name = Some(container_name);
        self.image = Some(image);
        self.mount_point = Some(share.mount_point.to_string_lossy().to_string());
        // env_file_guard の Drop でコンテナ起動成功後に env-file は自動削除される
        drop(env_file_guard);

        // Agent の Ready を待つ
        match self.wait_for_ready().await {
            Ok(()) => {
                // フォールバック防御: ALLOW_NO_TOKEN で起動しているため、
                // build_run_args() で 127.0.0.1 バインドが設定されていることが前提。
                // Config::validate() と build_run_args() の二重チェックにより、
                // ポートが外部に公開される設定は拒否される。
                self.status = SandboxStatus::Running;
                Ok(())
            }
            Err(e) => {
                // タイムアウト時はコンテナを停止
                let _ = self.stop_container().await;
                self.status = SandboxStatus::Stopped;
                Err(e)
            }
        }
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

        let container_name = self
            .container_name
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("container name not set"))?;

        let args = build_exec_args(
            container_name,
            cmd,
            env,
            self.mount_point.as_deref().unwrap_or("/workspace"),
        );

        let output = Command::new(&self.container_binary)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let exit_code = output.status.code().unwrap_or(-1);

        Ok(ExecOutput {
            exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    async fn shell(&self) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }

        let container_name = self
            .container_name
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("container name not set"))?;

        let args = build_shell_args(
            container_name,
            self.mount_point.as_deref().unwrap_or("/workspace"),
        );

        let mut child = Command::new(&self.container_binary)
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let status = child.wait().await?;

        if !status.success() {
            let code = status.code().unwrap_or(1);
            anyhow::bail!("shell exited with code {}", code);
        }

        Ok(())
    }

    async fn down(&mut self) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }

        self.status = SandboxStatus::Stopping;
        self.stop_container().await?;
        self.status = SandboxStatus::Stopped;

        Ok(())
    }

    fn status(&self) -> SandboxStatus {
        self.status
    }

    fn session_backend(&self) -> Option<crate::session::SessionBackend> {
        let container_name = self.container_name.as_ref()?;
        Some(crate::session::SessionBackend::AppleContainer {
            container_name: container_name.clone(),
            image: self.image.clone().unwrap_or_default(),
            mount_point: self
                .mount_point
                .clone()
                .unwrap_or_else(|| "/workspace".to_string()),
        })
    }
}

impl AppleContainerSandbox {
    /// コンテナを停止・削除する。
    async fn stop_container(&mut self) -> anyhow::Result<()> {
        if let Some(ref name) = self.container_name {
            // コンテナを停止（--rm で既に削除済みの場合はエラーを無視）
            let output = Command::new(&self.container_binary)
                .args(["stop", name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stderr_lower = stderr.to_ascii_lowercase();
                // コンテナが既に存在しない場合は正常終了として扱う
                if !stderr_lower.contains("not found")
                    && !stderr_lower.contains("no such container")
                    && !stderr_lower.contains("is not running")
                {
                    eprintln!("警告: container stop failed: {}", stderr);
                }
            }

            // --rm 付きで起動しているが、異常終了時に残留する場合があるため明示的に削除
            let rm_output = Command::new(&self.container_binary)
                .args(["rm", "-f", name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await;

            // rm -f の結果もチェック (#218)
            match rm_output {
                Ok(output) if !output.status.success() => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stderr_lower = stderr.to_ascii_lowercase();
                    // コンテナが既に存在しない場合は正常
                    if !stderr_lower.contains("not found")
                        && !stderr_lower.contains("no such container")
                    {
                        eprintln!("警告: container rm failed: {}", stderr);
                    }
                }
                Err(e) => {
                    eprintln!("警告: container rm の実行に失敗: {}", e);
                }
                _ => {}
            }
        }
        self.container_name = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::ShareConfig;
    use std::path::PathBuf;

    // --- イメージ存在確認テスト (#149) ---

    #[test]
    fn image_exists_in_output_found() {
        let output = "REPOSITORY    TAG       IMAGE ID\n\
                       izanagi-vm    latest    abc123\n\
                       ubuntu        22.04     def456\n";
        assert!(image_exists_in_output(output, "izanagi-vm"));
    }

    #[test]
    fn image_exists_in_output_not_found() {
        let output = "REPOSITORY    TAG       IMAGE ID\n\
                       ubuntu        22.04     def456\n";
        assert!(!image_exists_in_output(output, "izanagi-vm"));
    }

    #[test]
    fn image_exists_in_output_empty() {
        assert!(!image_exists_in_output("", "izanagi-vm"));
    }

    #[test]
    fn image_exists_in_output_partial_match_rejected() {
        // "izanagi-vm-dev" には一致するが "izanagi-vm" フィールドとは一致しない
        let output = "REPOSITORY       TAG       IMAGE ID\n\
                       izanagi-vm-dev   latest    abc123\n";
        assert!(!image_exists_in_output(output, "izanagi-vm"));
    }

    // --- コマンドライン生成テスト (#150, #151) ---

    #[test]
    fn build_run_args_basic() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args("izanagi-test", "izanagi-vm", 9001, &share, None, None, None);

        assert!(args.contains(&"run".to_string()));
        assert!(args.contains(&"--rm".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"--name".to_string()));
        assert!(args.contains(&"izanagi-test".to_string()));
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"127.0.0.1:9001:9001".to_string()));
        assert!(args.contains(&"izanagi-vm".to_string()));
        // --env-file なし
        assert!(!args.contains(&"--env-file".to_string()));
        // コンテナには fw_cfg がないため ALLOW_NO_TOKEN と ALLOW_ALL_COMMANDS を渡す
        assert!(args.contains(&"IZANAGI_ALLOW_NO_TOKEN=1".to_string()));
        assert!(args.contains(&"IZANAGI_ALLOW_ALL_COMMANDS=1".to_string()));
        // シークレットは -e で直接渡さない
        assert!(!args.contains(&"IZANAGI_SHARED_SECRET".to_string()));
    }

    #[test]
    fn build_run_args_with_env_file() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args(
            "izanagi-test",
            "izanagi-vm",
            9001,
            &share,
            Some("/tmp/test-envfile.tmp"),
            None,
            None,
        );

        assert!(args.contains(&"--env-file".to_string()));
        assert!(args.contains(&"/tmp/test-envfile.tmp".to_string()));
        // シークレットは --env-file 経由で渡され、-e では直接渡さない
        assert!(!args.contains(&"IZANAGI_SHARED_SECRET".to_string()));
    }

    #[test]
    fn write_secret_env_file_creates_and_removes() {
        let guard = write_secret_env_file("test-secret-value").unwrap();
        let path = guard.path().unwrap().clone();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "IZANAGI_SHARED_SECRET=test-secret-value\n");

        // パーミッション確認 (unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Drop でファイルが自動削除されることを検証
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn write_secret_env_file_rejects_control_chars() {
        // 改行によるインジェクション防止
        assert!(write_secret_env_file("secret\nEVIL_VAR=hack").is_err());
        // タブ
        assert!(write_secret_env_file("secret\tvalue").is_err());
        // null バイト
        assert!(write_secret_env_file("secret\0value").is_err());
    }

    #[test]
    fn env_file_guard_double_drop_safe() {
        let guard = write_secret_env_file("test-double-drop").unwrap();
        let path = guard.path().unwrap().clone();
        // 手動でファイル削除
        std::fs::remove_file(&path).unwrap();
        // Drop でも panic しない (NotFound を無視)
        drop(guard);
    }

    #[test]
    fn build_run_args_with_volume() {
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/home/user/project")],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args("izanagi-test", "izanagi-vm", 8080, &share, None, None, None);

        assert!(args.contains(&"--volume".to_string()));
        assert!(args.contains(&"/home/user/project:/workspace".to_string()));
    }

    #[test]
    fn build_run_args_with_multiple_volumes_mounts_first_only() {
        let share = ShareConfig {
            host_paths: vec![
                PathBuf::from("/home/user/src"),
                PathBuf::from("/home/user/config"),
            ],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args("izanagi-test", "izanagi-vm", 8080, &share, None, None, None);

        // 複数 host_paths がある場合、最初のパスのみマウントされる (#163)
        let volume_count = args.iter().filter(|a| *a == "--volume").count();
        assert_eq!(volume_count, 1);
        assert!(args.contains(&"/home/user/src:/workspace".to_string()));
        assert!(!args.contains(&"/home/user/config:/workspace".to_string()));
    }

    #[test]
    fn build_run_args_port_mapping() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args(
            "izanagi-test",
            "izanagi-vm",
            12345,
            &share,
            None,
            None,
            None,
        );

        assert!(args.contains(&"127.0.0.1:12345:9001".to_string()));
    }

    // --- #209: DNS プロキシ設定テスト ---

    #[test]
    fn build_run_args_with_dns_proxy() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args(
            "izanagi-test",
            "izanagi-vm",
            9001,
            &share,
            None,
            Some("127.0.0.1"),
            None,
        );

        assert!(args.contains(&"--dns".to_string()));
        assert!(args.contains(&"127.0.0.1".to_string()));
        // --dns はイメージ名の前にあること
        let dns_pos = args.iter().position(|a| a == "--dns").unwrap();
        let image_pos = args.iter().position(|a| a == "izanagi-vm").unwrap();
        assert!(dns_pos < image_pos);
    }

    #[test]
    fn build_run_args_without_dns_proxy() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args("izanagi-test", "izanagi-vm", 9001, &share, None, None, None);

        assert!(!args.contains(&"--dns".to_string()));
    }

    // --- #206: ネットワーク制限テスト ---

    #[test]
    fn build_run_args_with_network_none() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        use crate::config::ContainerNetworkMode;
        let args = build_run_args(
            "izanagi-test",
            "izanagi-vm",
            9001,
            &share,
            None,
            None,
            Some(ContainerNetworkMode::None),
        );

        assert!(args.contains(&"--network".to_string()));
        assert!(args.contains(&"none".to_string()));
        // --network はイメージ名の前にあること
        let net_pos = args.iter().position(|a| a == "--network").unwrap();
        let image_pos = args.iter().position(|a| a == "izanagi-vm").unwrap();
        assert!(net_pos < image_pos);
    }

    #[test]
    fn build_run_args_without_network() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_run_args("izanagi-test", "izanagi-vm", 9001, &share, None, None, None);

        assert!(!args.contains(&"--network".to_string()));
    }

    // --- exec コマンドライン生成テスト (#152) ---

    #[test]
    fn build_exec_args_basic() {
        let env = HashMap::new();
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        let args = build_exec_args("izanagi-test", &cmd, &env, "/workspace");

        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "-u");
        assert_eq!(args[2], "izanagi");
        assert!(args.contains(&"izanagi-test".to_string()));
        assert!(args.contains(&"echo".to_string()));
        assert!(args.contains(&"hello".to_string()));
    }

    #[test]
    fn build_exec_args_with_env() {
        let mut env = HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        let cmd = vec!["env".to_string()];
        let args = build_exec_args("izanagi-test", &cmd, &env, "/workspace");

        assert!(args.contains(&"-e".to_string()));
        assert!(args.contains(&"FOO=bar".to_string()));
    }

    #[test]
    fn build_exec_args_env_does_not_leak_host() {
        // 明示的に渡した環境変数のみが含まれる
        let mut env = HashMap::new();
        env.insert("APP_KEY".to_string(), "value".to_string());
        let cmd = vec!["printenv".to_string()];
        let args = build_exec_args("izanagi-test", &cmd, &env, "/workspace");

        // -e フラグは1つだけ
        let env_count = args.iter().filter(|a| *a == "-e").count();
        assert_eq!(env_count, 1);
    }

    // --- shell コマンドライン生成テスト (#152) ---

    #[test]
    fn build_shell_args_basic() {
        let args = build_shell_args("izanagi-test", "/workspace");

        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "-it");
        assert_eq!(args[2], "-u");
        assert_eq!(args[3], "izanagi");
        assert_eq!(args[4], "-w");
        assert_eq!(args[5], "/workspace");
        assert_eq!(args[6], "izanagi-test");
        assert_eq!(args[7], "/bin/sh");
    }

    // --- 状態遷移テスト ---

    #[test]
    fn apple_container_sandbox_initial_state() {
        let sb = AppleContainerSandbox::new();
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }

    #[test]
    fn apple_container_sandbox_default() {
        let sb = AppleContainerSandbox::default();
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }

    #[tokio::test]
    async fn apple_container_sandbox_wrong_config() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let config = SandboxConfig::Landlock { share };

        let mut sb = AppleContainerSandbox::new();
        let result = sb.up(&config).await;
        assert!(result.is_err());
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }

    #[tokio::test]
    async fn apple_container_sandbox_exec_when_not_running() {
        let sb = AppleContainerSandbox::new();
        let env = HashMap::new();
        let result = sb.exec(&["echo".to_string()], &env).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not running"));
    }

    #[tokio::test]
    async fn apple_container_sandbox_shell_when_not_running() {
        let sb = AppleContainerSandbox::new();
        let result = sb.shell().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn apple_container_sandbox_down_when_not_running() {
        let mut sb = AppleContainerSandbox::new();
        let result = sb.down().await;
        assert!(result.is_err());
    }

    // --- コンテナ名生成テスト ---

    #[test]
    fn generate_container_name_format() {
        let name = generate_container_name();
        assert!(name.starts_with("izanagi-"));
        // フォーマット: izanagi-<timestamp+ms>-<pid>
        let rest = &name["izanagi-".len()..];
        assert!(rest.contains('-'), "should contain PID separator: {}", name);
        let parts: Vec<&str> = rest.splitn(2, '-').collect();
        // タイムスタンプ部分 (17桁: YYYYMMDDHHmmssmmm)
        assert_eq!(parts[0].len(), 17, "timestamp part: {}", parts[0]);
        // PID 部分
        assert!(
            parts[1].chars().all(|c| c.is_ascii_digit()),
            "pid part: {}",
            parts[1]
        );
    }
}
