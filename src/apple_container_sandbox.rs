//! Apple Container ベースのサンドボックス実装 (macOS only)。
//!
//! `container` CLI (Apple Container) を使用してコンテナを管理する。
//! Docker 互換の CLI: `container run`, `container stop`, `container exec`, `container rm`

use crate::util::find_available_port;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::Command;

use crate::config::ContainerRuntime;
use crate::sandbox::{ExecOutput, Sandbox, SandboxConfig, SandboxStatus, ShareConfig};

/// The private directory is mounted read-only under guest root's home.
/// Keep it alive until shutdown so later CLI/MCP connections can read the session key.
struct SessionCredentials {
    directory: tempfile::TempDir,
    auth_key: zeroize::Zeroizing<Vec<u8>>,
}

const GUEST_SECRET_DIR: &str = "/root/.izanagi-auth";
const SECRET_FILENAME: &str = "shared-secret";

impl SessionCredentials {
    fn new(runtime: ContainerRuntime) -> anyhow::Result<Self> {
        let shared_base = match runtime {
            ContainerRuntime::Container => None,
            ContainerRuntime::Docker | ContainerRuntime::Podman => {
                let path = crate::config::izanagi_home()?.join("runtime");
                create_private_directory(&path)?;
                Some(path)
            }
        };
        Self::new_in(shared_base.as_deref())
    }

    fn new_in(base: Option<&std::path::Path>) -> anyhow::Result<Self> {
        use std::io::Write;
        // rand's thread RNG is cryptographically secure; generate a fresh 256-bit key.
        let auth_key =
            zeroize::Zeroizing::new(hex::encode(rand::random::<[u8; 32]>()).into_bytes());
        let mut builder = tempfile::Builder::new();
        builder.prefix("izanagi-session-");
        let directory = match base {
            Some(base) => builder.tempdir_in(base)?,
            None => builder.tempdir()?,
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            options.mode(0o600);
        }
        options
            .open(directory.path().join(SECRET_FILENAME))?
            .write_all(&auth_key)?;
        Ok(Self {
            directory,
            auth_key,
        })
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join(SECRET_FILENAME)
    }
}

fn create_private_directory(path: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
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
                "コンテナランタイム `{}` を実行できません。インストール状況と PATH を確認してください: {}",
                binary,
                e,
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("`{} image list` の実行に失敗しました: {}", binary, stderr);
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
    let last = image.rsplit('/').next().unwrap_or(image);
    let requested = if !last.contains(':') && !image.contains('@') {
        format!("{image}:latest")
    } else {
        image.to_owned()
    };
    output.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            return false;
        };
        name == requested
            || fields
                .next()
                .is_some_and(|tag| format!("{name}:{tag}") == requested)
    })
}

/// `container run` コマンドの引数を構築する。
///
/// `secret_dir` が指定された場合、root 専用ファイルを read-only でマウントする。
pub fn build_run_args(
    container_name: &str,
    image: &str,
    host_port: u16,
    share: &ShareConfig,
    secret_dir: Option<&str>,
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

    push_container_port(&mut args, host_port, network);

    push_container_agent_env(&mut args, secret_dir);
    args.extend([
        "-e".into(),
        format!("IZANAGI_WORKDIR={}", share.mount_point.display()),
    ]);

    push_container_share(&mut args, share);

    // DNS プロキシ
    if let Some(dns_ip) = dns_proxy {
        args.extend([
            "--dns".into(),
            "127.0.0.1".into(),
            "-e".into(),
            format!("IZANAGI_DNS_PROXY={dns_ip}"),
        ]);
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

fn push_container_agent_env(args: &mut Vec<String>, secret_dir: Option<&str>) {
    // コンテナ環境には fw_cfg がないため、トークン認証をスキップする。
    // コマンド実行はホスト側で HMAC 認証済みのため、agent 側は全コマンドを許可する。
    // ポートは 127.0.0.1 にバインドされるため、外部からの接続は不可。
    args.extend_from_slice(&[
        "-e".to_string(),
        "IZANAGI_ALLOW_NO_TOKEN=1".to_string(),
        "-e".to_string(),
        "IZANAGI_ALLOW_ALL_COMMANDS=1".to_string(),
    ]);

    // Only a file path enters the container environment; the key never does.
    if let Some(path) = secret_dir {
        args.extend([
            "--volume".into(),
            format!("{path}:{GUEST_SECRET_DIR}:ro"),
            "-e".into(),
            format!("IZANAGI_SECRET_FILE={GUEST_SECRET_DIR}/{SECRET_FILENAME}"),
        ]);
    }
}

fn push_container_port(
    args: &mut Vec<String>,
    host_port: u16,
    network: Option<crate::config::ContainerNetworkMode>,
) {
    // ポートフォワード: --network none と非互換。
    // Config::validate() でガードされているが、防御的にここでもチェックする。
    if network.is_none() {
        // 127.0.0.1 にバインドし、ホスト外部からの接続を防ぐ
        args.extend_from_slice(&[
            "-p".to_string(),
            format!("127.0.0.1:{}:{}", host_port, AGENT_PORT),
        ]);
    }
}

fn push_container_share(args: &mut Vec<String>, share: &ShareConfig) {
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
            format!(
                "{}:{}{}",
                abs_path.display(),
                share.mount_point.display(),
                if share.read_only { ":ro" } else { "" }
            ),
        ]);
    }
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
    /// コンテナランタイムのバイナリ名 ("container", "docker", or "podman")。
    container_binary: String,
    container_runtime: ContainerRuntime,
    credentials: Option<SessionCredentials>,
}

struct ContainerBootSettings {
    image: String,
    share: ShareConfig,
    dns_proxy: Option<String>,
    network: Option<crate::config::ContainerNetworkMode>,
}

impl AppleContainerSandbox {
    async fn boot_settings(
        &mut self,
        config: &SandboxConfig,
    ) -> anyhow::Result<ContainerBootSettings> {
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

        Ok(ContainerBootSettings {
            image,
            share,
            dns_proxy,
            network,
        })
    }

    fn boot_args(
        &self,
        container_name: &str,
        boot: &ContainerBootSettings,
        credentials: &SessionCredentials,
    ) -> Vec<String> {
        // 複数 host_paths 指定時は警告（build_run_args は純関数なので呼び出し元で警告）
        if boot.share.host_paths.len() > 1 {
            eprintln!(
                "警告: 複数の host_paths が指定されていますが、同一マウントポイントには最初のパスのみマウントされます。"
            );
        }

        // container run コマンドを実行
        let secret_dir = credentials.directory.path().to_string_lossy();
        build_run_args(
            container_name,
            &boot.image,
            self.host_port,
            &boot.share,
            Some(&secret_dir),
            boot.dns_proxy.as_deref(),
            boot.network,
        )
    }

    async fn run_container(&mut self, args: &[String]) -> anyhow::Result<()> {
        let output = Command::new(&self.container_binary)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                self.status = SandboxStatus::Stopped;
                anyhow::anyhow!("Failed to start container: {}", e)
            })?;

        if !output.status.success() {
            self.status = SandboxStatus::Stopped;
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("container run failed: {}", stderr);
        }

        Ok(())
    }

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
        let container_runtime = match binary {
            "container" => ContainerRuntime::Container,
            "docker" => ContainerRuntime::Docker,
            "podman" => ContainerRuntime::Podman,
            _ => {
                anyhow::bail!(
                    "unknown container runtime '{}'. Allowed values: container, docker, podman",
                    binary
                );
            }
        };
        Ok(Self {
            status: SandboxStatus::Stopped,
            container_name: None,
            host_port: 0,
            image: None,
            mount_point: None,
            container_binary: binary.to_string(),
            container_runtime,
            credentials: None,
        })
    }

    async fn verify_dns_relay(&self, endpoint: &str) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", self.host_port)).await?;
            let (reader, writer) = stream.into_split();
            let mut client = crate::protocol_client::ProtocolClient::new(
                reader,
                writer,
                Some(self.session_secret()?.to_vec()),
            );
            client.handshake_and_wait_ready(None).await?;
            crate::guest_dns::verify_client(&mut client, endpoint.parse()?).await
        })
        .await?
    }

    fn session_secret(&self) -> anyhow::Result<&[u8]> {
        self.credentials
            .as_ref()
            .map(|credentials| credentials.auth_key.as_slice())
            .ok_or_else(|| anyhow::anyhow!("container session credentials missing"))
    }

    async fn connect_agent(&self) -> anyhow::Result<crate::agent_session::AgentClient> {
        crate::agent_session::connect(self.host_port, Some(self.session_secret()?.to_vec()), None)
            .await
    }

    /// Require a successful HMAC handshake before reporting the sandbox ready.
    async fn wait_for_ready(&self) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(START_TIMEOUT_SECS), async {
            loop {
                if self.connect_agent().await.is_ok() {
                    return Ok(());
                }
                if let Some(error) = self.early_container_exit().await {
                    return Err(error);
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "コンテナの Agent 認証がタイムアウトしました ({}秒)",
                START_TIMEOUT_SECS
            )
        })?
    }

    async fn early_container_exit(&self) -> Option<anyhow::Error> {
        if self.container_runtime == ContainerRuntime::Container {
            return None;
        }
        let name = self.container_name.as_deref()?;
        let inspect = Command::new(&self.container_binary)
            .args(["inspect", "--format", "{{.State.Running}}", name])
            .output()
            .await
            .ok()?;
        if inspect.status.success() && String::from_utf8_lossy(&inspect.stdout).trim() == "true" {
            return None;
        }
        let logs = Command::new(&self.container_binary)
            .args(["logs", name])
            .output()
            .await
            .ok();
        let detail = logs
            .as_ref()
            .map(|output| {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                format!("{stderr}{stdout}").trim().to_string()
            })
            .filter(|detail| !detail.is_empty())
            .unwrap_or_else(|| "コンテナログを取得できませんでした".into());
        Some(anyhow::anyhow!(
            "コンテナが Agent の起動前に終了しました: {detail}"
        ))
    }

    async fn rollback_startup(&mut self) {
        let _ = self.stop_container().await;
        self.credentials = None;
        self.status = SandboxStatus::Stopped;
    }

    async fn start_container(&mut self, boot: &ContainerBootSettings) -> anyhow::Result<()> {
        self.host_port = find_available_port().await?;
        let credentials = SessionCredentials::new(self.container_runtime)?;
        let container_name = generate_container_name();
        let args = self.boot_args(&container_name, boot, &credentials);
        self.credentials = Some(credentials);
        self.container_name = Some(container_name);
        self.run_container(&args).await?;
        self.image = Some(boot.image.clone());
        self.mount_point = Some(boot.share.mount_point.to_string_lossy().to_string());
        self.wait_for_ready().await?;
        if let Some(endpoint) = &boot.dns_proxy {
            self.verify_dns_relay(endpoint).await?;
        }
        Ok(())
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

        let boot = self.boot_settings(config).await?;

        if let Err(error) = self.start_container(&boot).await {
            self.rollback_startup().await;
            return Err(error);
        }
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

        let mut client = self.connect_agent().await?;
        crate::agent_session::execute(&mut client, cmd, env).await
    }

    async fn exec_with_environment(
        &self,
        cmd: &[String],
        env: &HashMap<String, String>,
        inherit: &[String],
    ) -> anyhow::Result<ExecOutput> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }
        if cmd.is_empty() {
            anyhow::bail!("Command must not be empty");
        }
        let mut client = self.connect_agent().await?;
        crate::agent_session::execute_with_environment(&mut client, cmd, env, inherit).await
    }

    async fn shell(&self) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }
        let mut client = self.connect_agent().await?;
        let code = crate::terminal_shell::interactive_shell(&mut client).await?;
        if code != 0 {
            anyhow::bail!("shell exited with code {}", code);
        }
        Ok(())
    }

    async fn shell_with_environment(
        &self,
        env: &HashMap<String, String>,
        inherit: &[String],
    ) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }
        let mut client = self.connect_agent().await?;
        let code =
            crate::terminal_shell::interactive_shell_with_environment(&mut client, env, inherit)
                .await?;
        if code != 0 {
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

    fn agent_host_port(&self) -> Option<u16> {
        self.credentials.as_ref().map(|_| self.host_port)
    }

    fn agent_secret(&self) -> Option<&[u8]> {
        self.credentials
            .as_ref()
            .map(|credentials| credentials.auth_key.as_slice())
    }

    fn session_backend(&self) -> Option<crate::session::SessionBackend> {
        let container_name = self.container_name.as_ref()?;
        Some(crate::session::SessionBackend::AppleContainer {
            container_name: container_name.clone(),
            auth: Some(crate::session::ContainerSessionAuth {
                host_port: self.host_port,
                secret_file: self.credentials.as_ref()?.path(),
            }),
            image: self.image.clone().unwrap_or_default(),
            mount_point: self
                .mount_point
                .clone()
                .unwrap_or_else(|| "/workspace".to_string()),
            runtime: self.container_runtime,
        })
    }
}

impl AppleContainerSandbox {
    /// コンテナを停止・削除する。
    async fn remove_container(&self, name: &str) {
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
                self.remove_container(name).await;
            }
        }
        self.container_name = None;
        self.credentials = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::ShareConfig;
    use std::path::PathBuf;

    #[test]
    fn supported_container_runtimes_are_accepted_and_unknown_values_rejected() {
        for runtime in ["container", "docker", "podman"] {
            let sandbox = AppleContainerSandbox::with_runtime(runtime).unwrap();
            assert_eq!(sandbox.container_binary, runtime);
        }
        let error = AppleContainerSandbox::with_runtime("containerd")
            .err()
            .expect("unsupported runtime must fail");
        assert!(error.to_string().contains("Allowed values"));
    }

    #[tokio::test]
    async fn missing_runtime_error_names_selected_executable() {
        let binary = "/nonexistent/izanagi-container-runtime";
        let error = check_image_exists_with("fixture", binary)
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains(binary));
        assert!(message.contains("PATH"));
    }

    #[tokio::test]
    async fn container_spawn_and_unsuccessful_exit_restore_stopped_state() {
        for binary in ["/nonexistent/izanagi-container", "/usr/bin/false"] {
            let mut sandbox = AppleContainerSandbox {
                container_binary: binary.into(),
                status: SandboxStatus::Starting,
                ..Default::default()
            };
            assert!(sandbox.run_container(&[]).await.is_err());
            assert_eq!(sandbox.status, SandboxStatus::Stopped);
            assert!(sandbox.container_name.is_none());
        }
    }

    #[tokio::test]
    async fn failed_start_releases_session_key() {
        let mut sandbox = AppleContainerSandbox {
            container_binary: "/nonexistent/izanagi-container".into(),
            ..Default::default()
        };
        let boot = ContainerBootSettings {
            image: "fixture".into(),
            share: ShareConfig {
                host_paths: vec![],
                mount_point: "/workspace".into(),
                read_only: true,
            },
            dns_proxy: None,
            network: None,
        };
        assert!(sandbox.start_container(&boot).await.is_err());
        let path = sandbox.credentials.as_ref().unwrap().path();
        // up's rollback must release the same credentials even when runtime spawn fails.
        sandbox.rollback_startup().await;
        assert!(!path.exists());
        assert_eq!(sandbox.status, SandboxStatus::Stopped);
    }

    #[tokio::test]
    #[ignore = "requires a disposable Linux agent image and running Apple Container/Docker"]
    async fn real_container_session_credentials_and_agent_execution() {
        let runtime =
            std::env::var("IZANAGI_TEST_CONTAINER_RUNTIME").unwrap_or_else(|_| "container".into());
        let image = std::env::var("IZANAGI_TEST_CONTAINER_IMAGE").expect("fixture image required");
        let mut sandbox = AppleContainerSandbox::with_runtime(&runtime).unwrap();
        let config = SandboxConfig::AppleContainer {
            image,
            share: ShareConfig {
                host_paths: vec![],
                mount_point: "/project".into(),
                read_only: true,
            },
            dns_proxy: None,
            network: None,
        };
        let mut previous = None;
        for _ in 0..2 {
            sandbox.up(&config).await.unwrap();
            let path = sandbox.credentials.as_ref().unwrap().path();
            let result = check_real_session(&sandbox, previous.as_deref()).await;
            previous = Some(sandbox.session_secret().unwrap().to_vec());
            let shutdown = sandbox.down().await;
            result.unwrap();
            shutdown.unwrap();
            assert!(!path.exists());
        }
    }

    async fn check_real_session(
        sandbox: &AppleContainerSandbox,
        previous: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let key = sandbox.session_secret()?;
        anyhow::ensure!(previous != Some(key), "session key reused");
        let host_key = crate::protocol::load_shared_secret_from_env()?;
        anyhow::ensure!(
            host_key.as_deref() != Some(key),
            "host long-term key reused"
        );
        check_runtime_environment(sandbox).await?;
        for wrong in [previous, host_key.as_deref(), None] {
            let authentication = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                crate::agent_session::connect(sandbox.host_port, wrong.map(<[u8]>::to_vec), None),
            )
            .await;
            anyhow::ensure!(
                !matches!(authentication, Ok(Ok(_))),
                "invalid key authenticated"
            );
        }
        check_agent_exec(sandbox).await?;
        let backend = persisted_container_backend(sandbox)?;
        check_external_session(&backend).await?;
        check_agent_shell(&backend).await
    }

    fn persisted_container_backend(
        sandbox: &AppleContainerSandbox,
    ) -> anyhow::Result<crate::session::SessionBackend> {
        let directory = tempfile::tempdir()?;
        let session = crate::session::Session {
            backend: sandbox.session_backend().unwrap(),
            pid: std::process::id(),
            started_at: 0,
        };
        crate::session::save_session(directory.path(), &session)?;
        let json = std::fs::read_to_string(crate::session::session_file_path(directory.path()))?;
        anyhow::ensure!(
            !json.contains(std::str::from_utf8(sandbox.session_secret()?)?),
            "session JSON contains key"
        );
        Ok(crate::session::load_session(directory.path())?
            .unwrap()
            .backend)
    }

    // Shared guest assertions for both authenticated execution paths.
    const GUEST_IDENTITY_CHECK: &str = r#"test -z "$IZANAGI_SHARED_SECRET" && test -z "$IZANAGI_SECRET_FILE" && test "$(pwd)" = /project && test "$(id -u)" = 1000 && test "$(id -G)" = 1000 && grep -q '^Groups:[[:space:]]*$' /proc/self/status"#;

    async fn check_agent_exec(sandbox: &AppleContainerSandbox) -> anyhow::Result<()> {
        let env = HashMap::from([
            ("LD_PRELOAD".into(), "/nonexistent/injected.so".into()),
            ("CANARY".into(), "fixture".into()),
        ]);
        let script = format!(
            "{GUEST_IDENTITY_CHECK} && test -z \"$LD_PRELOAD\" && test \"$CANARY\" = fixture"
        );
        let output = sandbox
            .exec(&["/bin/sh".into(), "-c".into(), script], &env)
            .await?;
        anyhow::ensure!(
            output.exit_code == 0,
            "agent exec credentials/environment/workdir failed"
        );
        Ok(())
    }

    async fn check_external_session(
        backend: &crate::session::SessionBackend,
    ) -> anyhow::Result<()> {
        let mut client = backend.connect_agent().await?;
        let output = crate::agent_session::execute(
            &mut client,
            &["/bin/echo".into(), "external-session".into()],
            &HashMap::new(),
        )
        .await?;
        anyhow::ensure!(
            output.stdout == b"external-session\n",
            "external session connection failed"
        );
        Ok(())
    }

    async fn check_runtime_environment(sandbox: &AppleContainerSandbox) -> anyhow::Result<()> {
        let name = sandbox.container_name.as_deref().unwrap();
        let output = Command::new(&sandbox.container_binary)
            .args(["exec", "-u", "izanagi", name, "env"])
            .output()
            .await?;
        anyhow::ensure!(output.status.success(), "runtime environment probe failed");
        let environment = String::from_utf8_lossy(&output.stdout);
        anyhow::ensure!(
            !environment.contains("IZANAGI_SHARED_SECRET=")
                && !environment.contains(std::str::from_utf8(sandbox.session_secret()?)?),
            "runtime leaked key"
        );
        check_mounted_file(sandbox).await
    }

    async fn check_mounted_file(sandbox: &AppleContainerSandbox) -> anyhow::Result<()> {
        let name = sandbox.container_name.as_deref().unwrap();
        let file = format!("{GUEST_SECRET_DIR}/{SECRET_FILENAME}");
        let output = Command::new(&sandbox.container_binary)
            .args([
                "exec",
                "-u",
                "izanagi",
                name,
                "/bin/sh",
                "-c",
                &format!("test ! -r {file}"),
            ])
            .output()
            .await?;
        anyhow::ensure!(output.status.success(), "unprivileged user can read secret");
        let output = Command::new(&sandbox.container_binary)
            .args([
                "exec",
                "-u",
                "root",
                name,
                "/bin/sh",
                "-c",
                &format!("printf x >> {file}"),
            ])
            .output()
            .await?;
        anyhow::ensure!(!output.status.success(), "secret mount is writable");
        anyhow::ensure!(
            crate::protocol::load_shared_secret_from_file(
                &sandbox.credentials.as_ref().unwrap().path()
            )? == sandbox.session_secret()?,
            "mounted key changed"
        );
        Ok(())
    }

    async fn check_agent_shell(backend: &crate::session::SessionBackend) -> anyhow::Result<()> {
        use crate::protocol::Message;
        let mut client = backend.connect_agent().await?;
        client
            .send_message(&Message::Shell { rows: 24, cols: 80 })
            .await?;
        client
            .send_message(&Message::ShellData {
                stream: 0,
                data: format!("{GUEST_IDENTITY_CHECK}; exit $?\n").into_bytes(),
            })
            .await?;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match client.recv_message().await? {
                    Some(Message::ShellData { .. }) => {}
                    Some(Message::ShellClose { exit_code }) => {
                        anyhow::ensure!(
                            exit_code == 0,
                            "agent shell environment/credentials/workdir failed"
                        );
                        return Ok(());
                    }
                    _ => anyhow::bail!("agent shell closed unexpectedly"),
                }
            }
        })
        .await?
    }

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

    #[test]
    fn image_exists_in_output_accepts_implicit_latest_tag() {
        let output = "REPOSITORY:TAG       IMAGE ID\n\
                      temiya-dev:latest   abc123\n";
        assert!(image_exists_in_output(output, "temiya-dev"));
        assert!(image_exists_in_output(output, "temiya-dev:latest"));
        assert!(!image_exists_in_output(output, "temiya"));
    }

    #[test]
    fn image_exists_in_output_matches_name_and_tag() {
        let output = "NAME TAG IMAGE ID\nregistry:5000/app stable abc\nregistry:5000/app latest def\nother stable ghi\n";
        assert!(image_exists_in_output(output, "registry:5000/app:stable"));
        assert!(image_exists_in_output(output, "registry:5000/app"));
        assert!(!image_exists_in_output(output, "other"));
        assert!(!image_exists_in_output(output, "registry:5000/app:missing"));
        assert!(!image_exists_in_output(output, "abc"));
    }

    // --- コマンドライン生成テスト (#150, #151) ---

    #[test]
    fn build_run_args_basic() {
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
            read_only: false,
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
    fn session_key_is_private_unique_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let first = SessionCredentials::new_in(None).unwrap();
        let second = SessionCredentials::new_in(None).unwrap();
        assert!(*first.auth_key != *second.auth_key);
        assert_eq!(first.auth_key.len(), 64);
        let path = first.path();
        assert!(crate::protocol::load_shared_secret_from_file(&path).unwrap() == *first.auth_key);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(first.directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        drop(first);
        assert!(!path.exists());
        assert!(second.path().exists());
    }

    #[test]
    fn run_mounts_secret_read_only_without_inline_environment() {
        let credentials = SessionCredentials::new_in(None).unwrap();
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: "/workspace".into(),
            read_only: false,
        };
        let args = build_run_args(
            "test",
            "image",
            9001,
            &share,
            credentials.directory.path().to_str(),
            None,
            None,
        );
        assert!(args.contains(&format!(
            "{}:{GUEST_SECRET_DIR}:ro",
            credentials.directory.path().display()
        )));
        assert!(args.contains(&format!(
            "IZANAGI_SECRET_FILE={GUEST_SECRET_DIR}/{SECRET_FILENAME}"
        )));
        assert!(!args.iter().any(|arg| arg.contains("IZANAGI_SHARED_SECRET")
            || arg.contains(std::str::from_utf8(&credentials.auth_key).unwrap())));
        assert!(!args.contains(&"--env-file".into()));
    }

    #[test]
    fn build_run_args_with_volume() {
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/home/user/project")],
            mount_point: PathBuf::from("/workspace"),
            read_only: false,
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
            read_only: false,
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
            read_only: false,
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
            read_only: false,
        };
        let args = build_run_args(
            "izanagi-test",
            "izanagi-vm",
            9001,
            &share,
            None,
            Some("192.168.1.2:15353"),
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
            read_only: false,
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
            read_only: false,
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
            read_only: false,
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
            read_only: false,
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

#[cfg(test)]
mod share_security_tests {
    #[test]
    fn volume_enforces_both_share_modes() {
        for (read_only, option) in [(true, ":ro"), (false, "")] {
            let share = crate::sandbox::ShareConfig {
                host_paths: vec!["/project".into()],
                mount_point: "/workspace".into(),
                read_only,
            };
            let mut args = Vec::new();
            super::push_container_share(&mut args, &share);
            assert_eq!(args, ["--volume", &format!("/project:/workspace{option}")]);
        }
    }
}
