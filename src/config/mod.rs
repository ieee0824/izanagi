use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::detector::Rule;
use crate::event::SyscallCategory;
use crate::rules::{
    EnvAccessRule, NetworkAllowlistRule, ProcessBaselineRule, SuspiciousPathRule,
    UnexpectedExecRule, WorkspaceWriteRule,
};
use crate::sandbox::{SandboxConfig, ShareConfig};
use crate::tracer::TraceFilter;

/// サンドボックスバックエンド。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxBackend {
    Qemu,
    Native,
    /// Apple Container (macOS only)。`container` CLI を使用。
    AppleContainer,
}

/// トレーサーバックエンド。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TracerBackend {
    /// トレーサーを使用しない。
    None,
    Auto,
    Ebpf,
    Dtrace,
    #[serde(rename = "vm-agent")]
    #[value(name = "vm-agent")]
    VmAgent,
}

/// izanagi.toml のトップレベル構造体。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub behavior: crate::behavior_config::BehaviorSection,
    pub sandbox: SandboxSection,
    pub share: ShareSection,
    pub monitor: MonitorSection,
    pub detect: DetectSection,
    /// `[dns_proxy]` セクション。DNS プロキシの自動構成。
    pub dns_proxy: Option<DnsProxySection>,
    /// `[http_capture]` セクション。HTTP/HTTPS キャプチャプロキシの自動構成。
    pub http_capture: Option<HttpCaptureSection>,
}

/// `[sandbox]` セクション。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSection {
    /// サンドボックスバックエンド。
    pub backend: SandboxBackend,
    /// トレーサー。
    pub tracer: TracerBackend,
    /// HMAC 認証を必須にするかどうか。
    /// `true` の場合、共有シークレットが設定されていなければ起動時にエラーとなる。
    /// デフォルトは `None`（= false 相当）。
    pub require_auth: Option<bool>,
    /// `[sandbox.qemu]` サブセクション。QEMU バックエンド使用時のみ必要。
    pub qemu: Option<QemuSection>,
    /// `[sandbox.apple_container]` サブセクション。Apple Container バックエンド使用時のオプション。
    pub apple_container: Option<AppleContainerSection>,
}

/// `[sandbox.qemu]` セクション。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QemuSection {
    pub cpus: u32,
    pub memory: String,
    pub image: String,
    /// Block guest access to the host and external network unless explicitly disabled.
    #[serde(default = "default_restrict_network")]
    pub restrict_network: bool,
}

/// コンテナのネットワークモード。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerNetworkMode {
    /// ネットワーク完全遮断。
    None,
}

/// `[sandbox.apple_container]` セクション。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleContainerSection {
    /// コンテナイメージ名。デフォルトは `"izanagi-vm"`。
    #[serde(default = "default_apple_container_image")]
    pub image: String,
    /// ネットワークモード。`None`（未指定）でデフォルト (bridge)。
    pub network: Option<ContainerNetworkMode>,
}

fn default_apple_container_image() -> String {
    "izanagi-vm".to_string()
}

impl Default for AppleContainerSection {
    fn default() -> Self {
        Self {
            image: default_apple_container_image(),
            network: None,
        }
    }
}

/// `[dns_proxy]` セクション。DNS プロキシの自動構成。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProxySection {
    /// DNS プロキシを有効にするかどうか。
    #[serde(default)]
    pub enabled: bool,
    /// DNS プロキシのリッスンアドレス。サンドボックスの DNS 設定に使用する。
    /// デフォルトは `"127.0.0.1:15353"`。
    #[serde(default = "default_dns_proxy_listen")]
    pub listen: String,
}

fn default_dns_proxy_listen() -> String {
    // ポート 53 は root 権限が必要なため、非特権ポートをデフォルトにする
    "127.0.0.1:15353".to_string()
}

/// `[http_capture]` セクション。HTTP/HTTPS キャプチャプロキシの自動構成。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCaptureSection {
    /// HTTP キャプチャプロキシを有効にするかどうか。
    #[serde(default)]
    pub enabled: bool,
    /// HTTP リッスンアドレス。
    #[serde(default = "default_http_listen")]
    pub listen_http: std::net::SocketAddr,
    /// HTTPS (TLS MITM) リッスンアドレス。
    #[serde(default = "default_https_listen")]
    pub listen_https: std::net::SocketAddr,
    /// 生成した CA 証明書の出力先パス。
    pub ca_cert_out: Option<std::path::PathBuf>,
    /// シークレット置換マッピング (`HOST:Authorization:DUMMY=REAL` 形式)。
    /// サンドボックス内ではダミー値を使い、プロキシが上流転送時に本物に置換する。
    /// セキュリティ上、設定ファイルに実際のトークンを直書きせず、
    /// 環境変数やファイルから読み込む運用を推奨する。
    #[serde(default)]
    pub secret_maps: Vec<String>,
}

fn default_http_listen() -> std::net::SocketAddr {
    "127.0.0.1:18080".parse().unwrap()
}

fn default_https_listen() -> std::net::SocketAddr {
    "127.0.0.1:18443".parse().unwrap()
}

/// `[share]` セクション。ホスト-ゲスト間のファイル共有設定。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSection {
    pub paths: Vec<String>,
    pub mount_point: String,
    /// Protect the entire share, including Git metadata, by default.
    #[serde(default = "default_read_only_share")]
    pub read_only: bool,
}

/// `[monitor]` セクション。監視対象の syscall カテゴリ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSection {
    pub syscalls: Vec<SyscallCategory>,
}

/// `[detect]` セクション。検知ルール。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectSection {
    pub suspicious_paths: Vec<String>,
    pub allowed_hosts: Vec<String>,
    /// ベースラインの既知プロセス名リスト。未設定の場合はデフォルトベースラインを使用。
    pub known_processes: Option<Vec<String>>,
}

// --- Default impls ---

impl Default for SandboxSection {
    fn default() -> Self {
        Self {
            backend: SandboxBackend::Native,
            tracer: TracerBackend::Auto,
            require_auth: None,
            qemu: None,
            apple_container: None,
        }
    }
}

fn default_restrict_network() -> bool {
    true
}

impl Default for QemuSection {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory: "4G".to_string(),
            image: "default".to_string(),
            restrict_network: true,
        }
    }
}

fn default_read_only_share() -> bool {
    true
}

impl Default for ShareSection {
    fn default() -> Self {
        Self {
            paths: vec![".".to_string()],
            mount_point: "/workspace".to_string(),
            read_only: true,
        }
    }
}

impl Default for MonitorSection {
    fn default() -> Self {
        Self {
            syscalls: vec![
                SyscallCategory::File,
                SyscallCategory::Network,
                SyscallCategory::Process,
            ],
        }
    }
}

impl Default for DetectSection {
    fn default() -> Self {
        Self {
            suspicious_paths: vec![
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "~/.ssh/*".to_string(),
                "~/.aws/*".to_string(),
                "~/.gnupg/*".to_string(),
                "~/.config/gh/*".to_string(),
            ],
            allowed_hosts: vec![],
            known_processes: None,
        }
    }
}

// --- Validation ---

/// 共有対象と祖先・子孫の重なりを拒否する機密パス。
const SENSITIVE_SHARE_PATHS: &[&str] = &["~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh"];

/// 共有が禁止されているシステムディレクトリ。
/// これらのパスそのものを共有対象にすることを禁止する。
const FORBIDDEN_SHARE_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/var",
    "/home",
    "/root",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/sys",
    "/proc",
    "/dev",
    "/boot",
    "/opt",
    "/Users",
    "/private",
    "/System",
    "/Library",
    "/Applications",
    "/Volumes",
    "/System/Volumes",
    "/System/Volumes/Data",
    "/System/Volumes/Data/System",
];

impl Config {
    /// TOML 文字列から Config をパースする。
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        let config: Config = toml::from_str(s)?;
        Ok(config)
    }

    /// 設定ファイルを読み込む。ファイルが存在しない場合はデフォルト値を返す。
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let config = Self::from_toml(&content)?;
                config.validate_config_location(path)?;
                Ok(config)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::Error::new(e).context(format!("failed to read {:?}", path))),
        }
    }

    /// 設定値のバリデーションを行う。
    /// 戻り値の `Vec<String>` はバリデーション時の警告メッセージ。
    pub fn validate(&self) -> anyhow::Result<Vec<String>> {
        self.validate_for_platform(cfg!(target_os = "linux"), cfg!(target_os = "macos"))
    }

    /// プラットフォーム判定を引数として受け取るバリデーション。テストで各プラットフォームの挙動を検証可能。
    fn validate_for_platform(&self, is_linux: bool, is_macos: bool) -> anyhow::Result<Vec<String>> {
        self.validate_behavior_backend()?;
        // プラットフォームに応じたバックエンド利用可能性チェック
        if self.sandbox.backend == SandboxBackend::Native && !is_linux && !is_macos {
            bail!(
                "sandbox.backend \"native\" は現在のプラットフォームではサポートされていません (Linux または macOS が必要)"
            );
        }

        // apple-container は macOS でのみ利用可能
        if self.sandbox.backend == SandboxBackend::AppleContainer && !is_macos {
            bail!("sandbox.backend \"apple-container\" は macOS でのみ利用可能です");
        }

        // tracer のプラットフォーム検証
        match self.sandbox.tracer {
            TracerBackend::Ebpf => {
                if !is_linux {
                    bail!("sandbox.tracer \"ebpf\" は Linux でのみ利用可能です");
                }
            }
            TracerBackend::Dtrace if !is_macos => {
                bail!("sandbox.tracer \"dtrace\" は macOS でのみ利用可能です");
            }
            _ => {}
        }

        self.validate_container_network()?;
        self.validate_qemu_network()?;
        self.validate_dns_proxy(is_macos)?;

        let mut warnings = Vec::new();
        if self.sandbox.backend == SandboxBackend::Qemu
            && self
                .sandbox
                .qemu
                .as_ref()
                .is_some_and(|q| !q.restrict_network)
        {
            warnings.push("QEMU network restrictions disabled: guests can reach host loopback services and external IPs; DNS filtering is not an IP firewall".into());
        }

        // share.paths のバリデーション
        warnings.extend(self.validate_share_paths()?);
        if !self.share.read_only {
            warnings.push("Writable shares allow sandbox code to change host files, including Git hooks/config and build/editor scripts; review changes before host execution".into());
        }

        Ok(warnings)
    }

    fn validate_behavior_backend(&self) -> anyhow::Result<()> {
        self.behavior.validate()?;
        if self.behavior.enabled
            && (self.sandbox.backend != SandboxBackend::Qemu
                || self.sandbox.tracer != TracerBackend::VmAgent)
        {
            bail!("behavior PoC requires sandbox.backend=qemu and tracer=vm-agent");
        }
        if self.behavior.enabled && self.sandbox.require_auth == Some(false) {
            bail!("behavior PoC requires token/HMAC authentication");
        }
        // backend=qemu の場合は qemu セクションが必要
        if self.sandbox.backend == SandboxBackend::Qemu && self.sandbox.qemu.is_none() {
            bail!("sandbox.backend が \"qemu\" の場合、[sandbox.qemu] セクションが必要です");
        }

        // qemu セクションのバリデーション
        if let Some(ref qemu) = self.sandbox.qemu
            && qemu.cpus == 0
        {
            bail!("sandbox.qemu.cpus は 1 以上でなければなりません");
        }

        Ok(())
    }

    fn validate_qemu_network(&self) -> anyhow::Result<()> {
        if self.sandbox.backend == SandboxBackend::Qemu
            && self
                .sandbox
                .qemu
                .as_ref()
                .is_some_and(|q| q.restrict_network)
            && (self.dns_proxy.as_ref().is_some_and(|p| p.enabled)
                || self.http_capture.as_ref().is_some_and(|p| p.enabled))
        {
            bail!(
                "QEMU restrict_network=true blocks proxy access; explicitly set sandbox.qemu.restrict_network=false to enable network proxies (including host loopback access)"
            );
        }
        Ok(())
    }

    fn validate_container_network(&self) -> anyhow::Result<()> {
        // apple-container の network=none はポートフォワードと非互換のためエラーにする。
        // エージェントとの TCP 通信ができなくなり、起動がタイムアウトする。
        // 将来的に container exec ベースの Ready 判定を実装した際に解除予定。
        if matches!(
            self.sandbox.backend,
            SandboxBackend::AppleContainer | SandboxBackend::Native
        ) && let Some(ref ac) = self.sandbox.apple_container
            && ac.network == Some(ContainerNetworkMode::None)
        {
            bail!(
                "sandbox.apple_container.network = \"none\" は現在サポートされていません。\
                 ポートフォワード (-p) が無効になり、エージェントとの通信ができません。\
                 ネットワーク隔離には QEMU restrict_network=true を使用してください"
            );
        }

        Ok(())
    }

    /// 共有パスのバリデーション。
    /// 戻り値の `Vec<String>` は警告メッセージのリスト。
    fn validate_share_paths(&self) -> anyhow::Result<Vec<String>> {
        let mut warnings = Vec::new();

        for path in &self.share.paths {
            validate_share_path_shape(path)?;

            // パスを正規化して機密パス判定を行う
            let normalized = normalize_share_path(path)?;

            // 存在するパスはシンボリックリンクを解決して実パスを取得する
            let resolved = resolve_share_path(path, &normalized)?;

            validate_share_boundaries(path, Path::new(&normalized), Path::new(&resolved))?;

            if let Some(warning) = missing_share_path_warning(path) {
                warnings.push(warning);
            }
        }

        Ok(warnings)
    }

    /// Reject settings that can be replaced through a shared directory, including symlinks.
    pub fn validate_config_location(&self, config_path: &Path) -> anyhow::Result<()> {
        let configured_path = absolute_path(config_path)?;
        let containing_dir = canonical_boundary_path(
            configured_path
                .parent()
                .context("configuration path has no parent")?,
        )?;
        let configured_path = containing_dir.join(
            configured_path
                .file_name()
                .context("configuration path has no file name")?,
        );
        let resolved_path = canonical_boundary_path(config_path)?;
        for share in &self.share.paths {
            validate_share_path_shape(share)?;
            let normalized = normalize_share_path(share)?;
            let resolved = resolve_share_path(share, &normalized)?;
            let resolved_share = absolute_path(Path::new(&resolved))?;
            if configured_path.starts_with(&resolved_share)
                || resolved_path.starts_with(&resolved_share)
            {
                bail!(
                    "設定ファイルは share.paths の配下に保存できません。`izanagi config path` が示す共有領域外の場所へ移し、内容を確認するか、`izanagi init` で再作成してください"
                );
            }
        }
        Ok(())
    }

    // --- Config → 内部型への変換 ---

    /// Config から SandboxConfig への変換。
    /// 事前に `validate()` を呼んでいることを前提とする。
    pub fn to_sandbox_config(&self) -> anyhow::Result<SandboxConfig> {
        self.to_sandbox_config_for_platform(cfg!(target_os = "linux"))
    }

    /// プラットフォーム判定を引数として受け取る SandboxConfig 変換。テストで各プラットフォームの挙動を検証可能。
    fn to_sandbox_config_for_platform(&self, is_linux: bool) -> anyhow::Result<SandboxConfig> {
        self.validate_dns_proxy(!is_linux)?;
        let share = ShareConfig {
            host_paths: self.share.paths.iter().map(PathBuf::from).collect(),
            mount_point: PathBuf::from(&self.share.mount_point),
            read_only: self.share.read_only,
        };

        // DNS プロキシが有効な場合、listen の IP とポートを保持する
        let dns_proxy_endpoint = self.dns_proxy_endpoint();

        match self.sandbox.backend {
            SandboxBackend::Qemu => {
                let qemu = self
                    .sandbox
                    .qemu
                    .as_ref()
                    .context("[sandbox.qemu] セクションが必要です")?;
                let memory_mb = parse_memory_mb(&qemu.memory)?;
                Ok(SandboxConfig::Qemu {
                    cpus: qemu.cpus,
                    memory_mb,
                    image: qemu.image.clone(),
                    share,
                    dns_proxy: dns_proxy_endpoint.clone(),
                    restrict_network: qemu.restrict_network,
                })
            }
            SandboxBackend::Native => {
                if is_linux {
                    Ok(SandboxConfig::Landlock { share })
                } else {
                    self.apple_sandbox_config(share, dns_proxy_endpoint)
                }
            }
            SandboxBackend::AppleContainer => self.apple_sandbox_config(share, dns_proxy_endpoint),
        }
    }

    fn apple_sandbox_config(
        &self,
        share: ShareConfig,
        dns_proxy: Option<String>,
    ) -> anyhow::Result<SandboxConfig> {
        let ac = self
            .sandbox
            .apple_container
            .as_ref()
            .cloned()
            .unwrap_or_default();
        if ac.network == Some(ContainerNetworkMode::None) {
            anyhow::bail!(
                "sandbox.apple_container.network = \"none\" は現在サポートされていません"
            );
        }
        Ok(SandboxConfig::AppleContainer {
            image: ac.image,
            share,
            dns_proxy,
            network: ac.network,
        })
    }

    /// Preserve the host endpoint, including its nonstandard port.
    fn dns_proxy_endpoint(&self) -> Option<String> {
        self.dns_proxy
            .as_ref()
            .filter(|p| p.enabled)
            .and_then(|p| p.listen.parse::<std::net::SocketAddr>().ok())
            .map(|addr| addr.to_string())
    }

    fn validate_dns_proxy(&self, is_macos: bool) -> anyhow::Result<()> {
        let Some(section) = self.dns_proxy.as_ref().filter(|p| p.enabled) else {
            return Ok(());
        };
        let addr: std::net::SocketAddr = section
            .listen
            .parse()
            .context("dns_proxy.listen must be an IP:port endpoint")?;
        if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
            bail!("dns_proxy.listen must be a concrete unicast address with a nonzero port");
        }
        match self.sandbox.backend {
            SandboxBackend::Qemu
                if addr.ip().is_loopback() && addr.ip() != std::net::Ipv4Addr::LOCALHOST =>
            {
                bail!("QEMU DNS relay supports only 127.0.0.1 as host loopback");
            }
            SandboxBackend::Qemu => {}
            SandboxBackend::AppleContainer | SandboxBackend::Native if is_macos => {
                if addr.ip().is_loopback() {
                    bail!(
                        "container DNS relay needs a guest-reachable host address; host loopback is not reachable"
                    );
                }
            }
            _ => bail!("DNS proxy integration requires QEMU or Apple Container"),
        }
        Ok(())
    }

    /// Config から TraceFilter への変換。
    pub fn to_trace_filter(&self) -> TraceFilter {
        TraceFilter {
            categories: self.monitor.syscalls.clone(),
            pids: None,
        }
    }

    /// Config から検知ルール一覧への変換。
    /// 設定に基づいて SuspiciousPathRule, NetworkAllowlistRule, UnexpectedExecRule, EnvAccessRule を生成する。
    ///
    /// ユーザ設定由来のルール（SuspiciousPathRule, NetworkAllowlistRule）が未設定の場合、
    /// `to_rules_with_warnings()` で警告が返る。警告内容を確認したい場合はそちらを使うこと。
    pub fn to_rules(&self) -> Vec<Box<dyn Rule>> {
        let (rules, _warnings) = self.to_rules_with_warnings();
        rules
    }

    /// `to_rules()` と同じだが、ルール構築時の警告メッセージも返す。
    ///
    /// 警告には以下が含まれる:
    /// - glob パターンの構文エラー
    /// - HOME 未設定によるチルダ展開失敗
    /// - DNS 解決の失敗
    /// - ユーザ設定由来のルール未設定
    pub fn to_rules_with_warnings(&self) -> (Vec<Box<dyn Rule>>, Vec<String>) {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        let mut warnings = Vec::new();

        if !self.detect.suspicious_paths.is_empty() {
            let (rule, rule_warnings) =
                SuspiciousPathRule::new_with_warnings(&self.detect.suspicious_paths);
            warnings.extend(rule_warnings);
            rules.push(Box::new(rule));
        }

        // allowed_hosts が空でも NetworkAllowlistRule を生成し、全通信を警告する
        let mut network_rule = NetworkAllowlistRule::new(&self.detect.allowed_hosts);
        let resolve_warnings = network_rule.resolve_hosts_with_warnings();
        warnings.extend(resolve_warnings);
        rules.push(Box::new(network_rule));

        // UnexpectedExecRule と EnvAccessRule は常に有効
        rules.push(Box::new(UnexpectedExecRule::new()));
        rules.push(Box::new(EnvAccessRule::new()));
        rules.push(Box::new(WorkspaceWriteRule::new(
            &self.share.paths,
            &self.share.mount_point,
        )));

        // ProcessBaselineRule: 設定があればそれを使い、なければデフォルトベースライン
        match &self.detect.known_processes {
            Some(procs) => rules.push(Box::new(ProcessBaselineRule::new(procs))),
            None => rules.push(Box::new(ProcessBaselineRule::with_defaults())),
        }

        if self.detect.suspicious_paths.is_empty() && self.detect.allowed_hosts.is_empty() {
            warnings.push(
                "警告: ユーザ設定由来の検知ルール (suspicious_paths, allowed_hosts) が未設定です。detect セクションの設定を確認してください"
                    .to_string(),
            );
        }

        (rules, warnings)
    }

    /// `to_rules_with_warnings()` の非同期版。DNS 解決にタイムアウトを適用する。
    pub async fn to_rules_with_warnings_async(
        &self,
        dns_timeout: std::time::Duration,
    ) -> (Vec<Box<dyn Rule>>, Vec<String>) {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        let mut warnings = Vec::new();

        if !self.detect.suspicious_paths.is_empty() {
            let (rule, rule_warnings) =
                SuspiciousPathRule::new_with_warnings(&self.detect.suspicious_paths);
            warnings.extend(rule_warnings);
            rules.push(Box::new(rule));
        }

        let mut network_rule = NetworkAllowlistRule::new(&self.detect.allowed_hosts);
        let resolve_warnings = network_rule.resolve_hosts_with_timeout(dns_timeout).await;
        warnings.extend(resolve_warnings);
        rules.push(Box::new(network_rule));

        rules.push(Box::new(UnexpectedExecRule::new()));
        rules.push(Box::new(EnvAccessRule::new()));
        rules.push(Box::new(WorkspaceWriteRule::new(
            &self.share.paths,
            &self.share.mount_point,
        )));

        // ProcessBaselineRule: 設定があればそれを使い、なければデフォルトベースライン
        match &self.detect.known_processes {
            Some(procs) => rules.push(Box::new(ProcessBaselineRule::new(procs))),
            None => rules.push(Box::new(ProcessBaselineRule::with_defaults())),
        }

        if self.detect.suspicious_paths.is_empty() && self.detect.allowed_hosts.is_empty() {
            warnings.push(
                "警告: ユーザ設定由来の検知ルール (suspicious_paths, allowed_hosts) が未設定です。detect セクションの設定を確認してください"
                    .to_string(),
            );
        }

        (rules, warnings)
    }
}

/// 共有パスを正規化する。`~` 展開を行い、正規化した文字列を返す。
fn normalize_share_path(path: &str) -> anyhow::Result<String> {
    crate::util::expand_tilde(path)
}

/// メモリ量の文字列 (例: "4G", "512M") を MB 単位の u32 に変換する。
fn parse_memory_mb(s: &str) -> anyhow::Result<u32> {
    let s = s.trim();
    if s.is_empty() {
        bail!("メモリ量が空です");
    }

    let (num_str, suffix) = if let Some(n) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        (n, "G")
    } else if let Some(n) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        (n, "M")
    } else {
        // サフィックスなしの場合は MB とみなす
        (s, "M")
    };

    let num: u32 = num_str
        .parse()
        .with_context(|| format!("メモリ量のパースに失敗: \"{}\"", s))?;

    match suffix {
        "G" => Ok(num
            .checked_mul(1024)
            .context("メモリ量がオーバーフローしました")?),
        _ => Ok(num),
    }
}

// ---------------------------------------------------------------------------
// 設定ファイルパスの自動解決
// ---------------------------------------------------------------------------

/// izanagi のベースディレクトリ (`~/.izanagi`)。
///
/// `HOME` 環境変数が設定されていない場合はエラーを返す。
pub fn izanagi_home() -> anyhow::Result<PathBuf> {
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME 環境変数が設定されていません"))?;
    Ok(PathBuf::from(home).join(".izanagi"))
}

/// カレントディレクトリに基づく設定ファイルのパスを返す。
///
/// パス: `~/.izanagi/settings/{sha256(canonical_pwd)}/izanagi.toml`
///
/// pwd の正規化に失敗した場合は `None` を返す。
pub fn settings_path_for_pwd() -> anyhow::Result<PathBuf> {
    let pwd = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("カレントディレクトリの取得に失敗: {e}"))?;
    let canonical = pwd
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("パスの正規化に失敗: {e}"))?;
    settings_path_for_dir(&canonical)
}

/// 指定ディレクトリに基づく設定ファイルのパスを返す。
pub fn settings_path_for_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(dir.as_os_str().as_encoded_bytes()));
    Ok(izanagi_home()?
        .join("settings")
        .join(hash)
        .join("izanagi.toml"))
}

/// 設定ファイルを自動解決する。
/// プロジェクト内の設定にはフォールバックせず、settings パスを返す。
pub fn resolve_config_path() -> anyhow::Result<PathBuf> {
    settings_path_for_pwd()
}

fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}

fn missing_share_path_warning(path: &str) -> Option<String> {
    let p = Path::new(path);
    if !path.starts_with('~') && p.is_absolute() && !p.exists() {
        Some(format!(
            "警告: share.paths のパス \"{}\" は存在しません",
            path
        ))
    } else {
        None
    }
}

fn validate_share_path_shape(path: &str) -> anyhow::Result<()> {
    // ルートパスの共有を禁止
    if path == "/" {
        bail!("share.paths にルートパス \"/\" を指定することはできません");
    }

    // ".." コンポーネントを含むパスを拒否（パストラバーサル防止）
    let p = Path::new(path);
    for component in p.components() {
        if component == std::path::Component::ParentDir {
            bail!(
                "share.paths に \"..\" を含むパス \"{}\" を指定することはできません",
                path
            );
        }
    }

    Ok(())
}

fn resolve_share_path(path: &str, normalized: &str) -> anyhow::Result<String> {
    resolve_existing_prefix(Path::new(normalized))
        .with_context(|| {
            format!(
                "share.paths のパス \"{}\" のシンボリックリンク解決に失敗しました",
                path
            )
        })
        .map(|resolved| resolved.to_string_lossy().into_owned())
}

/// Resolve the existing prefix too, so missing children below an alias stay protected.
fn resolve_existing_prefix(path: &Path) -> anyhow::Result<PathBuf> {
    let absolute = absolute_path(path)?;
    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match canonical_boundary_path(ancestor) {
            Ok(mut resolved) => {
                append_missing_components(&mut resolved, &missing)?;
                return Ok(resolved);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                // An existing dangling symlink must fail closed, not become a lexical path.
                if std::fs::symlink_metadata(ancestor).is_ok() {
                    return Err(error.into());
                }
                missing.push(
                    ancestor
                        .file_name()
                        .context("path has no resolvable ancestor")?,
                );
                ancestor = ancestor
                    .parent()
                    .context("path has no resolvable ancestor")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Use the filesystem's actual names on macOS: realpath leaves case/firmlink aliases intact.
fn canonical_boundary_path(path: &Path) -> std::io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        // O_EVTONLY obtains a descriptor without reading file contents.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_EVTONLY)
            .open(canonical)?;
        let mut bytes = [0u8; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH writes at most PATH_MAX bytes to the provided live buffer.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, bytes.as_mut_ptr()) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| std::io::Error::other("filesystem returned an unterminated path"))?;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..length])))
    }
    #[cfg(not(target_os = "macos"))]
    Ok(canonical)
}

fn append_missing_components(
    resolved: &mut PathBuf,
    missing: &[&std::ffi::OsStr],
) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    if !missing.is_empty() {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(resolved.as_os_str().as_bytes())?;
        // SAFETY: path is a live, NUL-terminated pathname; pathconf does not retain it.
        let case_sensitive = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
        anyhow::ensure!(
            case_sensitive == 0 || case_sensitive == 1,
            "filesystem case sensitivity could not be determined"
        );
        if case_sensitive == 0 {
            // Protected directory names are ASCII; preserve Unicode bytes while folding ASCII aliases.
            for component in missing.iter().rev() {
                resolved.push(std::ffi::OsStr::from_bytes(
                    &component.as_bytes().to_ascii_lowercase(),
                ));
            }
            return Ok(());
        }
    }
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(())
}

fn validate_share_boundaries(
    original: &str,
    normalized: &Path,
    resolved: &Path,
) -> anyhow::Result<()> {
    let normalized = absolute_path(normalized)?;
    let shares = [normalized.as_path(), resolved];
    validate_system_share(original, &shares)?;
    let home_path = absolute_path(Path::new(&crate::util::expand_tilde("~")?))?;
    let resolved_home = resolve_existing_prefix(&home_path)?;
    if shares
        .iter()
        .any(|share| home_path.starts_with(share) || resolved_home.starts_with(share))
    {
        bail!(
            "share.paths にホームディレクトリを含む \"{}\" を指定することはできません",
            original
        );
    }
    for sensitive in SENSITIVE_SHARE_PATHS {
        let sensitive = PathBuf::from(crate::util::expand_tilde(sensitive)?);
        validate_sensitive_share(original, &shares, &sensitive)?;
    }
    Ok(())
}

fn validate_system_share(original: &str, shares: &[&Path]) -> anyhow::Result<()> {
    for forbidden in FORBIDDEN_SHARE_PATHS {
        let forbidden = Path::new(forbidden);
        let canonical = resolve_existing_prefix(forbidden)?;
        if shares
            .iter()
            .any(|share| *share == forbidden || *share == canonical)
        {
            bail!(
                "share.paths にシステムディレクトリ \"{}\" を指定することはできません",
                original
            );
        }
    }
    Ok(())
}

fn validate_sensitive_share(
    original: &str,
    shares: &[&Path],
    sensitive: &Path,
) -> anyhow::Result<()> {
    let canonical = resolve_existing_prefix(sensitive)
        .with_context(|| format!("機密パス \"{}\" の解決に失敗しました", sensitive.display()))?;
    if shares
        .iter()
        .any(|share| paths_overlap(share, sensitive) || paths_overlap(share, &canonical))
    {
        bail!(
            "share.paths に機密パスと重なる \"{}\" を指定することはできません",
            original
        );
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(test)]
mod tests;
