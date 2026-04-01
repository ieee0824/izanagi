use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::detector::Rule;
use crate::event::SyscallCategory;
use crate::rules::{
    EnvAccessRule, NetworkAllowlistRule, ProcessBaselineRule, SuspiciousPathRule,
    UnexpectedExecRule,
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
    /// デフォルトは `"127.0.0.1:53"`。
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
    /// シークレット置換マッピング (`DUMMY=REAL` 形式)。
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

impl Default for QemuSection {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory: "4G".to_string(),
            image: "default".to_string(),
        }
    }
}

impl Default for ShareSection {
    fn default() -> Self {
        Self {
            paths: vec![".".to_string()],
            mount_point: "/workspace".to_string(),
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

/// 共有が禁止されている機密パスのプレフィックス。
const SENSITIVE_PATH_PREFIXES: &[&str] = &["~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh"];

/// 共有が禁止されているシステムディレクトリ。
/// これらのパスそのものを共有対象にすることを禁止する。
const FORBIDDEN_SHARE_PATHS: &[&str] = &[
    "/etc", "/var", "/home", "/root", "/usr", "/bin", "/sbin", "/lib", "/sys", "/proc",
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
            Ok(content) => Self::from_toml(&content),
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
            TracerBackend::Dtrace => {
                if !is_macos {
                    bail!("sandbox.tracer \"dtrace\" は macOS でのみ利用可能です");
                }
            }
            _ => {}
        }

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
                 ネットワーク制限には dns_proxy の使用を推奨します"
            );
        }

        let mut warnings = Vec::new();

        // share.paths のバリデーション
        warnings.extend(self.validate_share_paths()?);

        Ok(warnings)
    }

    /// 共有パスのバリデーション。
    /// 戻り値の `Vec<String>` は警告メッセージのリスト。
    fn validate_share_paths(&self) -> anyhow::Result<Vec<String>> {
        let mut warnings = Vec::new();

        for path in &self.share.paths {
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

            // パスを正規化して機密パス判定を行う
            let normalized = normalize_share_path(path)?;

            // 存在するパスはシンボリックリンクを解決して実パスを取得する
            let resolved = {
                let normalized_path = Path::new(&normalized);
                if normalized_path.exists() {
                    let canon = std::fs::canonicalize(normalized_path).with_context(|| {
                        format!(
                            "share.paths のパス \"{}\" のシンボリックリンク解決に失敗しました",
                            path
                        )
                    })?;
                    canon.to_string_lossy().to_string()
                } else {
                    normalized.clone()
                }
            };

            // システムディレクトリの共有を禁止（正規化後のパスで判定）
            // resolved がシステムディレクトリそのものである場合のみ拒否。
            // /home/user/project のような子孫パスは許可する。
            let resolved_path = Path::new(&resolved);
            for forbidden in FORBIDDEN_SHARE_PATHS {
                let forbidden_path = Path::new(forbidden);
                if resolved_path == forbidden_path {
                    bail!(
                        "share.paths にシステムディレクトリ \"{}\" を指定することはできません",
                        path
                    );
                }
            }

            // 機密パスとの重複チェック（正規化後・シンボリックリンク解決後のパスで判定）
            for sensitive in SENSITIVE_PATH_PREFIXES {
                let sensitive_expanded = crate::util::expand_tilde(sensitive)?;
                if normalized.starts_with(&sensitive_expanded)
                    || resolved.starts_with(&sensitive_expanded)
                {
                    bail!(
                        "share.paths に機密パス \"{}\" を指定することはできません",
                        path
                    );
                }
            }

            // パスが存在するか警告
            if !path.starts_with('~') && p.is_absolute() && !p.exists() {
                warnings.push(format!(
                    "警告: share.paths のパス \"{}\" は存在しません",
                    path
                ));
            }
        }

        Ok(warnings)
    }

    // --- Config → 内部型への変換 ---

    /// Config から SandboxConfig への変換。
    /// 事前に `validate()` を呼んでいることを前提とする。
    pub fn to_sandbox_config(&self) -> anyhow::Result<SandboxConfig> {
        self.to_sandbox_config_for_platform(cfg!(target_os = "linux"))
    }

    /// プラットフォーム判定を引数として受け取る SandboxConfig 変換。テストで各プラットフォームの挙動を検証可能。
    fn to_sandbox_config_for_platform(&self, is_linux: bool) -> anyhow::Result<SandboxConfig> {
        let share = ShareConfig {
            host_paths: self.share.paths.iter().map(PathBuf::from).collect(),
            mount_point: PathBuf::from(&self.share.mount_point),
        };

        // DNS プロキシが有効な場合、listen アドレスから IP 部分を抽出する
        let dns_proxy_ip = self.dns_proxy_ip();

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
                    dns_proxy: dns_proxy_ip.clone(),
                })
            }
            SandboxBackend::Native => {
                if is_linux {
                    Ok(SandboxConfig::Landlock { share })
                } else {
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
                        dns_proxy: dns_proxy_ip,
                        network: ac.network,
                    })
                }
            }
            SandboxBackend::AppleContainer => {
                let ac = self
                    .sandbox
                    .apple_container
                    .as_ref()
                    .cloned()
                    .unwrap_or_default();
                // 防御的チェック: network = "none" は未サポート（validate() でも検証済み）
                if ac.network == Some(ContainerNetworkMode::None) {
                    anyhow::bail!(
                        "sandbox.apple_container.network = \"none\" は現在サポートされていません"
                    );
                }
                Ok(SandboxConfig::AppleContainer {
                    image: ac.image,
                    share,
                    dns_proxy: dns_proxy_ip,
                    network: ac.network,
                })
            }
        }
    }

    /// DNS プロキシが有効な場合、listen アドレスから IP 部分を抽出する。
    /// `listen` は `SocketAddr` 形式（例: `"127.0.0.1:53"`, `"[::1]:53"`）を期待する。
    fn dns_proxy_ip(&self) -> Option<String> {
        let section = self.dns_proxy.as_ref()?;
        if !section.enabled {
            return None;
        }
        match section.listen.parse::<std::net::SocketAddr>() {
            Ok(addr) => Some(addr.ip().to_string()),
            Err(_) => {
                // SocketAddr としてパースできない場合は、IP アドレス単体として試みる
                match section.listen.parse::<std::net::IpAddr>() {
                    Ok(ip) => Some(ip.to_string()),
                    Err(_) => {
                        eprintln!("警告: dns_proxy.listen のパースに失敗: {}", section.listen);
                        None
                    }
                }
            }
        }
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
///
/// 1. `~/.izanagi/settings/{hash}/izanagi.toml` が存在すればそれを返す
/// 2. `./izanagi.toml` が存在する場合は警告付きで使用（非推奨）
/// 3. どちらもなければ settings パスを返す
pub fn resolve_config_path() -> anyhow::Result<PathBuf> {
    let settings = settings_path_for_pwd()?;
    if settings.exists() {
        return Ok(settings);
    }
    let local = std::env::current_dir()?.join("izanagi.toml");
    if local.exists() {
        eprintln!(
            "警告: ./izanagi.toml を使用しています。セキュリティ上の理由から `izanagi init` で \
             ~/.izanagi/settings/ 以下に移行することを推奨します。"
        );
        return Ok(local);
    }
    // どちらもない場合は settings パスを返す
    Ok(settings)
}

#[cfg(test)]
mod tests;
