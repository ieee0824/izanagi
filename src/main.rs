use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::{CommandFactory, Parser, Subcommand};
use izanagi::config::{Config, SandboxBackend, TracerBackend, izanagi_home, resolve_config_path};
use izanagi::engine::{AlertHandler, Engine, build_engine};
use izanagi::log_formatter;
use izanagi::log_storage::LogStorage;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

mod commands;
#[cfg(test)]
mod pty_test_support;

/// Izanagi — サプライチェーン攻撃から開発環境を守るサンドボックスツール
#[derive(Parser)]
#[command(name = "izanagi", version, about)]
pub(crate) struct Cli {
    /// 設定ファイルパス (init 時は出力先、それ以外は読み込み元。未指定時は自動決定)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// サンドボックスバックエンド (qemu | native)
    #[arg(long, global = true)]
    sandbox: Option<SandboxBackend>,

    /// トレーサーバックエンド (none | auto | ebpf | dtrace | vm-agent)
    #[arg(long, global = true)]
    tracer: Option<TracerBackend>,

    /// トレーサーを無効化 (--tracer=none と同等)
    #[arg(long, global = true, conflicts_with = "tracer")]
    no_tracer: bool,

    /// 詳細出力
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 行動分析のローカル再生・監査表示・比較評価
    Behavior {
        #[command(subcommand)]
        action: Box<izanagi::behavior_cli::BehaviorAction>,
    },
    /// サンドボックスを起動
    Up {
        /// host <-> agent 間の通信を pcap 形式で記録するファイルパス
        #[arg(long)]
        pcap: Option<PathBuf>,
    },
    /// サンドボックスを停止
    Down,
    /// サンドボックス内でコマンドを実行
    Exec {
        /// 実行するコマンドと引数
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// サンドボックス内でシェルを起動
    Shell,
    /// syscall ログを表示
    Logs {
        /// 不審なアクセスのみ表示
        #[arg(long)]
        suspicious: bool,
        /// リアルタイムでログを追尾表示
        #[arg(short, long)]
        follow: bool,
    },
    /// 設定関連のサブコマンド
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// 対話形式で izanagi.toml を生成 (-c で出力先を指定可能)
    Init,
    /// MCP Server として起動 (stdio transport)
    Mcp,
    /// シェル補完スクリプトを生成
    Completions {
        /// 対象シェル (bash, zsh, fish, elvish, powershell)
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// 現在の設定を TOML 形式で表示
    Show,
    /// 設定ファイルのパスを表示
    Path,
    /// パケット検閲 (DNS プロキシ + HTTP キャプチャ) を対話的に設定
    Mitm,
}

// ---------------------------------------------------------------------------
// パス・PID・ロック関連のユーティリティ
// ---------------------------------------------------------------------------

/// プロジェクトごとのインスタンスディレクトリを返す。
/// カレントディレクトリの SHA256 ハッシュで分離し、複数プロジェクトの同時起動を可能にする。
/// パス: `~/.izanagi/instances/<sha256(cwd)>/`
fn izanagi_dir() -> PathBuf {
    let home = izanagi_home().expect("HOME 環境変数が未設定です");
    let cwd = std::env::current_dir().expect("カレントディレクトリを取得できません");
    // canonicalize して symlink を解決。config/mod.rs の settings_path_for_pwd と同じ方式。
    let canonical = cwd
        .canonicalize()
        .expect("カレントディレクトリの canonicalize に失敗しました");
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()));
    home.join("instances").join(hash)
}

/// ログディレクトリのデフォルトパス (`~/.izanagi/instances/<hash>/logs`)。
fn default_log_dir() -> PathBuf {
    izanagi_dir().join("logs")
}

/// PID ファイルのパス (`~/.izanagi/izanagi.pid`)。
fn pid_file_path() -> PathBuf {
    izanagi_dir().join("izanagi.pid")
}

/// PID ファイルを書き込む。
/// 既存の PID ファイルがある場合はプロセスの生存を確認し、
/// 生存中ならエラーを返す。
fn write_pid_file() -> anyhow::Result<()> {
    let path = pid_file_path();

    // 既存 PID ファイルがあればプロセスの生存確認
    if path.exists()
        && let Ok(content) = std::fs::read_to_string(&path)
        && let Some(existing_pid) = content
            .lines()
            .next()
            .and_then(|l| l.trim().parse::<u32>().ok())
    {
        match check_process_alive(existing_pid) {
            ProcessStatus::Running => {
                anyhow::bail!("既に izanagi が起動しています (PID: {})", existing_pid);
            }
            ProcessStatus::PermissionDenied => {
                anyhow::bail!("PID {} のプロセス確認に権限がありません", existing_pid);
            }
            ProcessStatus::NotRunning => {
                // 停止済み: 上書きする
            }
        }
    }

    let pid = std::process::id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, format!("{}\n{}", pid, timestamp))?;
    Ok(())
}

/// プロセスの生存状態。
enum ProcessStatus {
    Running,
    NotRunning,
    PermissionDenied,
}

/// kill(pid, 0) でプロセスの生存を確認する。
/// ESRCH → NotRunning, EPERM → PermissionDenied, 成功 → Running。
fn check_process_alive(pid: u32) -> ProcessStatus {
    let ret = unsafe { libc::kill(pid as i32, 0) };
    if ret == 0 {
        return ProcessStatus::Running;
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::ESRCH {
        ProcessStatus::NotRunning
    } else {
        // EPERM やその他: プロセスは存在するが権限なし
        ProcessStatus::PermissionDenied
    }
}

/// PID ファイルを削除する。
fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_file_path());
}

/// ロックファイルを削除する。
fn remove_lock_file() {
    if let Err(e) = std::fs::remove_file(lock_file_path())
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("警告: ロックファイルの削除に失敗: {}", e);
    }
}

/// ノンブロッキングでロック取得を試みる。
/// 成功した場合は File を返す（ドロップでロック解放）。
/// 失敗した場合（別プロセスがロック保持中）はエラーを返す。
/// ロックファイルが存在しない場合は `Ok(None)` を返す。
#[cfg(unix)]
fn try_instance_lock() -> anyhow::Result<Option<std::fs::File>> {
    let path = lock_file_path();
    // exists() を使わず open() の結果で判定し TOCTOU を排除する
    let file = match std::fs::OpenOptions::new().write(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context("ロックファイルを開けません")),
    };
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            anyhow::bail!("別のプロセスがロックを保持しています");
        }
        return Err(anyhow::Error::new(err).context("flock の取得に失敗しました"));
    }
    Ok(Some(file))
}

#[cfg(not(unix))]
fn try_instance_lock() -> anyhow::Result<Option<std::fs::File>> {
    Ok(None)
}

/// ロックファイルのパス (`~/.izanagi/izanagi.lock`)。
fn lock_file_path() -> PathBuf {
    izanagi_dir().join("izanagi.lock")
}

/// flock による排他ロックを取得する。
/// 取得成功時はロックファイルの `File` を返す（ドロップでロック解放）。
/// 取得失敗時（別プロセスが起動中）はエラーを返す。
/// ロックファイルが存在するが保持プロセスが存在しない（stale）場合は
/// ロックを取得して続行する（エラーにしない）。
#[cfg(unix)]
fn acquire_instance_lock() -> anyhow::Result<std::fs::File> {
    let path = lock_file_path();
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent)?;
        }
    }

    // create_new で新規作成を試みて stale 判定に使う（exists() の TOCTOU を排除）
    let (file, lock_existed) = match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
    {
        Ok(f) => (f, false),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(false)
                .open(&path)
                .context("ロックファイルを開けません")?;
            (f, true)
        }
        Err(e) => return Err(anyhow::Error::new(e).context("ロックファイルの作成に失敗")),
    };

    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            anyhow::bail!("既に izanagi が起動しています");
        }
        return Err(err).context("ロック取得に失敗しました");
    }

    // flock 取得成功: ロックファイルが既に存在していた場合は stale だったことを通知
    if lock_existed {
        eprintln!(
            "情報: stale ロックファイルを検出しました。前回のプロセスが正常終了しなかった可能性があります。"
        );
    }

    Ok(file)
}

/// 非 Unix 環境ではロックをスキップする。
#[cfg(not(unix))]
fn acquire_instance_lock() -> anyhow::Result<()> {
    Ok(())
}

/// PID ファイルからプロセス ID とタイムスタンプを読み取る。
fn read_pid_file() -> anyhow::Result<(u32, u64)> {
    let path = pid_file_path();
    let content = std::fs::read_to_string(&path)
        .context("PID ファイルが見つかりません。izanagi up で起動してください")?;
    let mut lines = content.lines();
    let pid: u32 = lines
        .next()
        .unwrap_or("")
        .trim()
        .parse()
        .context("PID ファイルの内容が不正です")?;
    let timestamp: u64 = lines.next().unwrap_or("0").trim().parse().unwrap_or(0);
    Ok((pid, timestamp))
}

// ---------------------------------------------------------------------------
// Engine 初期化ヘルパー（Up / Exec / Shell で共通）
// ---------------------------------------------------------------------------

/// LogStorage + AlertHandler を生成する。
fn create_alert_handler(log_storage: &Arc<LogStorage>) -> AlertHandler {
    let storage = log_storage.clone();
    Box::new(move |alert| {
        let formatted = log_formatter::format_alert(alert);
        eprintln!("{}", formatted);
        if let Err(e) = storage.store_alert(alert) {
            eprintln!("アラートの保存に失敗: {}", e);
        }
    })
}

/// Engine を構築・起動し、LogStorage と共に返す。
async fn start_engine(
    config: &Config,
    pcap_writer: Option<Arc<izanagi::pcap_writer::PcapWriter>>,
) -> anyhow::Result<(Engine, Arc<LogStorage>)> {
    let sandbox_config = config.to_sandbox_config()?;
    let trace_filter = config.to_trace_filter();

    let log_storage = Arc::new(LogStorage::new(&default_log_dir())?);
    let on_alert = create_alert_handler(&log_storage);

    // up 中の全 syscall イベントを LogStorage に記録 (#216)
    // エラーが連続する場合はログ洪水を防ぐため、最初の 1 回のみ警告を出す
    let event_storage = log_storage.clone();
    let event_error_logged = std::sync::atomic::AtomicBool::new(false);

    let mut engine = build_engine(config)?;
    if config.behavior.enabled {
        engine.attach_behavior(
            &config.behavior,
            config.detect.allowed_hosts.clone(),
            default_log_dir().join("behavior"),
        )?;
    }
    engine.set_event_handler(Box::new(move |event: &izanagi::event::SyscallEvent| {
        if let Err(e) = event_storage.store_event(event)
            && !event_error_logged.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!("イベントの保存に失敗: {} (以降のエラーは抑制)", e);
        }
    }));

    // pcap ライターが指定されている場合、Engine に設定する
    if let Some(writer) = pcap_writer {
        engine.set_pcap_writer(writer);
    }

    engine
        .start(&sandbox_config, &trace_filter, on_alert)
        .await?;

    Ok((engine, log_storage))
}

/// Engine を停止し LogStorage をフラッシュする。エラーは警告として出力する。
async fn stop_engine(mut engine: Engine, log_storage: &LogStorage) {
    if let Err(e) = engine.stop().await {
        eprintln!("警告: engine の停止に失敗: {}", e);
    }
    if let Err(e) = log_storage.flush() {
        eprintln!("警告: ログのフラッシュに失敗: {}", e);
    }
}

/// サンドボックス内コマンド実行用の基本環境変数を構築する。
fn build_sandbox_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
    );
    if let Ok(term) = std::env::var("TERM") {
        env.insert("TERM".to_string(), term);
    }
    env
}

// ---------------------------------------------------------------------------
// メインエントリポイント
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<u8> {
    run_with(Cli::parse()).await
}

/// テスト可能なエントリポイント。`Cli::try_parse_from()` でテスト用引数を渡せる。
pub(crate) async fn run_with(cli: Cli) -> anyhow::Result<u8> {
    if let Commands::Behavior { action } = cli.command {
        return izanagi::behavior_cli::run(*action, &default_log_dir().join("behavior")).await;
    }
    // init / mcp は設定ファイルを必要としないため、ロード・バリデーションをスキップ
    if matches!(cli.command, Commands::Init) {
        return commands::cmd_init(cli.config.as_ref());
    }
    if matches!(cli.command, Commands::Mcp) {
        return commands::cmd_mcp().await;
    }
    if let Commands::Completions { shell } = cli.command {
        clap_complete::generate(
            shell,
            &mut Cli::command(),
            env!("CARGO_PKG_NAME"),
            &mut std::io::stdout(),
        );
        return Ok(0);
    }
    // config path は設定ファイルの存在を必要としない
    if matches!(
        cli.command,
        Commands::Config {
            action: ConfigAction::Path
        }
    ) {
        let path = match &cli.config {
            Some(p) => p.clone(),
            None => resolve_config_path()?,
        };
        println!("{}", path.display());
        return Ok(0);
    }
    // logs は設定ファイルを必要としない (ログファイルを直接読む)
    if let Commands::Logs { suspicious, follow } = cli.command {
        if follow {
            return commands::cmd_logs_follow(suspicious).await;
        } else {
            return commands::cmd_logs(suspicious);
        }
    }

    // -c 未指定時は自動解決
    let config_path = match cli.config {
        Some(p) => p,
        None => resolve_config_path()?,
    };

    // 設定ファイル読み込み
    if !config_path.exists() {
        anyhow::bail!(
            "設定ファイルが見つかりません: {}\n\
             `izanagi init` で設定ファイルを生成してください。",
            config_path.display()
        );
    }
    let mut config = Config::load(&config_path)?;

    // グローバルオプションで設定を上書き
    if let Some(backend) = cli.sandbox {
        config.sandbox.backend = backend;
    }
    if cli.no_tracer {
        config.sandbox.tracer = TracerBackend::None;
    } else if let Some(tracer) = cli.tracer {
        config.sandbox.tracer = tracer;
    }

    // バリデーション
    let warnings = config.validate()?;
    for warning in &warnings {
        eprintln!("{}", warning);
    }
    if config.behavior.enabled && matches!(cli.command, Commands::Up { pcap: Some(_) }) {
        anyhow::bail!("behavior analysis and raw --pcap capture cannot be enabled together");
    }

    // シークレット設定の検証:
    // 1. IZANAGI_SECRET_FILE が設定されているなら読み込み失敗はハードエラー（require_auth に関係なく）
    // 2. require_auth = true（デフォルト）ならシークレット未設定もエラー
    let secret = izanagi::protocol::load_shared_secret_from_env()?;
    if config.sandbox.require_auth.unwrap_or(true) && secret.is_none() {
        anyhow::bail!(
            "sandbox.require_auth が true（未設定時のデフォルト）ですが、共有シークレットが設定されていません。\
             IZANAGI_SECRET_FILE または IZANAGI_SHARED_SECRET 環境変数を設定してください。\
             認証を無効化する場合は izanagi.toml に require_auth = false を設定してください"
        );
    }

    if cli.verbose {
        eprintln!("設定ファイル: {:?}", config_path);
        eprintln!("バックエンド: {:?}", config.sandbox.backend);
        eprintln!("トレーサー: {:?}", config.sandbox.tracer);
    }

    // サブコマンド分岐
    match cli.command {
        Commands::Behavior { .. } => unreachable!("behavior is handled before config loading"),
        Commands::Up { pcap } => commands::cmd_up(&config, &config_path, pcap.as_deref()).await,
        Commands::Down => commands::cmd_down().await,
        Commands::Exec { cmd } => commands::cmd_exec(&config, &cmd).await,
        Commands::Shell => commands::cmd_shell(&config).await,
        Commands::Logs { .. } => unreachable!("logs is handled before config loading"),
        Commands::Config { action } => commands::cmd_config(action, &config, &config_path),
        Commands::Init => unreachable!("init is handled before config loading"),
        Commands::Mcp => unreachable!("mcp is handled before config loading"),
        Commands::Completions { .. } => {
            unreachable!("completions is handled before config loading")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parse_config_show() {
        let cli = Cli::try_parse_from(["izanagi", "config", "show"]).unwrap();
        assert!(matches!(cli.command, Commands::Config { .. }));
        assert!(cli.config.is_none());
    }

    #[test]
    fn cli_parse_exec_with_args() {
        let cli = Cli::try_parse_from(["izanagi", "exec", "--", "npm", "install"]).unwrap();
        match cli.command {
            Commands::Exec { cmd } => assert_eq!(cmd, vec!["npm", "install"]),
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn cli_parse_no_tracer_flag() {
        let cli = Cli::try_parse_from(["izanagi", "--no-tracer", "up"]).unwrap();
        assert!(cli.no_tracer);
        assert!(cli.tracer.is_none());
    }

    #[test]
    fn cli_parse_tracer_and_no_tracer_conflict() {
        let result = Cli::try_parse_from(["izanagi", "--no-tracer", "--tracer", "ebpf", "up"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_parse_sandbox_override() {
        let cli = Cli::try_parse_from(["izanagi", "--sandbox", "qemu", "up"]).unwrap();
        assert_eq!(cli.sandbox, Some(SandboxBackend::Qemu));
    }

    #[test]
    fn cli_parse_verbose() {
        let cli = Cli::try_parse_from(["izanagi", "-v", "up"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn cli_parse_custom_config() {
        let cli = Cli::try_parse_from(["izanagi", "-c", "/tmp/custom.toml", "up"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/custom.toml")));
    }

    #[tokio::test]
    async fn run_with_nonexistent_config_fails() {
        let cli =
            Cli::try_parse_from(["izanagi", "-c", "/nonexistent/izanagi.toml", "up"]).unwrap();
        let result = run_with(cli).await;
        assert!(result.is_err());
    }

    #[test]
    fn cli_parse_up_pcap() {
        let cli = Cli::try_parse_from(["izanagi", "up", "--pcap", "/tmp/capture.pcap"]).unwrap();
        match cli.command {
            Commands::Up { pcap } => assert_eq!(pcap, Some(PathBuf::from("/tmp/capture.pcap"))),
            _ => panic!("expected Up"),
        }
    }

    #[test]
    fn cli_parse_up_without_pcap() {
        let cli = Cli::try_parse_from(["izanagi", "up"]).unwrap();
        match cli.command {
            Commands::Up { pcap } => assert!(pcap.is_none()),
            _ => panic!("expected Up"),
        }
    }

    #[test]
    fn cli_parse_logs_suspicious() {
        let cli = Cli::try_parse_from(["izanagi", "logs", "--suspicious"]).unwrap();
        match cli.command {
            Commands::Logs { suspicious, .. } => assert!(suspicious),
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn cli_parse_completions_bash() {
        let cli = Cli::try_parse_from(["izanagi", "completions", "bash"]).unwrap();
        assert!(matches!(cli.command, Commands::Completions { .. }));
        assert!(cli.config.is_none());
    }

    #[test]
    fn cli_parse_completions_zsh() {
        let cli = Cli::try_parse_from(["izanagi", "completions", "zsh"]).unwrap();
        assert!(matches!(cli.command, Commands::Completions { .. }));
    }

    #[test]
    fn cli_parse_completions_invalid_shell() {
        let result = Cli::try_parse_from(["izanagi", "completions", "invalid"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_parse_logs_follow_short() {
        let cli = Cli::try_parse_from(["izanagi", "logs", "-f"]).unwrap();
        match cli.command {
            Commands::Logs { follow, suspicious } => {
                assert!(follow);
                assert!(!suspicious);
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn cli_parse_logs_follow_long() {
        let cli = Cli::try_parse_from(["izanagi", "logs", "--follow"]).unwrap();
        match cli.command {
            Commands::Logs { follow, .. } => assert!(follow),
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn cli_parse_logs_follow_suspicious() {
        let cli = Cli::try_parse_from(["izanagi", "logs", "-f", "--suspicious"]).unwrap();
        match cli.command {
            Commands::Logs { follow, suspicious } => {
                assert!(follow);
                assert!(suspicious);
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn izanagi_dir_is_deterministic() {
        let dir1 = izanagi_dir();
        let dir2 = izanagi_dir();
        assert_eq!(dir1, dir2);
    }

    #[test]
    fn izanagi_dir_contains_instances_and_hash() {
        let dir = izanagi_dir();
        let components: Vec<_> = dir.components().collect();
        // パスに "instances" を含み、その後に 64 文字の hex ハッシュが続く
        let has_instances = components.iter().any(|c| c.as_os_str() == "instances");
        assert!(
            has_instances,
            "izanagi_dir should contain 'instances': {:?}",
            dir
        );
        let last = dir.file_name().unwrap().to_str().unwrap();
        assert_eq!(last.len(), 64, "hash should be 64 hex chars: {}", last);
        assert!(
            last.chars().all(|c| c.is_ascii_hexdigit()),
            "hash should be hex: {}",
            last
        );
    }
}
