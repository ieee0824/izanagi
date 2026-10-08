mod ca;
mod cert_cache;
mod http_capture;
mod ip_filter;
mod logger;
mod secret_map;
mod tls_mitm;
mod tls_sni;
mod upstream;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use crate::ca::CaAuthority;
use crate::cert_cache::CertCache;
use crate::logger::CaptureLogger;
use crate::secret_map::SecretMap;

/// izanagi HTTP キャプチャ & プロキシサーバー
///
/// HTTPS 通信は TLS MITM で復号し、リクエスト内容をログに記録する。
/// --secret-map でダミー値→本物のシークレットマッピングを指定すると、
/// リクエスト body 内のダミー値を本物に置換して上流に転送する。
/// --allowed-host で上流転送を許可するホストを指定する（未指定時は全て 403）。
#[derive(Parser)]
#[command(name = "izanagi-http-capture", version, about)]
struct Cli {
    /// HTTP リッスンアドレス
    #[arg(long, default_value = "127.0.0.1:80")]
    listen_http: SocketAddr,

    /// HTTPS (TLS MITM) リッスンアドレス
    #[arg(long, default_value = "127.0.0.1:443")]
    listen_https: SocketAddr,

    /// ログ出力ディレクトリ（未指定時は stderr のみ）
    #[arg(long)]
    log_dir: Option<PathBuf>,

    /// Body キャプチャの最大バイト数
    #[arg(long, default_value = "4096")]
    max_body_bytes: usize,

    /// 接続タイムアウト（秒）
    #[arg(long, default_value = "10")]
    timeout_secs: u64,

    /// 同時接続数の上限
    #[arg(long, default_value = "1024")]
    max_connections: usize,

    /// CA 証明書ファイルパス（PEM）。--ca-key と一緒に指定。未指定時はエフェメラル CA を生成。
    #[arg(long, requires = "ca_key")]
    ca_cert: Option<PathBuf>,

    /// CA 秘密鍵ファイルパス（PEM）。--ca-cert と一緒に指定。
    #[arg(long, requires = "ca_cert")]
    ca_key: Option<PathBuf>,

    /// 生成した CA 証明書の出力先。サンドボックスのトラストストアに注入するために使用。
    #[arg(long)]
    ca_cert_out: Option<PathBuf>,

    /// シークレットマッピング（DUMMY=REAL 形式、複数指定可）。
    /// リクエスト body 内のダミー値を本物に置換して上流に転送する。
    #[arg(long = "secret-map", value_name = "DUMMY=REAL")]
    secret_maps: Vec<String>,

    /// 上流転送を許可するホスト（複数指定可）。未指定時は全て 403。
    #[arg(long = "allowed-host")]
    allowed_hosts: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // CA の生成またはロード
    let ca = if let (Some(cert_path), Some(key_path)) = (&cli.ca_cert, &cli.ca_key) {
        eprintln!("CA 証明書を読み込んでいます: {}", cert_path.display());
        CaAuthority::from_pem_files(cert_path, key_path)?
    } else {
        eprintln!("エフェメラル CA を生成しています...");
        CaAuthority::generate()?
    };

    if let Some(ref out_path) = cli.ca_cert_out {
        ca.write_cert_pem(out_path)?;
        eprintln!("CA 証明書を出力しました: {}", out_path.display());
    }

    // シークレットマッピング
    let mut secret_map = SecretMap::new();
    for s in &cli.secret_maps {
        secret_map.add_from_str(s)?;
    }
    if !secret_map.is_empty() {
        eprintln!("シークレットマッピング: {} エントリ", cli.secret_maps.len());
    }

    // 許可ホスト
    let allowed_hosts: HashSet<String> = cli
        .allowed_hosts
        .into_iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    if allowed_hosts.is_empty() {
        eprintln!(
            "警告: --allowed-host が未指定のため、全 HTTPS リクエストを 403 で拒否します。\
             上流転送を有効にするには --allowed-host <HOST> を指定してください。"
        );
    } else {
        eprintln!("上流転送許可ホスト:");
        for host in &allowed_hosts {
            eprintln!("  - {}", host);
        }
    }

    let ca = Arc::new(ca);
    let cert_cache = Arc::new(CertCache::new(ca, Arc::new(allowed_hosts.clone())));
    let logger = Arc::new(CaptureLogger::new(cli.log_dir.as_deref())?);
    let timeout = std::time::Duration::from_secs(cli.timeout_secs);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(cli.max_connections));
    let secret_map = Arc::new(secret_map);
    let allowed_hosts = Arc::new(allowed_hosts);

    // シャットダウンチャネル
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    let mut shutdown_http = shutdown_rx.clone();
    let mut shutdown_https = shutdown_rx;

    let http_handle = {
        let logger = logger.clone();
        let semaphore = semaphore.clone();
        let listen = cli.listen_http;
        let max_body = cli.max_body_bytes;
        tokio::spawn(async move {
            http_capture::run(
                listen,
                max_body,
                timeout,
                logger,
                semaphore,
                &mut shutdown_http,
            )
            .await
        })
    };

    let https_handle = {
        let logger = logger.clone();
        let semaphore = semaphore.clone();
        let cert_cache = cert_cache.clone();
        let secret_map = secret_map.clone();
        let allowed_hosts = allowed_hosts.clone();
        let listen = cli.listen_https;
        let max_body = cli.max_body_bytes;
        tokio::spawn(async move {
            tls_mitm::run(
                listen,
                max_body,
                timeout,
                logger,
                semaphore,
                cert_cache,
                secret_map,
                allowed_hosts,
                &mut shutdown_https,
            )
            .await
        })
    };

    // Ctrl+C / SIGTERM でシャットダウン
    let signal_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("SIGTERM ハンドラの登録に失敗");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .expect("シグナルハンドラの登録に失敗");
        }
        eprintln!("\nシャットダウン中...");
        let _ = shutdown_tx.send(());
    });

    tokio::select! {
        r = http_handle => r??,
        r = https_handle => r??,
    }

    signal_handle.abort();
    Ok(())
}
