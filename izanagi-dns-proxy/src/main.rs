mod allowlist;
use izanagi_common::ip_filter;
mod proxy;
mod response;
mod upstream;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::bail;
use clap::Parser;
use izanagi::config::Config;

use crate::allowlist::DomainAllowlist;
use crate::proxy::DnsProxy;
use crate::upstream::UpstreamResolver;

/// izanagi DNS プロキシ — allowed_hosts フィルタ付き名前解決
#[derive(Parser)]
#[command(name = "izanagi-dns-proxy", version, about)]
struct Cli {
    /// 設定ファイルパス
    #[arg(short, long, default_value = "./izanagi.toml")]
    config: PathBuf,

    /// リッスンアドレス
    #[arg(long, default_value = "127.0.0.1:53")]
    listen: SocketAddr,

    /// 上流 DNS サーバー（未指定時は /etc/resolv.conf から取得）
    #[arg(long)]
    upstream: Option<SocketAddr>,

    /// ブロック時に返すダミー IP アドレス
    #[arg(long, default_value = "127.0.0.1")]
    dummy_ip: Ipv4Addr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let allowlist = load_allowlist(&cli.config)?;

    // 上流 DNS リゾルバ
    let upstream = match cli.upstream {
        Some(addr) => UpstreamResolver::new(addr, std::time::Duration::from_secs(5)),
        None => UpstreamResolver::from_resolv_conf()?,
    };

    // シャットダウンチャネル
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    let proxy = DnsProxy {
        allowlist: Arc::new(allowlist),
        upstream: Arc::new(upstream),
        dummy_ip: cli.dummy_ip,
        listen_addr: cli.listen,
    };

    // Ctrl+C / SIGTERM でシャットダウン
    let signal_handle = tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("シグナルハンドラの登録に失敗");
        eprintln!("\nシャットダウン中...");
        let _ = shutdown_tx.send(());
    });

    proxy.run(shutdown_rx).await?;
    signal_handle.abort();

    Ok(())
}

fn load_allowlist(path: &std::path::Path) -> anyhow::Result<DomainAllowlist> {
    // 設定ファイルの存在チェック（Config::load は NotFound 時にデフォルトを返すため）
    if !path.exists() {
        bail!("設定ファイルが見つかりません: {}", path.display());
    }

    // 設定ファイル読み込み
    let config = Config::load(path)?;
    let allowlist = DomainAllowlist::new(&config.detect.allowed_hosts);

    eprintln!(
        "allowed_hosts: {} エントリ (完全一致 + ワイルドカード)",
        config.detect.allowed_hosts.len()
    );
    for host in &config.detect.allowed_hosts {
        eprintln!("  - {}", host);
    }

    Ok(allowlist)
}
