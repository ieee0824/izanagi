//! Real-backend DNS regression: start the production proxy and sandbox, run the guest probe.
//! Requires /usr/local/bin/izanagi-dns-probe in the updated guest image.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: dns_sandbox_smoke CONFIG"))?;
    let path = std::path::Path::new(&path);
    let config = izanagi::config::Config::load(path)?;
    config.validate()?;
    let mut proxies = izanagi::proxy_manager::ProxyManager::start(&config, path).await?;
    let mut sandbox = izanagi::engine::select_sandbox(&config)?;
    let result = async {
        sandbox.up(&config.to_sandbox_config()?).await?;
        let result = sandbox
            .exec(
                &["/usr/local/bin/izanagi-dns-probe".into()],
                &Default::default(),
            )
            .await?;
        anyhow::ensure!(
            result.exit_code == 0,
            "DNS guest probe failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        println!("{}", String::from_utf8_lossy(&result.stdout));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = sandbox.down().await;
    proxies.stop().await;
    result?;
    cleanup
}
