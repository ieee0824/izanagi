//! Guest-side DNS integration probe. Build for the guest's Linux target.
use anyhow::ensure;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let domain = "denied.izanagi-test.org";
    let addresses = tokio::net::lookup_host((domain, 80))
        .await
        .inspect_err(|_| {
            eprintln!(
                "resolver config: {:?}; nss: {:?}",
                std::fs::read_to_string("/etc/resolv.conf"),
                std::fs::read_to_string("/etc/nsswitch.conf")
            );
        })?;
    let addresses: Vec<_> = addresses.collect();
    ensure!(
        !addresses.is_empty() && addresses.iter().all(|a| a.ip().is_loopback()),
        "system resolver bypassed proxy: {addresses:?}"
    );
    let mut query = vec![0x65, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend([0, 0, 1, 0, 1]);
    let mut tcp = tokio::net::TcpStream::connect("127.0.0.1:53").await?;
    tcp.write_u16(query.len() as u16).await?;
    tcp.write_all(&query).await?;
    let length = tcp.read_u16().await?;
    let mut response = vec![0; length as usize];
    tcp.read_exact(&mut response).await?;
    ensure!(
        response.len() >= 12 && response[..2] == query[..2] && response.ends_with(&[127, 0, 0, 1]),
        "DNS TCP probe was not blocked"
    );
    println!("PASS: system resolver and TCP use guest relay");
    Ok(())
}
