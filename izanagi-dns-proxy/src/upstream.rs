use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::net::UdpSocket;

/// 上流 DNS サーバーへクエリを転送するリゾルバ。
pub struct UpstreamResolver {
    addr: SocketAddr,
    timeout: Duration,
}

impl UpstreamResolver {
    pub fn new(addr: SocketAddr, timeout: Duration) -> Self {
        Self { addr, timeout }
    }

    /// /etc/resolv.conf から最初の nameserver を読み取って構築する。
    pub fn from_resolv_conf() -> anyhow::Result<Self> {
        let content = std::fs::read_to_string("/etc/resolv.conf")
            .context("/etc/resolv.conf の読み取りに失敗")?;
        let addr = parse_resolv_conf(&content)?;
        Ok(Self::new(addr, Duration::from_secs(5)))
    }

    /// DNS クエリを上流サーバーに UDP で転送し、応答を返す。
    pub async fn forward(&self, query_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("上流転送用ソケットのバインドに失敗")?;
        socket
            .send_to(query_bytes, self.addr)
            .await
            .context("上流 DNS への送信に失敗")?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf))
            .await
            .context("上流 DNS の応答がタイムアウトしました")?
            .context("上流 DNS からの受信に失敗")?;

        buf.truncate(len);
        Ok(buf)
    }
}

/// resolv.conf から最初の nameserver エントリをパースする。
fn parse_resolv_conf(content: &str) -> anyhow::Result<SocketAddr> {
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ip_str = rest.trim();
            if ip_str.is_empty() {
                continue;
            }
            let ip: std::net::IpAddr = ip_str
                .parse()
                .with_context(|| format!("nameserver のパースに失敗: {}", ip_str))?;
            return Ok(SocketAddr::new(ip, 53));
        }
    }
    bail!("/etc/resolv.conf に nameserver が見つかりません")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolv_conf_basic() {
        let content = "\
# comment
nameserver 8.8.8.8
nameserver 8.8.4.4
";
        let addr = parse_resolv_conf(content).unwrap();
        assert_eq!(addr, SocketAddr::new("8.8.8.8".parse().unwrap(), 53));
    }

    #[test]
    fn parse_resolv_conf_ipv6() {
        let content = "nameserver ::1\n";
        let addr = parse_resolv_conf(content).unwrap();
        assert_eq!(addr, SocketAddr::new("::1".parse().unwrap(), 53));
    }

    #[test]
    fn parse_resolv_conf_with_extra_whitespace() {
        let content = "  nameserver   192.168.1.1  \n";
        let addr = parse_resolv_conf(content).unwrap();
        assert_eq!(addr, SocketAddr::new("192.168.1.1".parse().unwrap(), 53));
    }

    #[test]
    fn parse_resolv_conf_no_nameserver() {
        let content = "# only comments\nsearch example.com\n";
        assert!(parse_resolv_conf(content).is_err());
    }
}
