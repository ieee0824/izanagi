//! Guest-local UDP/TCP DNS relay. No resolver fallback is permitted.
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_QUERIES: usize = 256;

/// Slirp exposes the host's IPv4 loopback at 10.0.2.2.
pub fn qemu_endpoint(mut host: SocketAddr) -> SocketAddr {
    if host.ip() == std::net::Ipv4Addr::LOCALHOST {
        host.set_ip(std::net::Ipv4Addr::new(10, 0, 2, 2).into());
    }
    host
}

pub fn resolver_config(upstream: SocketAddr) -> String {
    format!(
        "# izanagi DNS relay upstream={upstream}\nnameserver 127.0.0.1\noptions timeout:2 attempts:1\n"
    )
}

/// Query over the existing handshake's authentication and token boundary.
pub async fn verify_client<R, W>(
    client: &mut crate::protocol_client::ProtocolClient<R, W>,
    expected: SocketAddr,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(TIMEOUT, async {
        client
            .send_message(&crate::protocol::Message::DnsStatus { endpoint: None })
            .await?;
        match client.recv_message().await? {
            Some(crate::protocol::Message::DnsStatus {
                endpoint: Some(endpoint),
            }) if endpoint == expected.to_string() => Ok(()),
            _ => anyhow::bail!("guest DNS relay is not ready; rebuild the guest agent/image"),
        }
    })
    .await
    .context("guest DNS status timed out; rebuild the guest agent/image")?
}

/// Both transports must bind and reach the host proxy before publishing Ready.
pub struct DnsRelay {
    udp: UdpSocket,
    tcp: TcpListener,
    upstream: SocketAddr,
}

impl DnsRelay {
    pub async fn bind(listen: SocketAddr, upstream: SocketAddr) -> anyhow::Result<Self> {
        let udp = UdpSocket::bind(listen)
            .await
            .context("bind guest DNS UDP")?;
        let tcp = TcpListener::bind(udp.local_addr()?)
            .await
            .context("bind guest DNS TCP")?;
        tokio::time::timeout(TIMEOUT, probe(upstream))
            .await
            .context("host DNS proxy unreachable (UDP/TCP)")??;
        Ok(Self { udp, tcp, upstream })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.udp.local_addr()?)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tokio::try_join!(
            serve_udp(self.udp, self.upstream),
            serve_tcp(self.tcp, self.upstream)
        )?;
        Ok(())
    }
}

async fn forward_udp(query: &[u8], upstream: SocketAddr) -> anyhow::Result<Vec<u8>> {
    let bind = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut response = vec![0; 65535];
    let size = socket.recv(&mut response).await?;
    response.truncate(size);
    Ok(response)
}

async fn serve_udp(socket: UdpSocket, upstream: SocketAddr) -> anyhow::Result<()> {
    let socket = std::sync::Arc::new(socket);
    let mut jobs = JoinSet::new();
    let mut buffer = vec![0; 65535];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buffer) => {
                let (size, client) = result?;
                if jobs.len() >= MAX_QUERIES { continue; }
                let query = buffer[..size].to_vec();
                let socket = socket.clone();
                jobs.spawn(async move {
                    if let Ok(Ok(response)) = tokio::time::timeout(TIMEOUT, forward_udp(&query, upstream)).await {
                        let _ = socket.send_to(&response, client).await;
                    }
                });
            }
            _ = jobs.join_next(), if !jobs.is_empty() => {}
        }
    }
}

async fn serve_tcp(listener: TcpListener, upstream: SocketAddr) -> anyhow::Result<()> {
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut client, _) = result?;
                if jobs.len() >= MAX_QUERIES { continue; }
                jobs.spawn(async move {
                    let _ = tokio::time::timeout(TIMEOUT, async {
                        let mut host = TcpStream::connect(upstream).await?;
                        tokio::io::copy_bidirectional(&mut client, &mut host).await?;
                        Ok::<_, std::io::Error>(())
                    }).await;
                });
            }
            _ = jobs.join_next(), if !jobs.is_empty() => {}
        }
    }
}

async fn probe(upstream: SocketAddr) -> anyhow::Result<()> {
    // Reserved .invalid name; restrictive allowlists log this as BLOCKED.
    let mut query = vec![0x65, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["izanagi-dns-probe", "invalid"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend([0, 0, 1, 0, 1]);
    validate_probe(&query, &forward_udp(&query, upstream).await?)?;
    let mut tcp = TcpStream::connect(upstream).await?;
    tcp.write_u16(query.len() as u16).await?;
    tcp.write_all(&query).await?;
    let size = tcp.read_u16().await?;
    let mut response = vec![0; size as usize];
    tcp.read_exact(&mut response).await?;
    validate_probe(&query, &response)
}

fn validate_probe(query: &[u8], response: &[u8]) -> anyhow::Result<()> {
    if response.len() < 12 || response[..2] != query[..2] || response[2] & 0x80 == 0 {
        anyhow::bail!("host DNS proxy returned an invalid response");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Message;
    use crate::protocol_client::ProtocolClient;

    #[tokio::test]
    async fn status_requires_the_configured_endpoint_and_rejects_old_or_unconfigured_agents() {
        let expected: SocketAddr = "10.0.2.2:15353".parse().unwrap();
        for endpoint in [None, Some("10.0.2.2:53".into()), Some(expected.to_string())] {
            let succeeds = endpoint == Some(expected.to_string());
            let (host, guest) = tokio::io::duplex(4096);
            let (reader, writer) = tokio::io::split(host);
            let mut client = ProtocolClient::new(reader, writer, Some(b"fixture-key".to_vec()));
            let server = tokio::spawn(async move {
                let (reader, writer) = tokio::io::split(guest);
                let mut client = ProtocolClient::new(reader, writer, Some(b"fixture-key".to_vec()));
                assert_eq!(
                    client.recv_message().await.unwrap(),
                    Some(Message::DnsStatus { endpoint: None })
                );
                client
                    .send_message(&Message::DnsStatus { endpoint })
                    .await
                    .unwrap();
            });
            assert_eq!(verify_client(&mut client, expected).await.is_ok(), succeeds);
            server.await.unwrap();
        }
        let (host, guest) = tokio::io::duplex(4096);
        drop(guest);
        let (reader, writer) = tokio::io::split(host);
        let mut client = ProtocolClient::new(reader, writer, None);
        assert!(verify_client(&mut client, expected).await.is_err());
    }
}
