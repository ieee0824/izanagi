use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;

use crate::allowlist::DomainAllowlist;
use crate::ip_filter;
use crate::response;
use crate::upstream::UpstreamResolver;

/// 同時処理可能な DNS クエリの上限。DNS 増幅攻撃や無制限 spawn を防止する。
const MAX_CONCURRENT_QUERIES: usize = 256;

/// DNS プロキシ本体。UDP と TCP の両方でリッスンする。
pub struct DnsProxy {
    pub allowlist: Arc<DomainAllowlist>,
    pub upstream: Arc<UpstreamResolver>,
    pub dummy_ip: Ipv4Addr,
    pub listen_addr: SocketAddr,
}

impl DnsProxy {
    /// UDP と TCP のリスナーを起動し、シャットダウンシグナルまで待機する。
    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<()>) -> anyhow::Result<()> {
        let udp_socket = UdpSocket::bind(self.listen_addr)
            .await
            .with_context(|| format!("{} への UDP バインドに失敗", self.listen_addr))?;
        let tcp_listener = TcpListener::bind(self.listen_addr)
            .await
            .with_context(|| format!("{} への TCP バインドに失敗", self.listen_addr))?;

        eprintln!("DNS プロキシを起動しました: {} (UDP+TCP)", self.listen_addr);
        if self.allowlist.is_empty() {
            eprintln!("警告: allowed_hosts が空です。すべての DNS クエリをブロックします。");
        }

        let udp_socket = Arc::new(udp_socket);

        let mut shutdown_udp = shutdown.clone();
        let mut shutdown_tcp = shutdown;

        let udp_handle = {
            let allowlist = self.allowlist.clone();
            let upstream = self.upstream.clone();
            let dummy_ip = self.dummy_ip;
            let socket = udp_socket.clone();
            tokio::spawn(async move {
                Self::run_udp(socket, allowlist, upstream, dummy_ip, &mut shutdown_udp).await
            })
        };

        let tcp_handle = {
            let allowlist = self.allowlist.clone();
            let upstream = self.upstream.clone();
            let dummy_ip = self.dummy_ip;
            tokio::spawn(async move {
                Self::run_tcp(
                    tcp_listener,
                    allowlist,
                    upstream,
                    dummy_ip,
                    &mut shutdown_tcp,
                )
                .await
            })
        };

        // どちらかが完了したら両方を停止
        tokio::select! {
            r = udp_handle => r??,
            r = tcp_handle => r??,
        }

        Ok(())
    }

    async fn run_udp(
        socket: Arc<UdpSocket>,
        allowlist: Arc<DomainAllowlist>,
        upstream: Arc<UpstreamResolver>,
        dummy_ip: Ipv4Addr,
        shutdown: &mut tokio::sync::watch::Receiver<()>,
    ) -> anyhow::Result<()> {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));
        let mut buf = vec![0u8; 4096];
        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    let (len, src) = result.context("UDP recv_from に失敗")?;
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            eprintln!("DNS 同時クエリ数上限に達しました。UDP パケットをドロップ ({})", src);
                            continue;
                        }
                    };
                    let query_bytes = buf[..len].to_vec();
                    let socket = socket.clone();
                    let allowlist = allowlist.clone();
                    let upstream = upstream.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let resp = handle_query(&query_bytes, &allowlist, &upstream, dummy_ip, src).await;
                        if let Err(e) = socket.send_to(&resp, src).await {
                            eprintln!("UDP 応答の送信に失敗 ({}): {}", src, e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    eprintln!("UDP リスナーをシャットダウンします");
                    return Ok(());
                }
            }
        }
    }

    async fn run_tcp(
        listener: TcpListener,
        allowlist: Arc<DomainAllowlist>,
        upstream: Arc<UpstreamResolver>,
        dummy_ip: Ipv4Addr,
        shutdown: &mut tokio::sync::watch::Receiver<()>,
    ) -> anyhow::Result<()> {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, src) = result.context("TCP accept に失敗")?;
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            eprintln!("DNS 同時接続数上限に達しました。TCP 接続を拒否 ({})", src);
                            drop(stream);
                            continue;
                        }
                    };
                    let allowlist = allowlist.clone();
                    let upstream = upstream.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = handle_tcp_connection(stream, &allowlist, &upstream, dummy_ip, src).await {
                            eprintln!("TCP 接続の処理に失敗 ({}): {}", src, e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    eprintln!("TCP リスナーをシャットダウンします");
                    return Ok(());
                }
            }
        }
    }
}

/// TCP 接続を処理する。DNS over TCP は 2 バイトの長さプレフィクス + メッセージ。
async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    allowlist: &DomainAllowlist,
    upstream: &UpstreamResolver,
    dummy_ip: Ipv4Addr,
    src: SocketAddr,
) -> anyhow::Result<()> {
    loop {
        // 2 バイトの長さプレフィクスを読む
        let len = match stream.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e).context("TCP 長さプレフィクスの読み取りに失敗"),
        };

        if len == 0 || len > 65535 {
            return Ok(());
        }

        let mut query_bytes = vec![0u8; len];
        stream
            .read_exact(&mut query_bytes)
            .await
            .context("TCP メッセージの読み取りに失敗")?;

        let resp = handle_query(&query_bytes, allowlist, upstream, dummy_ip, src).await;

        // 長さプレフィクス + 応答を書き込む
        let resp_len = resp.len() as u16;
        stream.write_u16(resp_len).await?;
        stream.write_all(&resp).await?;
    }
}

/// DNS クエリを処理する共通ロジック。
async fn handle_query(
    query_bytes: &[u8],
    allowlist: &DomainAllowlist,
    upstream: &UpstreamResolver,
    dummy_ip: Ipv4Addr,
    src: SocketAddr,
) -> Vec<u8> {
    // クエリをパース
    let query = match Message::from_bytes(query_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("不正な DNS パケット ({}): {}", src, e);
            // ID を推測して FORMERR を返す（最低 2 バイトあれば ID は取れる）
            let id = if query_bytes.len() >= 2 {
                u16::from_be_bytes([query_bytes[0], query_bytes[1]])
            } else {
                0
            };
            return response::build_formerr_response(id)
                .to_vec()
                .unwrap_or_default();
        }
    };

    // Question セクションからドメイン名を取得
    let domain = match query.queries.first() {
        Some(q) => {
            let name = q.name().to_ascii();
            // 末尾のドットを除去
            name.strip_suffix('.').unwrap_or(&name).to_lowercase()
        }
        None => {
            return response::build_servfail_response(&query)
                .to_vec()
                .unwrap_or_default();
        }
    };

    // allowlist チェック
    if allowlist.is_allowed(&domain) {
        // 許可: 上流に転送
        match upstream.forward(query_bytes).await {
            Ok(resp) => {
                // DNS リバインディング対策: 応答の A/AAAA レコードにプライベート IP が
                // 含まれていないか検証する。攻撃者がパブリックドメインを内部 IP に解決
                // させて SSRF を引き起こすことを防止する。
                // パース失敗時は安全側に倒す: 応答内容を検証できないため SERVFAIL を返す
                let resp_msg = match Message::from_bytes(&resp) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!(
                            "[BLOCKED] upstream DNS 応答のパースに失敗 ({}): {} — {}",
                            src, domain, e
                        );
                        return response::build_servfail_response(&query)
                            .to_vec()
                            .unwrap_or_default();
                    }
                };
                // answers, additionals, name_servers の全セクションを検証する。
                // クライアント実装によっては additional セクションの A/AAAA レコードを
                // 利用するため、answers のみの検証ではバイパスされる可能性がある。
                let all_records = resp_msg
                    .answers
                    .iter()
                    .chain(resp_msg.additionals.iter())
                    .chain(resp_msg.authorities.iter());
                for record in all_records {
                    let ip: Option<IpAddr> = match &record.data {
                        RData::A(a) => Some(IpAddr::V4(a.0)),
                        RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        if ip_filter::is_private_ip(ip) {
                            eprintln!(
                                "[BLOCKED] DNS リバインディング検知: {} → {} ({})",
                                domain, ip, src
                            );
                            return response::build_servfail_response(&query)
                                .to_vec()
                                .unwrap_or_default();
                        }
                    }
                }
                resp
            }
            Err(e) => {
                eprintln!("[ERROR] 上流 DNS 転送失敗 ({}): {} — {}", src, domain, e);
                response::build_servfail_response(&query)
                    .to_vec()
                    .unwrap_or_default()
            }
        }
    } else {
        // 拒否: ダミー IP で応答
        eprintln!("[BLOCKED] {} from {} ", domain, src);
        response::build_blocked_response(&query, dummy_ip)
            .to_vec()
            .unwrap_or_default()
    }
}

// NOTE: handle_query の統合テスト (DNS リバインディング検知・レート制限) は
// UpstreamResolver が実ネットワーク接続を必要とするため現時点では追加していない。
// IP アドレス検証ロジックは ip_filter モジュールの単体テストでカバーしている。
// リファクタリング Phase で UpstreamResolver を trait 化しモック可能にした後、
// handle_query の統合テストを追加すること。(tasks.db Phase 8 / task 320)
