use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rustls::server::ClientHello;
use rustls::sign::CertifiedKey;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::cert_cache::CertCache;
use crate::http_capture;
use crate::logger::{CaptureLogger, HttpCapture};
use crate::secret_map::SecretMap;
use crate::upstream;

/// rustls の ResolvesServerCert 実装。SNI に応じてオンデマンドで証明書を生成する。
#[derive(Debug)]
struct MitmCertResolver {
    cache: Arc<CertCache>,
}

impl rustls::server::ResolvesServerCert for MitmCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        tokio::task::block_in_place(|| match self.cache.get_or_create(sni) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("証明書の生成に失敗 (sni={}): {}", sni, e);
                None
            }
        })
    }
}

/// TLS MITM プロキシリスナーを起動する。
pub async fn run(
    listen_addr: SocketAddr,
    max_body_bytes: usize,
    timeout: Duration,
    logger: Arc<CaptureLogger>,
    semaphore: Arc<Semaphore>,
    cert_cache: Arc<CertCache>,
    secret_map: Arc<SecretMap>,
    allowed_hosts: Arc<HashSet<String>>,
    shutdown: &mut tokio::sync::watch::Receiver<()>,
) -> anyhow::Result<()> {
    let resolver = MitmCertResolver {
        cache: cert_cache,
    };

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("{} への HTTPS (MITM) バインドに失敗", listen_addr))?;

    let mode = if allowed_hosts.is_empty() {
        "キャプチャのみ (全て 403)"
    } else {
        "上流転送有効"
    };
    eprintln!(
        "TLS MITM プロキシを起動しました: {} (CA 証明書動的生成, {})",
        listen_addr, mode
    );

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, src) = result.context("HTTPS accept に失敗")?;
                let logger = logger.clone();
                let acceptor = acceptor.clone();
                let secret_map = secret_map.clone();
                let allowed_hosts = allowed_hosts.clone();
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        eprintln!("TLS MITM 同時接続数上限に達しました ({})", src);
                        drop(stream);
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    // 接続全体のタイムアウト: Slowloris 攻撃等による
                    // 長時間スロット占有を防止する。個別タイムアウトの 3 倍を上限とする。
                    let conn_timeout = timeout * 3;
                    match tokio::time::timeout(conn_timeout, handle_connection(
                        stream, src, max_body_bytes, timeout, &logger,
                        acceptor, &secret_map, &allowed_hosts,
                    )).await {
                        Ok(Err(e)) => eprintln!("TLS MITM 接続の処理に失敗 ({}): {}", src, e),
                        Err(_) => eprintln!("TLS MITM 接続タイムアウト (全体) ({})", src),
                        Ok(Ok(())) => {}
                    }
                });
            }
            _ = shutdown.changed() => {
                eprintln!("TLS MITM リスナーをシャットダウンします");
                return Ok(());
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    src: SocketAddr,
    max_body_bytes: usize,
    timeout: Duration,
    logger: &CaptureLogger,
    acceptor: TlsAcceptor,
    secret_map: &SecretMap,
    allowed_hosts: &HashSet<String>,
) -> anyhow::Result<()> {
    // TLS ハンドシェイク
    let mut tls_stream = match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("TLS ハンドシェイク失敗 ({}): {}", src, e);
            return Ok(());
        }
        Err(_) => {
            eprintln!("TLS ハンドシェイクタイムアウト ({})", src);
            return Ok(());
        }
    };

    let sni = tls_stream
        .get_ref()
        .1
        .server_name()
        .map(|s| s.to_string());

    // 復号された HTTP リクエストをパース
    let result = tokio::time::timeout(timeout, async {
        http_capture::parse_http_request(&mut tls_stream, max_body_bytes, src).await
    })
    .await;

    let req = match result {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(e)) => {
            eprintln!("HTTPS パースエラー ({}): {}", src, e);
            http_capture::write_forbidden(&mut tls_stream).await;
            return Ok(());
        }
        Err(_) => {
            eprintln!("HTTPS タイムアウト ({})", src);
            http_capture::write_forbidden(&mut tls_stream).await;
            return Ok(());
        }
    };

    let target_host = req
        .host
        .clone()
        .unwrap_or_else(|| sni.clone().unwrap_or_default());

    // Host ヘッダーからポートを抽出（例: "example.com:8443" → 8443）
    let target_port = target_host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(443);
    let target_hostname = target_host
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|_| h))
        .unwrap_or(&target_host);

    // allowed_hosts チェック: 大文字小文字を無視して比較（DNS は case-insensitive）
    let hostname_lower = target_hostname.to_ascii_lowercase();
    if !allowed_hosts.is_empty() && allowed_hosts.contains(&hostname_lower) {
        // シークレット置換（body + ヘッダー値）
        let substituted_body = secret_map.substitute(&req.body);
        let substituted_path = secret_map.substitute_str(&req.path);
        let substituted_headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), secret_map.substitute_str(v)))
            .collect();

        // ログ（置換前で記録 — 本物のシークレットをログに残さない）
        logger.log_http(&HttpCapture {
            src_addr: src,
            method: req.method.clone(),
            path: req.path.clone(),
            host: target_host.clone(),
            content_length: req.content_length,
            body_preview: req.body.clone(),
            tls_sni: sni.clone(),
        });

        // 上流に転送（ヘッダー含む、Host はポート付きの元の値を保持）
        let request_bytes = upstream::build_http_request(
            &req.method,
            &substituted_path,
            &target_host,
            &substituted_headers,
            &substituted_body,
        );

        match upstream::forward_https(target_hostname, target_port, &request_bytes, timeout)
            .await
        {
            Ok(response) => {
                let _ = tls_stream.write_all(&response).await;
            }
            Err(e) => {
                eprintln!("上流転送失敗 ({} → {}): {}", src, target_host, e);
                let _ = tls_stream
                    .write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
            }
        }
    } else {
        // 許可リスト外 → 403 + ログ
        logger.log_http(&HttpCapture {
            src_addr: src,
            method: req.method,
            path: req.path,
            host: target_host,
            content_length: req.content_length,
            body_preview: req.body,
            tls_sni: sni,
        });

        http_capture::write_forbidden(&mut tls_stream).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaAuthority;
    use crate::cert_cache::CertCache;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_mitm_returns_403_for_blocked_host() {
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cert_cache = Arc::new(CertCache::new(ca.clone(), Arc::new(HashSet::new())));
        let logger = Arc::new(CaptureLogger::new(None).unwrap());
        let semaphore = Arc::new(Semaphore::new(10));
        let secret_map = Arc::new(SecretMap::new());
        let allowed_hosts = Arc::new(HashSet::new()); // 空 = 全て 403

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut shutdown_clone = shutdown_rx.clone();
        let logger_clone = logger.clone();
        let semaphore_clone = semaphore.clone();
        let cache_clone = cert_cache.clone();
        let secret_clone = secret_map.clone();
        let hosts_clone = allowed_hosts.clone();

        let server = tokio::spawn(async move {
            run(
                addr, 4096, Duration::from_secs(5), logger_clone, semaphore_clone,
                cache_clone, secret_clone, hosts_clone, &mut shutdown_clone,
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // CA を信頼する rustls クライアント
        let mut root_store = rustls::RootCertStore::empty();
        let mut cursor = std::io::Cursor::new(ca.cert_pem().as_bytes());
        let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
            .filter_map(|r| r.ok())
            .collect();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("blocked.example.com").unwrap();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        tls_stream
            .write_all(b"GET /secret HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tls_stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("403 Forbidden"),
            "expected 403, got: {}",
            response
        );

        shutdown_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }
}
