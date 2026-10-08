use std::sync::{Arc, OnceLock};

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// キャッシュされた TLS クライアント設定（プロセス生存期間中有効）。
fn cached_tls_connector() -> TlsConnector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    });
    TlsConnector::from(config.clone())
}

/// 上流サーバーへ HTTPS リクエストを転送し、レスポンスを返す。
///
/// 接続前に DNS 解決結果を検証し、プライベート IP アドレスへの接続をブロックする。
/// これにより DNS リバインディング攻撃による内部 SSRF を防止する。
///
/// 全工程（DNS 解決 → IP 検証 → TCP 接続 → TLS → 送信 → 受信）を
/// 単一の `timeout` で制限し、呼び出し元のタイムアウトと矛盾しないようにする。
pub async fn forward_https(
    host: &str,
    port: u16,
    request_bytes: &[u8],
    timeout: std::time::Duration,
) -> anyhow::Result<Vec<u8>> {
    tokio::time::timeout(timeout, forward_https_inner(host, port, request_bytes))
        .await
        .context("上流転送タイムアウト")?
}

async fn forward_https_inner(
    host: &str,
    port: u16,
    request_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let addr = format!("{}:{}", host, port);

    // DNS 解決を明示的に行い、プライベート IP を除外してパブリック候補のみに接続する。
    // split-horizon DNS 等で「パブリック + プライベート」が返るケースでも、
    // パブリック候補があればそちらへ接続し可用性を維持する。
    // 全候補がプライベート IP の場合のみ SSRF 防止のためブロックする。
    let resolved = tokio::net::lookup_host(&addr)
        .await
        .with_context(|| format!("上流ホスト名の解決に失敗: {}", addr))?;
    let resolved: Vec<_> = resolved.collect();

    let public_addrs: Vec<_> = resolved
        .iter()
        .filter(|sa| !crate::ip_filter::is_private_ip(sa.ip()))
        .collect();

    if public_addrs.is_empty() {
        if resolved.is_empty() {
            anyhow::bail!("上流ホスト {} の DNS 解決結果が空です", host);
        }
        let private_ips: Vec<String> = resolved.iter().map(|sa| sa.ip().to_string()).collect();
        anyhow::bail!(
            "上流ホスト {} がプライベート IP ({}) のみに解決されました。SSRF 防止のため接続をブロックします。",
            host,
            private_ips.join(", ")
        );
    }

    let target_addr = public_addrs[0];

    let connector = cached_tls_connector();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("無効なホスト名: {}: {}", host, e))?;

    let tcp_stream = TcpStream::connect(target_addr)
        .await
        .with_context(|| format!("上流サーバーへの接続に失敗: {}", addr))?;

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .context("上流 TLS ハンドシェイクに失敗")?;

    // リクエストを送信
    tls_stream
        .write_all(request_bytes)
        .await
        .context("上流へのリクエスト送信に失敗")?;

    // レスポンスを受信（最大 1MB）
    let mut response = Vec::new();
    let max_response = 1024 * 1024;

    let mut buf = [0u8; 8192];
    loop {
        let n = tls_stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.len() > max_response {
            anyhow::bail!(
                "上流レスポンスが最大サイズ({} bytes)を超過しました",
                max_response
            );
        }
    }

    Ok(response)
}

// NOTE: forward_https / forward_https_inner の統合テスト (SSRF 防止・タイムアウト) は
// tokio::net::lookup_host + TcpStream::connect が実ネットワーク接続を必要とするため
// 現時点では追加していない。プライベート IP 検証ロジックは ip_filter モジュールの
// 単体テストでカバーしている。リファクタリング Phase で DNS 解決・TCP 接続を
// trait 化しモック可能にした後、forward_https の統合テストを追加すること。
// (tasks.db Phase 8 / task 320)

/// HTTP/1.1 リクエストバイト列を構築する。
pub fn build_http_request(
    method: &str,
    path: &str,
    host: &str,
    headers_extra: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        sanitize_header_value(method),
        sanitize_header_value(path),
        sanitize_header_value(host),
    );

    // hop-by-hop ヘッダーと重複管理ヘッダーを除外
    const SKIP_HEADERS: &[&str] = &[
        "host",
        "content-length",
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "transfer-encoding",
        "trailer",
        "upgrade",
    ];

    for (key, value) in headers_extra {
        let key_lower = key.to_ascii_lowercase();
        if SKIP_HEADERS.contains(&key_lower.as_str()) {
            continue;
        }
        // CRLF インジェクション防止: key/value から制御文字を除去
        request.push_str(&format!(
            "{}: {}\r\n",
            sanitize_header_value(key),
            sanitize_header_value(value),
        ));
    }

    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }

    request.push_str("Connection: close\r\n\r\n");

    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// HTTP ヘッダーの key/value から CR/LF を除去してヘッダーインジェクションを防止する。
fn sanitize_header_value(s: &str) -> String {
    s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_get() {
        let req = build_http_request("GET", "/api", "example.com", &[], &[]);
        let s = String::from_utf8(req).unwrap();
        assert!(s.starts_with("GET /api HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(!s.contains("Content-Length"));
    }

    #[test]
    fn build_request_post_with_body() {
        let body = b"{\"key\":\"value\"}";
        let req = build_http_request("POST", "/data", "api.example.com", &[], body);
        let s = String::from_utf8(req).unwrap();
        assert!(s.starts_with("POST /data HTTP/1.1\r\n"));
        assert!(s.contains("Content-Length: 15\r\n"));
        assert!(s.ends_with("{\"key\":\"value\"}"));
    }

    #[test]
    fn build_request_with_extra_headers() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer token".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let req = build_http_request("GET", "/", "example.com", &headers, &[]);
        let s = String::from_utf8(req).unwrap();
        assert!(s.contains("Authorization: Bearer token\r\n"));
        assert!(s.contains("Accept: application/json\r\n"));
    }

    #[test]
    fn build_request_skips_host_and_content_length() {
        let headers = vec![
            ("Host".to_string(), "old-host".to_string()),
            ("Content-Length".to_string(), "999".to_string()),
        ];
        let body = b"data";
        let req = build_http_request("POST", "/", "new-host", &headers, body);
        let s = String::from_utf8(req).unwrap();
        // Host は build_http_request が設定するので extra からは除外される
        assert!(!s.contains("old-host"));
        assert!(s.contains("Host: new-host\r\n"));
        // Content-Length は body.len() から計算される
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(!s.contains("Content-Length: 999"));
    }

    #[test]
    fn build_request_sanitizes_crlf_injection() {
        let headers = vec![(
            "X-Custom".to_string(),
            "value\r\nEvil-Header: injected".to_string(),
        )];
        let req = build_http_request("GET", "/", "example.com", &headers, &[]);
        let s = String::from_utf8(req).unwrap();
        // CRLF が除去されて別ヘッダー行としてのインジェクションが防止される
        assert!(!s.contains("\r\nEvil-Header:"));
        // 値は連結される（制御文字が除去されただけ）
        assert!(s.contains("X-Custom: "));
    }

    #[test]
    fn sanitize_header_value_removes_crlf() {
        assert_eq!(sanitize_header_value("normal"), "normal");
        assert_eq!(sanitize_header_value("a\r\nb"), "ab");
        assert_eq!(sanitize_header_value("a\nb"), "ab");
        assert_eq!(sanitize_header_value("a\rb"), "ab");
    }
}
