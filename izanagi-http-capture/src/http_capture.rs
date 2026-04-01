use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::logger::{CaptureLogger, HttpCapture};

/// HTTP キャプチャリスナーを起動する。
pub async fn run(
    listen_addr: SocketAddr,
    max_body_bytes: usize,
    timeout: Duration,
    logger: Arc<CaptureLogger>,
    semaphore: Arc<Semaphore>,
    shutdown: &mut tokio::sync::watch::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("{} への HTTP バインドに失敗", listen_addr))?;

    eprintln!("HTTP キャプチャを起動しました: {}", listen_addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, src) = result.context("HTTP accept に失敗")?;
                let logger = logger.clone();
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        eprintln!("HTTP 同時接続数上限に達しました ({})", src);
                        drop(stream);
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, src, max_body_bytes, timeout, &logger).await {
                        eprintln!("HTTP 接続の処理に失敗 ({}): {}", src, e);
                    }
                });
            }
            _ = shutdown.changed() => {
                eprintln!("HTTP リスナーをシャットダウンします");
                return Ok(());
            }
        }
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    src: SocketAddr,
    max_body_bytes: usize,
    timeout: Duration,
    logger: &CaptureLogger,
) -> anyhow::Result<()> {
    let result = tokio::time::timeout(timeout, async {
        parse_http_request(&mut stream, max_body_bytes, src).await
    })
    .await;

    match result {
        Ok(Ok(req)) => {
            logger.log_http(&HttpCapture {
                src_addr: src,
                method: req.method,
                path: req.path,
                host: req.host.unwrap_or_default(),
                content_length: req.content_length,
                body_preview: req.body,
                tls_sni: None,
            });
        }
        Ok(Err(e)) => {
            eprintln!("HTTP パースエラー ({}): {}", src, e);
        }
        Err(_) => {
            eprintln!("HTTP タイムアウト ({})", src);
        }
    }

    write_forbidden(&mut stream).await;

    Ok(())
}

/// パースされた HTTP リクエスト。
pub(crate) struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub content_length: Option<u64>,
    pub body: Vec<u8>,
    /// ヘッダーの (key, value) リスト（request line を除く）。
    pub headers: Vec<(String, String)>,
}

/// HTTP リクエストを任意の AsyncRead ストリームからパースする。
pub(crate) async fn parse_http_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_body_bytes: usize,
    src: SocketAddr,
) -> anyhow::Result<ParsedRequest> {
    let mut buf = vec![0u8; 8192];
    let mut total = 0;
    let header_end;

    loop {
        if total >= buf.len() {
            anyhow::bail!("HTTP ヘッダーが {} バイトを超えました（\\r\\n\\r\\n が見つかりません）", buf.len());
        }
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            if total == 0 {
                anyhow::bail!("クライアントが接続を閉じました（データなし）");
            }
            anyhow::bail!("HTTP ヘッダーが不完全です（\\r\\n\\r\\n が見つかりません、{} バイト受信）", total);
        }
        total += n;

        if let Some(pos) = find_header_end(&buf[..total]) {
            header_end = pos;
            break;
        }
    }

    let header_bytes = &buf[..header_end];
    let header_str = String::from_utf8_lossy(header_bytes);

    let (method, path) = parse_request_line(&header_str);

    // ヘッダーを (key, value) リストとしてパース
    let mut headers = Vec::new();
    for line in header_str.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let host = extract_header(&header_str, "host");
    let content_length =
        extract_header(&header_str, "content-length").and_then(|v| v.parse::<u64>().ok());

    let body = if let Some(cl) = content_length {
        if cl > 0 {
            let to_read = (cl as usize).min(max_body_bytes);
            let header_with_sep = find_header_end(&buf[..total])
                .map(|p| p + 4)
                .unwrap_or(total);
            let already_read = &buf[header_with_sep..total];
            let mut body = already_read.to_vec();

            // 要求サイズに達するまでループで読み切る
            while body.len() < to_read {
                let remaining = to_read - body.len();
                let mut extra = vec![0u8; remaining.min(8192)];
                match stream.read(&mut extra).await {
                    Ok(0) => break, // EOF
                    Ok(n) => body.extend_from_slice(&extra[..n]),
                    Err(e) => {
                        eprintln!("HTTP body 読み取りエラー ({}): {}", src, e);
                        break;
                    }
                }
            }
            body.truncate(to_read);
            body
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(ParsedRequest {
        method,
        path,
        host,
        content_length,
        body,
        headers,
    })
}

/// 403 Forbidden レスポンスを書き込む。
pub(crate) async fn write_forbidden<S: AsyncWrite + Unpin>(stream: &mut S) {
    let _ = stream
        .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        .await;
}

/// ヘッダー末尾の `\r\n\r\n` の位置を探す。
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// リクエスト行から method と path を抽出する。
fn parse_request_line(header: &str) -> (String, String) {
    let first_line = header.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("?").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    (method, path)
}

/// ヘッダーから指定されたキーの値を抽出する（大文字小文字を無視）。
fn extract_header(header: &str, key: &str) -> Option<String> {
    let key_lower = key.to_ascii_lowercase();
    for line in header.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == key_lower {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_line_get() {
        let (method, path) =
            parse_request_line("GET /index.html HTTP/1.1\r\nHost: example.com\r\n");
        assert_eq!(method, "GET");
        assert_eq!(path, "/index.html");
    }

    #[test]
    fn parse_request_line_post() {
        let (method, path) = parse_request_line("POST /api/data HTTP/1.1\r\n");
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/data");
    }

    #[test]
    fn parse_request_line_empty() {
        let (method, path) = parse_request_line("");
        assert_eq!(method, "?");
        assert_eq!(path, "/");
    }

    #[test]
    fn extract_header_host() {
        let header = "GET / HTTP/1.1\r\nHost: evil.example.com\r\nAccept: */*\r\n";
        assert_eq!(
            extract_header(header, "host"),
            Some("evil.example.com".to_string())
        );
    }

    #[test]
    fn extract_header_case_insensitive() {
        let header = "GET / HTTP/1.1\r\nContent-Length: 42\r\n";
        assert_eq!(
            extract_header(header, "content-length"),
            Some("42".to_string())
        );
    }

    #[test]
    fn extract_header_missing() {
        let header = "GET / HTTP/1.1\r\n";
        assert_eq!(extract_header(header, "host"), None);
    }

    #[test]
    fn find_header_end_present() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(data), Some(23));
    }

    #[test]
    fn find_header_end_missing() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(find_header_end(data), None);
    }
}
