use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::logger::{CaptureLogger, TlsCapture};

/// TLS SNI キャプチャリスナーを起動する。
pub async fn run(
    listen_addr: SocketAddr,
    timeout: Duration,
    logger: Arc<CaptureLogger>,
    semaphore: Arc<Semaphore>,
    shutdown: &mut tokio::sync::watch::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("{} への HTTPS バインドに失敗", listen_addr))?;

    eprintln!("TLS SNI キャプチャを起動しました: {}", listen_addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, src) = result.context("HTTPS accept に失敗")?;
                let logger = logger.clone();
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        eprintln!("TLS 同時接続数上限に達しました ({})", src);
                        drop(stream);
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, src, timeout, &logger).await {
                        eprintln!("TLS 接続の処理に失敗 ({}): {}", src, e);
                    }
                });
            }
            _ = shutdown.changed() => {
                eprintln!("TLS SNI リスナーをシャットダウンします");
                return Ok(());
            }
        }
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    src: SocketAddr,
    timeout: Duration,
    logger: &CaptureLogger,
) -> anyhow::Result<()> {
    let result = tokio::time::timeout(timeout, async {
        // TLS record header (5 bytes): content_type (1) + version (2) + length (2)
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;

        let content_type = header[0];
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        if content_type != 0x16 {
            // Handshake ではない
            return Ok(None);
        }

        // レコード本体を読む（最大 16KB）
        let record_len = record_len.min(16384);
        let mut record = vec![0u8; record_len];
        stream.read_exact(&mut record).await?;

        Ok::<_, anyhow::Error>(extract_sni(&record))
    })
    .await;

    let sni = match result {
        Ok(Ok(sni)) => sni,
        Ok(Err(e)) => {
            eprintln!("TLS パースエラー ({}): {}", src, e);
            None
        }
        Err(_) => {
            eprintln!("TLS タイムアウト ({})", src);
            None
        }
    };

    logger.log_tls(&TlsCapture { src_addr: src, sni });

    Ok(())
}

/// TLS Handshake レコードから ClientHello の SNI extension を抽出する。
///
/// RFC 5246 Section 7.4.1.2 (ClientHello)
/// RFC 6066 Section 3 (Server Name Indication)
pub fn extract_sni(record: &[u8]) -> Option<String> {
    let mut pos = client_hello_fields_start(record)?;

    // session_id: length (1 byte) + data
    let session_id_len = *record.get(pos)? as usize;
    pos += 1 + session_id_len;
    if pos > record.len() {
        return None;
    }

    // cipher_suites: length (2 bytes) + data
    if pos + 2 > record.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos > record.len() {
        return None;
    }

    // compression_methods: length (1 byte) + data
    let comp_len = *record.get(pos)? as usize;
    pos += 1 + comp_len;
    if pos > record.len() {
        return None;
    }

    find_server_name_extension(record, pos)
}

fn client_hello_fields_start(record: &[u8]) -> Option<usize> {
    let mut pos = 0;

    // Handshake type (1 byte): 0x01 = ClientHello
    if record.get(pos).copied()? != 0x01 {
        return None;
    }
    pos += 1;

    // Handshake length (3 bytes)
    if pos + 3 > record.len() {
        return None;
    }
    pos += 3;

    // client_version (2 bytes)
    pos += 2;
    if pos > record.len() {
        return None;
    }

    // random (32 bytes)
    pos += 32;
    if pos > record.len() {
        return None;
    }

    Some(pos)
}

fn find_server_name_extension(record: &[u8], mut pos: usize) -> Option<String> {
    // extensions: total length (2 bytes)
    if pos + 2 > record.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total_len;
    if ext_end > record.len() {
        return None;
    }

    // extensions をイテレートして server_name (type 0x0000) を探す
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;

        // ext_len で宣言されたバイト数が extensions 範囲および record 全体に収まっているかチェック
        if pos + ext_len > ext_end || pos + ext_len > record.len() {
            return None;
        }

        if ext_type == 0x0000 {
            // server_name extension
            return parse_server_name_extension(&record[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

/// server_name extension のデータから hostname を抽出する。
fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    // server_name_list length (2 bytes)
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = (2 + list_len).min(data.len());

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0x00 {
            // host_name
            let name_end = (pos + name_len).min(data.len());
            let name_bytes = &data[pos..name_end];
            return String::from_utf8(name_bytes.to_vec()).ok();
        }

        pos += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 実際の TLS 1.2 ClientHello (curl で生成) を模したテストデータ。
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();

        // server_name extension の構築
        // name_type (1) + name_len (2) + name
        let sn_entry_len = 1 + 2 + sni_bytes.len();
        // server_name_list_len (2) + entry
        let sn_ext_data_len = 2 + sn_entry_len;
        // ext_type (2) + ext_len (2) + data
        let sn_ext_total = 4 + sn_ext_data_len;

        let mut ext_data = Vec::new();
        // ext_type = 0x0000 (server_name)
        ext_data.extend_from_slice(&[0x00, 0x00]);
        // ext_len
        ext_data.extend_from_slice(&(sn_ext_data_len as u16).to_be_bytes());
        // server_name_list_len
        ext_data.extend_from_slice(&(sn_entry_len as u16).to_be_bytes());
        // name_type = 0x00 (host_name)
        ext_data.push(0x00);
        // name_len
        ext_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        // name
        ext_data.extend_from_slice(sni_bytes);

        // ClientHello の構築
        let mut hello = Vec::new();
        // client_version
        hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        // random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);
        // session_id_len = 0
        hello.push(0x00);
        // cipher_suites: len=2, one suite
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]);
        // compression_methods: len=1, null
        hello.extend_from_slice(&[0x01, 0x00]);
        // extensions total length
        hello.extend_from_slice(&(sn_ext_total as u16).to_be_bytes());
        // extensions
        hello.extend_from_slice(&ext_data);

        // Handshake record: type=0x01 (ClientHello) + length (3 bytes) + hello
        let hello_len = hello.len();
        let mut record = Vec::new();
        record.push(0x01); // ClientHello
        record.push(0x00);
        record.extend_from_slice(&(hello_len as u16).to_be_bytes());
        record.extend_from_slice(&hello);

        record
    }

    #[test]
    fn extract_sni_rejects_every_truncated_client_hello() {
        let record = build_client_hello("example.test");
        for length in 0..record.len() {
            assert_eq!(extract_sni(&record[..length]), None, "prefix {length}");
        }
        assert_eq!(extract_sni(&record), Some("example.test".into()));
        let mut oversized = record.clone();
        // Fixed ClientHello fields occupy 45 bytes including the handshake header.
        oversized[45..47].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(extract_sni(&oversized), None);
    }

    #[test]
    fn extract_sni_basic() {
        let record = build_client_hello("evil.example.com");
        let sni = extract_sni(&record);
        assert_eq!(sni, Some("evil.example.com".to_string()));
    }

    #[test]
    fn extract_sni_long_domain() {
        let record = build_client_hello("very.long.subdomain.of.example.com");
        let sni = extract_sni(&record);
        assert_eq!(sni, Some("very.long.subdomain.of.example.com".to_string()));
    }

    #[test]
    fn extract_sni_not_client_hello() {
        // Handshake type = 0x02 (ServerHello)
        let record = vec![0x02, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00];
        assert_eq!(extract_sni(&record), None);
    }

    #[test]
    fn extract_sni_empty() {
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn extract_sni_truncated() {
        let record = build_client_hello("test.com");
        // 途中で切る
        let truncated = &record[..record.len() / 2];
        assert_eq!(extract_sni(truncated), None);
    }
}
