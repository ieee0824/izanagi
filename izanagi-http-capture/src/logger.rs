use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use tokio::sync::mpsc;

/// HTTP リクエストのキャプチャ結果。
pub struct HttpCapture {
    pub src_addr: SocketAddr,
    pub method: String,
    pub path: String,
    pub host: String,
    pub content_length: Option<u64>,
    pub body_preview: Vec<u8>,
    /// TLS MITM 経由の場合、ClientHello の SNI を記録する。
    pub tls_sni: Option<String>,
}

/// TLS SNI のキャプチャ結果。
pub struct TlsCapture {
    pub src_addr: SocketAddr,
    pub sni: Option<String>,
}

/// ログチャネルのバッファサイズ。
/// 満杯時は send が非同期で待機する（バックプレッシャー）。
const LOG_CHANNEL_CAPACITY: usize = 4096;

/// キャプチャログの出力先（stderr + オプションでファイル）。
/// 容量付き mpsc チャネル経由でバックグラウンドタスクにログを送信する。
pub struct CaptureLogger {
    tx: mpsc::Sender<String>,
}

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
const MAX_GENERATIONS: u32 = 3;
const FLUSH_INTERVAL: u32 = 10; // 10 行ごとにフラッシュ

impl CaptureLogger {
    /// ロガーを作成し、バックグラウンドのファイル書き込みタスクを spawn する。
    pub fn new(log_dir: Option<&Path>) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel(LOG_CHANNEL_CAPACITY);

        let log_file = if let Some(dir) = log_dir {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
            let path = dir.join("http-capture.log");
            let file = open_log_file(&path)?;
            let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
            Some(LogFile {
                writer: std::io::BufWriter::new(file),
                path,
                bytes_written,
                flush_count: 0,
            })
        } else {
            None
        };

        // バックグラウンドタスクで spawn_blocking を使いファイル書き込みを処理
        tokio::spawn(async move {
            writer_task(rx, log_file).await;
        });

        Ok(Self { tx })
    }

    pub fn log_http(&self, capture: &HttpCapture) {
        let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let body_str = sanitize_for_log(&capture.body_preview);
        let proto = if let Some(ref sni) = capture.tls_sni {
            format!("HTTPS sni={}", sanitize_str(sni))
        } else {
            "HTTP".to_string()
        };
        let line = format!(
            "[{}] {} src={} method={} host={} path={} body_len={} body=\"{}\"",
            ts,
            proto,
            capture.src_addr,
            sanitize_str(&capture.method),
            sanitize_str(&capture.host),
            sanitize_str(&capture.path),
            capture.content_length.unwrap_or(0),
            body_str,
        );
        eprintln!("{}", line);
        // try_send: チャネルが満杯ならドロップ（接続処理をブロックしない）
        if self.tx.try_send(line).is_err() {
            eprintln!("警告: ログチャネルが満杯のためログ行をドロップしました");
        }
    }

    pub fn log_tls(&self, capture: &TlsCapture) {
        let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let sni = capture.sni.as_deref().unwrap_or("<no SNI>");
        let line = format!(
            "[{}] TLS_SNI src={} sni={}",
            ts,
            capture.src_addr,
            sanitize_str(sni),
        );
        eprintln!("{}", line);
        if self.tx.try_send(line).is_err() {
            eprintln!("警告: ログチャネルが満杯のためログ行をドロップしました");
        }
    }
}

struct LogFile {
    writer: std::io::BufWriter<std::fs::File>,
    path: PathBuf,
    bytes_written: u64,
    flush_count: u32,
}

/// ログファイルを 0600 パーミッションで作成・オープンする。
///
/// `mode(0o600)` でファイル作成し、作成後に `set_permissions()` で矯正する
/// 多層防御により、umask の影響を受けずに正しいパーミッションを保証する。
/// umask の一時変更は process-wide でスレッドセーフでないため行わない。
#[cfg(unix)]
fn open_log_file(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;

    // 既存ファイルや umask の影響を受けた場合もパーミッションを矯正する
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(file)
}

#[cfg(not(unix))]
fn open_log_file(path: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    Ok(file)
}

/// バックグラウンドでチャネルからログ行を受信し、
/// spawn_blocking でファイルに書き込む。
async fn writer_task(mut rx: mpsc::Receiver<String>, log_file: Option<LogFile>) {
    // ファイルがない場合はチャネルを drain するだけ
    let Some(mut lf) = log_file else {
        while rx.recv().await.is_some() {}
        return;
    };

    while let Some(line) = rx.recv().await {
        // 同期 I/O を spawn_blocking で実行して tokio ワーカーをブロックしない
        lf = match tokio::task::spawn_blocking(move || {
            write_line(&mut lf, &line);
            lf
        })
        .await
        {
            Ok(lf) => lf,
            Err(e) => {
                eprintln!("警告: ログ書き込みタスクがパニック: {}", e);
                return;
            }
        };
    }

    // チャネルが閉じたら最終フラッシュ
    let _ = lf.writer.flush();
}

/// 1行をファイルに書き込み、フラッシュ・ローテーションを処理する。
fn write_line(lf: &mut LogFile, line: &str) {
    let bytes = format!("{}\n", line);
    if let Err(e) = lf.writer.write_all(bytes.as_bytes()) {
        eprintln!("警告: ログファイルへの書き込みに失敗: {}", e);
        return;
    }
    lf.bytes_written += bytes.len() as u64;
    lf.flush_count += 1;

    if lf.flush_count >= FLUSH_INTERVAL {
        let _ = lf.writer.flush();
        lf.flush_count = 0;
    }

    if lf.bytes_written >= MAX_FILE_SIZE {
        let _ = lf.writer.flush();
        rotate(&lf.path);
        match open_log_file(&lf.path) {
            Ok(file) => {
                lf.writer = std::io::BufWriter::new(file);
                lf.bytes_written = 0;
            }
            Err(e) => {
                eprintln!("警告: ローテーション後のファイルオープンに失敗: {}", e);
            }
        }
    }
}

fn rotate(path: &Path) {
    for i in (1..MAX_GENERATIONS).rev() {
        let from = path.with_extension(format!("log.{}", i));
        let to = path.with_extension(format!("log.{}", i + 1));
        let _ = std::fs::rename(&from, &to);
    }
    let rotated = path.with_extension("log.1");
    let _ = std::fs::rename(path, &rotated);
}

/// 制御文字をエスケープする。
fn sanitize_str(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => result.push_str(&format!("\\x{:02x}", c as u32)),
            _ => result.push(c),
        }
    }
    result
}

/// バイト列をログ用の文字列に変換する。
fn sanitize_for_log(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    sanitize_str(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_str_normal() {
        assert_eq!(sanitize_str("hello world"), "hello world");
    }

    #[test]
    fn sanitize_str_control_chars() {
        assert_eq!(
            sanitize_str("line1\nline2\r\tend"),
            "line1\\nline2\\r\\tend"
        );
    }

    #[test]
    fn sanitize_str_null() {
        assert_eq!(sanitize_str("abc\0def"), "abc\\x00def");
    }

    #[test]
    fn sanitize_for_log_utf8() {
        assert_eq!(sanitize_for_log(b"hello"), "hello");
    }

    #[test]
    fn sanitize_for_log_binary() {
        let bytes = &[0xFF, 0xFE, b'a', b'b'];
        let result = sanitize_for_log(bytes);
        assert!(result.contains("ab"));
    }
}
