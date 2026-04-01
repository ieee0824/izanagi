use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use izanagi::detector::AlertLevel;
use izanagi::log_storage::LogStorage;

use super::default_log_dir;

/// follow モードの行長上限 (1MB)。これを超える行は切り詰める。
const MAX_LINE_LEN: usize = 1024 * 1024;

pub fn cmd_logs(suspicious: bool) -> anyhow::Result<u8> {
    let log_storage = LogStorage::new(&default_log_dir())?;
    if suspicious {
        let alerts = log_storage.read_alerts_filtered(AlertLevel::Warn)?;
        for line in &alerts {
            println!("{}", line);
        }
        if alerts.is_empty() {
            println!("不審なアクセスは記録されていません。");
        }
    } else {
        let events = log_storage.read_events()?;
        for line in &events {
            println!("{}", line);
        }
        let alerts = log_storage.read_alerts()?;
        for line in &alerts {
            println!("{}", line);
        }
        if events.is_empty() && alerts.is_empty() {
            println!("ログは記録されていません。");
        }
    }
    Ok(0)
}

/// ログをリアルタイムで追尾表示する (tail -f 相当)。
/// 既存ログを表示した後、新しい行が追加されるたびに出力する。
/// Ctrl-C で終了。
pub async fn cmd_logs_follow(suspicious: bool) -> anyhow::Result<u8> {
    // まず既存ログを表示
    cmd_logs(suspicious)?;

    let log_dir = default_log_dir();
    let events_path = log_dir.join("events.log");
    let alerts_path = log_dir.join("alerts.log");

    let mut events_tail = TailReader::open(&events_path);
    let mut alerts_tail = TailReader::open(&alerts_path);

    let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut printed = 0;
                printed += tokio::task::block_in_place(|| events_tail.read_new_lines(suspicious))?;
                printed += tokio::task::block_in_place(|| alerts_tail.read_new_lines(suspicious))?;
                if printed > 0 {
                    std::io::stdout().flush().ok();
                }
            }
            _ = &mut ctrl_c => {
                break;
            }
        }
    }

    Ok(0)
}

/// ログファイルを追尾する構造体。
/// ローテーション (inode 変更) を検知して自動的に reopen する。
struct TailReader {
    path: PathBuf,
    reader: Option<BufReader<std::fs::File>>,
    inode: u64,
}

impl TailReader {
    /// ファイルを開き末尾にシークする。ファイルが存在しない場合も構築する。
    fn open(path: &Path) -> Self {
        let (reader, inode) = match open_tail(path) {
            Some((r, ino)) => (Some(r), ino),
            None => (None, 0),
        };
        Self {
            path: path.to_owned(),
            reader,
            inode,
        }
    }

    /// 新しい行を読んで表示する。ローテーション検知付き。
    fn read_new_lines(&mut self, suspicious: bool) -> anyhow::Result<usize> {
        // ファイルが未オープンなら開く
        if self.reader.is_none() {
            if let Some((r, ino)) = open_tail(&self.path) {
                self.reader = Some(r);
                self.inode = ino;
            } else {
                return Ok(0);
            }
        }

        // ローテーション検知: 現在のファイルの inode と比較
        if let Ok(current_inode) = get_inode(&self.path) {
            if current_inode != self.inode {
                // ローテーションが発生した。旧ファイルの残りを読み切ってから reopen
                if let Some(ref mut r) = self.reader {
                    let _ = tail_lines(r, suspicious);
                }
                // 新しいファイルを先頭から開く (seek to start)
                if let Some((r, ino)) = open_from_start(&self.path) {
                    self.reader = Some(r);
                    self.inode = ino;
                } else {
                    self.reader = None;
                    return Ok(0);
                }
            }
        }

        match self.reader {
            Some(ref mut r) => tail_lines(r, suspicious),
            None => Ok(0),
        }
    }
}

/// ファイルを読み取り専用で開き末尾にシークした BufReader と inode を返す。
fn open_tail(path: &Path) -> Option<(BufReader<std::fs::File>, u64)> {
    match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(file) => {
            let inode = get_file_inode(&file);
            let mut reader = BufReader::new(file);
            if reader.seek(SeekFrom::End(0)).is_err() {
                eprintln!("警告: ファイルのシークに失敗: {}", path.display());
                return None;
            }
            Some((reader, inode))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("警告: ファイルを開けません: {}: {}", path.display(), e);
            None
        }
    }
}

/// ファイルを読み取り専用で先頭から開いた BufReader と inode を返す。
fn open_from_start(path: &Path) -> Option<(BufReader<std::fs::File>, u64)> {
    match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(file) => {
            let inode = get_file_inode(&file);
            Some((BufReader::new(file), inode))
        }
        Err(_) => None,
    }
}

/// パスから inode を取得する。
fn get_inode(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok(meta.ino())
}

/// 開いている File から inode を取得する。
fn get_file_inode(file: &std::fs::File) -> u64 {
    use std::os::unix::fs::MetadataExt;
    file.metadata().map(|m| m.ino()).unwrap_or(0)
}

/// BufReader から新しい行を読み、フィルタに応じて表示する。表示した行数を返す。
/// 未完了行 (改行なし) はシークバックして次回ポーリングに回す。
/// 行長上限を超える行は読み捨てて OOM を防止する。
fn tail_lines(reader: &mut BufReader<std::fs::File>, suspicious: bool) -> anyhow::Result<usize> {
    let mut count = 0;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let bytes = reader.read_until(b'\n', &mut buf)?;
        if bytes == 0 {
            break;
        }
        // 改行で終わっていない場合
        if !buf.ends_with(b"\n") {
            if buf.len() <= MAX_LINE_LEN {
                // 部分行 → シークバックして次回に回す
                reader.seek_relative(-(bytes as i64))?;
                break;
            }
            // 上限超過の長大行 → 次の改行まで読み捨てる
            let mut discard = Vec::new();
            loop {
                discard.clear();
                let n = reader.read_until(b'\n', &mut discard)?;
                if n == 0 || discard.ends_with(b"\n") {
                    break;
                }
            }
            continue;
        }
        // 改行を除いた表示用バイト列
        let display_end = (buf.len() - 1).min(MAX_LINE_LEN);
        let trimmed = String::from_utf8_lossy(&buf[..display_end]);
        let trimmed = trimmed.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let overlong = buf.len() - 1 > MAX_LINE_LEN;
        if suspicious {
            if is_suspicious_line(trimmed) {
                print!("{}", trimmed);
                if overlong {
                    print!("...[truncated]");
                }
                println!();
                count += 1;
            }
        } else {
            print!("{}", trimmed);
            if overlong {
                print!("...[truncated]");
            }
            println!();
            count += 1;
        }
    }
    Ok(count)
}

/// ログ行が WARN または CRITICAL レベルかどうかを構造的に判定する。
fn is_suspicious_line(line: &str) -> bool {
    if let Some(after_bracket) = line.split("] ").nth(1) {
        let level = after_bracket.split_whitespace().next().unwrap_or("");
        matches!(level, "WARN" | "CRITICAL")
    } else {
        false
    }
}
