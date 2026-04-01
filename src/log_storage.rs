use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Context;

use crate::detector::{Alert, AlertLevel};
use crate::event::SyscallEvent;
use crate::log_formatter;

/// ログファイルのデフォルト名。
const EVENT_LOG_FILE: &str = "events.log";
const ALERT_LOG_FILE: &str = "alerts.log";

/// N 件書き込みごとに flush するためのデフォルト閾値。
const DEFAULT_FLUSH_INTERVAL: u64 = 100;

/// ログファイルのデフォルト最大サイズ（10MB）。
const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// ログローテーションのデフォルト最大世代数。
const DEFAULT_MAX_GENERATIONS: u32 = 3;

/// BufWriter とカウンタベースの flush 制御をまとめた構造体。
/// ログローテーション機能を内蔵する。
struct FlushingWriter {
    writer: BufWriter<File>,
    count: u64,
    flush_interval: u64,
    path: PathBuf,
    current_size: u64,
    max_file_size: u64,
    max_generations: u32,
}

impl FlushingWriter {
    fn new(
        file: File,
        flush_interval: u64,
        path: PathBuf,
        max_file_size: u64,
        max_generations: u32,
    ) -> Self {
        // flush_interval=0 は is_multiple_of(0) でパニックするため最低1に
        let flush_interval = if flush_interval == 0 {
            1
        } else {
            flush_interval
        };
        let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Self {
            writer: BufWriter::new(file),
            count: 0,
            flush_interval,
            path,
            current_size,
            max_file_size,
            max_generations,
        }
    }

    fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
        let line_bytes = line.len() as u64 + 1; // +1 for newline
        // サイズ超過時にローテーション
        if self.current_size + line_bytes > self.max_file_size && self.current_size > 0 {
            self.rotate()?;
        }
        writeln!(self.writer, "{}", line).with_context(|| "ログへの書き込みに失敗")?;
        self.current_size += line_bytes;
        self.count += 1;
        if self.count.is_multiple_of(self.flush_interval) {
            self.writer
                .flush()
                .with_context(|| "ログのフラッシュに失敗")?;
        }
        Ok(())
    }

    /// ログファイルをローテーションする。
    /// .3 を削除し、.2 → .3、.1 → .2、現在 → .1 とリネームする。
    fn rotate(&mut self) -> anyhow::Result<()> {
        // まず現在の writer を flush して閉じる
        self.writer
            .flush()
            .with_context(|| "ローテーション前のフラッシュに失敗")?;

        // 最大世代を削除
        let oldest = rotated_path(&self.path, self.max_generations);
        if oldest.exists() {
            fs::remove_file(&oldest)
                .with_context(|| format!("古いログファイルの削除に失敗: {:?}", oldest))?;
        }

        // 世代を繰り上げ
        for i in (1..self.max_generations).rev() {
            let from = rotated_path(&self.path, i);
            let to = rotated_path(&self.path, i + 1);
            if from.exists() {
                fs::rename(&from, &to).with_context(|| {
                    format!("ログファイルのリネームに失敗: {:?} -> {:?}", from, to)
                })?;
            }
        }

        // 現在のファイル → .1
        let first_gen = rotated_path(&self.path, 1);
        fs::rename(&self.path, &first_gen).with_context(|| {
            format!(
                "ログファイルのリネームに失敗: {:?} -> {:?}",
                self.path, first_gen
            )
        })?;

        // 新しいファイルを開く
        let new_file = open_log_file(&self.path)?;
        self.writer = BufWriter::new(new_file);
        self.current_size = 0;

        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        self.writer
            .flush()
            .with_context(|| "ログのフラッシュに失敗")?;
        Ok(())
    }
}

/// ローテーション済みファイルのパスを返す（例: events.log.1）。
fn rotated_path(base: &Path, generation: u32) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{}", generation));
    PathBuf::from(name)
}

impl Drop for FlushingWriter {
    fn drop(&mut self) {
        let _ = self.writer.flush();
    }
}

/// イベントとアラートをファイルに永続化し、読み込みとフィルタリングを提供する。
///
/// BufWriter + Mutex 方式でスレッドセーフかつ効率的な書き込みを行う。
/// N 件ごとにバッファを flush し、Drop 時に残りを flush する。
pub struct LogStorage {
    log_dir: PathBuf,
    event_writer: Mutex<FlushingWriter>,
    alert_writer: Mutex<FlushingWriter>,
}

/// ログファイルを append モードでオープンし、パーミッションを設定する。
/// 既存ファイルのパーミッションが 0600 でなければ矯正する。
///
/// `mode(0o600)` でファイル作成し、作成後に `set_permissions()` で矯正する
/// 多層防御により、umask の影響を受けずに正しいパーミッションを保証する。
/// umask の一時変更は process-wide でスレッドセーフでないため行わない。
fn open_log_file(path: &Path) -> anyhow::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("ログファイルのオープンに失敗: {:?}", path))?;

        // 既存ファイルや umask の影響を受けた場合もパーミッションを矯正する
        let metadata = file
            .metadata()
            .with_context(|| format!("ログファイルのメタデータ取得に失敗: {:?}", path))?;
        let current_mode = metadata.permissions().mode() & 0o777;
        if current_mode != 0o600 {
            let perms = std::fs::Permissions::from_mode(0o600);
            file.set_permissions(perms).with_context(|| {
                format!(
                    "ログファイルのパーミッション矯正に失敗: {:?} (現在: {:o})",
                    path, current_mode
                )
            })?;
        }

        Ok(file)
    }

    #[cfg(not(unix))]
    {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("ログファイルのオープンに失敗: {:?}", path))?;
        Ok(file)
    }
}

impl LogStorage {
    /// 指定ディレクトリにログを保存する LogStorage を作成する。
    /// ディレクトリが存在しない場合は作成する。
    pub fn new(log_dir: &Path) -> anyhow::Result<Self> {
        Self::with_options(
            log_dir,
            DEFAULT_FLUSH_INTERVAL,
            DEFAULT_MAX_FILE_SIZE,
            DEFAULT_MAX_GENERATIONS,
        )
    }

    /// フラッシュ間隔を指定して LogStorage を作成する。
    pub fn with_flush_interval(log_dir: &Path, flush_interval: u64) -> anyhow::Result<Self> {
        Self::with_options(
            log_dir,
            flush_interval,
            DEFAULT_MAX_FILE_SIZE,
            DEFAULT_MAX_GENERATIONS,
        )
    }

    /// 全オプションを指定して LogStorage を作成する。
    pub fn with_options(
        log_dir: &Path,
        flush_interval: u64,
        max_file_size: u64,
        max_generations: u32,
    ) -> anyhow::Result<Self> {
        fs::create_dir_all(log_dir)
            .with_context(|| format!("ログディレクトリの作成に失敗: {:?}", log_dir))?;

        // Unix: ディレクトリのパーミッションを 0700 に設定（新規・既存問わず矯正）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(log_dir, perms).with_context(|| {
                format!("ログディレクトリのパーミッション設定に失敗: {:?}", log_dir)
            })?;
        }

        let event_path = log_dir.join(EVENT_LOG_FILE);
        let alert_path = log_dir.join(ALERT_LOG_FILE);

        let event_file = open_log_file(&event_path)?;
        let alert_file = open_log_file(&alert_path)?;

        Ok(Self {
            log_dir: log_dir.to_path_buf(),
            event_writer: Mutex::new(FlushingWriter::new(
                event_file,
                flush_interval,
                event_path,
                max_file_size,
                max_generations,
            )),
            alert_writer: Mutex::new(FlushingWriter::new(
                alert_file,
                flush_interval,
                alert_path,
                max_file_size,
                max_generations,
            )),
        })
    }

    /// イベントをファイルに追記する。
    pub fn store_event(&self, event: &SyscallEvent) -> anyhow::Result<()> {
        let line = log_formatter::format_event(event);
        let mut writer = self
            .event_writer
            .lock()
            .map_err(|e| anyhow::anyhow!("イベントログの Mutex ロック取得に失敗: {}", e))?;
        writer.write_line(&line)?;
        Ok(())
    }

    /// アラートをファイルに追記する。
    /// ファイルには ANSI カラーコードなしのプレーンテキストで書き込む。
    pub fn store_alert(&self, alert: &Alert) -> anyhow::Result<()> {
        let line = log_formatter::format_alert_plain(alert);
        let mut writer = self
            .alert_writer
            .lock()
            .map_err(|e| anyhow::anyhow!("アラートログの Mutex ロック取得に失敗: {}", e))?;
        writer.write_line(&line)?;
        Ok(())
    }

    /// バッファに残っているデータを明示的にフラッシュする。
    pub fn flush(&self) -> anyhow::Result<()> {
        let mut event_writer = self
            .event_writer
            .lock()
            .map_err(|e| anyhow::anyhow!("イベントログの Mutex ロック取得に失敗: {}", e))?;
        event_writer.flush()?;
        let mut alert_writer = self
            .alert_writer
            .lock()
            .map_err(|e| anyhow::anyhow!("アラートログの Mutex ロック取得に失敗: {}", e))?;
        alert_writer.flush()?;
        Ok(())
    }

    /// イベントログの行をストリーミングで読み込むイテレータを返す。
    /// 読み込み前にバッファをフラッシュして未書き込みデータを確実にファイルに反映する。
    pub fn read_events_iter(&self) -> anyhow::Result<LogLineIterator> {
        self.event_writer
            .lock()
            .map_err(|e| anyhow::anyhow!("イベントログの Mutex ロック取得に失敗: {}", e))?
            .flush()?;
        LogLineIterator::new(&self.event_log_path())
    }

    /// アラートログの行をストリーミングで読み込むイテレータを返す。
    /// 読み込み前にバッファをフラッシュして未書き込みデータを確実にファイルに反映する。
    pub fn read_alerts_iter(&self) -> anyhow::Result<LogLineIterator> {
        self.alert_writer
            .lock()
            .map_err(|e| anyhow::anyhow!("アラートログの Mutex ロック取得に失敗: {}", e))?
            .flush()?;
        LogLineIterator::new(&self.alert_log_path())
    }

    /// イベントログの全行を読み込む（互換性のため維持、内部はストリーミング）。
    pub fn read_events(&self) -> anyhow::Result<Vec<String>> {
        self.read_events_iter()?.collect_all()
    }

    /// アラートログの全行を読み込む（互換性のため維持、内部はストリーミング）。
    pub fn read_alerts(&self) -> anyhow::Result<Vec<String>> {
        self.read_alerts_iter()?.collect_all()
    }

    /// アラートログから指定レベル以上のアラートのみフィルタして返す。
    ///
    /// ログフォーマットは `[timestamp] LEVEL ...` なので、`]` の後の空白区切り要素でレベルを判定する。
    pub fn read_alerts_filtered(&self, min_level: AlertLevel) -> anyhow::Result<Vec<String>> {
        let level_strs: Vec<&str> = match min_level {
            AlertLevel::Info => vec!["INFO", "WARN", "CRITICAL"],
            AlertLevel::Warn => vec!["WARN", "CRITICAL"],
            AlertLevel::Critical => vec!["CRITICAL"],
        };

        let iter = self.read_alerts_iter()?;
        let mut result = Vec::new();
        for line_result in iter {
            let line = line_result?;
            // フォーマット: "[timestamp] LEVEL ..."
            // "]" の後ろを空白で分割し、最初の非空要素をレベルとして判定する
            if let Some(after_bracket) = line.split(']').nth(1)
                && let Some(level_token) = after_bracket.split_whitespace().next()
                && level_strs.contains(&level_token)
            {
                result.push(line);
            }
        }
        Ok(result)
    }

    fn event_log_path(&self) -> PathBuf {
        self.log_dir.join(EVENT_LOG_FILE)
    }

    fn alert_log_path(&self) -> PathBuf {
        self.log_dir.join(ALERT_LOG_FILE)
    }
}

/// ログファイルを BufReader でストリーミング読み込みするイテレータ。
/// ファイルが存在しない場合は空のイテレータとして振る舞う。
pub struct LogLineIterator {
    reader: Option<BufReader<File>>,
    buf: String,
}

impl LogLineIterator {
    fn new(path: &Path) -> anyhow::Result<Self> {
        match File::open(path) {
            Ok(file) => Ok(Self {
                reader: Some(BufReader::new(file)),
                buf: String::new(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // ファイルが存在しない場合は空のイテレータとして返す
                Ok(Self {
                    reader: None,
                    buf: String::new(),
                })
            }
            Err(e) => {
                Err(anyhow::Error::new(e)
                    .context(format!("ログファイルのオープンに失敗: {:?}", path)))
            }
        }
    }

    /// 全行を Vec<String> に収集する。
    fn collect_all(self) -> anyhow::Result<Vec<String>> {
        let mut lines = Vec::new();
        for line_result in self {
            lines.push(line_result?);
        }
        Ok(lines)
    }
}

impl Iterator for LogLineIterator {
    type Item = anyhow::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        loop {
            self.buf.clear();
            match reader.read_line(&mut self.buf) {
                Ok(0) => return None, // EOF
                Ok(_) => {
                    // 末尾の改行を除去
                    let line = self
                        .buf
                        .trim_end_matches('\n')
                        .trim_end_matches('\r')
                        .to_string();
                    if line.is_empty() && self.buf.trim().is_empty() {
                        // 空行はスキップして次を読む
                        continue;
                    }
                    return Some(Ok(line));
                }
                Err(e) => {
                    return Some(Err(
                        anyhow::Error::new(e).context("ログファイルの読み込みに失敗")
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Syscall, SyscallArg, SyscallResult};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_event() -> SyscallEvent {
        SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 1234,
            tgid: 0,
            process_name: "test".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![SyscallArg::Path(PathBuf::from("/etc/passwd"))],
            result: SyscallResult::Ok(0),
        }
    }

    fn make_alert(level: AlertLevel) -> Alert {
        Alert {
            level,
            event: Arc::new(make_event()),
            rule_name: "test-rule".to_string(),
            message: "test alert".to_string(),
        }
    }

    fn temp_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "izanagi_test_{}_{}_{}",
            std::process::id(),
            id,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn store_and_read_event() {
        let dir = temp_dir();
        let storage = LogStorage::new(&dir).unwrap();
        storage.store_event(&make_event()).unwrap();

        let lines = storage.read_events().unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("pid=1234"));
        assert!(lines[0].contains("/etc/passwd"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_and_read_alert() {
        let dir = temp_dir();
        let storage = LogStorage::new(&dir).unwrap();
        storage.store_alert(&make_alert(AlertLevel::Warn)).unwrap();

        let lines = storage.read_alerts().unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("WARN"));
        assert!(lines[0].contains("test alert"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_empty_returns_empty_vec() {
        let dir = temp_dir();
        let storage = LogStorage::new(&dir).unwrap();

        assert!(storage.read_events().unwrap().is_empty());
        assert!(storage.read_alerts().unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn filter_alerts_by_level() {
        let dir = temp_dir();
        let storage = LogStorage::new(&dir).unwrap();

        storage.store_alert(&make_alert(AlertLevel::Info)).unwrap();
        storage.store_alert(&make_alert(AlertLevel::Warn)).unwrap();
        storage
            .store_alert(&make_alert(AlertLevel::Critical))
            .unwrap();

        let all = storage.read_alerts_filtered(AlertLevel::Info).unwrap();
        assert_eq!(all.len(), 3);

        let warn_up = storage.read_alerts_filtered(AlertLevel::Warn).unwrap();
        assert_eq!(warn_up.len(), 2);

        let critical_only = storage.read_alerts_filtered(AlertLevel::Critical).unwrap();
        assert_eq!(critical_only.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiple_events_appended() {
        let dir = temp_dir();
        let storage = LogStorage::new(&dir).unwrap();

        storage.store_event(&make_event()).unwrap();
        storage.store_event(&make_event()).unwrap();
        storage.store_event(&make_event()).unwrap();

        let lines = storage.read_events().unwrap();
        assert_eq!(lines.len(), 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn log_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let storage = LogStorage::new(&dir).unwrap();
        storage.store_event(&make_event()).unwrap();

        // ディレクトリのパーミッションを確認
        let dir_perms = fs::metadata(&dir).unwrap().permissions();
        assert_eq!(dir_perms.mode() & 0o777, 0o700);

        // ファイルのパーミッションを確認
        let event_path = dir.join(EVENT_LOG_FILE);
        let file_perms = fs::metadata(&event_path).unwrap().permissions();
        assert_eq!(file_perms.mode() & 0o777, 0o600);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn streaming_read_events() {
        let dir = temp_dir();
        let storage = LogStorage::new(&dir).unwrap();

        storage.store_event(&make_event()).unwrap();
        storage.store_event(&make_event()).unwrap();

        let iter = storage.read_events_iter().unwrap();
        let mut count = 0;
        for line_result in iter {
            let line = line_result.unwrap();
            assert!(line.contains("pid=1234"));
            count += 1;
        }
        assert_eq!(count, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_interval_triggers_flush() {
        let dir = temp_dir();
        // flush_interval=2 で LogStorage を作成
        let storage = LogStorage::with_flush_interval(&dir, 2).unwrap();

        // 1件目: まだ flush されていない（BufWriter にバッファされている）
        storage.store_event(&make_event()).unwrap();
        let on_disk_1 = fs::read_to_string(dir.join(EVENT_LOG_FILE)).unwrap_or_default();
        // BufWriter のバッファサイズ次第だが、1件目は flush されていない可能性がある
        let lines_after_1 = on_disk_1.lines().filter(|l| !l.is_empty()).count();

        // 2件目: flush_interval=2 なので flush が走る
        storage.store_event(&make_event()).unwrap();
        let on_disk_2 = fs::read_to_string(dir.join(EVENT_LOG_FILE)).unwrap();
        let lines_after_2 = on_disk_2.lines().filter(|l| !l.is_empty()).count();

        // 2件書き込み後、ディスク上に2行あることを確認（flush 済み）
        assert_eq!(
            lines_after_2, 2,
            "flush_interval=2 で 2件書き込み後にディスクに反映されるべき"
        );
        // 1件目の時点ではまだ flush されていないか、されていてもよい（BufWriter の実装依存）
        assert!(lines_after_1 <= 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_interval_custom_value() {
        let dir = temp_dir();
        // flush_interval=3 でテスト
        let storage = LogStorage::with_flush_interval(&dir, 3).unwrap();

        for _ in 0..3 {
            storage.store_event(&make_event()).unwrap();
        }

        // 3件書き込み後、ディスクに全て反映されているはず
        let on_disk = fs::read_to_string(dir.join(EVENT_LOG_FILE)).unwrap();
        let line_count = on_disk.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(
            line_count, 3,
            "flush_interval=3 で 3件書き込み後にディスクに反映されるべき"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // --- ログローテーションテスト (#169) ---

    #[test]
    fn rotation_triggers_on_size_exceeded() {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("izanagi_test_rotation_{}", id));
        let _ = fs::remove_dir_all(&dir);

        // max_file_size=100 で 2行目書き込み時にローテーション発生
        let storage = LogStorage::with_options(&dir, 1, 100, 3).unwrap();
        storage.store_event(&make_event()).unwrap();
        storage.store_event(&make_event()).unwrap();
        storage.store_event(&make_event()).unwrap();

        // ローテーションが発生し .1 ファイルが存在する
        let rotated = dir.join("events.log.1");
        assert!(
            rotated.exists(),
            "ローテーション済みファイル .1 が存在すべき"
        );

        // 現在のファイルにも書き込みが継続されている
        let current = fs::read_to_string(dir.join(EVENT_LOG_FILE)).unwrap();
        assert!(
            !current.is_empty(),
            "ローテーション後も現在ファイルに書き込みが継続されるべき"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_respects_max_generations() {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("izanagi_test_rotation_gen_{}", id));
        let _ = fs::remove_dir_all(&dir);

        // max_generations=2, max_file_size=50 で多数書き込み → 世代数を超えない
        let storage = LogStorage::with_options(&dir, 1, 50, 2).unwrap();
        for _ in 0..20 {
            storage.store_event(&make_event()).unwrap();
        }

        // .1 と .2 は存在しうるが .3 は存在しない
        let gen3 = dir.join("events.log.3");
        assert!(!gen3.exists(), "max_generations=2 では .3 は存在しないべき");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_preserves_content_in_rotated_file() {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("izanagi_test_rotation_content_{}", id));
        let _ = fs::remove_dir_all(&dir);

        // 1行だけ書いてサイズを超過させ、2行目でローテーション発生
        let storage = LogStorage::with_options(&dir, 1, 80, 3).unwrap();
        storage.store_event(&make_event()).unwrap();
        // この時点のファイル内容を保存
        let first_line = fs::read_to_string(dir.join(EVENT_LOG_FILE)).unwrap();

        storage.store_event(&make_event()).unwrap();

        // .1 にはローテーション前の内容が入っている
        let rotated_content = fs::read_to_string(dir.join("events.log.1")).unwrap();
        assert_eq!(
            first_line.trim(),
            rotated_content.trim(),
            "ローテーション済みファイルにはローテーション前の内容が保持されるべき"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_continues_writing_after_rotate() {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("izanagi_test_rotation_continue_{}", id));
        let _ = fs::remove_dir_all(&dir);

        let storage = LogStorage::with_options(&dir, 1, 80, 3).unwrap();

        // ローテーションを複数回発生させる
        for _ in 0..10 {
            storage.store_event(&make_event()).unwrap();
        }

        // 現在のファイルが読める
        let events = storage.read_events().unwrap();
        assert!(!events.is_empty(), "ローテーション後もイベントが読めるべき");

        let _ = fs::remove_dir_all(&dir);
    }
}
