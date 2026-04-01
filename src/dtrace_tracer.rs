//! DTrace ベースの Tracer 実装。
//!
//! macOS 上で `dtrace` コマンドをサブプロセスとして起動し、
//! stdout 出力をパースして `SyscallEvent` に変換する。
//!
//! Linux など非 macOS 環境では stub 実装となり、`start()` はエラーを返す。

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::event::SyscallEvent;
#[cfg(target_os = "macos")]
use crate::event::{Syscall, SyscallCategory};
#[cfg(target_os = "macos")]
use crate::tracer::EVENT_CHANNEL_CAPACITY;
use crate::tracer::{TraceFilter, Tracer};

/// DTrace の出力行プレフィックス。パーサーはこのプレフィックスで始まる行のみ処理する。
#[cfg(target_os = "macos")]
const OUTPUT_PREFIX: &str = "IZANAGI";

/// stderr ログの最大行数。これを超えたらサマリのみ出力する。
#[cfg(target_os = "macos")]
const STDERR_LOG_LIMIT: usize = 100;

/// DTrace ベースの Tracer。
///
/// macOS 上でのみ動作する。`dtrace` コマンドをサブプロセスとして起動し、
/// stdout からイベントを読み取って `SyscallEvent` に変換する。
pub struct DTraceTracer {
    #[cfg(target_os = "macos")]
    inner: std::sync::Mutex<DTraceTracerInner>,
    _private: (),
}

#[cfg(target_os = "macos")]
struct DTraceTracerInner {
    child: Option<tokio::process::Child>,
    stdout_handle: Option<tokio::task::JoinHandle<()>>,
    stderr_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Default for DTraceTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl DTraceTracer {
    /// 新しい `DTraceTracer` を作成する。
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            inner: std::sync::Mutex::new(DTraceTracerInner {
                child: None,
                stdout_handle: None,
                stderr_handle: None,
            }),
            _private: (),
        }
    }
}

// ---------------------------------------------------------------------------
// D スクリプト生成 (#27)
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
/// TraceFilter のカテゴリに基づいて DTrace 用 D スクリプトを生成する。
///
/// 出力フォーマット: `IZANAGI|<timestamp_ns>|<pid>|<execname>|<syscall>|<arg0>|<arg1>|...`
fn generate_dscript(filter: &TraceFilter) -> String {
    let probes = probes_for_categories(&filter.categories);
    if probes.is_empty() {
        // カテゴリが空の場合でもコンパイルは通るが何も出力しない
        return "BEGIN { exit(0); }".to_string();
    }

    let mut script = String::new();

    // 各 probe ごとにアクション節を生成
    for probe in &probes {
        let predicate = build_predicate(filter);
        let action = build_action(probe.syscall_name, probe.arg_kinds);

        script.push_str(&format!(
            "syscall::{}:entry\n{}\n{{\n{}\n}}\n\n",
            probe.dtrace_name, predicate, action,
        ));
    }

    script
}

#[cfg(target_os = "macos")]
/// DTrace 引数の型。D スクリプト生成とパーサーの両方で参照する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgKind {
    /// 整数引数 (`(long long)argN`)
    Int,
    /// 文字列引数 (`copyinstr(argN)`) — パーサーでは `SyscallArg::Path` に変換
    Path,
}

#[cfg(target_os = "macos")]
/// DTrace プローブ情報。
struct ProbeInfo {
    /// DTrace の syscall プローブ名 (e.g., "open", "connect")
    dtrace_name: &'static str,
    /// 出力する syscall 名 (SyscallEvent との対応)
    syscall_name: &'static str,
    /// arg0, arg1 の型情報
    arg_kinds: &'static [ArgKind],
}

#[cfg(target_os = "macos")]
/// カテゴリと DTrace プローブの対応テーブル。
/// (カテゴリ, DTrace プローブ名, 出力 syscall 名, 引数型) のタプル。
const PROBE_TABLE: &[(SyscallCategory, &str, &str, &[ArgKind])] = &[
    // File — macOS では open syscall は廃止済み。open_nocancel と openat のみ使用。
    (
        SyscallCategory::File,
        "open_nocancel",
        "open",
        &[ArgKind::Path, ArgKind::Int],
    ),
    (
        SyscallCategory::File,
        "openat",
        "openat",
        &[ArgKind::Int, ArgKind::Path],
    ),
    (
        SyscallCategory::File,
        "openat_nocancel",
        "openat",
        &[ArgKind::Int, ArgKind::Path],
    ),
    (
        SyscallCategory::File,
        "read",
        "read",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::File,
        "read_nocancel",
        "read",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::File,
        "write",
        "write",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::File,
        "write_nocancel",
        "write",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::File,
        "stat64",
        "stat",
        &[ArgKind::Path, ArgKind::Int],
    ),
    (
        SyscallCategory::File,
        "access",
        "access",
        &[ArgKind::Path, ArgKind::Int],
    ),
    // Network
    (
        SyscallCategory::Network,
        "connect",
        "connect",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Network,
        "connect_nocancel",
        "connect",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Network,
        "sendto",
        "sendto",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Network,
        "sendto_nocancel",
        "sendto",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Network,
        "recvfrom",
        "recvfrom",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Network,
        "recvfrom_nocancel",
        "recvfrom",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Network,
        "socket",
        "socket",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Network,
        "bind",
        "bind",
        &[ArgKind::Int, ArgKind::Int],
    ),
    // Process — execve は arg0 がパス
    (
        SyscallCategory::Process,
        "execve",
        "execve",
        &[ArgKind::Path, ArgKind::Int],
    ),
    (
        SyscallCategory::Process,
        "posix_spawn",
        "clone",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Process,
        "fork",
        "fork",
        &[ArgKind::Int, ArgKind::Int],
    ),
    (
        SyscallCategory::Process,
        "vfork",
        "fork",
        &[ArgKind::Int, ArgKind::Int],
    ),
    // Env — readlink は arg0 がパス
    (
        SyscallCategory::Env,
        "readlink",
        "readlink",
        &[ArgKind::Path, ArgKind::Int],
    ),
];

#[cfg(target_os = "macos")]
/// カテゴリ群に対応する DTrace プローブ一覧を返す。
fn probes_for_categories(categories: &[SyscallCategory]) -> Vec<ProbeInfo> {
    PROBE_TABLE
        .iter()
        .filter(|(cat, _, _, _)| categories.contains(cat))
        .map(|(_, dtrace_name, syscall_name, arg_kinds)| ProbeInfo {
            dtrace_name,
            syscall_name,
            arg_kinds,
        })
        .collect()
}

#[cfg(target_os = "macos")]
/// PID フィルタ用の predicate を構築する。
fn build_predicate(filter: &TraceFilter) -> String {
    match &filter.pids {
        Some(pids) if !pids.is_empty() => {
            let conditions: Vec<String> = pids.iter().map(|p| format!("pid == {}", p)).collect();
            format!("/ {} /", conditions.join(" || "))
        }
        _ => String::new(),
    }
}

#[cfg(target_os = "macos")]
/// DTrace printf のヘッダー部分のフォーマット指定子。
/// 出力: `IZANAGI|<walltimestamp>|<pid>|<execname>|<syscall>`
const DTRACE_HEADER_FMT: &str = "IZANAGI|%lld|%d|%s";

#[cfg(target_os = "macos")]
/// DTrace printf のヘッダー部分の値式。
const DTRACE_HEADER_VALS: &str = "(long long)walltimestamp, pid, execname";

#[cfg(target_os = "macos")]
/// 各 probe のアクション (printf 文) を `arg_kinds` に基づいて構築する。
///
/// `ArgKind::Path` の引数は `copyinstr()` で文字列として取得する（NULL ガード付き）。
/// `ArgKind::Int` の引数は整数として出力する。
///
/// 生成される DTrace コード例:
/// ```d
/// printf("IZANAGI|%lld|%d|%s|execve|%s|%lld\n",
///        (long long)walltimestamp, pid, execname,
///        arg0 != 0 ? copyinstr(arg0) : "<null>", (long long)arg1);
/// ```
fn build_action(syscall_name: &str, arg_kinds: &[ArgKind]) -> String {
    // arg_kinds からフォーマット指定子と値式を生成
    let mut fmt_specs = Vec::new();
    let mut value_exprs = Vec::new();
    for (i, kind) in arg_kinds.iter().enumerate() {
        match kind {
            ArgKind::Path => {
                fmt_specs.push("%s".to_string());
                value_exprs.push(format!("arg{i} != 0 ? copyinstr(arg{i}) : \"<null>\""));
            }
            ArgKind::Int => {
                fmt_specs.push("%lld".to_string());
                value_exprs.push(format!("(long long)arg{i}"));
            }
        }
    }

    let arg_fmt = fmt_specs.join("|");
    let arg_vals = value_exprs.join(", ");

    // DTrace printf: ヘッダー (固定) + syscall 名 + 引数 (スキーマ駆動)
    format!(
        "    printf(\"{header}|{syscall}|{arg_fmt}\\n\", {header_vals}, {arg_vals});",
        header = DTRACE_HEADER_FMT,
        header_vals = DTRACE_HEADER_VALS,
        syscall = syscall_name,
        arg_fmt = arg_fmt,
        arg_vals = arg_vals,
    )
}

#[cfg(target_os = "macos")]
/// syscall 名から引数型スキーマを取得する。
/// PROBE_TABLE を正とする一元管理。
fn arg_kinds_for_syscall(syscall_name: &str) -> &'static [ArgKind] {
    PROBE_TABLE
        .iter()
        .find(|(_, _, name, _)| *name == syscall_name)
        .map(|(_, _, _, kinds)| *kinds)
        .unwrap_or(&[ArgKind::Int, ArgKind::Int])
}

// ---------------------------------------------------------------------------
// DTrace 出力パーサー (#29)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
/// DTrace の 1 行出力を `SyscallEvent` にパースする。
///
/// フォーマット: `IZANAGI|<timestamp_ns>|<pid>|<execname>|<syscall>|<arg0>|<arg1>|...`
fn parse_dtrace_line(line: &str) -> Option<SyscallEvent> {
    let line = line.trim();
    if !line.starts_with(OUTPUT_PREFIX) {
        return None;
    }

    // ヘッダー 5 フィールドを splitn で分離し、Vec アロケーションを回避 (#94)
    // splitn(6) で最大 6 分割: [IZANAGI, ts, pid, execname, syscall, 残り引数]
    let mut header_iter = line.splitn(6, '|');
    let _prefix = header_iter.next()?; // "IZANAGI"
    let timestamp_ns: u64 = header_iter.next()?.trim().parse().ok()?;
    let pid: u32 = header_iter.next()?.trim().parse().ok()?;
    let process_name: Arc<str> = header_iter.next()?.trim().into();
    let syscall_str = header_iter.next()?.trim();
    // 残りの引数部分 (存在しない場合もある)
    let args_remainder = header_iter.next();

    let syscall = match syscall_str {
        "open" => Syscall::Open,
        "openat" => Syscall::OpenAt,
        "read" => Syscall::Read,
        "write" => Syscall::Write,
        "stat" => Syscall::Stat,
        "access" => Syscall::Access,
        "connect" => Syscall::Connect,
        "sendto" => Syscall::SendTo,
        "recvfrom" => Syscall::RecvFrom,
        "socket" => Syscall::Socket,
        "bind" => Syscall::Bind,
        "execve" => Syscall::Execve,
        "clone" => Syscall::Clone,
        "fork" => Syscall::Fork,
        "readlink" => Syscall::ReadLink,
        _ => return None,
    };

    // 追加引数をパース (スキーマ駆動)
    //
    // PROBE_TABLE の arg_kinds を参照し、各引数の型に応じてパースする。
    // ArgKind::Path の引数は copyinstr() 由来の文字列で、パス内に `|` を含む場合
    // フィールドが分割される。スキーマの先頭 Int を消費し、Path 部分は末尾の
    // trailing Int を差し引いた中間フィールドを結合して復元する。
    let arg_kinds = arg_kinds_for_syscall(syscall_str);
    let mut args = smallvec::smallvec![];
    let has_path_arg = arg_kinds.iter().any(|k| *k == ArgKind::Path);

    if let Some(remainder) = args_remainder {
        if has_path_arg {
            // Path 引数がある場合: | で split して collect が必要（パス内 | の復元）
            let extra: Vec<&str> = remainder.split('|').collect();
            if extra.len() >= 2 {
                let leading_int_count =
                    arg_kinds.iter().take_while(|k| **k == ArgKind::Int).count();
                let trailing_int_count = arg_kinds
                    .iter()
                    .rev()
                    .take_while(|k| **k == ArgKind::Int)
                    .count();

                // 先頭の Int 引数を消費
                for part in &extra[..leading_int_count.min(extra.len())] {
                    let trimmed = part.trim();
                    if let Ok(val) = trimmed.parse::<i64>() {
                        args.push(crate::event::SyscallArg::Int(val));
                    }
                }

                // 中間フィールドを Path として結合
                let path_start = leading_int_count.min(extra.len());
                let path_end = extra.len().saturating_sub(trailing_int_count);
                if path_start < path_end {
                    let path_str = extra[path_start..path_end]
                        .iter()
                        .map(|s| s.trim())
                        .collect::<Vec<_>>()
                        .join("|");
                    if !path_str.is_empty() && path_str != "<null>" {
                        args.push(crate::event::SyscallArg::Path(std::path::PathBuf::from(
                            &path_str,
                        )));
                    }
                }

                // 末尾の Int 引数を消費
                for part in &extra[path_end..] {
                    let trimmed = part.trim();
                    if let Ok(val) = trimmed.parse::<i64>() {
                        args.push(crate::event::SyscallArg::Int(val));
                    }
                }
            } else {
                // フィールド 1 個のみ — スキーマの先頭 ArgKind で型を決定
                let trimmed = remainder.trim();
                if !trimmed.is_empty() && trimmed != "<null>" {
                    match arg_kinds.first() {
                        Some(ArgKind::Path) => {
                            args.push(crate::event::SyscallArg::Path(std::path::PathBuf::from(
                                trimmed,
                            )));
                        }
                        _ => {
                            if let Ok(val) = trimmed.parse::<i64>() {
                                args.push(crate::event::SyscallArg::Int(val));
                            } else {
                                args.push(crate::event::SyscallArg::Str(trimmed.to_string()));
                            }
                        }
                    }
                }
            }
        } else {
            // Path 引数なし: | で split するだけで Vec 不要（イテレータで処理）
            for part in remainder.split('|') {
                let trimmed = part.trim();
                if let Ok(val) = trimmed.parse::<i64>() {
                    args.push(crate::event::SyscallArg::Int(val));
                } else if !trimmed.is_empty() {
                    args.push(crate::event::SyscallArg::Str(trimmed.to_string()));
                }
            }
        }
    }

    // walltimestamp はナノ秒単位の UNIX epoch
    let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(timestamp_ns);

    Some(SyscallEvent {
        timestamp,
        pid,
        tgid: 0, // DTrace は tgid を提供しない
        process_name,
        syscall,
        args,
        result: crate::event::SyscallResult::Ok(0), // entry probe では戻り値未取得
    })
}

// ---------------------------------------------------------------------------
// macOS 実装 (#28)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[async_trait::async_trait]
impl Tracer for DTraceTracer {
    async fn start(
        &self,
        filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        let script = generate_dscript(filter);

        // dtrace コマンドの存在確認
        let dtrace_path = "/usr/sbin/dtrace";
        if !std::path::Path::new(dtrace_path).exists() {
            anyhow::bail!(
                "dtrace command not found at {}. DTrace is only available on macOS.",
                dtrace_path
            );
        }

        // dtrace サブプロセスを起動
        // euid == 0 (root) なら sudo 不要。それ以外は sudo -n (非対話モード) を使用。
        let is_root = unsafe { libc::geteuid() } == 0;
        let mut cmd = if is_root {
            Command::new(dtrace_path)
        } else {
            let mut c = Command::new("sudo");
            c.arg("-n");
            c.arg(dtrace_path);
            c
        };
        let mut child = cmd
            .arg("-qn")
            .arg(&script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    anyhow::anyhow!(
                        "DTrace requires root privileges. Run with sudo or grant appropriate permissions.\n\
                         Original error: {}", e
                    )
                } else {
                    anyhow::anyhow!("Failed to start dtrace process: {}", e)
                }
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to capture dtrace stdout"))?;

        // stderr を非同期で読み取り、バッファ詰まりによるハングを防止する (#102)
        // レートリミット: STDERR_LOG_LIMIT 行を超えたら抑制し、終了時にサマリを出力
        let mut stderr_handle = if let Some(stderr) = child.stderr.take() {
            Some(tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                let mut count: usize = 0;
                let mut suppressed: usize = 0;
                while let Ok(Some(line)) = lines.next_line().await {
                    count += 1;
                    if count <= STDERR_LOG_LIMIT {
                        eprintln!("[dtrace stderr] {}", line);
                    } else {
                        suppressed += 1;
                    }
                }
                if suppressed > 0 {
                    eprintln!(
                        "[dtrace stderr] ... {} additional lines suppressed (total: {})",
                        suppressed, count
                    );
                }
            }))
        } else {
            None
        };

        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        // stdout を非同期に読み取り、パースしてチャネルに送信
        // try_send でバックプレッシャー時にイベントを drop し、stdout 読み取りが
        // 詰まって dtrace プロセスがハングするのを防止する
        let stdout_handle = tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(event) = parse_dtrace_line(&line) {
                    match tx.try_send(Arc::new(event)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // チャネル満杯 → イベントを drop して読み取りを継続
                        }
                    }
                }
            }
        });

        // チェックと設定を同一ロック内で行い TOCTOU を防止。
        // 二重起動時は新しく生成したリソースをクリーンアップしてからエラーを返す。
        let mut stdout_handle = Some(stdout_handle);
        let mut child = Some(child);
        let already_running = {
            let mut inner = self.inner.lock().expect("DTraceTracerInner lock poisoned");
            if inner.child.is_some() {
                true
            } else {
                inner.stdout_handle = stdout_handle.take();
                inner.stderr_handle = stderr_handle.take();
                inner.child = child.take();
                false
            }
        };
        if already_running {
            if let Some(h) = stdout_handle {
                h.abort();
            }
            if let Some(h) = stderr_handle {
                h.abort();
            }
            if let Some(mut c) = child {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            anyhow::bail!("DTraceTracer is already running");
        }
        Ok(rx)
    }

    async fn stop(&self) -> anyhow::Result<()> {
        let (child, stdout_handle, stderr_handle) = {
            let mut inner = self.inner.lock().expect("DTraceTracerInner lock poisoned");
            (
                inner.child.take(),
                inner.stdout_handle.take(),
                inner.stderr_handle.take(),
            )
        };
        if let Some(mut child) = child {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        if let Some(handle) = stdout_handle {
            handle.abort();
        }
        if let Some(handle) = stderr_handle {
            handle.abort();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Linux / その他 OS のスタブ実装
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
#[async_trait::async_trait]
impl Tracer for DTraceTracer {
    async fn start(
        &self,
        _filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>> {
        anyhow::bail!("DTrace is only supported on macOS")
    }

    async fn stop(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use crate::event::SyscallCategory;

    // -- DTrace スクリプト生成テスト (#27) --

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_empty_categories() {
        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("exit(0)"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_file_category() {
        let filter = TraceFilter {
            categories: vec![SyscallCategory::File],
            pids: None,
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("syscall::open_nocancel:entry"));
        assert!(script.contains("syscall::openat:entry"));
        assert!(script.contains("syscall::read:entry"));
        assert!(script.contains("syscall::write:entry"));
        assert!(script.contains("syscall::stat64:entry"));
        assert!(script.contains("syscall::access:entry"));
        assert!(script.contains("IZANAGI"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_network_category() {
        let filter = TraceFilter {
            categories: vec![SyscallCategory::Network],
            pids: None,
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("syscall::connect:entry"));
        assert!(script.contains("syscall::sendto:entry"));
        assert!(script.contains("syscall::recvfrom:entry"));
        assert!(script.contains("syscall::socket:entry"));
        assert!(script.contains("syscall::bind:entry"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_process_category() {
        let filter = TraceFilter {
            categories: vec![SyscallCategory::Process],
            pids: None,
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("syscall::execve:entry"));
        assert!(script.contains("syscall::fork:entry"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_env_category() {
        let filter = TraceFilter {
            categories: vec![SyscallCategory::Env],
            pids: None,
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("syscall::readlink:entry"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_multiple_categories() {
        let filter = TraceFilter {
            categories: vec![SyscallCategory::File, SyscallCategory::Network],
            pids: None,
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("syscall::open_nocancel:entry"));
        assert!(script.contains("syscall::connect:entry"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_with_pid_filter() {
        let filter = TraceFilter {
            categories: vec![SyscallCategory::File],
            pids: Some(vec![1234, 5678]),
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("pid == 1234"));
        assert!(script.contains("pid == 5678"));
        assert!(script.contains("||"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_dscript_with_single_pid() {
        let filter = TraceFilter {
            categories: vec![SyscallCategory::File],
            pids: Some(vec![42]),
        };
        let script = generate_dscript(&filter);
        assert!(script.contains("pid == 42"));
        assert!(!script.contains("||"));
    }

    // -- DTrace 出力パーサーテスト (#29) --

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_valid_open_event() {
        let line = "IZANAGI|1700000000000000000|1234|bash|open|/tmp/file|0";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.pid, 1234);
        assert_eq!(event.tgid, 0, "DTrace does not provide tgid");
        assert_eq!(&*event.process_name, "bash");
        assert_eq!(event.syscall, Syscall::Open);
        assert_eq!(event.args.len(), 2);
        assert_eq!(
            event.args[0],
            crate::event::SyscallArg::Path(std::path::PathBuf::from("/tmp/file"))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_valid_connect_event() {
        let line = "IZANAGI|1700000000000000000|5678|curl|connect|4|0";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.pid, 5678);
        assert_eq!(&*event.process_name, "curl");
        assert_eq!(event.syscall, Syscall::Connect);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_valid_execve_event() {
        let line = "IZANAGI|1700000000000000000|100|sh|execve|/usr/bin/curl|0";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.syscall, Syscall::Execve);
        assert_eq!(event.args.len(), 2);
        // execve の arg0 は Path としてパースされる
        assert_eq!(
            event.args[0],
            crate::event::SyscallArg::Path(std::path::PathBuf::from("/usr/bin/curl"))
        );
        // arg1 は整数
        assert_eq!(event.args[1], crate::event::SyscallArg::Int(0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_valid_readlink_event() {
        let line = "IZANAGI|1700000000000000000|200|ls|readlink|0|0";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.syscall, Syscall::ReadLink);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_all_syscall_types() {
        // Path 引数を持つ syscall はパスっぽい値、それ以外は整数を使う
        let syscalls = [
            ("open", Syscall::Open, "/tmp/f|0"),     // arg0=Path
            ("openat", Syscall::OpenAt, "3|/tmp/f"), // arg0=Int, arg1=Path
            ("read", Syscall::Read, "0|0"),
            ("write", Syscall::Write, "0|0"),
            ("stat", Syscall::Stat, "/tmp/f|0"),     // arg0=Path
            ("access", Syscall::Access, "/tmp/f|0"), // arg0=Path
            ("connect", Syscall::Connect, "0|0"),
            ("sendto", Syscall::SendTo, "0|0"),
            ("recvfrom", Syscall::RecvFrom, "0|0"),
            ("socket", Syscall::Socket, "0|0"),
            ("bind", Syscall::Bind, "0|0"),
            ("execve", Syscall::Execve, "/usr/bin/test|0"), // arg0=Path
            ("clone", Syscall::Clone, "0|0"),
            ("fork", Syscall::Fork, "0|0"),
            ("readlink", Syscall::ReadLink, "/tmp/link|0"), // arg0=Path
        ];

        for (name, expected, args) in &syscalls {
            let line = format!("IZANAGI|1000000000|1|test|{}|{}", name, args);
            let event = parse_dtrace_line(&line)
                .unwrap_or_else(|| panic!("should parse syscall: {}", name));
            assert_eq!(event.syscall, *expected, "mismatch for {}", name);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_ignores_non_izanagi_lines() {
        assert!(
            parse_dtrace_line("dtrace: description 'syscall:::entry' matched 42 probes").is_none()
        );
        assert!(parse_dtrace_line("").is_none());
        assert!(parse_dtrace_line("CPU     ID                    FUNCTION:NAME").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_ignores_malformed_lines() {
        // フィールド不足
        assert!(parse_dtrace_line("IZANAGI|1000|1234").is_none());
        // PID が数値でない
        assert!(parse_dtrace_line("IZANAGI|1000|abc|bash|open|0|0").is_none());
        // timestamp が数値でない
        assert!(parse_dtrace_line("IZANAGI|notanumber|1234|bash|open|0|0").is_none());
        // 未知の syscall
        assert!(parse_dtrace_line("IZANAGI|1000|1234|bash|unknown_syscall|0|0").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_handles_whitespace() {
        // read は [Int, Int] なので whitespace テストに適切
        let line = "  IZANAGI|1000000000|1234|bash|read|3|0  ";
        let event = parse_dtrace_line(line).expect("should parse with whitespace");
        assert_eq!(event.pid, 1234);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_timestamp_is_correct() {
        let ts_ns: u64 = 1_700_000_000_000_000_000;
        let line = format!("IZANAGI|{}|1|test|open|0|0", ts_ns);
        let event = parse_dtrace_line(&line).expect("should parse");
        let expected = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ts_ns);
        assert_eq!(event.timestamp, expected);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_no_extra_args() {
        let line = "IZANAGI|1000000000|1|test|open";
        let event = parse_dtrace_line(line).expect("should parse without extra args");
        assert!(event.args.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_action_execve_uses_copyinstr() {
        let action = build_action("execve", &[ArgKind::Path, ArgKind::Int]);
        assert!(
            action.contains("copyinstr(arg0)"),
            "execve should use copyinstr for arg0"
        );
        assert!(
            action.contains("arg0 != 0"),
            "execve should have NULL guard"
        );
        assert!(
            !action.contains("(long long)arg0"),
            "execve should not cast arg0 to long long"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_action_all_int_uses_integer() {
        let action = build_action("read", &[ArgKind::Int, ArgKind::Int]);
        assert!(
            action.contains("(long long)arg0"),
            "all-Int should cast arg0 to long long"
        );
        assert!(
            !action.contains("copyinstr"),
            "all-Int should not use copyinstr"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_action_open_uses_copyinstr_for_arg0() {
        let action = build_action("open", &[ArgKind::Path, ArgKind::Int]);
        assert!(
            action.contains("copyinstr(arg0)"),
            "open should use copyinstr for arg0"
        );
        assert!(
            action.contains("(long long)arg1"),
            "open should cast arg1 to long long"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_action_openat_uses_copyinstr_for_arg1() {
        let action = build_action("openat", &[ArgKind::Int, ArgKind::Path]);
        assert!(
            action.contains("(long long)arg0"),
            "openat should cast arg0 (dirfd) to long long"
        );
        assert!(
            action.contains("copyinstr(arg1)"),
            "openat should use copyinstr for arg1"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_execve_with_pipe_in_path() {
        // パス内の | がフィールド分割を壊さないことを確認
        let line = "IZANAGI|1700000000000000000|100|sh|execve|/tmp/evil|file|0";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.syscall, Syscall::Execve);
        // パス部分は結合されて /tmp/evil|file になる
        assert_eq!(
            event.args[0],
            crate::event::SyscallArg::Path(std::path::PathBuf::from("/tmp/evil|file"))
        );
        assert_eq!(event.args[1], crate::event::SyscallArg::Int(0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_execve_null_arg0() {
        // copyinstr が NULL を返した場合 (<null>) は Path を生成しない
        let line = "IZANAGI|1700000000000000000|100|sh|execve|<null>|0";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.syscall, Syscall::Execve);
        // <null> は Path として生成されない
        assert_eq!(event.args.len(), 1);
        assert_eq!(event.args[0], crate::event::SyscallArg::Int(0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn arg_kinds_for_syscall_returns_correct_schema() {
        // execve: arg0=Path, arg1=Int
        assert_eq!(
            arg_kinds_for_syscall("execve"),
            &[ArgKind::Path, ArgKind::Int]
        );
        // open: arg0=Path, arg1=Int (flags)
        assert_eq!(
            arg_kinds_for_syscall("open"),
            &[ArgKind::Path, ArgKind::Int]
        );
        // openat: arg0=Int (dirfd), arg1=Path
        assert_eq!(
            arg_kinds_for_syscall("openat"),
            &[ArgKind::Int, ArgKind::Path]
        );
        // stat: arg0=Path, arg1=Int
        assert_eq!(
            arg_kinds_for_syscall("stat"),
            &[ArgKind::Path, ArgKind::Int]
        );
        // access: arg0=Path, arg1=Int (mode)
        assert_eq!(
            arg_kinds_for_syscall("access"),
            &[ArgKind::Path, ArgKind::Int]
        );
        // readlink: arg0=Path, arg1=Int
        assert_eq!(
            arg_kinds_for_syscall("readlink"),
            &[ArgKind::Path, ArgKind::Int]
        );
        // read/write: arg0=Int (fd), arg1=Int
        assert_eq!(arg_kinds_for_syscall("read"), &[ArgKind::Int, ArgKind::Int]);
        assert_eq!(
            arg_kinds_for_syscall("write"),
            &[ArgKind::Int, ArgKind::Int]
        );
        // 未知の syscall はデフォルトで Int, Int
        assert_eq!(
            arg_kinds_for_syscall("unknown"),
            &[ArgKind::Int, ArgKind::Int]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_open_returns_path() {
        // open(path, flags) — arg0 はファイルパス
        let line = "IZANAGI|1700000000000000000|1234|bash|open|/etc/passwd|0";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.syscall, Syscall::Open);
        assert_eq!(
            event.args[0],
            crate::event::SyscallArg::Path(std::path::PathBuf::from("/etc/passwd"))
        );
        assert_eq!(event.args[1], crate::event::SyscallArg::Int(0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_openat_returns_dirfd_and_path() {
        // openat(dirfd, path, flags) — arg0=Int(dirfd), arg1=Path
        let line = "IZANAGI|1700000000000000000|1234|bash|openat|3|/etc/passwd";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.syscall, Syscall::OpenAt);
        assert_eq!(event.args[0], crate::event::SyscallArg::Int(3));
        assert_eq!(
            event.args[1],
            crate::event::SyscallArg::Path(std::path::PathBuf::from("/etc/passwd"))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_openat_with_pipe_in_path() {
        // openat でパス内に | が含まれるケース
        let line = "IZANAGI|1700000000000000000|1234|bash|openat|3|/tmp/a|b";
        let event = parse_dtrace_line(line).expect("should parse");
        assert_eq!(event.syscall, Syscall::OpenAt);
        assert_eq!(event.args[0], crate::event::SyscallArg::Int(3));
        assert_eq!(
            event.args[1],
            crate::event::SyscallArg::Path(std::path::PathBuf::from("/tmp/a|b"))
        );
    }

    // -- DTraceTracer 構造テスト --

    #[test]
    fn dtrace_tracer_can_be_constructed() {
        let _tracer = DTraceTracer::new();
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn dtrace_tracer_start_fails_on_non_macos() {
        let mut tracer = DTraceTracer::new();
        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };
        let result = tracer.start(&filter).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only supported on macOS")
        );
    }
}
