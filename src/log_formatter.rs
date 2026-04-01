use std::time::SystemTime;

use chrono::{DateTime, Local};
use colored::Colorize;

use crate::detector::{Alert, AlertLevel};
use crate::event::{SyscallArg, SyscallEvent, SyscallResult};

/// Alert をログ行にフォーマットする。
///
/// フォーマット: `[timestamp] LEVEL pid=PID process: syscall(args) → result`
/// AlertLevel に応じて色分けする。
pub fn format_alert(alert: &Alert) -> String {
    let event = &alert.event;
    let timestamp = format_timestamp(event.timestamp);
    let level_str = format_level(alert.level);
    let args_str = format_args(&event.args);
    let result_str = format_result(event.result);
    let syscall_name = format!("{:?}", event.syscall).to_lowercase();

    format!(
        "[{}] {} pid={} {}: {}({}) → {} | {}",
        timestamp,
        level_str,
        event.pid,
        sanitize(&event.process_name),
        syscall_name,
        args_str,
        result_str,
        sanitize(&alert.message),
    )
}

/// SyscallEvent をログ行にフォーマットする（アラートなし、イベントのみ）。
pub fn format_event(event: &SyscallEvent) -> String {
    let timestamp = format_timestamp(event.timestamp);
    let args_str = format_args(&event.args);
    let result_str = format_result(event.result);
    let syscall_name = format!("{:?}", event.syscall).to_lowercase();

    format!(
        "[{}] INFO pid={} {}: {}({}) → {}",
        timestamp,
        event.pid,
        sanitize(&event.process_name),
        syscall_name,
        args_str,
        result_str,
    )
}

/// AlertLevel に応じた色付きレベル文字列を返す。
fn format_level(level: AlertLevel) -> String {
    match level {
        AlertLevel::Info => "INFO".normal().to_string(),
        AlertLevel::Warn => "WARN".yellow().to_string(),
        AlertLevel::Critical => "CRITICAL".red().bold().to_string(),
    }
}

/// Alert をログ行にフォーマットする（色なし版）。
///
/// ファイル保存用。ANSI カラーコードを含まないプレーンテキストを返す。
pub fn format_alert_plain(alert: &Alert) -> String {
    let event = &alert.event;
    let timestamp = format_timestamp(event.timestamp);
    let level_str = format_level_plain(alert.level);
    let args_str = format_args(&event.args);
    let result_str = format_result(event.result);
    let syscall_name = format!("{:?}", event.syscall).to_lowercase();

    format!(
        "[{}] {} pid={} {}: {}({}) → {} | {}",
        timestamp,
        level_str,
        event.pid,
        sanitize(&event.process_name),
        syscall_name,
        args_str,
        result_str,
        sanitize(&alert.message),
    )
}

/// AlertLevel に応じたレベル文字列を返す（色なし）。
pub fn format_level_plain(level: AlertLevel) -> &'static str {
    match level {
        AlertLevel::Info => "INFO",
        AlertLevel::Warn => "WARN",
        AlertLevel::Critical => "CRITICAL",
    }
}

fn format_timestamp(ts: SystemTime) -> String {
    let datetime: DateTime<Local> = ts.into();
    datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// 制御文字（改行、タブ、ANSI エスケープシーケンス等）をエスケープする。
/// ログインジェクション防止のため、ログに書き込む文字列に適用する。
///
/// 共通ロジックは `crate::sanitize::escape_control_chars` に統合。
fn sanitize(s: &str) -> String {
    crate::sanitize::escape_control_chars(s)
}

fn format_args(args: &[SyscallArg]) -> String {
    args.iter()
        .map(|arg| {
            let display = arg.redacted_display();
            match arg {
                SyscallArg::Path(_) | SyscallArg::Str(_) => {
                    format!("\"{}\"", sanitize(&display))
                }
                _ => sanitize(&display),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_result(result: SyscallResult) -> String {
    match result {
        SyscallResult::Ok(v) => v.to_string(),
        SyscallResult::Err(e) => format!("err={}", e),
    }
}

/// --suspicious フィルタ: Warn 以上のアラートのみ通す。
pub fn is_suspicious(alert: &Alert) -> bool {
    alert.level >= AlertLevel::Warn
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::AlertLevel;
    use crate::event::{Syscall, SyscallArg, SyscallResult};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_alert(level: AlertLevel, syscall: Syscall, args: Vec<SyscallArg>) -> Alert {
        Alert {
            level,
            event: Arc::new(SyscallEvent {
                timestamp: SystemTime::UNIX_EPOCH,
                pid: 42,
                tgid: 0,
                process_name: "npm".into(),
                syscall,
                args: args.into(),
                result: SyscallResult::Ok(0),
            }),
            rule_name: "test-rule".to_string(),
            message: "test message".to_string(),
        }
    }

    #[test]
    fn format_alert_contains_required_parts() {
        let alert = make_alert(
            AlertLevel::Warn,
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/etc/passwd"))],
        );
        let output = format_alert(&alert);
        assert!(output.contains("pid=42"));
        assert!(output.contains("npm"));
        assert!(output.contains("open"));
        assert!(output.contains("/etc/passwd"));
        assert!(output.contains("test message"));
    }

    #[test]
    fn format_event_contains_required_parts() {
        let event = SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 100,
            tgid: 0,
            process_name: "node".into(),
            syscall: Syscall::Connect,
            args: smallvec::smallvec![SyscallArg::Addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                53,
            ))],
            result: SyscallResult::Err(111),
        };
        let output = format_event(&event);
        assert!(output.contains("pid=100"));
        assert!(output.contains("node"));
        assert!(output.contains("connect"));
        assert!(output.contains("8.8.8.8:53"));
        assert!(output.contains("err=111"));
    }

    #[test]
    fn format_level_plain_values() {
        assert_eq!(format_level_plain(AlertLevel::Info), "INFO");
        assert_eq!(format_level_plain(AlertLevel::Warn), "WARN");
        assert_eq!(format_level_plain(AlertLevel::Critical), "CRITICAL");
    }

    #[test]
    fn format_args_redacts_sensitive_str() {
        let alert = make_alert(
            AlertLevel::Warn,
            Syscall::Execve,
            vec![SyscallArg::Str("DB_PASSWORD=secret123".to_string())],
        );
        let output = format_alert(&alert);
        assert!(
            output.contains("[REDACTED]"),
            "sensitive value should be redacted"
        );
        assert!(
            !output.contains("secret123"),
            "raw sensitive value should not appear"
        );
        assert!(
            output.contains("DB_PASSWORD"),
            "key name should still be visible"
        );
    }

    #[test]
    fn format_args_does_not_redact_normal_str() {
        let alert = make_alert(
            AlertLevel::Info,
            Syscall::Execve,
            vec![SyscallArg::Str("HOME=/home/user".to_string())],
        );
        let output = format_alert(&alert);
        assert!(
            output.contains("HOME=/home/user"),
            "non-sensitive value should not be redacted"
        );
    }

    #[test]
    fn is_suspicious_filters_correctly() {
        let info_alert = make_alert(AlertLevel::Info, Syscall::Open, vec![]);
        let warn_alert = make_alert(AlertLevel::Warn, Syscall::Open, vec![]);
        let critical_alert = make_alert(AlertLevel::Critical, Syscall::Open, vec![]);

        assert!(!is_suspicious(&info_alert));
        assert!(is_suspicious(&warn_alert));
        assert!(is_suspicious(&critical_alert));
    }
}
