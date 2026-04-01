use crate::detector::{AlertLevel, Rule, RuleMatch};
use crate::event::{Syscall, SyscallArg, SyscallEvent};

use super::normalize_path;

/// /proc/self/environ への readlink / open を検知する。
pub struct EnvAccessRule;

impl EnvAccessRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnvAccessRule {
    fn default() -> Self {
        Self::new()
    }
}

/// /proc/self/environ および /proc/<pid>/environ にマッチする判定。
fn is_env_access_path(path_str: &str) -> bool {
    // /proc/self/environ, /proc/self/env
    if path_str == "/proc/self/environ" || path_str == "/proc/self/env" {
        return true;
    }
    // /proc/<pid>/environ — pid は数字のみ
    if let Some(rest) = path_str.strip_prefix("/proc/")
        && let Some(after_pid) = rest.find('/')
    {
        let pid_part = &rest[..after_pid];
        let tail = &rest[after_pid..];
        if pid_part.chars().all(|c| c.is_ascii_digit()) && (tail == "/environ" || tail == "/env") {
            return true;
        }
    }
    false
}

impl Rule for EnvAccessRule {
    fn name(&self) -> &str {
        "env-access"
    }

    fn check(&self, event: &SyscallEvent) -> Option<RuleMatch> {
        match event.syscall {
            Syscall::Open | Syscall::OpenAt | Syscall::ReadLink => {}
            _ => return None,
        }

        for arg in &event.args {
            if let SyscallArg::Path(path) = arg {
                let normalized = normalize_path(path);
                let path_str = normalized.to_string_lossy();
                if is_env_access_path(&path_str) {
                    return Some(RuleMatch {
                        level: AlertLevel::Critical,
                        message: format!("Environment variable access detected: {}", path_str),
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::detector::{AlertLevel, Rule};
    use crate::event::{Syscall, SyscallArg, SyscallEvent, SyscallResult};

    use super::*;

    fn make_event(syscall: Syscall, args: Vec<SyscallArg>) -> Arc<SyscallEvent> {
        Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 1234,
            tgid: 0,
            process_name: "test".into(),
            syscall,
            args: args.into(),
            result: SyscallResult::Ok(0),
        })
    }

    #[test]
    fn detects_proc_environ() {
        let rule = EnvAccessRule::new();
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/proc/self/environ"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some());
        assert_eq!(m.unwrap().level, AlertLevel::Critical);
    }

    #[test]
    fn detects_readlink() {
        let rule = EnvAccessRule::new();
        let event = make_event(
            Syscall::ReadLink,
            vec![SyscallArg::Path(PathBuf::from("/proc/self/environ"))],
        );
        assert!(rule.check(&event).is_some());
    }

    #[test]
    fn ignores_safe_path() {
        let rule = EnvAccessRule::new();
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/proc/self/status"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn ignores_non_matching_syscall() {
        let rule = EnvAccessRule::new();
        let event = make_event(
            Syscall::Connect,
            vec![SyscallArg::Path(PathBuf::from("/proc/self/environ"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn detects_pid_environ() {
        let rule = EnvAccessRule::new();
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/proc/1234/environ"))],
        );
        assert!(
            rule.check(&event).is_some(),
            "/proc/<pid>/environ を検知すべき"
        );
    }

    #[test]
    fn detects_traversal() {
        let rule = EnvAccessRule::new();
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from(
                "/proc/../proc/self/environ",
            ))],
        );
        assert!(
            rule.check(&event).is_some(),
            "パストラバーサルによる環境変数アクセスを検知すべき"
        );
    }
}
