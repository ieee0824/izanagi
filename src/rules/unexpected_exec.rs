use std::path::PathBuf;

use crate::detector::{AlertLevel, Rule, RuleMatch};
use crate::event::{Syscall, SyscallArg, SyscallEvent};

/// execve で起動される不審なコマンド（curl, wget, nc 等）を検知する。
pub struct UnexpectedExecRule {
    suspicious_commands: Vec<String>,
}

/// デフォルトの不審コマンドリスト。
const DEFAULT_SUSPICIOUS_COMMANDS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "nmap", "ssh", "scp", "sftp",
    "base64", "xxd",
];

impl UnexpectedExecRule {
    pub fn new() -> Self {
        Self {
            suspicious_commands: DEFAULT_SUSPICIOUS_COMMANDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    pub fn with_commands(commands: Vec<String>) -> Self {
        Self {
            suspicious_commands: commands,
        }
    }
}

impl Default for UnexpectedExecRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnexpectedExecRule {
    fn name(&self) -> &str {
        "unexpected-exec"
    }

    fn check(&self, event: &SyscallEvent) -> Option<RuleMatch> {
        if event.syscall != Syscall::Execve {
            return None;
        }

        for arg in &event.args {
            let cmd_name = match arg {
                SyscallArg::Path(p) => p.file_name().map(|n| n.to_string_lossy().to_string()),
                SyscallArg::Str(s) => PathBuf::from(s)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string()),
                _ => None,
            };

            if let Some(name) = cmd_name
                && self.suspicious_commands.iter().any(|c| c == &name)
            {
                return Some(RuleMatch {
                    level: AlertLevel::Warn,
                    message: format!("Unexpected command execution: {}", name),
                });
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
    fn detects_curl() {
        let rule = UnexpectedExecRule::new();
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/curl"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some());
        assert_eq!(m.unwrap().level, AlertLevel::Warn);
    }

    #[test]
    fn detects_nc() {
        let rule = UnexpectedExecRule::new();
        let event = make_event(Syscall::Execve, vec![SyscallArg::Str("nc".to_string())]);
        assert!(rule.check(&event).is_some());
    }

    #[test]
    fn allows_safe_command() {
        let rule = UnexpectedExecRule::new();
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/ls"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn ignores_non_execve() {
        let rule = UnexpectedExecRule::new();
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/curl"))],
        );
        assert!(rule.check(&event).is_none());
    }
}
