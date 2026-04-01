use std::collections::HashSet;

use crate::detector::{AlertLevel, Rule, RuleMatch};
use crate::event::{Syscall, SyscallArg, SyscallEvent};

/// 実行パスが不審なディレクトリにあるかを判定する。
/// symlink やリネームによるバイパスが疑われる場所。
///
/// # 設計上の制限
/// check() メソッドは同期かつパフォーマンスクリティカルなため、実際のシンボリックリンク解決
/// (std::fs::canonicalize 等) は行わない。代わりに、不審なディレクトリからの実行を
/// ヒューリスティックに検出し、アラートレベルを Critical に引き上げることで
/// symlink/リネームバイパスのリスクを軽減する。
fn is_suspicious_exec_directory(path: &str) -> bool {
    let suspicious_prefixes = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"];
    suspicious_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// プロファイル別の追加ベースラインプロセス。
fn profile_baseline(profile: &str) -> &'static [&'static str] {
    match profile {
        "node" | "nodejs" => &[
            "node", "npm", "npx", "yarn", "pnpm", "tsc", "esbuild", "vite", "webpack",
        ],
        "python" => &["python", "python3", "pip", "pip3", "poetry", "pipenv", "uv"],
        "go" | "golang" => &["go", "gopls", "dlv"],
        "rust" => &["cargo", "rustc", "rustup", "clippy-driver"],
        "ruby" => &["ruby", "gem", "bundle", "bundler", "rake"],
        _ => &[],
    }
}

/// デフォルトのベースラインプロセス。フルパスとファイル名の両方でマッチする。
/// ssh/scp は UnexpectedExecRule で不審コマンドとして検知するためベースラインには含めない。
const DEFAULT_BASELINE_PROCESSES: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/env",
    "sh",
    "bash",
    "env",
    "node",
    "npm",
    "npx",
    "python",
    "python3",
    "pip",
    "cargo",
    "rustc",
    "gcc",
    "g++",
    "make",
    "cmake",
    "git",
    "ls",
    "cat",
    "echo",
    "mkdir",
    "rm",
    "cp",
    "mv",
];

/// execve syscall で起動されたプロセスがベースライン（既知プロセス名リスト）に
/// 含まれない場合に検知する。
pub struct ProcessBaselineRule {
    pub(crate) known_processes: HashSet<String>,
}

impl ProcessBaselineRule {
    /// 既知プロセス名でルールを初期化する。
    pub fn new(known: &[String]) -> Self {
        Self {
            known_processes: known.iter().cloned().collect(),
        }
    }

    /// デフォルトベースラインでルールを初期化する。
    pub fn with_defaults() -> Self {
        Self {
            known_processes: DEFAULT_BASELINE_PROCESSES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// デフォルトベースライン + 指定プロファイルでルールを初期化する。
    pub fn with_profile(profiles: &[String]) -> Self {
        let mut known: HashSet<String> = DEFAULT_BASELINE_PROCESSES
            .iter()
            .map(|s| s.to_string())
            .collect();
        for profile in profiles {
            for proc_name in profile_baseline(&profile.to_lowercase()) {
                known.insert(proc_name.to_string());
            }
        }
        Self {
            known_processes: known,
        }
    }
}

impl Rule for ProcessBaselineRule {
    fn name(&self) -> &str {
        "process-baseline"
    }

    fn check(&self, event: &SyscallEvent) -> Option<RuleMatch> {
        if event.syscall != Syscall::Execve {
            return None;
        }

        for arg in &event.args {
            let (full_path, file_name) = match arg {
                SyscallArg::Path(p) => {
                    let full = p.to_string_lossy().to_string();
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    (full, name)
                }
                SyscallArg::Str(s) => {
                    let p = std::path::Path::new(s);
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| s.clone());
                    (s.clone(), name)
                }
                _ => continue,
            };

            // フルパスまたはファイル名でベースラインと照合
            if !self.known_processes.contains(&full_path)
                && !self.known_processes.contains(&file_name)
            {
                // 不審なディレクトリからの実行は Critical に引き上げる。
                // symlink やリネームによるバイパス対策として、/tmp, /var/tmp, /dev/shm
                // などユーザ書き込み可能なディレクトリからの未知プロセス実行を重視する。
                // AlertLevel::High は存在しないため Critical を使用する。
                let (level, suffix) = if is_suspicious_exec_directory(&full_path) {
                    (AlertLevel::Critical, " (suspicious directory)")
                } else {
                    (AlertLevel::Warn, "")
                };
                return Some(RuleMatch {
                    level,
                    message: format!("Unknown process not in baseline: {}{}", full_path, suffix),
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
    fn suspicious_directory_detection() {
        assert!(is_suspicious_exec_directory("/tmp/evil"));
        assert!(is_suspicious_exec_directory("/var/tmp/backdoor"));
        assert!(is_suspicious_exec_directory("/dev/shm/miner"));
        assert!(is_suspicious_exec_directory("/run/user/1000/malware"));
        assert!(!is_suspicious_exec_directory("/usr/bin/ls"));
        assert!(!is_suspicious_exec_directory("/usr/local/bin/node"));
    }

    #[test]
    fn detects_unknown_process() {
        let rule = ProcessBaselineRule::new(&["ls".to_string(), "cat".to_string()]);
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/malware"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some());
        let m = m.unwrap();
        assert_eq!(m.level, AlertLevel::Warn);
        assert!(m.message.contains("Unknown process not in baseline"));
        assert!(m.message.contains("/usr/bin/malware"));
    }

    #[test]
    fn allows_known_by_name() {
        let rule = ProcessBaselineRule::new(&["ls".to_string()]);
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/ls"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn allows_known_by_full_path() {
        let rule = ProcessBaselineRule::new(&["/bin/sh".to_string()]);
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/bin/sh"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn ignores_non_execve() {
        let rule = ProcessBaselineRule::new(&["ls".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/malware"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn with_defaults_allows_common() {
        let rule = ProcessBaselineRule::with_defaults();
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/git"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn with_defaults_detects_unknown() {
        let rule = ProcessBaselineRule::with_defaults();
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/tmp/suspicious_binary"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some());
        let m = m.unwrap();
        assert_eq!(m.level, AlertLevel::Critical);
        assert!(m.message.contains("suspicious directory"));
    }

    #[test]
    fn suspicious_directory_escalates() {
        let rule = ProcessBaselineRule::with_defaults();
        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/tmp/evil"))],
        );
        let m = rule.check(&event).unwrap();
        assert_eq!(m.level, AlertLevel::Critical);
        assert!(m.message.contains("suspicious directory"));

        let event = make_event(
            Syscall::Execve,
            vec![SyscallArg::Path(PathBuf::from("/usr/bin/unknown_tool"))],
        );
        let m = rule.check(&event).unwrap();
        assert_eq!(m.level, AlertLevel::Warn);
        assert!(!m.message.contains("suspicious directory"));
    }

    #[test]
    fn with_profile_includes_node_processes() {
        let rule = ProcessBaselineRule::with_profile(&["node".to_string()]);
        assert!(rule.known_processes.contains("node"));
        assert!(rule.known_processes.contains("npm"));
        assert!(rule.known_processes.contains("ls"));
    }

    #[test]
    fn with_profile_unknown_profile_uses_defaults_only() {
        let rule = ProcessBaselineRule::with_profile(&["unknown_profile".to_string()]);
        assert!(rule.known_processes.contains("ls"));
        assert!(!rule.known_processes.contains("yarn"));
    }
}
