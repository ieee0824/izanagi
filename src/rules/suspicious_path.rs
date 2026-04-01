use crate::detector::{AlertLevel, Rule, RuleMatch};
use crate::event::{Syscall, SyscallArg, SyscallEvent};

use super::normalize_path;

/// ~/.ssh/*, ~/.aws/*, ~/.gnupg/*, ~/.config/gh/*, /etc/passwd, /etc/shadow
/// などの機密パスへのアクセスを検知する。
pub struct SuspiciousPathRule {
    patterns: Vec<glob::Pattern>,
    raw_patterns: Vec<String>,
}

impl SuspiciousPathRule {
    /// `suspicious_paths` は glob パターンのリスト。
    /// チルダ (`~`) はこのコンストラクタ内部で展開する。
    /// HOME 環境変数が未設定の場合、チルダ付きパターンはスキップされる。
    ///
    /// 警告が不要な場合はこちらを使用する。警告を取得したい場合は
    /// `new_with_warnings` を使用すること。
    pub fn new(suspicious_paths: &[String]) -> Self {
        let (rule, _warnings) = Self::new_with_warnings(suspicious_paths);
        rule
    }

    /// `new` と同じだが、構築時の警告メッセージも返す。
    ///
    /// 警告には以下が含まれる:
    /// - glob パターンの構文エラー
    /// - HOME 未設定によるチルダ展開失敗
    pub fn new_with_warnings(suspicious_paths: &[String]) -> (Self, Vec<String>) {
        let mut patterns = Vec::new();
        let mut raw_patterns = Vec::new();
        let mut warnings = Vec::new();
        for p in suspicious_paths {
            match crate::util::expand_tilde(p).ok() {
                Some(expanded) => match glob::Pattern::new(&expanded) {
                    Ok(pat) => {
                        patterns.push(pat);
                        raw_patterns.push(expanded);
                    }
                    Err(e) => {
                        warnings.push(format!(
                            "警告: 不正な glob パターン \"{}\": {}",
                            expanded, e
                        ));
                    }
                },
                None => {
                    warnings.push(format!(
                        "警告: HOME 未設定のためチルダ展開できないパターンをスキップ: \"{}\"",
                        p
                    ));
                }
            }
        }
        (
            Self {
                patterns,
                raw_patterns,
            },
            warnings,
        )
    }
}

impl Rule for SuspiciousPathRule {
    fn name(&self) -> &str {
        "suspicious-path"
    }

    fn check(&self, event: &SyscallEvent) -> Option<RuleMatch> {
        // ファイル系 syscall のみ対象
        match event.syscall {
            Syscall::Open
            | Syscall::OpenAt
            | Syscall::Read
            | Syscall::Write
            | Syscall::Stat
            | Syscall::Access => {}
            _ => return None,
        }

        for arg in &event.args {
            if let SyscallArg::Path(path) = arg {
                let normalized = normalize_path(path);
                let path_str = normalized.to_string_lossy();
                for (i, pattern) in self.patterns.iter().enumerate() {
                    if pattern.matches(&path_str) {
                        return Some(RuleMatch {
                            level: AlertLevel::Critical,
                            message: format!(
                                "Suspicious file access: {} (matched pattern: {})",
                                path_str, self.raw_patterns[i]
                            ),
                        });
                    }
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

    use serial_test::serial;

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
    fn matches_exact() {
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/etc/passwd"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some());
        assert_eq!(m.unwrap().level, AlertLevel::Critical);
    }

    #[test]
    #[serial(env)]
    fn matches_glob() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let rule = SuspiciousPathRule::new(&["~/.ssh/*".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from(format!(
                "{}/.ssh/id_rsa",
                home
            )))],
        );
        let m = rule.check(&event);
        assert!(m.is_some());
    }

    #[test]
    fn no_match() {
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/tmp/safe_file"))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn detects_traversal() {
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/etc/../etc/passwd"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some(), "パストラバーサルを検知すべき");
    }

    #[test]
    fn detects_dot_traversal() {
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/tmp/../etc/passwd"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some(), "../によるパストラバーサルを検知すべき");
    }

    #[test]
    fn detects_traversal_beyond_root() {
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/../etc/passwd"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some(), "ルートより上への/../はルートに留まるべき");
    }

    #[test]
    fn detects_multi_level_traversal_beyond_root() {
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from(
                "/../../../../../../etc/passwd",
            ))],
        );
        let m = rule.check(&event);
        assert!(m.is_some(), "複数段の/../でもルートに留まるべき");
    }

    #[test]
    fn normalizes_mid_path_traversal() {
        // /etc/foo/../passwd → /etc/passwd（中間ディレクトリの .. が正しく解決される）
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Path(PathBuf::from("/etc/foo/../passwd"))],
        );
        let m = rule.check(&event);
        assert!(m.is_some(), "中間ディレクトリでの..も正規化されるべき");
    }

    #[test]
    fn ignores_non_file_syscall() {
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let event = make_event(
            Syscall::Connect,
            vec![SyscallArg::Path(PathBuf::from("/etc/passwd"))],
        );
        assert!(rule.check(&event).is_none());
    }
}
