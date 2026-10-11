use std::path::{Component, Path, PathBuf};

use crate::detector::{AlertLevel, Rule, RuleMatch};
use crate::event::{Syscall, SyscallArg, SyscallEvent};

use super::normalize_path;

/// Warn about observed write intent to files host tools may later execute.
/// This is an audit rule, not the enforcement boundary. Paths are normalized
/// lexically; symlink targets, fd-only writes and unobserved syscalls are unknown.
pub struct WorkspaceWriteRule {
    roots: Vec<PathBuf>,
}

impl WorkspaceWriteRule {
    pub fn new(host_paths: &[String], mount_point: &str) -> Self {
        let mut roots = vec![normalize_path(Path::new(mount_point))];
        for host in host_paths {
            let Ok(expanded) = crate::util::expand_tilde(host) else {
                continue;
            };
            let path = PathBuf::from(expanded);
            let absolute = if path.is_absolute() {
                path
            } else if let Ok(current) = std::env::current_dir() {
                current.join(path)
            } else {
                continue;
            };
            roots.push(normalize_path(&absolute));
            if let Ok(resolved) = absolute.canonicalize() {
                roots.push(resolved);
            }
        }
        Self { roots }
    }

    fn protected(&self, path: &Path) -> bool {
        let normalized = normalize_path(path);
        if !normalized.is_absolute() {
            return host_execution_path(&normalized);
        }
        self.roots
            .iter()
            .any(|root| normalized.strip_prefix(root).is_ok_and(host_execution_path))
    }
}

fn host_execution_path(path: &Path) -> bool {
    let components: Vec<_> = path.components().collect();
    if components.iter().any(|component| {
        matches!(component, Component::Normal(name) if *name == ".git" || *name == ".vscode" || *name == ".idea")
    }) {
        return true;
    }
    path.starts_with(".github/workflows")
        || matches!(
            path.file_name().and_then(|s| s.to_str()),
            Some(
                "build.rs"
                    | "Makefile"
                    | "GNUmakefile"
                    | "Cargo.toml"
                    | "package.json"
                    | "pyproject.toml"
                    | "setup.py"
                    | "tox.ini"
                    | ".npmrc"
                    | ".yarnrc.yml"
            )
        )
}

/// Open schemas place flags immediately after the pathname (also after dirfd
/// in DTrace openat). Linux and Darwin share access bits; their create/truncate
/// masks differ, so the union conservatively includes possible write intent.
fn write_intent(event: &SyscallEvent, path_index: usize) -> Option<&'static str> {
    match event.syscall {
        Syscall::Write => Some("write"),
        Syscall::Open | Syscall::OpenAt => match event.args.get(path_index + 1) {
            Some(SyscallArg::Int(flags)) if flags & (3 | 0x40 | 0x200 | 0x400) != 0 => {
                Some("write/create/truncate open attempt")
            }
            Some(SyscallArg::Int(_)) => None,
            _ => Some("access with unknown write intent"),
        },
        _ => None,
    }
}

impl Rule for WorkspaceWriteRule {
    fn name(&self) -> &str {
        "workspace-write"
    }

    fn check(&self, event: &SyscallEvent) -> Option<RuleMatch> {
        event.args.iter().enumerate().find_map(|(index, arg)| {
            let SyscallArg::Path(path) = arg else {
                return None;
            };
            let intent = write_intent(event, index)?;
            self.protected(path).then(|| RuleMatch {
                level: AlertLevel::Warn,
                message: format!(
                    "Host execution path: {} ({intent}, outcome={:?}); review before running host tools",
                    path.display(), event.result
                ),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SyscallResult;

    fn event(path: &str, flags: Option<i64>, result: SyscallResult) -> SyscallEvent {
        let mut args = smallvec::smallvec![SyscallArg::Path(path.into())];
        if let Some(flags) = flags {
            args.push(SyscallArg::Int(flags));
        }
        SyscallEvent {
            timestamp: std::time::UNIX_EPOCH,
            pid: 1,
            tgid: 1,
            process_name: "fixture".into(),
            syscall: Syscall::OpenAt,
            args,
            result,
        }
    }

    #[test]
    fn writable_git_editor_and_build_paths_warn_in_shared_roots() {
        let rule = WorkspaceWriteRule::new(&["/host/project".into()], "/workspace");
        for path in [
            "/workspace/.git/config",
            "/host/project/.git/hooks/pre-commit",
            ".git",
            ".git/hooks/post-checkout",
            "/workspace/.vscode/tasks.json",
            "/workspace/build.rs",
            "/workspace/sub/../.git/config",
            "/workspace/sub/package.json",
        ] {
            assert!(
                rule.check(&event(path, Some(1), SyscallResult::Unknown))
                    .is_some(),
                "{path}"
            );
        }
        for path in [
            "/other/.git/config",
            "/workspace-other/.git/config",
            "/workspace/.git-backup/config",
            "/workspace/src/main.rs",
        ] {
            assert!(
                rule.check(&event(path, Some(1), SyscallResult::Unknown))
                    .is_none(),
                "{path}"
            );
        }
    }

    #[test]
    fn read_only_open_is_quiet_and_denied_or_unknown_write_intent_is_labelled() {
        let rule = WorkspaceWriteRule::new(&[], "/workspace");
        assert!(
            rule.check(&event(
                "/workspace/.git/config",
                Some(0),
                SyscallResult::Ok(4)
            ))
            .is_none()
        );
        for flags in [1, 2, 0x40, 0x200, 0x400] {
            let denied = rule
                .check(&event(
                    "/workspace/.git/config",
                    Some(flags),
                    SyscallResult::Err(13),
                ))
                .unwrap();
            assert!(denied.message.contains("attempt"));
            assert!(denied.message.contains("Err(13)"));
        }
        let unknown = rule
            .check(&event(".git/config", None, SyscallResult::Unknown))
            .unwrap();
        assert!(unknown.message.contains("unknown write intent"));
    }

    #[test]
    fn dtrace_dirfd_does_not_replace_open_flags_and_reads_are_quiet() {
        let rule = WorkspaceWriteRule::new(&[], "/workspace");
        let mut observed = event("/workspace/.git/config", Some(0), SyscallResult::Unknown);
        observed.args.insert(0, SyscallArg::Int(1));
        assert!(rule.check(&observed).is_none());
        observed.args[2] = SyscallArg::Int(2);
        assert!(rule.check(&observed).is_some());
        observed.syscall = Syscall::Read;
        assert!(rule.check(&observed).is_none());
        observed.syscall = Syscall::Write;
        assert!(rule.check(&observed).is_some());
    }
}
