mod env_access;
mod network_allowlist;
mod process_baseline;
mod suspicious_path;
mod unexpected_exec;

pub use env_access::EnvAccessRule;
pub use network_allowlist::NetworkAllowlistRule;
pub use process_baseline::ProcessBaselineRule;
pub use suspicious_path::SuspiciousPathRule;
pub use unexpected_exec::UnexpectedExecRule;

use std::path::{Component, PathBuf};

/// パスを正規化する。`..` や `.` を論理的に解決し、パストラバーサルによるバイパスを防止する。
/// シンボリックリンクの解決は行わない（ファイルシステムアクセスを避けるため）。
fn normalize_path(path: &std::path::Path) -> PathBuf {
    let is_absolute = path.has_root();
    let mut normalized = PathBuf::new();
    // depth: ルートより下のコンポーネント数を追跡（絶対パスでのルート超え防止用）
    let mut depth: usize = 0;
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if is_absolute && depth == 0 {
                    // 絶対パスの場合、ルートより上には遡らない（パストラバーサル防止）
                } else if depth > 0 {
                    normalized.pop();
                    depth -= 1;
                } else {
                    // 相対パスで depth == 0: .. を保持してパターンマッチ側で検知可能にする
                    normalized.push("..");
                }
            }
            Component::CurDir => {}
            _ => {
                normalized.push(component);
                // RootDir はルート自体なのでカウントしない
                if !matches!(component, Component::RootDir) {
                    depth += 1;
                }
            }
        }
    }
    normalized
}
