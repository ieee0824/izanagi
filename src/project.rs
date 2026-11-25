//! プロジェクトディレクトリの解決。
//!
//! 設定 (`~/.izanagi/settings/<hash>/`) とインスタンスの状態
//! (`~/.izanagi/instances/<hash>/`) は、プロジェクトディレクトリのハッシュで分ける。
//! サブディレクトリや MCP クライアントの起動ディレクトリからでも同じプロジェクトを
//! 指せるよう、次の順で解決する。
//!
//! 1. 明示指定 (`--project-dir` / `IZANAGI_PROJECT_DIR`)
//! 2. cwd から祖先へ遡り、設定ファイルが存在する最も近いディレクトリ
//! 3. cwd

use std::path::{Path, PathBuf};

use anyhow::Context;

/// プロジェクトディレクトリを明示する環境変数。
pub const PROJECT_DIR_ENV: &str = "IZANAGI_PROJECT_DIR";

/// 正規化したディレクトリのパスから、設定とインスタンスの分離に使うハッシュを返す。
pub fn path_hash(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(dir.as_os_str().as_encoded_bytes()))
}

/// 明示指定されたプロジェクトディレクトリを正規化する。
pub fn canonical_project_dir(path: &Path) -> anyhow::Result<PathBuf> {
    let canonical = path.canonicalize().with_context(|| {
        format!(
            "プロジェクトディレクトリを解決できません: {}",
            path.display()
        )
    })?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "プロジェクトディレクトリがディレクトリではありません: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

/// プロジェクトディレクトリを解決する。
///
/// - `explicit`: 明示指定。指定されていれば、祖先の探索をしない
/// - `cwd`: カレントディレクトリ
/// - `home`: ホームディレクトリ。cwd がその配下なら、ホームとその祖先は探索しない
/// - `has_settings`: ディレクトリに設定ファイルがあるか
pub fn resolve_project_dir(
    explicit: Option<&Path>,
    cwd: &Path,
    home: Option<&Path>,
    has_settings: impl Fn(&Path) -> bool,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return canonical_project_dir(path);
    }
    let cwd = cwd
        .canonicalize()
        .with_context(|| format!("カレントディレクトリを解決できません: {}", cwd.display()))?;
    Ok(find_configured_ancestor(&cwd, home, has_settings).unwrap_or(cwd))
}

/// cwd から祖先へ遡り、設定ファイルがある最も近いディレクトリを返す。
pub fn find_configured_ancestor(
    cwd: &Path,
    home: Option<&Path>,
    has_settings: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let home = home.map(|home| home.canonicalize().unwrap_or_else(|_| home.to_path_buf()));
    let stop_at = home.as_deref().filter(|home| cwd.starts_with(home));
    for dir in cwd.ancestors() {
        if stop_at == Some(dir) {
            return None;
        }
        if has_settings(dir) {
            return Some(dir.to_path_buf());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn project_tree() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap().join("home");
        let nested = home.join("work/app/src/module");
        std::fs::create_dir_all(&nested).unwrap();
        (temp, home, nested)
    }

    fn configured(dirs: &[&Path]) -> impl Fn(&Path) -> bool {
        let set: HashSet<PathBuf> = dirs.iter().map(|dir| dir.to_path_buf()).collect();
        move |dir| set.contains(dir)
    }

    #[test]
    fn subdirectory_resolves_to_nearest_configured_ancestor() {
        let (_temp, home, nested) = project_tree();
        let app = home.join("work/app");
        let resolved =
            resolve_project_dir(None, &nested, Some(&home), configured(&[&app])).unwrap();
        assert_eq!(resolved, app);
    }

    #[test]
    fn nested_projects_prefer_the_closest_configuration() {
        let (_temp, home, nested) = project_tree();
        let app = home.join("work/app");
        let src = app.join("src");
        let resolved =
            resolve_project_dir(None, &nested, Some(&home), configured(&[&app, &src])).unwrap();
        assert_eq!(resolved, src);
    }

    #[test]
    fn search_stops_before_home_directory() {
        let (_temp, home, nested) = project_tree();
        let resolved =
            resolve_project_dir(None, &nested, Some(&home), configured(&[&home])).unwrap();
        assert_eq!(resolved, nested);
    }

    #[test]
    fn search_continues_to_root_outside_home() {
        let (_temp, home, nested) = project_tree();
        let other_home = home.join("work/app/src/module/elsewhere");
        let app = home.join("work/app");
        let resolved =
            resolve_project_dir(None, &nested, Some(&other_home), configured(&[&app])).unwrap();
        assert_eq!(resolved, app);
    }

    #[test]
    fn unconfigured_directory_falls_back_to_cwd() {
        let (_temp, home, nested) = project_tree();
        let resolved = resolve_project_dir(None, &nested, Some(&home), configured(&[])).unwrap();
        assert_eq!(resolved, nested);
    }

    #[test]
    fn explicit_directory_wins_over_ancestor_search() {
        let (_temp, home, nested) = project_tree();
        let app = home.join("work/app");
        let explicit = home.join("work");
        let resolved =
            resolve_project_dir(Some(&explicit), &nested, Some(&home), configured(&[&app]))
                .unwrap();
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn explicit_directory_must_exist_and_be_a_directory() {
        let (_temp, home, nested) = project_tree();
        let missing = home.join("missing");
        assert!(resolve_project_dir(Some(&missing), &nested, None, configured(&[])).is_err());
        let file = home.join("file");
        std::fs::write(&file, "").unwrap();
        assert!(resolve_project_dir(Some(&file), &nested, None, configured(&[])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cwd_resolves_to_the_real_project() {
        let (_temp, home, nested) = project_tree();
        let app = home.join("work/app");
        let link = home.join("link");
        std::os::unix::fs::symlink(&nested, &link).unwrap();
        let resolved = resolve_project_dir(None, &link, Some(&home), configured(&[&app])).unwrap();
        assert_eq!(resolved, app);
    }

    #[test]
    fn missing_cwd_is_an_error_not_a_panic() {
        let (_temp, home, _nested) = project_tree();
        let gone = home.join("gone");
        assert!(resolve_project_dir(None, &gone, Some(&home), configured(&[])).is_err());
    }

    #[test]
    fn path_hash_matches_previous_instance_hash() {
        use sha2::{Digest, Sha256};
        let dir = Path::new("/Users/example/project");
        let previous = hex::encode(Sha256::digest(dir.as_os_str().as_encoded_bytes()));
        assert_eq!(path_hash(dir), previous);
    }
}
