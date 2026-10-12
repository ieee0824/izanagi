//! Share validation rejects broad and aliased credential exposure before sandbox startup.
use izanagi::config::Config;
use std::path::{Path, PathBuf};

fn validate(path: &Path, read_only: bool) -> anyhow::Result<Vec<String>> {
    let mut config = Config::default();
    config.share.paths = vec![path.to_str().unwrap().to_owned()];
    config.share.read_only = read_only;
    config.validate()
}

fn host_home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("test requires a configured host home"))
}

#[test]
fn home_and_its_aliases_are_rejected_in_both_share_modes() {
    let directory = tempfile::tempdir().unwrap();
    let home_path = host_home();
    let resolved_home = home_path.canonicalize().unwrap();
    let alias = directory.path().join("home-alias");
    std::os::unix::fs::symlink(&home_path, &alias).unwrap();
    for read_only in [true, false] {
        for path in [
            Path::new("~"),
            home_path.as_path(),
            resolved_home.as_path(),
            alias.as_path(),
            Path::new("~/."),
        ] {
            assert!(
                validate(path, read_only).is_err(),
                "accepted {}",
                path.display()
            );
        }
        for ancestor in home_path.ancestors() {
            assert!(
                validate(ancestor, read_only).is_err(),
                "accepted ancestor {}",
                ancestor.display()
            );
        }
    }
}

#[test]
fn sensitive_ancestors_descendants_and_missing_alias_children_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let alias = directory.path().join("home-alias");
    std::os::unix::fs::symlink(host_home(), &alias).unwrap();
    for relative in [
        ".ssh",
        ".ssh/izanagi69-missing-key",
        ".aws/credentials",
        ".gnupg",
        ".config",
        ".config/gh",
        ".config/gh/izanagi69-missing-child",
    ] {
        for read_only in [true, false] {
            assert!(validate(&host_home().join(relative), read_only).is_err());
            assert!(validate(&alias.join(relative), read_only).is_err());
        }
    }
}

#[test]
fn component_prefix_siblings_and_project_children_remain_allowed() {
    let home_path = host_home();
    for relative in [
        ".ssh-backup-izanagi69",
        ".aws-other-izanagi69",
        ".gnupg-other-izanagi69",
        ".config/gh-other-izanagi69",
        "izanagi69-project",
    ] {
        for read_only in [true, false] {
            assert!(
                validate(&home_path.join(relative), read_only).is_ok(),
                "rejected sibling {relative}"
            );
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    assert!(validate(&project, true).is_ok());
}

const SYSTEM_BOUNDARIES: &[&str] = &[
    "/",
    "/etc",
    "/var",
    "/home",
    "/root",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/sys",
    "/proc",
    "/dev",
    "/boot",
    "/opt",
    "/Users",
    "/private",
    "/System",
    "/Library",
    "/Applications",
    "/Volumes",
    "/.",
    "/System/Volumes",
    "/System/Volumes/Data",
    "/System/Volumes/Data/System",
];

#[test]
fn major_system_directories_and_symlink_aliases_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    for path in SYSTEM_BOUNDARIES {
        assert!(validate(Path::new(path), true).is_err(), "accepted {path}");
        if Path::new(path).exists() {
            let alias = directory.path().join("system-alias");
            std::os::unix::fs::symlink(*path, &alias).unwrap();
            assert!(validate(&alias, true).is_err(), "accepted alias for {path}");
            std::fs::remove_file(alias).unwrap();
        }
    }
}

#[test]
fn cli_rejects_relative_home_before_any_sandbox_launch() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("trusted.toml");
    let mut config = Config::default();
    config.sandbox.tracer = izanagi::config::TracerBackend::None;
    config.sandbox.require_auth = Some(false);
    config.share.paths = vec![".".into()];
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_izanagi"))
        .current_dir(host_home())
        .arg("-c")
        .arg(config_path)
        .args(["config", "show"])
        .env_remove("IZANAGI_SHARED_SECRET")
        .env_remove("IZANAGI_SECRET_FILE")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ホームディレクトリ"));
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_data_volume_home_alias_and_sensitive_descendants_are_rejected() {
    use std::os::unix::fs::MetadataExt;
    let home_path = host_home().canonicalize().unwrap();
    let data_home = Path::new("/System/Volumes/Data").join(home_path.strip_prefix("/").unwrap());
    let home_metadata = std::fs::metadata(&home_path).unwrap();
    let data_metadata =
        std::fs::metadata(&data_home).expect("macOS runner must expose Data volume home alias");
    assert_eq!(
        (home_metadata.dev(), home_metadata.ino()),
        (data_metadata.dev(), data_metadata.ino())
    );
    for read_only in [true, false] {
        for path in [
            data_home.clone(),
            data_home.join(".ssh/izanagi69-missing-child"),
            data_home.join(".config/gh"),
        ] {
            assert!(
                validate(&path, read_only).is_err(),
                "accepted physical home alias {}",
                path.display()
            );
        }
        for ancestor in data_home.ancestors() {
            assert!(
                validate(ancestor, read_only).is_err(),
                "accepted Data volume ancestor {}",
                ancestor.display()
            );
        }
        assert!(validate(&data_home.join("izanagi69-project"), read_only).is_ok());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn case_aliases_of_home_system_and_sensitive_directories_are_rejected() {
    use std::os::unix::fs::MetadataExt;
    let home_path = host_home();
    let alias = PathBuf::from(home_path.to_str().unwrap().to_ascii_uppercase());
    if alias.exists() {
        let original = std::fs::metadata(&home_path).unwrap();
        let alternate = std::fs::metadata(&alias).unwrap();
        if (original.dev(), original.ino()) == (alternate.dev(), alternate.ino()) {
            for read_only in [true, false] {
                for relative in ["", ".SSH/izanagi69-missing-child", ".AWS", ".CONFIG/GH"] {
                    assert!(validate(&alias.join(relative), read_only).is_err());
                }
                assert!(validate(&alias.join("izanagi69-project"), read_only).is_ok());
            }
        }
    }
    let alias = Path::new("/uSeRs");
    if alias.exists() {
        assert!(validate(alias, true).is_err());
    }
}
