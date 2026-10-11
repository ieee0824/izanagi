use std::{path::PathBuf, process::Command};

fn temporary() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("izanagi-config-trust-{}", rand::random::<u64>()));
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn implicit_config_does_not_select_project_configuration() {
    let dir = temporary();
    let home = dir.join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(dir.join("izanagi.toml"), "untrusted project configuration").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_izanagi"))
        .current_dir(&dir)
        .env("HOME", &home)
        .args(["config", "path"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let selected = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    assert_ne!(selected, dir.join("izanagi.toml"));
    assert!(selected.starts_with(home.join(".izanagi/settings")));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_config_inside_shared_directory_is_rejected() {
    let dir = temporary();
    let shared = dir.join("shared");
    std::fs::create_dir(&shared).unwrap();
    let path = shared.join("izanagi.toml");
    let mut config = izanagi::config::Config::default();
    config.share.paths = vec![shared.to_str().unwrap().to_owned()];
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    assert!(izanagi::config::Config::load(&path).is_err());
    let link = dir.join("config-link.toml");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(izanagi::config::Config::load(&link).is_err());
    let trusted = dir.join("trusted.toml");
    std::fs::write(&trusted, toml::to_string(&config).unwrap()).unwrap();
    assert!(izanagi::config::Config::load(&trusted).is_ok());
    let output = Command::new(env!("CARGO_BIN_EXE_izanagi"))
        .args(["-c", path.to_str().unwrap(), "config", "show"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("share.paths"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn shared_directory_alias_and_shared_config_symlink_are_rejected() {
    let dir = temporary();
    let shared = dir.join("shared");
    std::fs::create_dir(&shared).unwrap();
    let alias = dir.join("share-alias");
    std::os::unix::fs::symlink(&shared, &alias).unwrap();
    let mut config = izanagi::config::Config::default();
    config.share.paths = vec![alias.to_str().unwrap().to_owned()];
    let trusted = dir.join("trusted.toml");
    std::fs::write(&trusted, toml::to_string(&config).unwrap()).unwrap();
    let shared_link = shared.join("izanagi.toml");
    std::os::unix::fs::symlink(&trusted, &shared_link).unwrap();
    for path in [shared_link, alias.join("izanagi.toml")] {
        assert!(izanagi::config::Config::load(&path).is_err());
    }
    assert!(izanagi::config::Config::load(&trusted).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn similarly_named_directory_outside_share_remains_usable() {
    let dir = temporary();
    let shared = dir.join("shared");
    let neighbor = dir.join("shared-backup");
    std::fs::create_dir(&shared).unwrap();
    std::fs::create_dir(&neighbor).unwrap();
    let mut config = izanagi::config::Config::default();
    config.share.paths = vec![shared.to_str().unwrap().to_owned()];
    config.sandbox.require_auth = Some(false);
    let trusted = neighbor.join("izanagi.toml");
    std::fs::write(&trusted, toml::to_string(&config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_izanagi"))
        .args(["-c", trusted.to_str().unwrap(), "config", "show"])
        .env_remove("IZANAGI_SECRET_FILE")
        .env_remove("IZANAGI_SHARED_SECRET")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_settings_fail_with_migration_guidance_without_reading_project_config() {
    let dir = temporary();
    let home = dir.join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(dir.join("izanagi.toml"), "INVALID_PROJECT_CONFIG").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_izanagi"))
        .current_dir(&dir)
        .env("HOME", &home)
        .args(["config", "show"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("izanagi init"));
    assert!(error.contains("./izanagi.toml は自動読み込みしません"));
    assert!(!error.contains("INVALID_PROJECT_CONFIG"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn relative_share_is_resolved_from_current_directory() {
    let dir = temporary();
    let shared = dir.join("shared");
    std::fs::create_dir(&shared).unwrap();
    let path = shared.join("izanagi.toml");
    let mut config = izanagi::config::Config::default();
    config.share.paths = vec!["shared".into()];
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_izanagi"))
        .current_dir(&dir)
        .args(["-c", "shared/izanagi.toml", "config", "show"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("share.paths"));
    std::fs::remove_dir_all(dir).unwrap();
}
