#![cfg(all(target_os = "linux", feature = "landlock"))]

use std::collections::HashMap;
use std::path::Path;

use izanagi::landlock_sandbox::LandlockSandbox;
use izanagi::sandbox::{Sandbox, SandboxConfig, ShareConfig};

async fn sandbox(path: &Path, read_only: bool) -> Option<LandlockSandbox> {
    let mut sandbox = LandlockSandbox::new();
    let config = SandboxConfig::Landlock {
        share: ShareConfig {
            host_paths: vec![path.into()],
            mount_point: "/workspace".into(),
            read_only,
        },
    };
    if let Err(error) = sandbox.up(&config).await {
        assert!(
            std::env::var_os("IZANAGI_REQUIRE_LANDLOCK_TEST").is_none(),
            "mandatory Landlock boundary test unavailable: {error}"
        );
        eprintln!("Landlock boundary test unavailable: {error}");
        return None;
    }
    Some(sandbox)
}

async fn run(sandbox: &LandlockSandbox, script: &str, path: &Path) -> i32 {
    sandbox
        .exec(
            &[
                "/bin/sh".into(),
                "-c".into(),
                script.into(),
                "fixture".into(),
                path.to_string_lossy().into_owned(),
            ],
            &HashMap::new(),
        )
        .await
        .unwrap()
        .exit_code
}

#[tokio::test]
async fn read_only_share_under_tmp_denies_mutation_through_aliases() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let protected = directory.path().join(".git/config");
    std::fs::create_dir_all(protected.parent().unwrap()).unwrap();
    std::fs::write(&protected, b"fixture-original").unwrap();
    let alias = directory.path().join("alias");
    symlink(directory.path(), &alias).unwrap();
    let Some(mut sandbox) = sandbox(&alias, true).await else {
        return;
    };
    assert_eq!(run(&sandbox, "cat \"$1\"", &protected).await, 0);
    for script in [
        "printf changed > \"$1\"",
        "printf changed >> \"$1\"",
        "truncate -s 0 \"$1\"",
        "rm \"$1\"",
        "mv \"$1\" \"$1.moved\"",
        "touch \"$1.new\"",
        "ln \"$1\" \"$1.link\"",
    ] {
        assert_ne!(run(&sandbox, script, &protected).await, 0, "{script}");
        assert_eq!(std::fs::read(&protected).unwrap(), b"fixture-original");
    }
    assert_ne!(
        run(
            &sandbox,
            "printf changed > \"$1\"",
            &alias.join(".git/config")
        )
        .await,
        0
    );
    sandbox.down().await.unwrap();
}

#[tokio::test]
async fn explicitly_writable_share_has_a_real_write_positive_control() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture");
    std::fs::write(&path, b"original").unwrap();
    let Some(mut sandbox) = sandbox(directory.path(), false).await else {
        return;
    };
    assert_eq!(run(&sandbox, "printf changed > \"$1\"", &path).await, 0);
    assert_eq!(std::fs::read(&path).unwrap(), b"changed");
    sandbox.down().await.unwrap();
}
