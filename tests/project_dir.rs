//! プロジェクトディレクトリの解決 (#150) を、実際のバイナリで確かめる。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use izanagi::project::path_hash;

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    app: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap().join("home");
        let app = home.join("work/app");
        std::fs::create_dir_all(app.join("src/module")).unwrap();
        Self {
            _temp: temp,
            home,
            app,
        }
    }

    fn settings_path(&self, dir: &Path) -> PathBuf {
        self.home
            .join(".izanagi/settings")
            .join(path_hash(dir))
            .join("izanagi.toml")
    }

    fn write_settings(&self, dir: &Path) {
        let path = self.settings_path(dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut config = izanagi::config::Config::default();
        config.share.paths = vec![".".into()];
        config.share.mount_point = "/workspace".into();
        config.sandbox.tracer = izanagi::config::TracerBackend::None;
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    }

    fn command(&self, cwd: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_izanagi"));
        command
            .current_dir(cwd)
            .env("HOME", &self.home)
            .env_remove("IZANAGI_PROJECT_DIR")
            .env_remove("IZANAGI_SHARED_SECRET")
            .env_remove("IZANAGI_SECRET_FILE");
        command
    }

    fn config_path(&self, cwd: &Path, extra: &[&str]) -> String {
        let output = self
            .command(cwd)
            .args(extra)
            .args(["config", "path"])
            .output()
            .unwrap();
        assert_success(&output);
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn subdirectory_uses_the_configured_project_root() {
    let fixture = Fixture::new();
    fixture.write_settings(&fixture.app);
    let from_subdir = fixture.config_path(&fixture.app.join("src/module"), &[]);
    assert_eq!(
        from_subdir,
        fixture.settings_path(&fixture.app).display().to_string()
    );
}

#[test]
fn unconfigured_directory_keeps_its_own_settings_path() {
    let fixture = Fixture::new();
    let module = fixture.app.join("src/module");
    let path = fixture.config_path(&module, &[]);
    assert_eq!(path, fixture.settings_path(&module).display().to_string());
}

#[test]
fn explicit_project_dir_overrides_the_ancestor_search() {
    let fixture = Fixture::new();
    fixture.write_settings(&fixture.app);
    let module = fixture.app.join("src/module");
    let src = fixture.app.join("src");
    let expected = fixture.settings_path(&src).display().to_string();

    let flag = fixture.config_path(&module, &["--project-dir", src.to_str().unwrap()]);
    assert_eq!(flag, expected);

    let output = fixture
        .command(&module)
        .env("IZANAGI_PROJECT_DIR", &src)
        .args(["config", "path"])
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
}

#[test]
fn invalid_explicit_project_dir_is_rejected() {
    let fixture = Fixture::new();
    let output = fixture
        .command(&fixture.app)
        .args(["--project-dir", "does-not-exist", "config", "path"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("プロジェクトディレクトリ"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn relative_share_paths_are_anchored_to_the_project_root() {
    let fixture = Fixture::new();
    fixture.write_settings(&fixture.app);
    let output = fixture
        .command(&fixture.app.join("src/module"))
        .args(["config", "show"])
        .output()
        .unwrap();
    assert_success(&output);
    let shown = String::from_utf8(output.stdout).unwrap();
    let expected = format!("\"{}\"", fixture.app.display());
    assert!(shown.contains(&expected), "config show: {shown}");
    assert!(!shown.contains("src/module"), "config show: {shown}");
}

#[cfg(unix)]
#[test]
fn mcp_server_reports_an_error_instead_of_panicking_when_cwd_is_gone() {
    let fixture = Fixture::new();
    let gone = fixture.app.join("gone");
    std::fs::create_dir(&gone).unwrap();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "cd \"$1\" && rmdir \"$1\" && exec \"$2\" mcp", "sh"])
        .arg(&gone)
        .arg(env!("CARGO_BIN_EXE_izanagi"))
        .env("HOME", &fixture.home)
        .env_remove("IZANAGI_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sandbox_status","arguments":{}}}"#;
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{request}").unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let response: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(response["result"]["isError"], serde_json::json!(true));
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("project directory"), "text: {text}");
}
