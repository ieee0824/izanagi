use std::{path::PathBuf, process::Stdio};
use tokio::{io::AsyncReadExt, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "izanagi-capture-startup-{}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn mappings(&self, content: &str) -> PathBuf {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let path = self.0.join("mappings");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_izanagi-http-capture"));
    command
        .args([
            "--ready-stdout",
            "--listen-http",
            "127.0.0.1:0",
            "--listen-https",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

#[tokio::test]
async fn scoped_mapping_file_starts_and_reports_listener_readiness() {
    let fixture = Fixture::new();
    let path = fixture.mappings("api.example.com:Authorization:DUMMY=SECRET_CANARY\n");
    let mut child = command()
        .arg("--secret-map-file")
        .arg(&path)
        .args(["--allowed-host", "api.example.com"])
        .spawn()
        .unwrap();
    let mut ready = [0u8; b"IZANAGI_PROXY_READY\n".len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        child.stdout.as_mut().unwrap().read_exact(&mut ready),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&ready, b"IZANAGI_PROXY_READY\n");
    assert!(child.try_wait().unwrap().is_none());
    child.kill().await.unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET_CANARY"));
}

#[tokio::test]
async fn invalid_mapping_and_occupied_listener_fail_without_reporting_ready_or_secrets() {
    let fixture = Fixture::new();
    let path = fixture.mappings("DUMMY=SECRET_CANARY\n");
    let output = command()
        .arg("--secret-map-file")
        .arg(&path)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET_CANARY"));
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_izanagi-http-capture"))
        .args([
            "--ready-stdout",
            "--listen-http",
            &occupied.local_addr().unwrap().to_string(),
            "--listen-https",
            "127.0.0.1:0",
        ])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
