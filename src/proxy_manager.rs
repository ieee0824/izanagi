//! DNS プロキシと HTTP キャプチャプロキシのサブプロセス管理。
//!
//! `izanagi up` 時に設定に基づいてプロキシを自動起動し、
//! shutdown 時に停止する。
//!
//! `kill_on_drop(true)` により、`ProxyManager` がドロップされた場合も
//! サブプロセスに SIGKILL が送られる（フォールバック）。
//! 正常経路では `stop()` で明示的に停止する。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::{Child, Command};

use crate::config::Config;

/// 起動中のプロキシプロセスを管理する。
pub struct ProxyManager {
    dns_proxy: Option<Child>,
    http_capture: Option<Child>,
    /// シークレットマップ一時ファイルのガード。
    /// 子プロセスが起動中はファイルを保持し、stop() 時に削除する。
    _secret_map_guard: Option<TempFileGuard>,
}

impl ProxyManager {
    /// 設定に基づいてプロキシを起動する。
    ///
    /// - `dns_proxy.enabled = true` なら DNS プロキシを起動
    /// - `http_capture.enabled = true` なら HTTP キャプチャプロキシを起動
    pub async fn start(config: &Config, config_path: &Path) -> anyhow::Result<Self> {
        let mut manager = Self {
            dns_proxy: None,
            http_capture: None,
            _secret_map_guard: None,
        };
        manager.dns_proxy = Self::start_dns_proxy(config, config_path).await?;
        match Self::start_http_capture(config).await {
            Ok((child, guard)) => {
                manager.http_capture = child;
                manager._secret_map_guard = guard;
                Ok(manager)
            }
            Err(error) => {
                manager.stop().await;
                Err(error)
            }
        }
    }

    /// DNS プロキシをサブプロセスとして起動する。
    async fn start_dns_proxy(config: &Config, config_path: &Path) -> anyhow::Result<Option<Child>> {
        let section = match &config.dns_proxy {
            Some(s) if s.enabled => s,
            _ => return Ok(None),
        };

        let binary = find_binary("izanagi-dns-proxy")?;

        let mut child = Command::new(&binary)
            .arg("--ready-stdout")
            .arg("--config")
            .arg(config_path)
            .arg("--listen")
            .arg(&section.listen)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!("DNS プロキシの起動に失敗 ({}): {}", binary.display(), e)
            })?;
        wait_proxy_ready(&mut child).await?;

        eprintln!(
            "[proxy] DNS プロキシを起動しました (PID: {}, listen: {})",
            pid_display(child.id()),
            section.listen
        );

        Ok(Some(child))
    }

    /// HTTP キャプチャプロキシをサブプロセスとして起動する。
    async fn start_http_capture(
        config: &Config,
    ) -> anyhow::Result<(Option<Child>, Option<TempFileGuard>)> {
        let section = match &config.http_capture {
            Some(s) if s.enabled => s,
            _ => return Ok((None, None)),
        };

        // ca_cert_out のパス検証: シンボリックリンクと絶対パスの安全性チェック
        if let Some(ref ca_out) = section.ca_cert_out {
            validate_ca_cert_path(ca_out)?;
        }

        let binary = find_binary("izanagi-http-capture")?;

        let (mut cmd, secret_guard) = http_capture_command(&binary, section, config)?;

        let mut child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!(
                "HTTP キャプチャプロキシの起動に失敗 ({}): {}",
                binary.display(),
                e
            )
        })?;
        wait_proxy_ready(&mut child).await?;

        eprintln!(
            "[proxy] HTTP キャプチャプロキシを起動しました (PID: {}, http: {}, https: {})",
            pid_display(child.id()),
            section.listen_http,
            section.listen_https
        );

        Ok((Some(child), secret_guard))
    }

    /// 全プロキシプロセスを停止する。
    /// 子プロセス停止後にシークレットマップ一時ファイルも削除する。
    pub async fn stop(&mut self) {
        Self::stop_child(&mut self.dns_proxy, "DNS プロキシ").await;
        Self::stop_child(&mut self.http_capture, "HTTP キャプチャプロキシ").await;
        // 子プロセス停止後にシークレットマップ一時ファイルを削除
        self._secret_map_guard = None;
    }

    async fn stop_child(child: &mut Option<Child>, name: &str) {
        if let Some(c) = child {
            let pid = pid_display(c.id());
            if let Err(e) = c.kill().await {
                eprintln!("[proxy] {name} の停止に失敗 (PID: {pid}): {e}");
            } else {
                let _ = c.wait().await;
                eprintln!("[proxy] {name} を停止しました (PID: {pid})");
            }
        }
        *child = None;
    }
}

fn http_capture_command(
    binary: &Path,
    section: &crate::config::HttpCaptureSection,
    config: &Config,
) -> anyhow::Result<(Command, Option<TempFileGuard>)> {
    let mut cmd = Command::new(binary);
    cmd.arg("--ready-stdout")
        .arg("--listen-http")
        .arg(section.listen_http.to_string())
        .arg("--listen-https")
        .arg(section.listen_https.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    if let Some(ref ca_out) = section.ca_cert_out {
        cmd.arg("--ca-cert-out").arg(ca_out);
    }

    // allowed_hosts は detect セクションから取得
    for host in &config.detect.allowed_hosts {
        cmd.arg("--allowed-host").arg(host);
    }

    // シークレット置換マッピング (#273)
    // コマンドライン引数では ps でシークレットが漏洩するため、
    // 一時ファイル (0600) 経由で渡す。
    // TempFileGuard は ProxyManager に所有され、stop() 時に削除される。
    let secret_guard = if !section.secret_maps.is_empty() {
        let (tmp, guard) = write_secret_map_file(&section.secret_maps)?;
        cmd.arg("--secret-map-file").arg(&tmp);
        Some(guard)
    } else {
        None
    };

    Ok((cmd, secret_guard))
}

async fn wait_proxy_ready(child: &mut Child) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let stdout = child
            .stdout
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("proxy stdout unavailable"))?;
        let mut ready = [0u8; b"IZANAGI_PROXY_READY\n".len()];
        stdout.read_exact(&mut ready).await?;
        anyhow::ensure!(
            &ready == b"IZANAGI_PROXY_READY\n",
            "invalid proxy startup response"
        );
        anyhow::ensure!(child.try_wait()?.is_none(), "proxy exited during startup");
        Ok::<_, anyhow::Error>(())
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(()),
        failure => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            // Never echo child output: it might contain credentials.
            anyhow::bail!(
                "プロキシの起動確認に失敗しました ({})",
                if failure.is_err() {
                    "timeout"
                } else {
                    "startup error"
                }
            );
        }
    }
}

/// 一時ファイルの RAII ガード。Drop 時にファイルを削除する。
struct TempFileGuard {
    path: PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "警告: 一時ファイルの削除に失敗: {}: {}",
                self.path.display(),
                e
            );
        }
    }
}

/// シークレット置換マッピングを一時ファイルに書き出す (0600)。
/// コマンドライン引数経由では `ps` でシークレットが漏洩するため、
/// ファイル経由で子プロセスに渡す。
///
/// ランダムファイル名を使用し、予測可能なパスへのシンボリックリンク攻撃を防止する。
fn write_secret_map_file(maps: &[String]) -> anyhow::Result<(PathBuf, TempFileGuard)> {
    use std::os::unix::fs::OpenOptionsExt;

    anyhow::ensure!(
        maps.iter().all(|line| !line.chars().any(char::is_control)),
        "secret mappings must contain one mapping per line"
    );

    let random_suffix: String = (0..8)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    let path = std::env::temp_dir().join(format!("izanagi-secret-maps-{}.tmp", random_suffix));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("シークレットマップファイルの作成に失敗: {e}"))?;
    let guard = TempFileGuard { path: path.clone() };
    for line in maps {
        writeln!(f, "{line}")?;
    }
    Ok((path, guard))
}

/// プロキシバイナリのパスを検索する。
///
/// `current_exe()` と同じディレクトリからのみ解決する。
fn find_binary(name: &str) -> anyhow::Result<PathBuf> {
    sibling_binary(&std::env::current_exe()?, name)
}

fn sibling_binary(executable: &Path, name: &str) -> anyhow::Result<PathBuf> {
    if let Some(dir) = executable.parent() {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "プロキシバイナリ '{name}' が本体と同じディレクトリにありません。make install でインストールしてください。PATH は検索しません。"
    )
}

/// `ca_cert_out` のパス安全性を検証する。
/// シンボリックリンク先への書き込みやシステムディレクトリへの上書きを防止。
///
/// 親ディレクトリを `canonicalize()` で正規化し、シンボリックリンクチェーンを
/// 辿った実際のパスに対してシステムディレクトリチェックを行う。
fn validate_ca_cert_path(path: &Path) -> anyhow::Result<()> {
    // 既存ファイルがシンボリックリンクなら拒否
    if path.exists() && path.symlink_metadata()?.file_type().is_symlink() {
        anyhow::bail!(
            "ca_cert_out '{}' はシンボリックリンクです。直接のファイルパスを指定してください。",
            path.display()
        );
    }

    // 親ディレクトリを canonicalize して symlink を解決した上でチェック
    let check_path = resolved_ca_cert_path(path);

    // システムディレクトリへの書き込みを禁止
    // macOS では /etc → /private/etc, /var → /private/var のシンボリックリンクがあるため、
    // 元のパスと正規化パスの両方をチェックする。
    let system_dirs = [
        "/etc",
        "/usr",
        "/var/lib",
        "/System",
        "/private/etc",
        "/private/var/lib",
    ];
    for check in [path, check_path.as_path()] {
        if let Some(path_str) = check.to_str() {
            for dir in &system_dirs {
                if path_str.starts_with(dir) {
                    anyhow::bail!(
                        "ca_cert_out '{}' はシステムディレクトリ内です（実パス: {}）。安全な場所を指定してください。",
                        path.display(),
                        check_path.display()
                    );
                }
            }
        }
    }

    Ok(())
}

fn resolved_ca_cert_path(path: &Path) -> PathBuf {
    if let Some(parent) = path.parent() {
        if parent.exists() {
            parent
                .canonicalize()
                .unwrap_or_else(|_| parent.to_path_buf())
                .join(path.file_name().unwrap_or_default())
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    }
}

/// PID の表示用ヘルパー。取得できない場合は "unknown"。
fn pid_display(pid: Option<u32>) -> String {
    pid.map_or_else(|| "unknown".to_string(), |p| p.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn failed_proxy_startup_is_reaped_without_echoing_output() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "printf 'SECRET_CANARY'; exit 2"])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let error = wait_proxy_ready(&mut child).await.unwrap_err().to_string();
        assert!(!error.contains("SECRET_CANARY"));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    #[serial_test::serial(env)]
    fn proxy_does_not_search_path_even_when_it_contains_an_executable() {
        let dir =
            std::env::temp_dir().join(format!("izanagi-proxy-path-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let name = format!("izanagi-fixture-proxy-{}", rand::random::<u64>());
        std::fs::write(dir.join(&name), "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(dir.join(&name), std::fs::Permissions::from_mode(0o700)).unwrap();
        let old_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", &dir);
        }
        let result = find_binary(&name);
        unsafe {
            match old_path {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
        }
        assert!(result.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn proxy_resolution_requires_sibling_binary() {
        let dir =
            std::env::temp_dir().join(format!("izanagi-proxy-resolve-{}", rand::random::<u64>()));
        std::fs::create_dir_all(dir.join("trusted")).unwrap();
        let exe = dir.join("trusted/izanagi");
        std::fs::write(dir.join("izanagi-dns-proxy"), "untrusted").unwrap();
        assert!(sibling_binary(&exe, "izanagi-dns-proxy").is_err());
        let sibling = dir.join("trusted/izanagi-dns-proxy");
        std::fs::write(&sibling, "trusted").unwrap();
        assert_eq!(sibling_binary(&exe, "izanagi-dns-proxy").unwrap(), sibling);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn temp_file_guard_deletes_on_drop() {
        let path = std::env::temp_dir().join("izanagi-test-guard.tmp");
        std::fs::write(&path, "test").unwrap();
        assert!(path.exists());
        let guard = TempFileGuard { path: path.clone() };
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn temp_file_guard_ignores_not_found() {
        let path = std::env::temp_dir().join("izanagi-test-nonexistent.tmp");
        // ファイルが存在しない状態で Drop してもパニックしない
        let guard = TempFileGuard { path };
        drop(guard);
    }

    #[test]
    fn write_secret_map_file_creates_with_correct_perms() {
        let maps = vec!["DUMMY=REAL".to_string()];
        let (path, guard) = write_secret_map_file(&maps).unwrap();

        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "DUMMY=REAL\n");

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);

        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn write_secret_map_file_random_name() {
        let maps = vec!["A=B".to_string()];
        let (path1, _g1) = write_secret_map_file(&maps).unwrap();
        let (path2, _g2) = write_secret_map_file(&maps).unwrap();
        assert_ne!(
            path1, path2,
            "ランダムサフィックスにより異なるパスになるべき"
        );
    }

    #[test]
    fn validate_ca_cert_path_rejects_system_dirs() {
        assert!(validate_ca_cert_path(Path::new("/etc/ca.pem")).is_err());
        assert!(validate_ca_cert_path(Path::new("/usr/local/ca.pem")).is_err());
        assert!(validate_ca_cert_path(Path::new("/var/lib/ca.pem")).is_err());
        assert!(validate_ca_cert_path(Path::new("/System/ca.pem")).is_err());
    }

    #[test]
    fn validate_ca_cert_path_allows_tmp() {
        assert!(validate_ca_cert_path(Path::new("/tmp/ca.pem")).is_ok());
    }

    #[test]
    fn validate_ca_cert_path_rejects_symlink() {
        let dir = std::env::temp_dir().join("izanagi-test-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let target = dir.join("real.pem");
        std::fs::write(&target, "test").unwrap();
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(validate_ca_cert_path(&link).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_ca_cert_path_canonicalize_resolves_parent_symlink() {
        let dir = std::env::temp_dir().join("izanagi-test-parent-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // /tmp/.../link_to_usr -> /usr (シンボリックリンク)
        let link_dir = dir.join("link_to_usr");
        std::os::unix::fs::symlink("/usr", &link_dir).unwrap();

        // /tmp/.../link_to_usr/ca.pem は canonicalize で /usr/ca.pem に解決されるためブロック
        let ca_path = link_dir.join("ca.pem");
        assert!(
            validate_ca_cert_path(&ca_path).is_err(),
            "親ディレクトリが /usr へのシンボリックリンクの場合はブロックされるべき"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
