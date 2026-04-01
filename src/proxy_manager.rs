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
        let dns_proxy = Self::start_dns_proxy(config, config_path)?;
        let (http_capture, secret_guard) = Self::start_http_capture(config)?;

        Ok(Self {
            dns_proxy,
            http_capture,
            _secret_map_guard: secret_guard,
        })
    }

    /// DNS プロキシをサブプロセスとして起動する。
    fn start_dns_proxy(config: &Config, config_path: &Path) -> anyhow::Result<Option<Child>> {
        let section = match &config.dns_proxy {
            Some(s) if s.enabled => s,
            _ => return Ok(None),
        };

        let binary = find_binary("izanagi-dns-proxy")?;

        let child = Command::new(&binary)
            .arg("--config")
            .arg(config_path)
            .arg("--listen")
            .arg(&section.listen)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!("DNS プロキシの起動に失敗 ({}): {}", binary.display(), e)
            })?;

        eprintln!(
            "[proxy] DNS プロキシを起動しました (PID: {}, listen: {})",
            pid_display(child.id()),
            section.listen
        );

        Ok(Some(child))
    }

    /// HTTP キャプチャプロキシをサブプロセスとして起動する。
    fn start_http_capture(
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

        let mut cmd = Command::new(&binary);
        cmd.arg("--listen-http")
            .arg(section.listen_http.to_string())
            .arg("--listen-https")
            .arg(section.listen_https.to_string())
            .stdout(Stdio::null())
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

        let child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!(
                "HTTP キャプチャプロキシの起動に失敗 ({}): {}",
                binary.display(),
                e
            )
        })?;

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

/// 一時ファイルの RAII ガード。Drop 時にファイルを削除する。
struct TempFileGuard {
    path: PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "警告: 一時ファイルの削除に失敗: {}: {}",
                    self.path.display(),
                    e
                );
            }
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
    for line in maps {
        writeln!(f, "{line}")?;
    }
    let guard = TempFileGuard { path: path.clone() };
    Ok((path, guard))
}

/// プロキシバイナリのパスを検索する。
///
/// 1. `current_exe()` と同じディレクトリ (cargo target / インストール先)
/// 2. `PATH` 環境変数から検索 (シェル非経由、自前パース)
fn find_binary(name: &str) -> anyhow::Result<PathBuf> {
    // 同一ディレクトリ (開発時: cargo target、リリース時: インストール先)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // PATH から自前で検索 (which コマンドに依存しない)
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    anyhow::bail!(
        "プロキシバイナリ '{name}' が見つかりません。cargo build で事前にビルドしてください。"
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
    let check_path = if let Some(parent) = path.parent() {
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
    };

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

/// PID の表示用ヘルパー。取得できない場合は "unknown"。
fn pid_display(pid: Option<u32>) -> String {
    pid.map_or_else(|| "unknown".to_string(), |p| p.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
