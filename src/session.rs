//! セッション情報の永続化。
//!
//! `izanagi up` で起動したサンドボックスの接続情報を `~/.izanagi/session.json` に保存し、
//! `izanagi exec` / `izanagi shell` から起動中のサンドボックスに接続するために使用する。

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// セッションファイル名。
const SESSION_FILE: &str = "session.json";

/// セッション情報。`up` で起動したサンドボックスの接続に必要な情報を保持する。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    /// サンドボックスバックエンドの種別。
    pub backend: SessionBackend,
    /// `up` プロセスの PID。
    pub pid: u32,
    /// 起動時刻 (UNIX epoch seconds)。
    pub started_at: u64,
}

/// バックエンド固有の接続情報。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum SessionBackend {
    /// Apple Container バックエンド。
    #[serde(rename = "apple-container")]
    AppleContainer {
        /// コンテナ名。`container exec` で使用。
        container_name: String,
        /// イメージ名。
        image: String,
        /// マウントポイント。exec/shell の -w オプションに使用。
        mount_point: String,
    },
    /// QEMU バックエンド。
    #[serde(rename = "qemu")]
    Qemu {
        /// ホスト側の TCP ポート番号。agent への接続に使用。
        host_port: u16,
        /// fw_cfg トークンのハッシュ値 (sha256(token))。
        /// QEMU バックエンドでは Hello ハンドシェイクで agent に提示する。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_hash: Option<String>,
    },
}

/// セッションファイルのパスを返す。
pub fn session_file_path(izanagi_dir: &Path) -> PathBuf {
    izanagi_dir.join(SESSION_FILE)
}

/// セッション情報をファイルに書き込む。
pub fn save_session(izanagi_dir: &Path, session: &Session) -> anyhow::Result<()> {
    // ディレクトリが存在しない場合は作成し、パーミッションを 0700 に設定
    std::fs::create_dir_all(izanagi_dir)
        .with_context(|| format!("セッションディレクトリの作成に失敗: {:?}", izanagi_dir))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(izanagi_dir, perms);
    }

    let path = session_file_path(izanagi_dir);
    let json =
        serde_json::to_string_pretty(session).context("セッション情報のシリアライズに失敗")?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("セッションファイルの作成に失敗: {:?}", path))?;
        file.write_all(json.as_bytes())
            .with_context(|| "セッションファイルへの書き込みに失敗")?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&path, &json)
            .with_context(|| format!("セッションファイルの書き込みに失敗: {:?}", path))?;
    }

    Ok(())
}

/// セッション情報をファイルから読み込む。
/// ファイルが存在しない場合は `Ok(None)` を返す。
pub fn load_session(izanagi_dir: &Path) -> anyhow::Result<Option<Session>> {
    let path = session_file_path(izanagi_dir);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let session: Session = serde_json::from_str(&content)
                .with_context(|| format!("セッションファイルのパースに失敗: {:?}", path))?;
            Ok(Some(session))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("セッションファイルの読み込みに失敗: {:?}", path))),
    }
}

/// セッションファイルを削除する。存在しない場合は何もしない。
pub fn remove_session(izanagi_dir: &Path) {
    let path = session_file_path(izanagi_dir);
    let _ = std::fs::remove_file(path);
}

/// セッションが有効か（対応するプロセスが生存しているか）を検証する。
pub fn is_session_alive(session: &Session) -> bool {
    // kill(pid, 0) でプロセスの存在を確認する。
    // ret == 0: プロセスが存在し、シグナル送信権限がある。
    // ret != 0, errno == ESRCH: プロセスが存在しない。
    // ret != 0, errno == EPERM: プロセスは存在するが権限がない → 生存とみなす。
    let result = unsafe { libc::kill(session.pid as i32, 0) };
    if result == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        !matches!(err.raw_os_error(), Some(code) if code == libc::ESRCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("izanagi_session_test_{}", id))
    }

    #[test]
    fn save_and_load_apple_container_session() {
        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);

        let session = Session {
            backend: SessionBackend::AppleContainer {
                container_name: "izanagi-abc123".to_string(),
                image: "izanagi-vm".to_string(),
                mount_point: "/workspace".to_string(),
            },
            pid: 12345,
            started_at: 1700000000,
        };

        save_session(&dir, &session).unwrap();
        let loaded = load_session(&dir).unwrap().unwrap();
        assert_eq!(session, loaded);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_and_load_qemu_session() {
        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);

        let session = Session {
            backend: SessionBackend::Qemu {
                host_port: 9001,
                token_hash: None,
            },
            pid: 54321,
            started_at: 1700000000,
        };

        save_session(&dir, &session).unwrap();
        let loaded = load_session(&dir).unwrap().unwrap();
        assert_eq!(session, loaded);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let dir = test_dir();
        let result = load_session(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn remove_session_deletes_file() {
        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);

        let session = Session {
            backend: SessionBackend::Qemu {
                host_port: 9001,
                token_hash: None,
            },
            pid: 1,
            started_at: 0,
        };
        save_session(&dir, &session).unwrap();
        assert!(session_file_path(&dir).exists());

        remove_session(&dir);
        assert!(!session_file_path(&dir).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_session_alive_detects_current_process() {
        let session = Session {
            backend: SessionBackend::Qemu {
                host_port: 9001,
                token_hash: None,
            },
            pid: std::process::id(),
            started_at: 0,
        };
        assert!(is_session_alive(&session));
    }

    #[test]
    fn is_session_alive_detects_dead_process() {
        let session = Session {
            backend: SessionBackend::Qemu {
                host_port: 9001,
                token_hash: None,
            },
            // 存在しないはずの PID。i32::MAX は通常の pid_max (32768 or 4194304) を超える。
            // kill(i32::MAX, 0) → ESRCH が返る。
            pid: i32::MAX as u32,
            started_at: 0,
        };
        assert!(!is_session_alive(&session));
    }

    #[test]
    fn load_corrupted_session_returns_error() {
        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = session_file_path(&dir);
        std::fs::write(&path, "not valid json{{{").unwrap();
        let result = load_session(&dir);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_wrong_schema_session_returns_error() {
        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = session_file_path(&dir);
        // Valid JSON but wrong schema (missing required fields)
        std::fs::write(&path, r#"{"foo": "bar", "baz": 123}"#).unwrap();
        let result = load_session(&dir);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn session_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);

        let session = Session {
            backend: SessionBackend::Qemu {
                host_port: 9001,
                token_hash: None,
            },
            pid: 1,
            started_at: 0,
        };
        save_session(&dir, &session).unwrap();

        let meta = std::fs::metadata(session_file_path(&dir)).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
