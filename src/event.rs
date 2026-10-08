use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use regex::Regex;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::LazyLock;

/// syscall のカテゴリ。監視フィルタや検知ルールの単位。
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyscallCategory {
    File,
    Network,
    Process,
    Env,
}

/// 監視対象の syscall。String ではなく enum で網羅性を保証する。
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Syscall {
    // File
    Open,
    OpenAt,
    Read,
    Write,
    Stat,
    Access,

    // Network
    Connect,
    SendTo,
    RecvFrom,
    Socket,
    Bind,

    // Process
    Execve,
    Clone,
    Fork,

    // Env
    ReadLink,
}

impl Syscall {
    pub fn category(&self) -> SyscallCategory {
        match self {
            Self::Open | Self::OpenAt | Self::Read | Self::Write | Self::Stat | Self::Access => {
                SyscallCategory::File
            }
            Self::Connect | Self::SendTo | Self::RecvFrom | Self::Socket | Self::Bind => {
                SyscallCategory::Network
            }
            Self::Execve | Self::Clone | Self::Fork => SyscallCategory::Process,
            Self::ReadLink => SyscallCategory::Env,
        }
    }
}

/// syscall の引数。型で区別し、Detector 側で安全にパターンマッチできる。
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyscallArg {
    Path(PathBuf),
    Addr(SocketAddr),
    Fd(i32),
    Int(i64),
    Str(String),
}

/// 機密情報と判定する環境変数キーのパターン。
/// `KEY=VALUE` 形式の文字列で、KEY がこのパターンにマッチする場合に VALUE をレダクトする。
/// 単語境界 `(^|_)...(|$)` で区切り、KEYBOARD 等の偶発的マッチを防ぐ。
static SENSITIVE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|_)(PASSWORD|PASSWD|SECRET|TOKEN|ACCESS_KEY|API_KEY|APIKEY|KEY_ID|CREDENTIAL|AUTH|PRIVATE)(_|$)").expect("invalid regex")
});

/// base64 エンコードされた長い文字列のパターン（32 文字以上）。
/// 短い API キーやトークンも捕捉するために閾値を下げている。
static BASE64_LONG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/=]{32,}$").expect("invalid regex"));

/// Authorization ヘッダーのパターン（Bearer / Basic）。
static AUTH_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^Authorization:\s*(Bearer|Basic)\s+.+").expect("invalid regex")
});

/// `Bearer <token>` 形式の単独文字列パターン。
static BEARER_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^Bearer\s+\S+").expect("invalid regex"));

/// クエリパラメータ風の API キーパターン（URL 内の ?key=value や &key=value）。
static API_KEY_PARAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[?&](api[_-]?key|apikey)=\S+").expect("invalid regex"));

const REDACTED: &str = "[REDACTED]";

impl SyscallArg {
    /// レダクション済みの表示用文字列を返す。
    ///
    /// `SyscallArg::Str` が機密パターンに該当する場合、値を `[REDACTED]` に置換する。
    /// それ以外の variant はそのまま文字列化する。
    pub fn redacted_display(&self) -> String {
        match self {
            SyscallArg::Str(s) => redact_string(s),
            SyscallArg::Path(p) => p.display().to_string(),
            SyscallArg::Addr(a) => a.to_string(),
            SyscallArg::Fd(fd) => format!("fd={fd}"),
            SyscallArg::Int(i) => i.to_string(),
        }
    }
}

/// 文字列に対してレダクションを適用する。
///
/// 以下のパターンに該当する場合、機密部分を `[REDACTED]` に置換する:
/// - `KEY=VALUE` 形式でキーが機密キーワードを含む場合 → `KEY=[REDACTED]`
/// - `Authorization: Bearer/Basic ...` ヘッダー → `[REDACTED]`
/// - `Bearer <token>` 形式 → `[REDACTED]`
/// - `api_key=...` / `apikey=...` クエリパラメータ → `[REDACTED]`
/// - 32 文字以上の base64 風文字列 → `[REDACTED]`
fn redact_string(s: &str) -> String {
    // Authorization ヘッダーパターン
    if AUTH_HEADER_RE.is_match(s) {
        return REDACTED.to_string();
    }

    // Bearer <token> 形式
    if BEARER_TOKEN_RE.is_match(s) {
        return REDACTED.to_string();
    }

    // api_key=... クエリパラメータ風パターン
    if API_KEY_PARAM_RE.is_match(s) {
        return REDACTED.to_string();
    }

    // KEY=VALUE 形式のチェック
    if let Some(eq_pos) = s.find('=') {
        let key = &s[..eq_pos];
        let value = &s[eq_pos + 1..];
        // キーが機密キーワードを含む場合
        if SENSITIVE_KEY_RE.is_match(key) {
            return format!("{}={}", key, REDACTED);
        }
        // キーは機密でないが、VALUE が長い base64 の場合
        if BASE64_LONG_RE.is_match(value) {
            return format!("{}={}", key, REDACTED);
        }
    }

    // 文字列全体が長い base64 の場合
    if BASE64_LONG_RE.is_match(s) {
        return REDACTED.to_string();
    }

    s.to_string()
}

/// syscall の戻り値。
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SyscallResult {
    Ok(i64),
    Err(i32), // errno
    /// Entry-only observation: the syscall has not returned yet.
    Unknown,
}

/// Tracer から Detector へ流れる中心的なデータ型。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp: SystemTime,
    pub pid: u32,
    pub process_name: Arc<str>,
    pub syscall: Syscall,
    pub args: SmallVec<[SyscallArg; 4]>,
    pub result: SyscallResult,
    /// Linux の thread group ID (tgid、一般的な意味での「プロセスID」)。
    /// eBPF ではスレッドID (tid) が `pid` に、thread group ID (tgid) が `tgid` に入る。
    /// DTrace 等 tgid を提供しないトレーサー向けにデフォルト 0 とする。
    /// シリアライズ形式はバージョン非対応であり、プロデューサー/コンシューマーは
    /// lockstep アップグレードを前提とする。`#[serde(default)]` は postcard の
    /// 後方互換性保証ではなく、tgid を送れない実装向けのフォールバック用途。
    #[serde(default)]
    pub tgid: u32,
}

/// `SyscallEvent` を postcard でシリアライズする。
/// vm-agent ↔ host 間の転送フォーマットとして使用する。
pub fn serialize_event(event: &SyscallEvent) -> anyhow::Result<Vec<u8>> {
    let body = crate::wire_codec::encode(event)?;
    let mut bytes = Vec::with_capacity(body.len() + 2);
    bytes.extend_from_slice(&[0xff, 2]);
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// postcard バイト列から `SyscallEvent` をデシリアライズする。
pub fn deserialize_event(bytes: &[u8]) -> anyhow::Result<SyscallEvent> {
    if !bytes.starts_with(&[0xff, 2]) {
        anyhow::bail!("incompatible event format; upgrade producer and consumer together");
    }
    crate::wire_codec::decode(&bytes[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_postcard_serialization() {
        let event = SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 42,
            tgid: 0,
            process_name: "test-process".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![
                SyscallArg::Path(PathBuf::from("/etc/passwd")),
                SyscallArg::Fd(3),
            ],
            result: SyscallResult::Ok(0),
        };

        let bytes = serialize_event(&event).expect("serialize should succeed");
        let deserialized = deserialize_event(&bytes).expect("deserialize should succeed");

        assert_eq!(deserialized.pid, event.pid);
        assert_eq!(deserialized.tgid, event.tgid);
        assert_eq!(&*deserialized.process_name, &*event.process_name);
        assert_eq!(deserialized.syscall, event.syscall);
        assert_eq!(deserialized.args.len(), event.args.len());
    }

    #[test]
    fn roundtrip_tgid_nonzero() {
        let event = SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 100,
            process_name: "test".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![],
            result: SyscallResult::Ok(0),
            tgid: 12345,
        };
        let bytes = serialize_event(&event).unwrap();
        let deserialized = deserialize_event(&bytes).unwrap();
        assert_eq!(deserialized.tgid, 12345);
        assert_eq!(deserialized.pid, 100);
    }

    #[test]
    fn deserialize_old_format_without_tgid() {
        // 旧フォーマット (tgid なし) のペイロードをシミュレート
        // postcard はポジショナルなので、末尾フィールドが欠けた短いペイロードを渡す
        let event = SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 1,
            process_name: "test".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![],
            result: SyscallResult::Ok(0),
            tgid: 0,
        };
        let bytes = serialize_event(&event).unwrap();
        // tgid (末尾の varint 1 バイト) を削って旧フォーマットをシミュレート
        let old_bytes = &bytes[..bytes.len() - 1];
        // postcard は末尾が足りない場合エラーになるが、serde(default) は効かない
        // → 旧 agent との互換性は postcard では保証されない（lockstep upgrade 前提）
        // ここでは「現行フォーマットの round-trip は正常」であることを確認
        let result = deserialize_event(old_bytes);
        // postcard は厳密にバイト数が合わないとエラーになる
        assert!(
            result.is_err(),
            "truncated payload should fail deserialization"
        );
    }

    #[test]
    fn roundtrip_all_syscall_arg_variants() {
        use std::net::{IpAddr, Ipv4Addr};

        let event = SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 1,
            tgid: 0,
            process_name: "test".into(),
            syscall: Syscall::Connect,
            args: smallvec::smallvec![
                SyscallArg::Path(PathBuf::from("/tmp/test")),
                SyscallArg::Addr(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    8080
                )),
                SyscallArg::Fd(5),
                SyscallArg::Int(-1),
                SyscallArg::Str("hello".to_string()),
            ],
            result: SyscallResult::Err(13),
        };

        let bytes = serialize_event(&event).expect("serialize should succeed");
        let deserialized = deserialize_event(&bytes).expect("deserialize should succeed");

        assert_eq!(deserialized.args.len(), 5);
        assert_eq!(deserialized.pid, 1);
    }

    #[test]
    fn syscall_category_file() {
        assert_eq!(Syscall::Open.category(), SyscallCategory::File);
        assert_eq!(Syscall::OpenAt.category(), SyscallCategory::File);
        assert_eq!(Syscall::Read.category(), SyscallCategory::File);
        assert_eq!(Syscall::Write.category(), SyscallCategory::File);
        assert_eq!(Syscall::Stat.category(), SyscallCategory::File);
        assert_eq!(Syscall::Access.category(), SyscallCategory::File);
    }

    #[test]
    fn syscall_category_network() {
        assert_eq!(Syscall::Connect.category(), SyscallCategory::Network);
        assert_eq!(Syscall::SendTo.category(), SyscallCategory::Network);
        assert_eq!(Syscall::RecvFrom.category(), SyscallCategory::Network);
        assert_eq!(Syscall::Socket.category(), SyscallCategory::Network);
        assert_eq!(Syscall::Bind.category(), SyscallCategory::Network);
    }

    #[test]
    fn syscall_category_process() {
        assert_eq!(Syscall::Execve.category(), SyscallCategory::Process);
        assert_eq!(Syscall::Clone.category(), SyscallCategory::Process);
        assert_eq!(Syscall::Fork.category(), SyscallCategory::Process);
    }

    #[test]
    fn syscall_category_env() {
        assert_eq!(Syscall::ReadLink.category(), SyscallCategory::Env);
    }

    #[test]
    fn redact_sensitive_env_password() {
        let arg = SyscallArg::Str("DB_PASSWORD=super_secret_123".to_string());
        assert_eq!(arg.redacted_display(), "DB_PASSWORD=[REDACTED]");
    }

    #[test]
    fn redact_sensitive_env_token() {
        let arg = SyscallArg::Str("API_TOKEN=abc123xyz".to_string());
        assert_eq!(arg.redacted_display(), "API_TOKEN=[REDACTED]");
    }

    #[test]
    fn redact_sensitive_env_secret() {
        let arg = SyscallArg::Str("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI".to_string());
        assert_eq!(arg.redacted_display(), "AWS_SECRET_ACCESS_KEY=[REDACTED]");
    }

    #[test]
    fn redact_sensitive_env_auth() {
        let arg = SyscallArg::Str("AUTH_HEADER=Bearer eyJhbG...".to_string());
        assert_eq!(arg.redacted_display(), "AUTH_HEADER=[REDACTED]");
    }

    #[test]
    fn redact_sensitive_env_private_key() {
        let arg = SyscallArg::Str("PRIVATE_KEY=-----BEGIN RSA".to_string());
        assert_eq!(arg.redacted_display(), "PRIVATE_KEY=[REDACTED]");
    }

    #[test]
    fn redact_case_insensitive() {
        let arg = SyscallArg::Str("password=mypass".to_string());
        assert_eq!(arg.redacted_display(), "password=[REDACTED]");
    }

    #[test]
    fn no_redact_normal_env() {
        let arg = SyscallArg::Str("PATH=/usr/bin:/usr/local/bin".to_string());
        assert_eq!(arg.redacted_display(), "PATH=/usr/bin:/usr/local/bin");
    }

    #[test]
    fn no_redact_normal_string() {
        let arg = SyscallArg::Str("hello world".to_string());
        assert_eq!(arg.redacted_display(), "hello world");
    }

    #[test]
    fn redact_long_base64_string() {
        // 32 文字以上の base64 はレダクト
        let base64_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
        let arg = SyscallArg::Str(base64_str.to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn no_redact_short_base64() {
        // 31 文字以下の base64 はレダクトしない
        let arg = SyscallArg::Str("aGVsbG8=".to_string());
        assert_eq!(arg.redacted_display(), "aGVsbG8=");
    }

    #[test]
    fn redact_authorization_header() {
        let arg = SyscallArg::Str("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_authorization_basic() {
        let arg = SyscallArg::Str("Authorization: Basic dXNlcjpwYXNz".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_bearer_token() {
        let arg = SyscallArg::Str("Bearer eyJhbGciOiJIUzI1NiJ9".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_api_key_param_in_url() {
        let arg = SyscallArg::Str("/path?api_key=sk-1234567890abcdef".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_apikey_param_in_url() {
        let arg = SyscallArg::Str("/path?apikey=sk-1234567890abcdef&foo=bar".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_api_key_env() {
        let arg = SyscallArg::Str("API_KEY=sk-1234567890abcdef".to_string());
        assert_eq!(arg.redacted_display(), "API_KEY=[REDACTED]");
    }

    #[test]
    fn redacted_display_path_unchanged() {
        let arg = SyscallArg::Path(PathBuf::from("/etc/passwd"));
        assert_eq!(arg.redacted_display(), "/etc/passwd");
    }

    #[test]
    fn redacted_display_fd_unchanged() {
        let arg = SyscallArg::Fd(3);
        assert_eq!(arg.redacted_display(), "fd=3");
    }

    #[test]
    fn redacted_display_int_unchanged() {
        let arg = SyscallArg::Int(42);
        assert_eq!(arg.redacted_display(), "42");
    }

    #[test]
    fn redacted_display_addr_unchanged() {
        use std::net::{IpAddr, Ipv4Addr};
        let arg = SyscallArg::Addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        ));
        assert_eq!(arg.redacted_display(), "127.0.0.1:8080");
    }

    #[test]
    fn no_redact_keyboard_layout() {
        // KEY 単体でのマッチを防ぐ（KEYBOARD は ACCESS_KEY ではない）
        let arg = SyscallArg::Str("KEYBOARD_LAYOUT=us".to_string());
        assert_eq!(arg.redacted_display(), "KEYBOARD_LAYOUT=us");
    }

    #[test]
    fn no_redact_monkey_token() {
        // TOKEN が単語境界でない場合はマッチしない
        let arg = SyscallArg::Str("TOKENIZER_PATH=/usr/bin/tok".to_string());
        assert_eq!(arg.redacted_display(), "TOKENIZER_PATH=/usr/bin/tok");
    }

    #[test]
    fn redact_value_long_base64() {
        // KEY は機密でないが VALUE が 32 文字以上の base64
        let base64_val = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
        let arg = SyscallArg::Str(format!("CERT={}", base64_val));
        assert_eq!(arg.redacted_display(), "CERT=[REDACTED]");
    }

    // -- 境界値テスト --

    #[test]
    fn no_redact_base64_31_chars() {
        // 31 文字はレダクトしない（閾値は 32）
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"; // 31 chars
        assert_eq!(s.len(), 31);
        let arg = SyscallArg::Str(s.to_string());
        assert_eq!(arg.redacted_display(), s);
    }

    #[test]
    fn redact_base64_exactly_32_chars() {
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"; // 32 chars
        assert_eq!(s.len(), 32);
        let arg = SyscallArg::Str(s.to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_authorization_lowercase() {
        let arg = SyscallArg::Str("authorization: bearer token123".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_bearer_lowercase() {
        let arg = SyscallArg::Str("bearer some-token".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn redact_api_hyphen_key_in_url() {
        let arg = SyscallArg::Str("/path?api-key=sk-12345".to_string());
        assert_eq!(arg.redacted_display(), "[REDACTED]");
    }

    #[test]
    fn no_redact_content_type_header() {
        let arg = SyscallArg::Str("Content-Type: application/json".to_string());
        assert_eq!(arg.redacted_display(), "Content-Type: application/json");
    }

    #[test]
    fn redact_key_empty_value() {
        // SECRET_KEY= (値が空) でもキーが機密ならレダクト
        let arg = SyscallArg::Str("SECRET_KEY=".to_string());
        assert_eq!(arg.redacted_display(), "SECRET_KEY=[REDACTED]");
    }

    #[test]
    fn no_redact_empty_string() {
        let arg = SyscallArg::Str(String::new());
        assert_eq!(arg.redacted_display(), "");
    }

    #[test]
    fn redact_key_with_multiple_equals() {
        // TOKEN=key=value の場合、最初の = で分割され KEY=TOKEN がマッチ
        let arg = SyscallArg::Str("TOKEN=key=value".to_string());
        assert_eq!(arg.redacted_display(), "TOKEN=[REDACTED]");
    }

    #[test]
    fn deserialize_invalid_bytes_fails() {
        let result = deserialize_event(&[0xFF, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_empty_bytes_fails() {
        let result = deserialize_event(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_preserves_result_ok() {
        let event = SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 1,
            tgid: 0,
            process_name: "test".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![],
            result: SyscallResult::Ok(42),
        };
        let bytes = serialize_event(&event).unwrap();
        let de = deserialize_event(&bytes).unwrap();
        assert_eq!(de.result, SyscallResult::Ok(42));
    }

    #[test]
    fn roundtrip_preserves_result_err() {
        let event = SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 1,
            tgid: 0,
            process_name: "test".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![],
            result: SyscallResult::Err(13), // EACCES
        };
        let bytes = serialize_event(&event).unwrap();
        let de = deserialize_event(&bytes).unwrap();
        assert_eq!(de.result, SyscallResult::Err(13));
    }

    #[test]
    fn roundtrip_ipv6_addr() {
        use std::net::{IpAddr, Ipv6Addr};
        let event = SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 1,
            tgid: 0,
            process_name: "test".into(),
            syscall: Syscall::Connect,
            args: smallvec::smallvec![SyscallArg::Addr(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                443
            ))],
            result: SyscallResult::Ok(0),
        };
        let bytes = serialize_event(&event).unwrap();
        let de = deserialize_event(&bytes).unwrap();
        assert_eq!(de.args[0], event.args[0]);
    }

    #[test]
    fn roundtrip_all_syscall_variants() {
        let syscalls = [
            Syscall::Open,
            Syscall::OpenAt,
            Syscall::Read,
            Syscall::Write,
            Syscall::Stat,
            Syscall::Access,
            Syscall::Connect,
            Syscall::SendTo,
            Syscall::RecvFrom,
            Syscall::Socket,
            Syscall::Bind,
            Syscall::Execve,
            Syscall::Clone,
            Syscall::Fork,
            Syscall::ReadLink,
        ];

        for syscall in &syscalls {
            let event = SyscallEvent {
                timestamp: SystemTime::UNIX_EPOCH,
                pid: 1,
                tgid: 0,
                process_name: "test".into(),
                syscall: *syscall,
                args: smallvec::smallvec![],
                result: SyscallResult::Ok(0),
            };

            let bytes = serialize_event(&event).expect("serialize should succeed");
            let deserialized = deserialize_event(&bytes).expect("deserialize should succeed");
            assert_eq!(deserialized.syscall, *syscall);
        }
    }
}
