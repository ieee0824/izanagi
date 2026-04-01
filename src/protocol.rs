//! VM Agent プロトコル定義。
//!
//! virtio-vsock を使った host ↔ guest 間通信のメッセージフォーマット。
//!
//! ## ワイヤーフォーマット
//!
//! ```text
//! +--------+----------+------------------+
//! | type   | length   | body             |
//! | (u8)   | (u32 LE) | (bincode bytes)  |
//! +--------+----------+------------------+
//! ```

use std::collections::HashMap;

use anyhow::Context;
use bincode::Options;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::event::SyscallEvent;

#[cfg(test)]
use crate::event::SyscallCategory;

/// bincode のデシリアライズオプションを返す。
/// サイズ制限と固定長エンコーディングを適用し、悪意あるペイロードによる
/// メモリ過大割り当てを防止する。
fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BODY_SIZE as u64)
}

/// メッセージタイプの識別子。
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Start = 0,
    Stop = 1,
    Event = 2,
    Ready = 3,
    Error = 4,
    Hello = 5,
    Exec = 6,
    ExecResult = 7,
    Shell = 8,
    ShellData = 9,
    ShellClose = 10,
    ShellResize = 11,
}

impl TryFrom<u8> for MessageType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0 => Ok(Self::Start),
            1 => Ok(Self::Stop),
            2 => Ok(Self::Event),
            3 => Ok(Self::Ready),
            4 => Ok(Self::Error),
            5 => Ok(Self::Hello),
            6 => Ok(Self::Exec),
            7 => Ok(Self::ExecResult),
            8 => Ok(Self::Shell),
            9 => Ok(Self::ShellData),
            10 => Ok(Self::ShellClose),
            11 => Ok(Self::ShellResize),
            _ => anyhow::bail!("unknown message type: {}", value),
        }
    }
}

/// プロトコルメッセージ。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Message {
    /// host → agent: トレース開始。
    Start(crate::tracer::TraceFilter),
    /// host → agent: トレース停止。
    Stop,
    /// agent → host: syscall イベント。
    Event(SyscallEvent),
    /// agent → host: エージェント準備完了。
    Ready,
    /// 双方向: エラー通知。
    Error(String),
    /// 双方向: 認証モードネゴシエーション。
    /// `token`: QEMU fw_cfg 経由で渡されるワンタイムトークン（オプション）。
    Hello {
        authenticated: bool,
        token: Option<String>,
    },
    /// host → agent: コマンド実行依頼。
    Exec {
        cmd: Vec<String>,
        env: HashMap<String, String>,
    },
    /// agent → host: コマンド実行結果。
    ExecResult {
        exit_code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// host → agent: 対話シェル起動要求。
    Shell { rows: u16, cols: u16 },
    /// 双方向: シェルデータストリーミング。
    /// `stream`: 0=stdin (host→agent), 1=stdout (agent→host), 2=stderr (agent→host)
    ShellData { stream: u8, data: Vec<u8> },
    /// agent → host: シェル終了通知。
    ShellClose { exit_code: i32 },
    /// host → agent: ターミナルリサイズ。
    ShellResize { rows: u16, cols: u16 },
}

impl Message {
    /// メッセージタイプを返す。
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Start(_) => MessageType::Start,
            Self::Stop => MessageType::Stop,
            Self::Event(_) => MessageType::Event,
            Self::Ready => MessageType::Ready,
            Self::Error(_) => MessageType::Error,
            Self::Hello { .. } => MessageType::Hello,
            Self::Exec { .. } => MessageType::Exec,
            Self::ExecResult { .. } => MessageType::ExecResult,
            Self::Shell { .. } => MessageType::Shell,
            Self::ShellData { .. } => MessageType::ShellData,
            Self::ShellClose { .. } => MessageType::ShellClose,
            Self::ShellResize { .. } => MessageType::ShellResize,
        }
    }
}

/// 最大メッセージボディサイズ (1 MiB)。
/// 実際の SyscallEvent は数百バイト程度なので 1 MiB で十分。
/// これを超えるメッセージは不正とみなす。
const MAX_BODY_SIZE: u32 = 1024 * 1024;

/// シーケンス番号の最大許容ギャップ。これを超えるギャップはエラーとする。
/// 本プロトコルは TCP 上の 1:1 接続で使用し、TCP が順序保証するため
/// 正常時にギャップは発生しない。ギャップ検出は即エラーとする。
const MAX_SEQUENCE_GAP: u64 = 0;

/// メッセージヘッダーのサイズ: type (u8) + length (u32 LE) = 5 バイト。
const HEADER_SIZE: usize = 1 + 4;

/// メッセージをワイヤーフォーマットにエンコードする。
///
/// フォーマット: type (u8) + length (u32 LE) + body (bincode)
///
/// ヘッダー 5 バイトを仮置きし、bincode::serialize_into で body を直接書き込む。
/// 中間 Vec を経由しないため、アロケーションが 1 回で済む (#95)。
pub fn encode_message(msg: &Message) -> anyhow::Result<Vec<u8>> {
    // bincode のシリアライズサイズを事前計算して with_capacity
    let body_size = bincode_options().serialized_size(msg)? as usize;
    if body_size > MAX_BODY_SIZE as usize {
        anyhow::bail!(
            "message body too large: {} bytes (max {})",
            body_size,
            MAX_BODY_SIZE
        );
    }
    let mut buf = Vec::with_capacity(HEADER_SIZE + body_size);
    buf.push(msg.message_type() as u8);
    buf.extend_from_slice(&(0u32).to_le_bytes()); // length は仮置き
    bincode_options().serialize_into(&mut buf, msg)?;

    // 実際のシリアライズサイズから length フィールドを確定（フレームの自己整合性を保証）
    let actual_body_size = buf.len() - HEADER_SIZE;
    if actual_body_size > MAX_BODY_SIZE as usize {
        anyhow::bail!(
            "message body too large: {} bytes (max {})",
            actual_body_size,
            MAX_BODY_SIZE
        );
    }
    buf[1..HEADER_SIZE].copy_from_slice(&(actual_body_size as u32).to_le_bytes());
    Ok(buf)
}

/// ワイヤーフォーマットからメッセージをデコードする。
///
/// デシリアライズ後にヘッダの型とメッセージの型が一致するか検証し、
/// 不一致の場合はエラーを返す。
/// ボディサイズが `MAX_BODY_SIZE` を超える場合もエラーを返す。
pub fn decode_message(data: &[u8]) -> anyhow::Result<Message> {
    if data.len() < HEADER_SIZE {
        anyhow::bail!("message too short: {} bytes", data.len());
    }
    let header_type = MessageType::try_from(data[0])?;
    let length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if length > MAX_BODY_SIZE as usize {
        anyhow::bail!("message body too large: {} bytes", length);
    }
    if data.len() < HEADER_SIZE + length {
        anyhow::bail!(
            "message body incomplete: expected {} bytes, got {}",
            length,
            data.len() - HEADER_SIZE
        );
    }
    let msg: Message = bincode_options().deserialize(&data[HEADER_SIZE..HEADER_SIZE + length])?;

    // ヘッダの型とデシリアライズされたメッセージの型が一致するか検証
    let actual_type = msg.message_type();
    if header_type != actual_type {
        anyhow::bail!(
            "message type mismatch: header says {:?}, body is {:?}",
            header_type,
            actual_type
        );
    }

    Ok(msg)
}

/// `AsyncWrite` にメッセージを書き込む。
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
) -> anyhow::Result<()> {
    let encoded = encode_message(msg)?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

/// `AsyncRead` からメッセージを読み取る。
///
/// ストリームが閉じた場合は `Ok(None)` を返す。
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Option<Message>> {
    // ヘッダー読み取り (type: u8 + length: u32 LE = 5 bytes)
    let mut header = [0u8; HEADER_SIZE];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let header_type = MessageType::try_from(header[0])?;
    let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);

    if length > MAX_BODY_SIZE {
        anyhow::bail!("message body too large: {} bytes", length);
    }

    // ボディ読み取り
    let mut body = vec![0u8; length as usize];
    reader.read_exact(&mut body).await?;

    let msg: Message = bincode_options().deserialize(&body)?;

    // ヘッダの型とデシリアライズされたメッセージの型が一致するか検証
    let actual_type = msg.message_type();
    if header_type != actual_type {
        anyhow::bail!(
            "message type mismatch: header says {:?}, body is {:?}",
            header_type,
            actual_type
        );
    }

    Ok(Some(msg))
}

// ---------------------------------------------------------------------------
// HMAC 認証付きプロトコル (#90)
// ---------------------------------------------------------------------------

/// HMAC-SHA256 のダイジェストサイズ (32 bytes)。
const HMAC_SIZE: usize = 32;

/// HMAC 認証付きワイヤーフォーマット:
///
/// ```text
/// +--------+----------+------------------+----------+--------+
/// | type   | length   | body             | sequence | hmac   |
/// | (u8)   | (u32 LE) | (bincode bytes)  | (u64 LE) | (32B)  |
/// +--------+----------+------------------+----------+--------+
/// ```
///
/// HMAC は type + length + body + sequence 全体に対して計算される。
/// sequence はリプレイ攻撃防止用の単調増加カウンタ。
///
/// 共有シークレットから HMAC-SHA256 を計算する。
/// `parts` はスライスのスライスで、連結せずに順次 `update` する。
fn compute_hmac(secret: &[u8], parts: &[&[u8]]) -> [u8; HMAC_SIZE] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    for part in parts {
        mac.update(part);
    }
    let result = mac.finalize();
    result.into_bytes().into()
}

/// HMAC を検証する。
/// `parts` はスライスのスライスで、連結せずに順次 `update` する。
fn verify_hmac(secret: &[u8], parts: &[&[u8]], expected: &[u8; HMAC_SIZE]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(expected).is_ok()
}

/// HMAC 認証付きでメッセージをエンコードする。
///
/// `sequence` はリプレイ攻撃防止用のシーケンス番号。
/// HMAC の署名対象に含まれる。
pub fn encode_message_authenticated(
    msg: &Message,
    secret: &[u8],
    sequence: u64,
) -> anyhow::Result<Vec<u8>> {
    let body = bincode_options().serialize(msg)?;
    if body.len() > MAX_BODY_SIZE as usize {
        anyhow::bail!(
            "message body too large: {} bytes (max {})",
            body.len(),
            MAX_BODY_SIZE
        );
    }
    let type_byte = [msg.message_type() as u8];
    let length_bytes = (body.len() as u32).to_le_bytes();
    let sequence_bytes = sequence.to_le_bytes();
    let hmac = compute_hmac(secret, &[&type_byte, &length_bytes, &body, &sequence_bytes]);
    let mut buf = Vec::with_capacity(1 + 4 + body.len() + 8 + HMAC_SIZE);
    buf.push(type_byte[0]);
    buf.extend_from_slice(&length_bytes);
    buf.extend_from_slice(&body);
    buf.extend_from_slice(&sequence_bytes);
    buf.extend_from_slice(&hmac);
    Ok(buf)
}

/// HMAC 認証付きで `AsyncWrite` にメッセージを書き込む。
///
/// `sequence` は送信側のシーケンスカウンタ。書き込み後にインクリメントされる。
pub async fn write_message_authenticated<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
    secret: &[u8],
    sequence: &mut u64,
) -> anyhow::Result<()> {
    let encoded = encode_message_authenticated(msg, secret, *sequence)?;
    *sequence = sequence
        .checked_add(1)
        .context("sequence number overflow in write_message_authenticated")?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

/// HMAC 認証付きで `AsyncRead` からメッセージを読み取る。
///
/// HMAC の検証に失敗した場合はエラーを返す。
/// ストリームが閉じた場合は `Ok(None)` を返す。
///
/// `expected_sequence` は受信側の期待シーケンス番号。
/// 受信した sequence が expected 以上であることを検証し、
/// 検証成功後に expected を受信値+1 に更新する。
pub async fn read_message_authenticated<R: AsyncRead + Unpin>(
    reader: &mut R,
    secret: &[u8],
    expected_sequence: &mut u64,
) -> anyhow::Result<Option<Message>> {
    // ヘッダー読み取り (type: u8 + length: u32 LE = 5 bytes)
    let mut header = [0u8; HEADER_SIZE];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let header_type = MessageType::try_from(header[0])?;
    let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);

    if length > MAX_BODY_SIZE {
        anyhow::bail!("message body too large: {} bytes", length);
    }

    // ボディ読み取り
    let mut body = vec![0u8; length as usize];
    reader.read_exact(&mut body).await?;

    // シーケンス番号読み取り (u64 LE = 8 bytes)
    let mut seq_bytes = [0u8; 8];
    reader.read_exact(&mut seq_bytes).await?;
    let received_sequence = u64::from_le_bytes(seq_bytes);

    // HMAC 読み取り
    let mut hmac_bytes = [0u8; HMAC_SIZE];
    reader.read_exact(&mut hmac_bytes).await?;

    // HMAC 検証: type + length + body + sequence に対して計算
    if !verify_hmac(secret, &[&header, &body, &seq_bytes], &hmac_bytes) {
        anyhow::bail!("HMAC verification failed: message authentication failed");
    }

    // シーケンス番号検証: リプレイ攻撃防止
    if received_sequence < *expected_sequence {
        anyhow::bail!(
            "sequence number too old: received {}, expected >= {}",
            received_sequence,
            *expected_sequence
        );
    }

    // ギャップ上限チェック (#201)
    // 注意: ここに到達する時点で received_sequence >= *expected_sequence が保証されている
    // （直前の replay check で received_sequence < *expected_sequence の場合は bail 済み）
    let gap = received_sequence.saturating_sub(*expected_sequence);
    if gap > MAX_SEQUENCE_GAP {
        anyhow::bail!(
            "sequence gap too large: received {}, expected {}, gap {} exceeds max {}",
            received_sequence,
            *expected_sequence,
            gap,
            MAX_SEQUENCE_GAP
        );
    }

    *expected_sequence = received_sequence.checked_add(1).ok_or_else(|| {
        anyhow::anyhow!("sequence number overflow: received {}", received_sequence)
    })?;

    let msg: Message = bincode_options().deserialize(&body)?;

    let actual_type = msg.message_type();
    if header_type != actual_type {
        anyhow::bail!(
            "message type mismatch: header says {:?}, body is {:?}",
            header_type,
            actual_type
        );
    }

    Ok(Some(msg))
}

/// ファイルパスから共有シークレットを読み込む。
/// ファイル内容の前後の空白をトリムする。
pub fn load_shared_secret_from_file(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    // File::open → metadata() で stat を1回にまとめる
    let file = std::fs::File::open(path)
        .with_context(|| format!("共有シークレットファイルの読み込みに失敗: {:?}", path))?;

    // Unix: ファイルパーミッションの検証 (#179)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = file
            .metadata()
            .with_context(|| format!("シークレットファイルのメタデータ取得に失敗: {:?}", path))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o400 {
            anyhow::bail!(
                "シークレットファイル {:?} のパーミッションが {:04o} です。\n修正: chmod 0600 (または 0400) {:?}",
                path,
                mode,
                path
            );
        }
    }

    let mut content = String::new();
    std::io::Read::read_to_string(&mut &file, &mut content)
        .with_context(|| format!("共有シークレットファイルの読み込みに失敗: {:?}", path))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        anyhow::bail!("共有シークレットファイルが空です: {:?}", path);
    }
    Ok(trimmed.as_bytes().to_vec())
}

/// 環境変数から共有シークレットを読み込む。
///
/// 優先順位:
/// 1. `IZANAGI_SECRET_FILE` — ファイルパスからシークレットを読み込む
/// 2. `IZANAGI_SHARED_SECRET` — 値をそのままシークレットとして使用
///
/// いずれも未設定の場合は `Ok(None)` を返す。
/// `IZANAGI_SECRET_FILE` が設定されているが読み込みに失敗した場合はエラーを返す。
pub fn load_shared_secret_from_env() -> anyhow::Result<Option<Vec<u8>>> {
    // まず IZANAGI_SECRET_FILE を確認
    if let Ok(path) = std::env::var("IZANAGI_SECRET_FILE") {
        let path = std::path::Path::new(&path);
        let secret = load_shared_secret_from_file(path)?;
        return Ok(Some(secret));
    }

    // フォールバック: IZANAGI_SHARED_SECRET (非推奨)
    if let Ok(secret) = std::env::var("IZANAGI_SHARED_SECRET") {
        eprintln!(
            "警告: IZANAGI_SHARED_SECRET 環境変数は非推奨です。IZANAGI_SECRET_FILE を使用してください。"
        );
        return Ok(Some(secret.into_bytes()));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Syscall, SyscallArg, SyscallResult};
    use std::time::SystemTime;

    fn make_start_message() -> Message {
        Message::Start(crate::tracer::TraceFilter {
            categories: vec![SyscallCategory::File, SyscallCategory::Network],
            pids: Some(vec![1234, 5678]),
        })
    }

    fn make_event_message() -> Message {
        Message::Event(SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid: 42,
            tgid: 0,
            process_name: "test-proc".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![SyscallArg::Fd(3)],
            result: SyscallResult::Ok(0),
        })
    }

    // --- encode/decode 単体テスト ---

    #[test]
    fn roundtrip_start_message() {
        let msg = make_start_message();
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_stop_message() {
        let msg = Message::Stop;
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_event_message() {
        let msg = make_event_message();
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_ready_message() {
        let msg = Message::Ready;
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_error_message() {
        let msg = Message::Error("something went wrong".to_string());
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_rejects_too_short() {
        let data = vec![0u8; 3];
        assert!(decode_message(&data).is_err());
    }

    #[test]
    fn decode_rejects_unknown_type() {
        let mut data = vec![255u8]; // unknown type
        data.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode_message(&data).is_err());
    }

    #[test]
    fn decode_rejects_type_mismatch() {
        // Start メッセージをエンコードしてからヘッダの type を Stop に書き換え
        let msg = make_start_message();
        let mut encoded = encode_message(&msg).unwrap();
        encoded[0] = MessageType::Stop as u8; // ヘッダを改ざん
        let result = decode_message(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("type mismatch"));
    }

    #[test]
    fn decode_rejects_truncated_body() {
        let msg = make_start_message();
        let mut encoded = encode_message(&msg).unwrap();
        encoded.truncate(encoded.len() - 5); // body を切り詰め
        assert!(decode_message(&encoded).is_err());
    }

    #[test]
    fn message_type_is_correct() {
        assert_eq!(make_start_message().message_type(), MessageType::Start);
        assert_eq!(Message::Stop.message_type(), MessageType::Stop);
        assert_eq!(make_event_message().message_type(), MessageType::Event);
        assert_eq!(Message::Ready.message_type(), MessageType::Ready);
        assert_eq!(
            Message::Error("e".into()).message_type(),
            MessageType::Error
        );
        assert_eq!(
            Message::Hello {
                authenticated: true,
                token: None,
            }
            .message_type(),
            MessageType::Hello
        );
        assert_eq!(
            Message::Exec {
                cmd: vec!["echo".into()],
                env: HashMap::new(),
            }
            .message_type(),
            MessageType::Exec
        );
        assert_eq!(
            Message::ExecResult {
                exit_code: 0,
                stdout: vec![],
                stderr: vec![],
            }
            .message_type(),
            MessageType::ExecResult
        );
    }

    #[test]
    fn roundtrip_hello_message() {
        let msg = Message::Hello {
            authenticated: true,
            token: None,
        };
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);

        let msg = Message::Hello {
            authenticated: false,
            token: None,
        };
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);

        let msg = Message::Hello {
            authenticated: true,
            token: Some("abcdef1234567890".to_string()),
        };
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn header_format_is_correct() {
        let msg = Message::Stop;
        let encoded = encode_message(&msg).unwrap();
        // type = 1 (Stop)
        assert_eq!(encoded[0], 1);
        // length is u32 LE
        let len = u32::from_le_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
        assert_eq!(len as usize, encoded.len() - HEADER_SIZE);
    }

    // --- async read/write テスト (tokio::io::duplex) ---

    #[tokio::test]
    async fn async_roundtrip_all_message_types() {
        let messages = vec![
            make_start_message(),
            Message::Stop,
            make_event_message(),
            Message::Ready,
            Message::Error("test error".to_string()),
            Message::Hello {
                authenticated: true,
                token: None,
            },
            Message::Hello {
                authenticated: false,
                token: None,
            },
            Message::Exec {
                cmd: vec!["echo".into(), "hello".into()],
                env: HashMap::new(),
            },
            Message::ExecResult {
                exit_code: 0,
                stdout: b"hello\n".to_vec(),
                stderr: vec![],
            },
        ];

        let (mut client, mut server) = tokio::io::duplex(4096);

        // 全メッセージを書き込み
        for msg in &messages {
            write_message(&mut client, msg).await.unwrap();
        }
        drop(client); // EOF を送る

        // 全メッセージを読み取り
        let mut received = Vec::new();
        while let Some(msg) = read_message(&mut server).await.unwrap() {
            received.push(msg);
        }

        assert_eq!(messages, received);
    }

    #[tokio::test]
    async fn async_read_returns_none_on_eof() {
        let (_client, mut server) = tokio::io::duplex(64);
        drop(_client); // 即座に EOF
        let result = read_message(&mut server).await.unwrap();
        assert!(result.is_none());
    }

    // --- HMAC 認証テスト ---

    #[tokio::test]
    async fn authenticated_roundtrip_all_message_types() {
        let key = b"test-hmac-signing-key-1234567890";
        let messages = vec![
            make_start_message(),
            Message::Stop,
            make_event_message(),
            Message::Ready,
            Message::Error("test error".to_string()),
            Message::Hello {
                authenticated: true,
                token: None,
            },
        ];

        let (mut client, mut server) = tokio::io::duplex(4096);

        let mut send_seq = 0u64;
        for msg in &messages {
            write_message_authenticated(&mut client, msg, key, &mut send_seq)
                .await
                .unwrap();
        }
        drop(client);

        let mut recv_seq = 0u64;
        let mut received = Vec::new();
        while let Some(msg) = read_message_authenticated(&mut server, key, &mut recv_seq)
            .await
            .unwrap()
        {
            received.push(msg);
        }

        assert_eq!(messages, received);
        assert_eq!(send_seq, messages.len() as u64);
        assert_eq!(recv_seq, messages.len() as u64);
    }

    #[tokio::test]
    async fn authenticated_rejects_wrong_key() {
        let key = b"correct-hmac-key-for-testing-abc";
        let wrong_key = b"wrong-hmac-key-for-testing-1234";

        let (mut client, mut server) = tokio::io::duplex(4096);

        let mut send_seq = 0u64;
        write_message_authenticated(&mut client, &Message::Ready, key, &mut send_seq)
            .await
            .unwrap();
        drop(client);

        let mut recv_seq = 0u64;
        let result = read_message_authenticated(&mut server, wrong_key, &mut recv_seq).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("HMAC verification failed")
        );
    }

    #[tokio::test]
    async fn authenticated_rejects_tampered_body() {
        let key = b"test-hmac-key-for-tamper-detect";

        let encoded = encode_message_authenticated(&Message::Ready, key, 0).unwrap();
        // ボディを改竄 (type バイトを変更)
        let mut tampered = encoded.clone();
        tampered[0] ^= 0xFF;

        let mut reader = &tampered[..];
        let mut recv_seq = 0u64;
        let result = read_message_authenticated(&mut reader, key, &mut recv_seq).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticated_rejects_body_tamper() {
        let key = b"test-hmac-key-for-body-tamper-00";

        // body を持つメッセージをエンコード
        let msg = Message::Error("hello world".to_string());
        let encoded = encode_message_authenticated(&msg, key, 0).unwrap();

        // body 領域の特定バイトを改竄（body は HEADER_SIZE から開始）
        let mut tampered = encoded.clone();
        assert!(
            tampered.len() > HEADER_SIZE + 1,
            "encoded message must have body bytes"
        );
        tampered[HEADER_SIZE + 1] ^= 0x01; // body の 2 バイト目を反転

        let mut reader = &tampered[..];
        let mut recv_seq = 0u64;
        let result = read_message_authenticated(&mut reader, key, &mut recv_seq).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("HMAC verification failed")
        );
    }

    #[tokio::test]
    async fn authenticated_rejects_replayed_sequence() {
        let key = b"test-hmac-key-for-replay-detect";

        // sequence=0 のメッセージをエンコード
        let encoded = encode_message_authenticated(&Message::Ready, key, 0).unwrap();

        // 最初の読み取りは成功（expected_sequence=0）
        let mut reader = &encoded[..];
        let mut recv_seq = 0u64;
        let msg = read_message_authenticated(&mut reader, key, &mut recv_seq)
            .await
            .unwrap();
        assert!(msg.is_some());
        assert_eq!(recv_seq, 1); // expected は 1 に更新

        // 同じ sequence=0 のメッセージをもう一度読み取る → リプレイ検知でエラー
        let mut reader = &encoded[..];
        let result = read_message_authenticated(&mut reader, key, &mut recv_seq).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("sequence number too old")
        );
    }

    #[tokio::test]
    async fn authenticated_rejects_skipped_sequence() {
        let key = b"test-hmac-key-for-skip-sequence";

        // sequence=5 のメッセージをエンコード（0〜4 をスキップ）
        let encoded = encode_message_authenticated(&Message::Ready, key, 5).unwrap();

        let mut reader = &encoded[..];
        let mut recv_seq = 0u64;
        // MAX_SEQUENCE_GAP=0 のため、ギャップはエラーになる
        let result = read_message_authenticated(&mut reader, key, &mut recv_seq).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("sequence gap too large")
        );
    }

    // --- #105: シークレットファイル読み込みテスト ---

    #[test]
    fn load_shared_secret_from_file_reads_and_trims() {
        let dir = std::env::temp_dir().join("izanagi_test_secret");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("secret.txt");
        std::fs::write(&path, "  my-secret-key\n  ").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let secret = load_shared_secret_from_file(&path).unwrap();
        assert_eq!(secret, b"my-secret-key");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_shared_secret_from_file_rejects_empty() {
        let dir = std::env::temp_dir().join("izanagi_test_secret");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty_secret.txt");
        std::fs::write(&path, "   \n  ").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let result = load_shared_secret_from_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("空です"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_shared_secret_from_file_rejects_missing() {
        let path = std::path::Path::new("/tmp/izanagi_nonexistent_secret_file");
        let result = load_shared_secret_from_file(path);
        assert!(result.is_err());
    }

    // --- Task 350: oversize message test ---

    #[tokio::test]
    async fn async_read_rejects_oversized_body() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(1024);
        // Write header: type=1 (Stop), length=MAX_BODY_SIZE+1
        let msg_type: u8 = 1;
        let length: u32 = MAX_BODY_SIZE + 1;
        client.write_all(&[msg_type]).await.unwrap();
        client.write_all(&length.to_le_bytes()).await.unwrap();
        drop(client);
        let result = read_message(&mut server).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("message body too large")
        );
    }

    // --- Task 351: secret file permission tests ---

    #[cfg(unix)]
    #[test]
    fn load_shared_secret_rejects_0644_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("izanagi_test_secret_perm");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("secret_0644.txt");
        std::fs::write(&path, "mysecret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = load_shared_secret_from_file(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("パーミッション"));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn load_shared_secret_rejects_0755_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("izanagi_test_secret_perm");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("secret_0755.txt");
        std::fs::write(&path, "mysecret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = load_shared_secret_from_file(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("パーミッション"));
        let _ = std::fs::remove_file(&path);
    }

    // --- Task 356: sequence number overflow test ---

    #[tokio::test]
    async fn authenticated_write_rejects_sequence_overflow() {
        let secret = b"test-secret-for-overflow-check!";
        let (_client, server) = tokio::io::duplex(4096);
        let (_reader, mut writer) = tokio::io::split(server);
        let mut seq = u64::MAX;
        let msg = Message::Ready;
        let result = write_message_authenticated(&mut writer, &msg, secret, &mut seq).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("sequence number overflow")
        );
    }
}
