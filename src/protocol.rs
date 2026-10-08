//! VM Agent プロトコル定義。
//!
//! virtio-vsock を使った host ↔ guest 間通信のメッセージフォーマット。
//!
//! ## ワイヤーフォーマット
//!
//! ```text
//! magic (0xff) + version (2) + type (u8) + length (u32 LE) + body (postcard)
//! Version 1 (bincode) is deliberately rejected; upgrade host and agent together.
//! ```

use std::collections::HashMap;

use crate::wire_codec;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::event::SyscallEvent;

#[cfg(test)]
use crate::event::SyscallCategory;

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
    TraceStarted = 12,
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
            12 => Ok(Self::TraceStarted),
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
    /// agent → host: tracing is active; emitted only after successful Start.
    TraceStarted,
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
            Self::TraceStarted => MessageType::TraceStarted,
        }
    }
}

/// 最大メッセージボディサイズ (1 MiB)。
/// 実際の SyscallEvent は数百バイト程度なので 1 MiB で十分。
/// これを超えるメッセージは不正とみなす。
const MAX_BODY_SIZE: u32 = wire_codec::MAX_BODY_SIZE as u32;
const WIRE_MAGIC: u8 = 0xff;
const WIRE_VERSION: u8 = 2;

/// シーケンス番号の最大許容ギャップ。これを超えるギャップはエラーとする。
/// 本プロトコルは TCP 上の 1:1 接続で使用し、TCP が順序保証するため
/// 正常時にギャップは発生しない。ギャップ検出は即エラーとする。
const MAX_SEQUENCE_GAP: u64 = 0;

/// Header: magic (u8) + version (u8) + type (u8) + length (u32 LE).
const HEADER_SIZE: usize = 2 + 1 + 4;

fn parse_header(header: &[u8; HEADER_SIZE]) -> anyhow::Result<(MessageType, u32)> {
    if header[0] != WIRE_MAGIC || header[1] != WIRE_VERSION {
        anyhow::bail!("incompatible protocol version; upgrade host and agent together");
    }
    let message_type = MessageType::try_from(header[2])?;
    let length = u32::from_le_bytes(header[3..7].try_into().unwrap());
    if length > MAX_BODY_SIZE {
        anyhow::bail!("message body too large: {} bytes", length);
    }
    Ok((message_type, length))
}

/// Connection-owned, cancellation-safe protocol receiver.
///
/// Keep this receiver for the entire connection, including handshake and shell
/// transitions. Cancelling `recv` preserves all consumed bytes. Authentication
/// mode and the sequence counter must remain the same when resuming a receive.
pub struct MessageReader<R> {
    reader: R,
    frame: Vec<u8>,
    filled: usize,
    failed: bool,
}

impl<R: AsyncRead + Unpin> MessageReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            frame: Vec::new(),
            filled: 0,
            failed: false,
        }
    }

    async fn fill_to(&mut self, target: usize) -> anyhow::Result<bool> {
        if self.frame.len() < target {
            self.frame.resize(target, 0);
        }
        while self.filled < target {
            let n = self
                .reader
                .read(&mut self.frame[self.filled..target])
                .await?;
            if n == 0 {
                if self.filled == 0 {
                    return Ok(false);
                }
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            // No await between consuming bytes and committing their position.
            self.filled += n;
        }
        Ok(true)
    }

    pub async fn recv(
        &mut self,
        auth_key: Option<&[u8]>,
        expected_sequence: &mut u64,
    ) -> anyhow::Result<Option<Message>> {
        if self.failed {
            anyhow::bail!("protocol receiver failed; close the connection");
        }
        let result = self.recv_frame(auth_key, expected_sequence).await;
        if result.is_err() {
            // A malformed/truncated frame cannot be retried as a new header.
            self.failed = true;
        } else {
            self.frame.clear();
            self.filled = 0;
        }
        result
    }

    async fn recv_frame(
        &mut self,
        auth_key: Option<&[u8]>,
        expected_sequence: &mut u64,
    ) -> anyhow::Result<Option<Message>> {
        if !self.fill_to(1).await? {
            return Ok(None);
        }
        if self.frame[0] != WIRE_MAGIC {
            anyhow::bail!("incompatible protocol version; upgrade host and agent together");
        }
        self.fill_to(2).await?;
        if self.frame[1] != WIRE_VERSION {
            anyhow::bail!("unsupported protocol version: {}", self.frame[1]);
        }
        self.fill_to(HEADER_SIZE).await?;
        // Validate the size before allocating body/trailer storage.
        let (_, length) = parse_header(self.frame[..HEADER_SIZE].try_into().unwrap())?;
        let body_end = HEADER_SIZE + length as usize;
        let frame_end = body_end + if auth_key.is_some() { 8 + HMAC_SIZE } else { 0 };
        self.fill_to(frame_end).await?;
        let message = match auth_key {
            Some(key) => {
                decode_authenticated_message(&self.frame, body_end, key, expected_sequence)?
            }
            None => decode_message(&self.frame)?,
        };
        Ok(Some(message))
    }
}

/// メッセージをワイヤーフォーマットにエンコードする。
///
/// フォーマット: magic + version + type (u8) + length (u32 LE) + body (postcard)
///
pub fn encode_message(msg: &Message) -> anyhow::Result<Vec<u8>> {
    let body = wire_codec::encode(msg)?;
    let mut buf = Vec::with_capacity(HEADER_SIZE + body.len());
    buf.extend_from_slice(&[WIRE_MAGIC, WIRE_VERSION, msg.message_type() as u8]);
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
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
    let (header_type, length) = parse_header(data[..HEADER_SIZE].try_into().unwrap())?;
    let length = length as usize;
    if data.len() < HEADER_SIZE + length {
        anyhow::bail!(
            "message body incomplete: expected {} bytes, got {}",
            length,
            data.len() - HEADER_SIZE
        );
    }
    if data.len() != HEADER_SIZE + length {
        anyhow::bail!("trailing bytes after message frame");
    }
    let msg: Message = wire_codec::decode(&data[HEADER_SIZE..])?;

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
/// One-shot API: if this future is cancelled, close the connection. Use a
/// connection-owned `MessageReader` when receives can be retried after cancellation.
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Option<Message>> {
    MessageReader::new(reader).recv(None, &mut 0).await
}

// ---------------------------------------------------------------------------
// HMAC 認証付きプロトコル (#90)
// ---------------------------------------------------------------------------

/// HMAC-SHA256 のダイジェストサイズ (32 bytes)。
const HMAC_SIZE: usize = 32;

/// HMAC 認証付きワイヤーフォーマット:
///
/// ```text
/// magic + version + type + length + body + sequence (u64 LE) + hmac (32B)
/// ```
///
/// HMAC は magic + version + type + length + body + sequence 全体に対して計算される。
/// sequence はリプレイ攻撃防止用の単調増加カウンタ。
///
/// 共有シークレットから HMAC-SHA256 を計算する。
/// `parts` はスライスのスライスで、連結せずに順次 `update` する。
fn compute_hmac(secret: &[u8], parts: &[&[u8]]) -> [u8; HMAC_SIZE] {
    use hmac::{Hmac, KeyInit, Mac};
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
    use hmac::{Hmac, KeyInit, Mac};
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
    let mut buf = encode_message(msg)?;
    let sequence_bytes = sequence.to_le_bytes();
    let hmac = compute_hmac(secret, &[&buf, &sequence_bytes]);
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
/// One-shot API; keep a `MessageReader` across cancellable receives instead.
pub async fn read_message_authenticated<R: AsyncRead + Unpin>(
    reader: &mut R,
    secret: &[u8],
    expected_sequence: &mut u64,
) -> anyhow::Result<Option<Message>> {
    MessageReader::new(reader)
        .recv(Some(secret), expected_sequence)
        .await
}

fn decode_authenticated_message(
    frame: &[u8],
    body_end: usize,
    auth_key: &[u8],
    expected_sequence: &mut u64,
) -> anyhow::Result<Message> {
    let seq_bytes: &[u8; 8] = frame[body_end..body_end + 8].try_into().unwrap();
    let hmac_bytes: &[u8; HMAC_SIZE] = frame[body_end + 8..].try_into().unwrap();
    let received_sequence = u64::from_le_bytes(*seq_bytes);

    // HMAC 検証: type + length + body + sequence に対して計算
    if !verify_hmac(auth_key, &[&frame[..body_end], seq_bytes], hmac_bytes) {
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

    let next_sequence = received_sequence.checked_add(1).ok_or_else(|| {
        anyhow::anyhow!("sequence number overflow: received {}", received_sequence)
    })?;

    let msg = decode_message(&frame[..body_end])?;

    *expected_sequence = next_sequence;
    Ok(msg)
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
    fn v2_fixed_wire_fixtures() {
        for (message, fixture) in [
            (Message::Stop, vec![0xff, 2, 1, 1, 0, 0, 0, 1]),
            (Message::Ready, vec![0xff, 2, 3, 1, 0, 0, 0, 3]),
            (Message::TraceStarted, vec![0xff, 2, 12, 1, 0, 0, 0, 12]),
            (
                Message::Error("x".into()),
                vec![0xff, 2, 4, 3, 0, 0, 0, 4, 1, b'x'],
            ),
            (
                Message::Hello {
                    authenticated: false,
                    token: None,
                },
                vec![0xff, 2, 5, 3, 0, 0, 0, 5, 0, 0],
            ),
        ] {
            assert_eq!(encode_message(&message).unwrap(), fixture);
            assert_eq!(decode_message(&fixture).unwrap(), message);
        }
    }

    #[test]
    fn roundtrip_every_v2_message_variant() {
        let messages = vec![
            make_start_message(),
            Message::Stop,
            Message::TraceStarted,
            make_event_message(),
            Message::Ready,
            Message::Error("失敗".into()),
            Message::Hello {
                authenticated: true,
                token: Some("token".into()),
            },
            Message::Exec {
                cmd: vec!["echo".into(), "hello".into()],
                env: HashMap::from([("A".into(), "B".into())]),
            },
            Message::ExecResult {
                exit_code: -1,
                stdout: vec![0, 255],
                stderr: vec![128],
            },
            Message::Shell { rows: 24, cols: 80 },
            Message::ShellData {
                stream: 2,
                data: vec![0, 255, 128],
            },
            Message::ShellClose { exit_code: -2 },
            Message::ShellResize {
                rows: 40,
                cols: 120,
            },
        ];
        for message in messages {
            assert_eq!(
                decode_message(&encode_message(&message).unwrap()).unwrap(),
                message
            );
        }
    }

    #[tokio::test]
    async fn legacy_peers_are_rejected_without_waiting_for_body() {
        for authenticated in [false, true] {
            let (mut client, mut server) = tokio::io::duplex(64);
            // v1 Stop frame. Keep the stream open to catch blocking on a longer v2 header.
            client
                .write_all(&[1, 4, 0, 0, 0, 1, 0, 0, 0])
                .await
                .unwrap();
            let secret = rand::random::<[u8; 32]>();
            let mut sequence = 0;
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                if authenticated {
                    read_message_authenticated(&mut server, &secret, &mut sequence).await
                } else {
                    read_message(&mut server).await
                }
            })
            .await
            .unwrap();
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("incompatible protocol")
            );
            assert_eq!(sequence, 0);
        }
        // A v1 reader's type parser rejects the first byte of every v2 frame.
        assert!(MessageType::try_from(encode_message(&Message::Stop).unwrap()[0]).is_err());
    }

    #[tokio::test]
    async fn unknown_version_and_partial_headers_are_errors() {
        let mut unsupported = &[WIRE_MAGIC, 99][..];
        assert!(
            read_message(&mut unsupported)
                .await
                .unwrap_err()
                .to_string()
                .contains("version")
        );
        for count in 1..HEADER_SIZE {
            let frame = encode_message(&Message::Ready).unwrap();
            let mut partial = &frame[..count];
            assert!(read_message(&mut partial).await.is_err());
        }
    }

    #[test]
    fn reject_trailing_frame_and_body_bytes() {
        let mut frame = encode_message(&Message::Stop).unwrap();
        frame.push(0);
        assert!(decode_message(&frame).is_err());
        frame[3..7].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            decode_message(&frame)
                .unwrap_err()
                .to_string()
                .contains("trailing")
        );
    }

    #[test]
    fn body_size_boundary_is_enforced_during_encoding() {
        // Error variant + three-byte string length prefix occupy four bytes.
        let message = Message::Error("x".repeat(MAX_BODY_SIZE as usize - 4));
        let frame = encode_message(&message).unwrap();
        assert_eq!(frame.len(), HEADER_SIZE + MAX_BODY_SIZE as usize);
        assert_eq!(decode_message(&frame).unwrap(), message);
        let oversized = Message::Error("x".repeat(MAX_BODY_SIZE as usize - 3));
        assert!(encode_message(&oversized).is_err());
        let secret = rand::random::<[u8; 32]>();
        assert!(encode_message_authenticated(&oversized, &secret, 0).is_err());
    }

    #[tokio::test]
    async fn authenticated_header_tampering_and_invalid_body_are_rejected() {
        let secret = rand::random::<[u8; 32]>();
        let frame = encode_message_authenticated(&Message::Ready, &secret, 0).unwrap();
        for index in [0, 1, 2, HEADER_SIZE] {
            let mut tampered = frame.clone();
            tampered[index] ^= 1;
            let mut reader = tampered.as_slice();
            let mut sequence = 0;
            assert!(
                read_message_authenticated(&mut reader, &secret, &mut sequence)
                    .await
                    .is_err()
            );
            assert_eq!(sequence, 0);
        }
        // A valid MAC does not make malformed postcard bytes valid. No sequence commit.
        let mut invalid = vec![WIRE_MAGIC, WIRE_VERSION, 3, 1, 0, 0, 0, 255];
        let sequence_bytes = 0u64.to_le_bytes();
        let tag = compute_hmac(&secret, &[&invalid, &sequence_bytes]);
        invalid.extend_from_slice(&sequence_bytes);
        invalid.extend_from_slice(&tag);
        let mut reader = invalid.as_slice();
        let mut sequence = 0;
        assert!(
            read_message_authenticated(&mut reader, &secret, &mut sequence)
                .await
                .is_err()
        );
        assert_eq!(sequence, 0);
    }

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
        encoded[2] = MessageType::Stop as u8; // ヘッダを改ざん
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
        assert_eq!(&encoded[..3], &[WIRE_MAGIC, WIRE_VERSION, 1]);
        // length is u32 LE
        let len = u32::from_le_bytes(encoded[3..7].try_into().unwrap());
        assert_eq!(len as usize, encoded.len() - HEADER_SIZE);
    }

    // --- async read/write テスト (tokio::io::duplex) ---

    #[tokio::test]
    async fn async_roundtrip_all_message_types() {
        let messages = vec![
            make_start_message(),
            Message::Stop,
            Message::TraceStarted,
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
        let key = &rand::random::<[u8; 32]>();
        let messages = vec![
            make_start_message(),
            Message::Stop,
            Message::TraceStarted,
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
        let key = &rand::random::<[u8; 32]>();
        let mut wrong_key_bytes = *key;
        wrong_key_bytes[0] ^= 1;
        let wrong_key = &wrong_key_bytes;

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
        let key = &rand::random::<[u8; 32]>();

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
        let key = &rand::random::<[u8; 32]>();

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
        let key = &rand::random::<[u8; 32]>();

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
        let key = &rand::random::<[u8; 32]>();

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
        client
            .write_all(&[WIRE_MAGIC, WIRE_VERSION, msg_type])
            .await
            .unwrap();
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
        let secret = &rand::random::<[u8; 32]>();
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

    #[tokio::test]
    async fn cancelled_authenticated_receive_rejects_invalid_frame_without_advancing_sequence() {
        let auth_key = rand::random::<[u8; 32]>();
        for mode in ["mac", "type", "sequence"] {
            let mut frame = encode_message_authenticated(&Message::Ready, &auth_key, 0).unwrap();
            let body_end = frame.len() - 8 - HMAC_SIZE;
            match mode {
                "mac" => *frame.last_mut().unwrap() ^= 1,
                "type" => frame[2] = MessageType::Stop as u8,
                "sequence" => frame[body_end] = 1,
                _ => unreachable!(),
            }
            if mode != "mac" {
                let mac = compute_hmac(&auth_key, &[&frame[..body_end + 8]]);
                frame[body_end + 8..].copy_from_slice(&mac);
            }
            let (mut peer, reader) = tokio::io::duplex(4096);
            let mut reader = MessageReader::new(reader);
            let mut sequence = 0;
            peer.write_all(&frame[..frame.len() - 1]).await.unwrap();
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(1),
                    reader.recv(Some(&auth_key), &mut sequence)
                )
                .await
                .is_err()
            );
            assert_eq!(sequence, 0);
            peer.write_all(&frame[frame.len() - 1..]).await.unwrap();
            let error = reader
                .recv(Some(&auth_key), &mut sequence)
                .await
                .unwrap_err()
                .to_string();
            let expected = match mode {
                "mac" => "HMAC verification failed",
                "type" => "message type mismatch",
                _ => "sequence gap too large",
            };
            assert!(error.contains(expected), "{mode}: {error}");
            assert_eq!(sequence, 0);
            assert!(
                reader
                    .recv(Some(&auth_key), &mut sequence)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("receiver failed")
            );
        }
    }

    #[tokio::test]
    async fn stateful_receiver_rejects_oversized_header_before_allocating_body() {
        let auth_key = rand::random::<[u8; 32]>();
        for authenticated in [false, true] {
            let mut header = [
                WIRE_MAGIC,
                WIRE_VERSION,
                MessageType::Ready as u8,
                0,
                0,
                0,
                0,
            ];
            header[3..].copy_from_slice(&(MAX_BODY_SIZE + 1).to_le_bytes());
            let (mut peer, reader) = tokio::io::duplex(4096);
            peer.write_all(&header).await.unwrap();
            let mut reader = MessageReader::new(reader);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                reader.recv(authenticated.then_some(&auth_key[..]), &mut 0),
            )
            .await
            .unwrap();
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("message body too large")
            );
            assert_eq!(reader.frame.len(), HEADER_SIZE);
        }
    }
}
