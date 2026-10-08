//! QEMU ベースの VM 隔離サンドボックス実装。
//!
//! macOS (Apple Silicon) 向けに以下の制約を考慮:
//! - virtio-fs の代わりに virtio-9p を使用
//! - virtio-vsock の代わりに TCP (localhost) を使用
//! - HVF (`-accel hvf`) でアクセラレーション

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use crate::pcap_writer::{Direction, PcapWriter};
use crate::protocol::{Message, load_shared_secret_from_env};
use crate::sandbox::{ExecOutput, Sandbox, SandboxConfig, SandboxStatus, ShareConfig};

/// TCP 接続の永続化された状態。
/// `up()` で確立した接続を `exec()` / `shell()` で使い回す。
/// 内部の `ProtocolClient` が HMAC 認証の分岐を隠蔽する。
struct PersistentConnection {
    client: crate::protocol_client::ProtocolClient<ReadHalf<TcpStream>, WriteHalf<TcpStream>>,
    /// 接続が切断されたかどうか。一度 true になったら再利用不可。
    /// 再接続にはシーケンス番号と HMAC 状態のリセットが必要なため、
    /// `down()` → `up()` で接続全体を再確立する必要がある。
    broken: bool,
}

/// QEMU イメージのキャッシュディレクトリ。
const IMAGE_CACHE_DIR: &str = ".izanagi/images";

/// Agent が Listen する VM 内部のポート。
const AGENT_PORT: u16 = 9001;

/// VM ブート待ちのデフォルトタイムアウト (秒)。
const BOOT_TIMEOUT_SECS: u64 = 120;

/// 現在の OS・アーキテクチャに応じた QEMU バイナリパスを返す。
/// macOS aarch64 のみ Homebrew のフルパス。それ以外は PATH から解決。
/// カスタムパスが必要な場合は `with_qemu_binary()` でオーバーライド可能。
fn default_qemu_binary() -> &'static str {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "/opt/homebrew/bin/qemu-system-aarch64"
    } else if cfg!(target_arch = "aarch64") {
        "qemu-system-aarch64"
    } else {
        "qemu-system-x86_64"
    }
}

/// QEMU の stdout/stderr から保持する最大バイト数（エラー診断用）。
const QEMU_OUTPUT_CAPTURE_BYTES: usize = 8192;

/// イメージキャッシュのベースディレクトリを返す。
fn image_cache_dir() -> PathBuf {
    dirs_home().join(IMAGE_CACHE_DIR)
}

/// ホームディレクトリを返す。
fn dirs_home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
}

/// イメージパスを解決する。
///
/// - 絶対パスの場合はそのまま返す
/// - "default" の場合はキャッシュディレクトリのデフォルトイメージ
/// - それ以外はキャッシュディレクトリ内のイメージ名として解決
pub fn resolve_image_path(image: &str) -> PathBuf {
    let p = Path::new(image);
    if p.is_absolute() {
        p.to_path_buf()
    } else if image == "default" {
        image_cache_dir().join("debian-aarch64.qcow2")
    } else {
        image_cache_dir().join(format!("{}.qcow2", image))
    }
}

/// イメージが存在するかチェックする。
pub fn check_image_exists(image: &str) -> anyhow::Result<PathBuf> {
    let path = resolve_image_path(image);
    if !path.exists() {
        anyhow::bail!(
            "VM image not found: {}. Place the image at {} or specify an absolute path.",
            image,
            path.display()
        );
    }
    Ok(path)
}

/// `build_qemu_args` に渡すパラメータをまとめた構造体。
pub struct QemuArgsParams<'a> {
    pub image_path: &'a Path,
    pub cpus: u32,
    pub memory_mb: u32,
    pub share: &'a ShareConfig,
    pub host_port: u16,
    pub token: Option<&'a str>,
    pub secret: Option<&'a str>,
    pub dns_proxy: Option<&'a str>,
}

/// QEMU コマンドライン引数を構築する。
///
/// `token` にファイルパスが指定された場合、`-fw_cfg name=opt/izanagi.token,file=<path>` で
/// ゲストにトークンを渡す。file= 形式により ps でトークンが表示されない。
/// Agent はこのトークンを `/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.token/raw` から
/// 読み取り、Hello ハンドシェイク時に検証する。
/// プラットフォーム依存の引数（UEFI、アクセラレーション、マシンタイプ）を追加する。
fn push_platform_args(args: &mut Vec<String>) {
    // UEFI ファームウェア (aarch64 の Alpine/Ubuntu 等は UEFI ブート必須)
    if cfg!(target_arch = "aarch64") {
        let bios = if cfg!(target_os = "macos") {
            "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
        } else {
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"
        };
        args.extend_from_slice(&["-bios".to_string(), bios.to_string()]);
    }

    // アクセラレーション
    let accel = if cfg!(target_os = "macos") {
        "hvf"
    } else {
        "kvm"
    };
    args.extend_from_slice(&["-accel".to_string(), accel.to_string()]);

    // Machine type
    let machine = if cfg!(target_arch = "aarch64") {
        "virt"
    } else {
        "q35"
    };
    args.extend_from_slice(&["-machine".to_string(), machine.to_string()]);
}

pub fn build_qemu_args(params: &QemuArgsParams<'_>) -> Vec<String> {
    let QemuArgsParams {
        image_path,
        cpus,
        memory_mb,
        share,
        host_port,
        token,
        secret,
        dns_proxy,
    } = params;
    let mut args = Vec::new();

    push_platform_args(&mut args);

    // 注意: QEMU monitor は shutdown_qemu() で stdin 経由の system_powerdown に使用するため
    // 無効化しない。snapshot=on のオーバーレイは QEMU プロセス終了時に自動破棄されるため、
    // monitor 経由の commit コマンドによる永続化リスクは VM 内部からはアクセスできない。

    // CPU・メモリ・SMP
    args.extend_from_slice(&["-cpu".to_string(), "host".to_string()]);
    args.extend_from_slice(&["-m".to_string(), format!("{}M", memory_mb)]);
    args.extend_from_slice(&["-smp".to_string(), cpus.to_string()]);

    // ディスク — snapshot=on でオーバーレイを使用し元イメージを保護 (#192)
    // VM 内の書き込みは一時オーバーレイに記録され、停止時に破棄される。
    // ランサムウェア等による暗号化からベースイメージを保護する。
    // 注意: virtio-9p 経由の共有ディレクトリはホスト側ファイルシステムに
    // 直接書き込まれるため、snapshot の保護対象外。
    args.extend_from_slice(&[
        "-drive".to_string(),
        format!("file={},format=qcow2,snapshot=on", image_path.display()),
    ]);

    // virtio-9p ファイル共有 (#37)
    if let Some(host_path) = share.host_paths.first() {
        args.extend_from_slice(&[
            "-fsdev".to_string(),
            format!(
                "local,id=fs0,path={},security_model=mapped-xattr",
                host_path.display()
            ),
        ]);
        args.extend_from_slice(&[
            "-device".to_string(),
            "virtio-9p-pci,fsdev=fs0,mount_tag=workspace".to_string(),
        ]);
    }

    // ネットワーク (TCP ポートフォワーディング + DNS プロキシ)
    let mut netdev = format!("user,id=net0,hostfwd=tcp::{}-:{}", host_port, AGENT_PORT);
    if let Some(dns_ip) = dns_proxy {
        netdev.push_str(&format!(",dns={}", dns_ip));
    }
    args.extend_from_slice(&["-netdev".to_string(), netdev]);
    args.extend_from_slice(&[
        "-device".to_string(),
        "virtio-net-pci,netdev=net0".to_string(),
    ]);

    // ヘッドレスモード
    args.push("-nographic".to_string());

    // fw_cfg でゲストにトークン・シークレットを渡す (#115, #161)
    // Agent は /sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.{token,secret}/raw から読み取る
    // file= 形式で渡すことで ps にトークンが表示されない
    if let Some(token_file) = token {
        args.extend_from_slice(&[
            "-fw_cfg".to_string(),
            format!("name=opt/izanagi.token,file={}", token_file),
        ]);
    }
    if let Some(secret_file) = secret {
        args.extend_from_slice(&[
            "-fw_cfg".to_string(),
            format!("name=opt/izanagi.secret,file={}", secret_file),
        ]);
    }

    args
}

/// セッショントークン（32 バイト = 64 文字 hex）を生成する。
fn generate_token() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

/// 0600 パーミッションの一時ファイルにデータを書き込む。
/// トークンファイルとシークレットファイルの作成で共通利用する。
fn write_secure_temp_file(prefix: &str, content: &[u8]) -> anyhow::Result<PathBuf> {
    let random_suffix: String = (0..8)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    let path = std::env::temp_dir().join(format!("izanagi-{}-{}.tmp", prefix, random_suffix));
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(content)?;
    }
    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(content)?;
    }
    Ok(path)
}

/// QEMU プロセスを起動し、stdout/stderr のキャプチャタスクを spawn する。
fn spawn_qemu_with_capture(
    binary: &str,
    args: &[String],
    stdout_buf: &Arc<Mutex<Vec<u8>>>,
    stderr_buf: &Arc<Mutex<Vec<u8>>>,
) -> anyhow::Result<Child> {
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to start QEMU: {}", e))?;

    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(drain_and_capture(stdout, Arc::clone(stdout_buf)));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(drain_and_capture(stderr, Arc::clone(stderr_buf)));
    }

    Ok(child)
}

/// SHA256 ハッシュを16進文字列で返す。
use crate::util::sha256_hex;

/// QEMU ベースの VM サンドボックス。
pub struct QemuSandbox {
    status: SandboxStatus,
    child: Option<Child>,
    host_port: u16,
    qemu_binary: String,
    /// VM 起動時に生成されるセッショントークン。Hello ハンドシェイクで検証する。
    token: Option<String>,
    /// トークンを書き出した一時ファイルのパス。QEMU 停止時に削除する。
    token_file: Option<PathBuf>,
    /// HMAC シークレットを書き出した一時ファイルのパス。QEMU 停止時に削除する。
    secret_file: Option<PathBuf>,
    /// `up()` で確立した TCP 接続を保持し、`exec()` で使い回す。
    connection: Option<Mutex<PersistentConnection>>,
    /// QEMU の stdout から保持した先頭バッファ（エラー診断用）。
    qemu_stdout_head: Arc<Mutex<Vec<u8>>>,
    /// QEMU の stderr から保持した先頭バッファ（エラー診断用）。
    qemu_stderr_head: Arc<Mutex<Vec<u8>>>,
    /// pcap キャプチャ用ライター。設定されている場合、通信を記録する。
    pcap_writer: Option<std::sync::Arc<PcapWriter>>,
}

impl QemuSandbox {
    /// 新しい `QemuSandbox` を作成する。
    pub fn new() -> Self {
        Self {
            status: SandboxStatus::Stopped,
            child: None,
            host_port: 0,
            qemu_binary: default_qemu_binary().to_string(),
            token: None,
            token_file: None,
            secret_file: None,
            connection: None,
            qemu_stdout_head: Arc::new(Mutex::new(Vec::new())),
            qemu_stderr_head: Arc::new(Mutex::new(Vec::new())),
            pcap_writer: None,
        }
    }

    /// VM 起動時に生成されたトークンを返す。
    /// VmAgentTracer に渡して Hello ハンドシェイクで使用する。
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// QEMU バイナリのパスをカスタマイズする。
    #[allow(dead_code)]
    pub fn with_qemu_binary(mut self, path: &str) -> Self {
        self.qemu_binary = path.to_string();
        self
    }

    /// Agent に TCP 接続して Hello ハンドシェイク + Ready 通知を待つ。
    /// 成功した場合、永続化用の接続状態を返す。
    async fn wait_for_agent_ready(&self) -> anyhow::Result<PersistentConnection> {
        let timeout = tokio::time::Duration::from_secs(BOOT_TIMEOUT_SECS);
        let addr = format!("127.0.0.1:{}", self.host_port);
        let secret = load_shared_secret_from_env()?;
        let token = self.token.clone();

        tokio::time::timeout(timeout, async {
            let mut backoff = tokio::time::Duration::from_millis(100);
            loop {
                // TCP 接続 + ハンドシェイクに個別タイムアウトを設定。
                // SLIRP が SYN を受け付けるが SYN/ACK を返さないケースを防ぐ。
                let connect_timeout = tokio::time::Duration::from_secs(10);
                let connect_result =
                    tokio::time::timeout(connect_timeout, TcpStream::connect(&addr)).await;
                match connect_result {
                    Ok(Ok(stream)) => {
                        // 接続成功 — ハンドシェイクを試行する。
                        // ハンドシェイク失敗（Connection reset 等）はリトライ可能とみなし、
                        // QEMU を再起動せずバックオフ後に再接続する。
                        let handshake_timeout = tokio::time::Duration::from_secs(15);
                        let handshake_result = tokio::time::timeout(
                            handshake_timeout,
                            Self::try_handshake(stream, &secret, &token),
                        )
                        .await;
                        match handshake_result {
                            Ok(Ok(conn)) => return Ok(conn),
                            Ok(Err(e)) => {
                                let msg = e.to_string();
                                // 認証/プロトコルエラーはリトライしても解決しない
                                let is_fatal = msg.contains("authentication mode mismatch")
                                    || msg.contains("incompatible protocol version")
                                    || msg.contains("unsupported protocol version")
                                    || msg.contains("HMAC verification failed")
                                    || msg.contains("token mismatch")
                                    || msg.contains("expected Hello message")
                                    || msg.contains("expected Ready message")
                                    || msg.contains("agent error on hello")
                                    || msg.contains("agent error on connect");
                                if is_fatal {
                                    return Err(e);
                                }
                                eprintln!("Handshake failed (will retry): {}", e,);
                            }
                            Err(_) => {
                                eprintln!("Handshake timed out (will retry)");
                            }
                        }
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, tokio::time::Duration::from_secs(5));
                    }
                    Ok(Err(_)) => {
                        // TCP 接続失敗 (Connection refused 等): VM がまだ起動していない
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, tokio::time::Duration::from_secs(5));
                    }
                    Err(_) => {
                        // TCP 接続タイムアウト: SLIRP がゲスト起動前に SYN を受け付けた
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, tokio::time::Duration::from_secs(5));
                    }
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for VM agent ({}s)", BOOT_TIMEOUT_SECS))?
    }

    /// TCP 接続上で Hello ハンドシェイク + Ready を待つ。
    async fn try_handshake(
        stream: TcpStream,
        secret: &Option<Vec<u8>>,
        token: &Option<String>,
    ) -> anyhow::Result<PersistentConnection> {
        let (reader, writer) = tokio::io::split(stream);
        let secret_vec = secret.clone();
        let mut client = crate::protocol_client::ProtocolClient::new(reader, writer, secret_vec);

        let token_hash = token.as_ref().map(|t| sha256_hex(t));
        client.handshake_and_wait_ready(token_hash).await?;

        Ok(PersistentConnection {
            client,
            broken: false,
        })
    }

    /// 保持した接続でコマンドを送信し、結果を受信する。
    async fn send_command(
        &self,
        cmd: &[String],
        env: &HashMap<String, String>,
    ) -> anyhow::Result<ExecOutput> {
        // Exec メッセージを作成
        let exec_msg = Message::Exec {
            cmd: cmd.to_vec(),
            env: env.clone(),
        };

        // conn_mutex ロック内で送受信のみ行い、pcap 記録はロック外で実行
        let result: anyhow::Result<Message> = {
            let conn_mutex = self
                .connection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no persistent connection available"))?;
            let mut conn = conn_mutex.lock().await;

            if conn.broken {
                anyhow::bail!(
                    "agent connection is broken (previous communication error). Restart with `izanagi down && izanagi up`."
                );
            }

            if let Err(e) = conn.client.send_message(&exec_msg).await {
                conn.broken = true;
                anyhow::bail!("agent connection lost during send: {}", e);
            }

            match conn.client.recv_message().await {
                Ok(Some(msg @ Message::ExecResult { .. })) => Ok(msg),
                Ok(Some(Message::Error(msg))) => {
                    anyhow::bail!("agent error: {}", msg);
                }
                Ok(Some(other)) => {
                    conn.broken = true;
                    anyhow::bail!("expected ExecResult, got {:?}", other);
                }
                Ok(None) => {
                    conn.broken = true;
                    anyhow::bail!("agent connection closed unexpectedly");
                }
                Err(e) => {
                    conn.broken = true;
                    anyhow::bail!("agent connection lost during recv: {}", e);
                }
            }
        }; // conn_mutex ロック解放

        // pcap 記録: ロック外で非同期に実行
        self.record_pcap(Direction::HostToGuest, &exec_msg);
        if let Ok(ref msg) = result {
            self.record_pcap(Direction::GuestToHost, msg);
        }

        match result? {
            Message::ExecResult {
                exit_code,
                stdout,
                stderr,
            } => Ok(ExecOutput {
                exit_code,
                stdout,
                stderr,
            }),
            _ => unreachable!(),
        }
    }

    /// QEMU 起動成功後に fw_cfg 一時ファイルを削除する。
    /// QEMU は起動時に1回だけ読むため、起動後の削除で問題ない。
    fn cleanup_temp_files(&mut self) {
        if let Some(ref path) = self.token_file {
            remove_temp_file_if_exists(path);
            self.token_file = None;
        }
        if let Some(ref path) = self.secret_file {
            remove_temp_file_if_exists(path);
            self.secret_file = None;
        }
    }

    /// QEMU の stdout/stderr をエラー診断用に出力する。
    async fn log_qemu_output(&self) {
        let stdout_captured = self.qemu_stdout_head.lock().await;
        let stderr_captured = self.qemu_stderr_head.lock().await;
        if !stderr_captured.is_empty() {
            eprintln!("QEMU stderr: {}", String::from_utf8_lossy(&stderr_captured));
        }
        if !stdout_captured.is_empty() {
            eprintln!("QEMU stdout: {}", String::from_utf8_lossy(&stdout_captured));
        }
    }

    /// メッセージを pcap ファイルに非同期で記録する。
    /// pcap_writer が未設定の場合は何もしない。
    /// エンコードは呼び出しスレッドで行い、ファイル I/O は spawn_blocking で実行する。
    /// conn_mutex のロック外から呼ぶこと。
    fn record_pcap(&self, direction: Direction, msg: &Message) {
        if let Some(ref writer) = self.pcap_writer {
            match crate::protocol::encode_message(msg) {
                Ok(encoded) => {
                    let writer = writer.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = writer.write_packet(direction, &encoded) {
                            eprintln!("[pcap] パケット書き込みに失敗: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[pcap] メッセージのエンコードに失敗: {}", e);
                }
            }
        }
    }

    /// QEMU プロセスを graceful shutdown する。
    /// 保持した接続を閉じてから ACPI shutdown シグナル → タイムアウト後に kill。
    async fn shutdown_qemu(&mut self) -> anyhow::Result<()> {
        // 保持した接続を閉じる
        self.connection = None;

        // トークン一時ファイルを削除
        if let Some(ref path) = self.token_file {
            remove_temp_file_if_exists(path);
        }
        self.token_file = None;

        // シークレット一時ファイルを削除 (#161)
        if let Some(ref path) = self.secret_file {
            remove_temp_file_if_exists(path);
        }
        self.secret_file = None;

        if let Some(ref mut child) = self.child {
            // まず QEMU monitor に system_powerdown を送信 (stdin 経由)
            if let Some(ref mut stdin) = child.stdin {
                // Ctrl-A c でモニタコンソールに切り替え、system_powerdown を送信
                let _ = stdin.write_all(b"\x01c").await;
                // QEMU monitor がコンソール切り替えを完了するまで待機
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let _ = stdin.write_all(b"system_powerdown\n").await;
            }

            // 10 秒待って終了しなければ kill
            let timeout = tokio::time::Duration::from_secs(10);
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(Ok(_)) => {}
                _ => {
                    child.kill().await?;
                }
            }
        }
        self.child = None;
        Ok(())
    }
}

impl Default for QemuSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for QemuSandbox {
    fn drop(&mut self) {
        // セッショントークンをメモリからゼロクリア (#197)
        if let Some(ref mut token) = self.token {
            zeroize::Zeroize::zeroize(token);
        }
    }
}

/// 空きポートを取得する。
///
/// **TOCTOU リスク**: ポート取得後にリスナーを閉じてから QEMU がバインドするまでの
/// 間に、他プロセスが同じポートを奪う可能性がある。この関数自体では解決できないため、
/// 呼び出し元で QEMU 起動→接続失敗時にリトライするロジックと組み合わせて使用すること。
async fn find_available_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// QEMU 起動時のポート TOCTOU リトライ最大回数。
const PORT_RETRY_MAX: u32 = 3;

/// 一時ファイルを削除する。存在しない場合は無視する。
fn remove_temp_file_if_exists(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("警告: 一時ファイルの削除に失敗 {:?}: {}", path, e),
    }
}

/// 非同期ストリームを読み捨てつつ、先頭の数 KB を保持する。
/// パイプバッファ詰まりを防止しながらエラー診断用の出力を残す。
async fn drain_and_capture<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    buffer: Arc<Mutex<Vec<u8>>>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let mut captured = buffer.lock().await;
                if captured.len() < QEMU_OUTPUT_CAPTURE_BYTES {
                    let remaining = QEMU_OUTPUT_CAPTURE_BYTES - captured.len();
                    let to_copy = n.min(remaining);
                    captured.extend_from_slice(&buf[..to_copy]);
                }
                // remaining bytes are discarded to prevent buffer bloat
            }
            Err(_) => break,
        }
    }
}

#[async_trait::async_trait]
impl Sandbox for QemuSandbox {
    async fn up(&mut self, config: &SandboxConfig) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Stopped {
            anyhow::bail!(
                "Sandbox is not in Stopped state (current: {:?})",
                self.status
            );
        }

        self.status = SandboxStatus::Starting;

        let (cpus, memory_mb, image, share, dns_proxy) = match config {
            SandboxConfig::Qemu {
                cpus,
                memory_mb,
                image,
                share,
                dns_proxy,
            } => (
                *cpus,
                *memory_mb,
                image.clone(),
                share.clone(),
                dns_proxy.clone(),
            ),
            _ => {
                self.status = SandboxStatus::Stopped;
                anyhow::bail!("QemuSandbox requires SandboxConfig::Qemu");
            }
        };

        // #35: イメージの存在確認
        let image_path = match check_image_exists(&image) {
            Ok(p) => p,
            Err(e) => {
                self.status = SandboxStatus::Stopped;
                return Err(e);
            }
        };

        // HMAC シークレットをリトライ間で共有するため先に読み出す
        let secret = load_shared_secret_from_env()?;

        // secret ファイルはリトライ間で内容が不変なのでループ外で1回だけ作成する。
        // self.secret_file にはリトライ成功後にセットする（shutdown_qemu での誤削除を防ぐため）。
        let secret_file_path = if let Some(ref secret_bytes) = secret {
            Some(write_secure_temp_file("secret", secret_bytes)?)
        } else {
            None
        };

        // ポート取得 → QEMU 起動 → Agent 接続のリトライループ。
        // find_available_port は TOCTOU リスクがあるため、接続失敗時に
        // 別のポートで再試行する。
        // トークンはリトライごとに再生成する (#194)。
        // 前回の QEMU プロセスが残留する場合に同一トークンが複数 VM に存在しうるため。
        let mut last_error = None;
        for attempt in 0..PORT_RETRY_MAX {
            // 旧トークンをゼロクリアしてからリトライ (#197)
            if let Some(ref mut old_token) = self.token {
                zeroize::Zeroize::zeroize(old_token);
            }

            // 前回のトークンファイルを削除（リーク防止）
            if let Some(ref path) = self.token_file {
                let _ = std::fs::remove_file(path);
                self.token_file = None;
            }

            // リトライごとにトークンを再生成 (#194)
            let token = generate_token();
            self.token = Some(token.clone());

            // リトライごとに fw_cfg トークンファイルを再生成 (#202)
            let token_file_path = write_secure_temp_file("token", token.as_bytes())?;
            self.token_file = Some(token_file_path.clone());

            self.host_port = find_available_port().await?;

            let args = build_qemu_args(&QemuArgsParams {
                image_path: &image_path,
                cpus,
                memory_mb,
                share: &share,
                host_port: self.host_port,
                token: Some(token_file_path.to_str().ok_or_else(|| {
                    anyhow::anyhow!(
                        "token temp file path is not valid UTF-8: {:?}",
                        token_file_path
                    )
                })?),
                secret: secret_file_path.as_ref().and_then(|p| p.to_str()),
                dns_proxy: dns_proxy.as_deref(),
            });

            // バッファをリセットして QEMU を起動
            self.qemu_stdout_head.lock().await.clear();
            self.qemu_stderr_head.lock().await.clear();

            match spawn_qemu_with_capture(
                &self.qemu_binary,
                &args,
                &self.qemu_stdout_head,
                &self.qemu_stderr_head,
            ) {
                Ok(child) => self.child = Some(child),
                Err(e) => {
                    self.status = SandboxStatus::Stopped;
                    return Err(e);
                }
            }

            // Agent からの Ready 通知を待ち、接続を保持する
            match self.wait_for_agent_ready().await {
                Ok(conn) => {
                    self.connection = Some(Mutex::new(conn));
                    self.status = SandboxStatus::Running;
                    // 成功時に secret_file を登録（down() での削除対象にする）
                    self.secret_file = secret_file_path.clone();
                    self.cleanup_temp_files();

                    // 注意: ハンドシェイク (Hello/Ready) は try_handshake 内で完結するため、
                    // pcap には記録しない。pcap に記録されるのは Exec/ExecResult 等の
                    // アプリケーションメッセージのみ。

                    return Ok(());
                }
                Err(e) => {
                    let incompatible = e.to_string().contains("incompatible protocol version")
                        || e.to_string().contains("unsupported protocol version");
                    self.log_qemu_output().await;
                    eprintln!(
                        "WARNING: QEMU startup attempt {} failed (port {}): {}. {}",
                        attempt + 1,
                        self.host_port,
                        e,
                        if attempt + 1 < PORT_RETRY_MAX && !incompatible {
                            "Retrying with a new port..."
                        } else {
                            "No more retries."
                        }
                    );
                    let _ = self.shutdown_qemu().await;
                    last_error = Some(e);
                    if incompatible {
                        break;
                    }
                }
            }
        }

        // 全リトライ失敗: secret ファイルをクリーンアップ
        if let Some(ref path) = secret_file_path {
            let _ = std::fs::remove_file(path);
        }
        self.status = SandboxStatus::Stopped;
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("QEMU startup failed after retries")))
    }

    async fn exec(
        &self,
        cmd: &[String],
        env: &HashMap<String, String>,
    ) -> anyhow::Result<ExecOutput> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }

        if cmd.is_empty() {
            anyhow::bail!("Command must not be empty");
        }

        self.send_command(cmd, env).await
    }

    async fn shell(&self) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }

        let conn_mutex = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no persistent connection available"))?;
        let mut conn = conn_mutex.lock().await;

        if conn.broken {
            anyhow::bail!("agent connection is broken. Restart with `izanagi down && izanagi up`.");
        }

        match crate::terminal_shell::interactive_shell(&mut conn.client).await {
            Ok(0) => Ok(()),
            Ok(code) => anyhow::bail!("shell exited with code {code}"),
            Err(error) => {
                conn.broken = true;
                Err(error)
            }
        }
    }

    async fn down(&mut self) -> anyhow::Result<()> {
        if self.status != SandboxStatus::Running {
            anyhow::bail!("Sandbox is not running (current: {:?})", self.status);
        }

        self.status = SandboxStatus::Stopping;
        self.shutdown_qemu().await?;
        self.status = SandboxStatus::Stopped;

        Ok(())
    }

    fn status(&self) -> SandboxStatus {
        self.status
    }

    fn session_token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    fn agent_host_port(&self) -> Option<u16> {
        if self.status == SandboxStatus::Running && self.host_port > 0 {
            Some(self.host_port)
        } else {
            None
        }
    }

    fn session_backend(&self) -> Option<crate::session::SessionBackend> {
        if self.status != SandboxStatus::Running {
            return None;
        }
        Some(crate::session::SessionBackend::Qemu {
            host_port: self.host_port,
            token_hash: self.token.as_ref().map(|t| crate::util::sha256_hex(t)),
        })
    }

    fn set_pcap_writer(&mut self, writer: std::sync::Arc<PcapWriter>) {
        self.pcap_writer = Some(writer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sandbox_shell_exits_and_restores_terminal_without_input() {
        for mode in ["close", "disconnect", "error", "cancel"] {
            crate::pty_test_support::exercise("qemu_sandbox::tests::shell_runtime_probe", mode);
        }
    }

    #[test]
    fn shell_runtime_probe() {
        let Ok(port) = std::env::var("IZANAGI_PTY_TEST_PORT") else {
            return;
        };
        let mode = std::env::var("IZANAGI_PTY_TEST_MODE").unwrap();
        let original = crate::pty_test_support::terminal_snapshot();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let stream = TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap()))
                .await
                .unwrap();
            let conn =
                QemuSandbox::try_handshake(stream, &load_shared_secret_from_env().unwrap(), &None)
                    .await
                    .unwrap();
            let mut sandbox = QemuSandbox::new();
            sandbox.status = SandboxStatus::Running;
            sandbox.connection = Some(Mutex::new(conn));
            if mode == "cancel" {
                tokio::time::timeout(std::time::Duration::from_millis(200), sandbox.shell())
                    .await
                    .map_err(anyhow::Error::from)?
            } else {
                sandbox.shell().await
            }
        });
        match mode.as_str() {
            "close" => result.unwrap(),
            "disconnect" => assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("agent disconnected during shell")
            ),
            "error" => assert!(result.unwrap_err().to_string().contains("shell test error")),
            "cancel" => assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("deadline has elapsed")
            ),
            _ => unreachable!(),
        }
        drop(runtime);
        crate::pty_test_support::assert_terminal_restored(&original);
    }

    /// テスト用ヘルパー: 旧シグネチャ互換の `build_qemu_args` ラッパー。
    #[allow(clippy::too_many_arguments)]
    fn build_args(
        image_path: &Path,
        cpus: u32,
        memory_mb: u32,
        share: &ShareConfig,
        host_port: u16,
        token: Option<&str>,
        secret: Option<&str>,
        dns_proxy: Option<&str>,
    ) -> Vec<String> {
        build_qemu_args(&QemuArgsParams {
            image_path,
            cpus,
            memory_mb,
            share,
            host_port,
            token,
            secret,
            dns_proxy,
        })
    }

    // --- #35: イメージ管理テスト ---

    #[test]
    fn resolve_image_path_default() {
        let path = resolve_image_path("default");
        assert!(
            path.to_string_lossy()
                .contains(".izanagi/images/debian-aarch64.qcow2")
        );
    }

    #[test]
    fn resolve_image_path_named() {
        let path = resolve_image_path("ubuntu");
        assert!(
            path.to_string_lossy()
                .contains(".izanagi/images/ubuntu.qcow2")
        );
    }

    #[test]
    fn resolve_image_path_absolute() {
        let path = resolve_image_path("/custom/path/image.qcow2");
        assert_eq!(path, PathBuf::from("/custom/path/image.qcow2"));
    }

    #[test]
    fn check_image_exists_nonexistent() {
        let result = check_image_exists("nonexistent_test_image_xyz");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // --- #36: QEMU コマンドライン生成テスト ---

    #[test]
    fn build_qemu_args_basic() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/home/user/project")],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 2, 4096, &share, 9001, None, None, None);

        assert!(args.contains(&"-accel".to_string()));
        let expected_accel = if cfg!(target_os = "macos") {
            "hvf"
        } else {
            "kvm"
        };
        assert!(args.contains(&expected_accel.to_string()));
        assert!(args.contains(&"-cpu".to_string()));
        assert!(args.contains(&"host".to_string()));
        assert!(args.contains(&"-m".to_string()));
        assert!(args.contains(&"4096M".to_string()));
        assert!(args.contains(&"-smp".to_string()));
        assert!(args.contains(&"2".to_string()));
        assert!(args.contains(&"-nographic".to_string()));
        assert!(args.contains(&"-machine".to_string()));
        let expected_machine = if cfg!(target_arch = "aarch64") {
            "virt"
        } else {
            "q35"
        };
        assert!(args.contains(&expected_machine.to_string()));
    }

    #[test]
    fn build_qemu_args_drive() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 1, 512, &share, 9001, None, None, None);

        let drive_arg = args
            .iter()
            .find(|a| a.starts_with("file="))
            .expect("drive arg should exist");
        assert!(drive_arg.contains("/tmp/test.qcow2"));
        assert!(drive_arg.contains("format=qcow2"));
    }

    // --- #37: virtio-9p テスト ---

    #[test]
    fn build_qemu_args_9p_share() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/home/user/project")],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 2, 4096, &share, 9001, None, None, None);

        // fsdev 引数の確認
        let fsdev_arg = args
            .iter()
            .find(|a| a.contains("local,id=fs0"))
            .expect("fsdev arg should exist");
        assert!(fsdev_arg.contains("path=/home/user/project"));
        assert!(fsdev_arg.contains("security_model=mapped-xattr"));

        // virtio-9p-pci デバイス引数の確認
        assert!(args.contains(&"virtio-9p-pci,fsdev=fs0,mount_tag=workspace".to_string()));
    }

    #[test]
    fn build_qemu_args_no_share_paths() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 1, 512, &share, 9001, None, None, None);

        // host_paths が空の場合、fsdev/9p 引数は含まれない
        assert!(!args.iter().any(|a| a.contains("fsdev")));
        assert!(!args.iter().any(|a| a.contains("virtio-9p")));
    }

    // --- #36: ネットワーク設定テスト ---

    #[test]
    fn build_qemu_args_network() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 1, 512, &share, 12345, None, None, None);

        let netdev_arg = args
            .iter()
            .find(|a| a.starts_with("user,id=net0"))
            .expect("netdev arg should exist");
        assert!(netdev_arg.contains("hostfwd=tcp::12345-:9001"));
        assert!(args.contains(&"virtio-net-pci,netdev=net0".to_string()));
    }

    // --- #210: DNS プロキシ設定テスト ---

    #[test]
    fn build_qemu_args_with_dns_proxy() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 1, 512, &share, 9001, None, None, Some("10.0.2.2"));

        let netdev_arg = args
            .iter()
            .find(|a| a.starts_with("user,id=net0"))
            .expect("netdev arg should exist");
        assert!(netdev_arg.contains("dns=10.0.2.2"));
        assert!(netdev_arg.contains("hostfwd=tcp::9001-:9001"));
    }

    #[test]
    fn build_qemu_args_without_dns_proxy() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 1, 512, &share, 9001, None, None, None);

        let netdev_arg = args
            .iter()
            .find(|a| a.starts_with("user,id=net0"))
            .expect("netdev arg should exist");
        assert!(!netdev_arg.contains("dns="));
    }

    // --- #36: 状態遷移テスト ---

    #[test]
    fn qemu_sandbox_initial_state() {
        let sb = QemuSandbox::new();
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }

    #[test]
    fn qemu_sandbox_default() {
        let sb = QemuSandbox::default();
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }

    #[tokio::test]
    async fn qemu_sandbox_wrong_config() {
        let config = SandboxConfig::Landlock {
            share: ShareConfig {
                host_paths: vec![],
                mount_point: PathBuf::from("/workspace"),
            },
        };

        let mut sb = QemuSandbox::new();
        let result = sb.up(&config).await;
        assert!(result.is_err());
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }

    #[tokio::test]
    async fn qemu_sandbox_exec_when_not_running() {
        let sb = QemuSandbox::new();
        let env = HashMap::new();
        let result = sb.exec(&["echo".to_string()], &env).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not running"));
    }

    #[tokio::test]
    async fn qemu_sandbox_shell_when_not_running() {
        let sb = QemuSandbox::new();
        let result = sb.shell().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn qemu_sandbox_down_when_not_running() {
        let mut sb = QemuSandbox::new();
        let result = sb.down().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn qemu_sandbox_up_with_missing_image() {
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/tmp")],
            mount_point: PathBuf::from("/workspace"),
        };
        let config = SandboxConfig::Qemu {
            cpus: 2,
            memory_mb: 4096,
            image: "nonexistent_image_xyz".to_string(),
            share,
            dns_proxy: None,
        };

        let mut sb = QemuSandbox::new();
        let result = sb.up(&config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
        assert_eq!(sb.status(), SandboxStatus::Stopped);
    }

    // --- 設定バリデーションテスト ---

    #[test]
    fn build_qemu_args_all_options() {
        let image = PathBuf::from("/var/lib/images/alpine.qcow2");
        let share = ShareConfig {
            host_paths: vec![PathBuf::from("/home/user/project")],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 4, 8192, &share, 9999, None, None, None);

        // 全主要引数が存在すること
        assert!(args.contains(&"-accel".to_string()));
        let expected_accel = if cfg!(target_os = "macos") {
            "hvf"
        } else {
            "kvm"
        };
        assert!(args.contains(&expected_accel.to_string()));
        assert!(args.contains(&"-cpu".to_string()));
        assert!(args.contains(&"host".to_string()));
        assert!(args.contains(&"-m".to_string()));
        assert!(args.contains(&"8192M".to_string()));
        assert!(args.contains(&"-smp".to_string()));
        assert!(args.contains(&"4".to_string()));
        assert!(args.contains(&"-machine".to_string()));
        let expected_machine = if cfg!(target_arch = "aarch64") {
            "virt"
        } else {
            "q35"
        };
        assert!(args.contains(&expected_machine.to_string()));
        assert!(args.contains(&"-nographic".to_string()));

        // コマンドライン全体を文字列として出力してデバッグ可能にする
        let full_cmd = format!("qemu-system-aarch64 {}", args.join(" "));
        assert!(full_cmd.contains("qemu-system-aarch64"));
        assert!(full_cmd.contains(&format!("-accel {expected_accel}")));
        assert!(full_cmd.contains("-cpu host"));
    }

    #[tokio::test]
    async fn find_available_port_works() {
        let port = find_available_port().await.expect("should find port");
        assert!(port > 0);
    }

    #[test]
    fn build_qemu_args_with_token() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(
            &image,
            1,
            512,
            &share,
            9001,
            Some("/tmp/token.tmp"),
            None,
            None,
        );

        // fw_cfg 引数が含まれること
        assert!(args.contains(&"-fw_cfg".to_string()));
        // fw_cfg の値に file= 形式でパスが含まれること
        let fw_cfg_arg = args
            .iter()
            .find(|a| a.starts_with("name=opt/izanagi.token,"))
            .unwrap();
        assert!(fw_cfg_arg.contains("file=/tmp/token.tmp"));
    }

    #[test]
    fn build_qemu_args_without_token() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 1, 512, &share, 9001, None, None, None);

        // fw_cfg 引数が含まれないこと
        assert!(!args.contains(&"-fw_cfg".to_string()));
    }

    #[test]
    fn build_qemu_args_with_secret() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(
            &image,
            1,
            512,
            &share,
            9001,
            None,
            Some("/tmp/secret.tmp"),
            None,
        );

        // fw_cfg 引数が含まれること
        assert!(args.contains(&"-fw_cfg".to_string()));
        let fw_cfg_arg = args
            .iter()
            .find(|a| a.starts_with("name=opt/izanagi.secret,"))
            .unwrap();
        assert!(fw_cfg_arg.contains("file=/tmp/secret.tmp"));
    }

    #[test]
    fn build_qemu_args_without_secret() {
        let image = PathBuf::from("/tmp/test.qcow2");
        let share = ShareConfig {
            host_paths: vec![],
            mount_point: PathBuf::from("/workspace"),
        };
        let args = build_args(&image, 1, 512, &share, 9001, None, None, None);

        // izanagi.secret の fw_cfg 引数が含まれないこと
        assert!(!args.iter().any(|a| a.contains("izanagi.secret")));
    }

    #[test]
    fn generate_token_is_64_hex_chars() {
        let token = generate_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Hello → Hello → Ready のハンドシェイクが成功するケースをテストする。
    #[tokio::test]
    async fn try_handshake_success_unauthenticated() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // エージェント役: Hello を受け取り、Hello + Ready を返す
        let agent = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            // Hello を読む
            let msg = crate::protocol::read_message(&mut reader).await.unwrap();
            assert!(matches!(msg, Some(Message::Hello { .. })));
            // Hello を返す
            let reply = Message::Hello {
                authenticated: false,
                token: None,
            };
            crate::protocol::write_message(&mut writer, &reply)
                .await
                .unwrap();
            // Ready を返す
            crate::protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let secret: Option<Vec<u8>> = None;
        let token: Option<String> = None;

        let conn = QemuSandbox::try_handshake(stream, &secret, &token)
            .await
            .unwrap();
        assert!(!conn.broken);
        // 非認証モードではシーケンス番号は 0 のまま
        assert_eq!(conn.client.sequences(), (0, 0));

        agent.await.unwrap();
    }

    /// エージェントが Hello の代わりに Error を返した場合、即座に失敗する。
    #[tokio::test]
    async fn try_handshake_agent_returns_error() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let agent = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let _ = crate::protocol::read_message(&mut reader).await;
            // Error を返す
            let err = Message::Error("authentication mode mismatch".to_string());
            crate::protocol::write_message(&mut writer, &err)
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let secret: Option<Vec<u8>> = None;
        let token: Option<String> = None;

        let result = QemuSandbox::try_handshake(stream, &secret, &token).await;
        assert!(result.is_err());

        agent.await.unwrap();
    }

    /// エージェントが接続直後に切断した場合のテスト。
    #[tokio::test]
    async fn try_handshake_agent_disconnects() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let agent = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream); // 即切断
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let secret: Option<Vec<u8>> = None;
        let token: Option<String> = None;

        let result = QemuSandbox::try_handshake(stream, &secret, &token).await;
        assert!(result.is_err());

        agent.await.unwrap();
    }
}
