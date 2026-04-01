//! VM Agent ベースの Tracer 実装。
//!
//! QEMU ゲスト内の `izanagi-agent` と TCP 経由で通信し、
//! エージェントがキャプチャした syscall イベントをホスト側で受信する。
//!
//! QEMU の `-netdev user,hostfwd=...` でポートフォワーディングされた
//! localhost ポートに接続するため、Linux / macOS いずれでも動作する。

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::event::SyscallEvent;
use crate::protocol::Message;

#[cfg(test)]
use crate::protocol;
use crate::tracer::{TraceFilter, Tracer};

use crate::tracer::EVENT_CHANNEL_CAPACITY;

/// agent との TCP 通信に使用するデフォルトポート番号。
pub const DEFAULT_AGENT_PORT: u32 = 9001;

/// VmAgentTracer の設定。
#[derive(Debug, Clone)]
pub struct VmAgentConfig {
    /// agent の TCP ポート番号（ホスト側ポートフォワーディング先）。
    pub port: u32,
}

impl Default for VmAgentConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_AGENT_PORT,
        }
    }
}

/// TCP 経由で VM Agent と通信する Tracer。
///
/// ホスト側で動作し、ゲスト内の `izanagi-agent` が送信する
/// `Event` メッセージを受信して `SyscallEvent` に復元する。
pub struct VmAgentTracer {
    config: VmAgentConfig,
    inner: std::sync::Mutex<VmAgentTracerInner>,
}

struct VmAgentTracerInner {
    /// 停止シグナル送信用。
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Hello ハンドシェイクで送信するトークン（SHA256 ハッシュ済み）。
    token: Option<String>,
    /// sandbox が動的に割り当てたポート。設定されていれば config.port より優先する。
    port_override: Option<u16>,
    /// HMAC 認証用の共有シークレット。
    secret: Option<Vec<u8>>,
}

impl VmAgentTracer {
    /// 新しい `VmAgentTracer` を作成する。
    pub fn new(config: VmAgentConfig) -> Self {
        Self {
            config,
            inner: std::sync::Mutex::new(VmAgentTracerInner {
                shutdown_tx: None,
                token: None,
                port_override: None,
                secret: None,
            }),
        }
    }

    /// Hello ハンドシェイクで送信するトークン（SHA256 ハッシュ済み）を設定する。
    /// `start()` の前に呼ぶこと。
    pub fn set_token(&self, token_hash: String) {
        self.inner
            .lock()
            .expect("VmAgentTracerInner lock poisoned")
            .token = Some(token_hash);
    }

    /// `AsyncRead + AsyncWrite` ストリーム上でプロトコル通信を行う。
    ///
    /// テスト時は `tokio::io::duplex` で代替可能。
    /// 実行時は vsock ストリームを渡す。
    pub async fn run_on_stream<S>(
        stream: S,
        filter: &TraceFilter,
        tx: mpsc::Sender<Arc<SyscallEvent>>,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        Self::run_on_stream_inner(stream, filter, tx, shutdown_rx, None, None).await
    }

    /// HMAC 認証付きでストリーム上のプロトコル通信を行う。
    pub async fn run_on_stream_authenticated<S>(
        stream: S,
        filter: &TraceFilter,
        tx: mpsc::Sender<Arc<SyscallEvent>>,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        secret: &[u8],
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        Self::run_on_stream_inner(stream, filter, tx, shutdown_rx, Some(secret.to_vec()), None)
            .await
    }

    async fn run_on_stream_inner<S>(
        stream: S,
        filter: &TraceFilter,
        tx: mpsc::Sender<Arc<SyscallEvent>>,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        secret: Option<Vec<u8>>,
        token: Option<String>,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        let mut client = crate::protocol_client::ProtocolClient::new(reader, writer, secret);

        client.handshake_and_wait_ready(token).await?;

        // Start メッセージを送信
        client.send_message(&Message::Start(filter.clone())).await?;

        // イベント受信ループ
        loop {
            tokio::select! {
                result = client.recv_message() => {
                    match result? {
                        Some(Message::Event(event)) => {
                            if tx.send(Arc::new(event)).await.is_err() {
                                break;
                            }
                        }
                        Some(Message::Error(e)) => {
                            anyhow::bail!("agent error: {}", e);
                        }
                        Some(_) => {}
                        None => {
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    let _ = client.send_message(&Message::Stop).await;
                    break;
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tracer 実装 (TCP 接続)
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl Tracer for VmAgentTracer {
    fn set_session_token(&self, token_hash: String) {
        self.inner
            .lock()
            .expect("VmAgentTracerInner lock poisoned")
            .token = Some(token_hash);
    }

    fn set_agent_port(&self, port: u16) {
        self.inner
            .lock()
            .expect("VmAgentTracerInner lock poisoned")
            .port_override = Some(port);
    }

    fn set_secret(&self, secret: Vec<u8>) {
        self.inner
            .lock()
            .expect("VmAgentTracerInner lock poisoned")
            .secret = Some(secret);
    }

    async fn start(
        &self,
        filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>> {
        use tokio::net::TcpStream;

        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // チェックと設定を同一ロック内で原子的に行い TOCTOU を防止
        let (token, port, secret) = {
            let mut inner = self.inner.lock().expect("VmAgentTracerInner lock poisoned");
            if inner.shutdown_tx.is_some() {
                anyhow::bail!("VmAgentTracer is already running");
            }
            inner.shutdown_tx = Some(shutdown_tx);
            let port = match inner.port_override {
                Some(p) => p,
                None => u16::try_from(self.config.port).map_err(|_| {
                    anyhow::anyhow!(
                        "invalid VmAgentConfig.port: {} exceeds u16 range",
                        self.config.port
                    )
                })?,
            };
            (inner.token.clone(), port, inner.secret.clone())
        };

        // TCP 接続（sandbox が動的に割り当てたポートを使用）
        // 接続失敗時は shutdown_tx をロールバックし、次回の start() を可能にする。
        let addr = format!("127.0.0.1:{}", port);
        let stream = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                let mut inner = self.inner.lock().expect("VmAgentTracerInner lock poisoned");
                inner.shutdown_tx = None;
                return Err(e.into());
            }
        };

        let filter = filter.clone();
        tokio::spawn(async move {
            if let Err(e) =
                Self::run_on_stream_inner(stream, &filter, tx, shutdown_rx, secret, token).await
            {
                eprintln!("VmAgentTracer error: {}", e);
            }
        });

        Ok(rx)
    }

    async fn stop(&self) -> anyhow::Result<()> {
        if let Some(tx) = self
            .inner
            .lock()
            .expect("VmAgentTracerInner lock poisoned")
            .shutdown_tx
            .take()
        {
            let _ = tx.send(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Syscall, SyscallArg, SyscallResult};

    #[test]
    fn vm_agent_tracer_can_be_constructed() {
        let _tracer = VmAgentTracer::new(VmAgentConfig::default());
    }

    #[test]
    fn default_config_values() {
        let config = VmAgentConfig::default();
        assert_eq!(config.port, DEFAULT_AGENT_PORT);
    }

    /// duplex ストリームを使った run_on_stream のインテグレーションテスト。
    ///
    /// agent 側をシミュレートして Ready → Event 送信 → 受信確認。
    #[tokio::test]
    async fn run_on_stream_receives_events() {
        let (client, server) = tokio::io::duplex(8192);
        let (tx, mut rx) = mpsc::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let filter = TraceFilter {
            categories: vec![crate::event::SyscallCategory::File],
            pids: None,
        };

        let test_event = SyscallEvent {
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            pid: 100,
            tgid: 0,
            process_name: "test-agent".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![SyscallArg::Fd(3)],
            result: SyscallResult::Ok(0),
        };
        let test_event_clone = test_event.clone();

        // agent 側をシミュレート
        let agent_handle = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);

            // Hello ハンドシェイク
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(
                msg,
                Message::Hello {
                    authenticated: false,
                    ..
                }
            ));
            protocol::write_message(
                &mut writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();

            // Ready を送信
            protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();

            // Start を受信
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(msg, Message::Start(_)));

            // Event を送信
            protocol::write_message(&mut writer, &Message::Event(test_event_clone))
                .await
                .unwrap();

            // ストリームを閉じる
            drop(writer);
            drop(reader);
        });

        // host 側
        let host_handle = tokio::spawn(async move {
            VmAgentTracer::run_on_stream(client, &filter, tx, shutdown_rx)
                .await
                .unwrap();
        });

        // イベント受信
        let received = rx.recv().await.expect("should receive event");
        assert_eq!(received.pid, test_event.pid);
        assert_eq!(received.syscall, test_event.syscall);
        assert_eq!(&*received.process_name, &*test_event.process_name);

        agent_handle.await.unwrap();
        host_handle.await.unwrap();
    }

    /// 認証付き通信の E2E テスト。
    ///
    /// duplex ストリームで secret あり、
    /// Hello(authenticated=true) → Ready → Start → Event → Stop の全フロー。
    #[tokio::test]
    async fn run_on_stream_authenticated_full_flow() {
        let hmac_key = b"test-e2e-shared-hmac-key-1234567";
        let (client, server) = tokio::io::duplex(8192);
        let (tx, mut rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let filter = TraceFilter {
            categories: vec![crate::event::SyscallCategory::File],
            pids: None,
        };

        let test_event = SyscallEvent {
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            pid: 200,
            tgid: 0,
            process_name: "auth-agent".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![SyscallArg::Fd(5)],
            result: SyscallResult::Ok(0),
        };
        let test_event_clone = test_event.clone();
        let agent_key = hmac_key.to_vec();

        // agent 側をシミュレート（認証付き）
        let agent_handle = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);

            // Hello ハンドシェイクも認証付き (#177)
            let mut send_seq = 0u64;
            let mut recv_seq = 0u64;
            let msg = protocol::read_message_authenticated(&mut reader, &agent_key, &mut recv_seq)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                msg,
                Message::Hello {
                    authenticated: true,
                    ..
                }
            ));
            protocol::write_message_authenticated(
                &mut writer,
                &Message::Hello {
                    authenticated: true,
                    token: None,
                },
                &agent_key,
                &mut send_seq,
            )
            .await
            .unwrap();

            // Ready を認証付きで送信
            protocol::write_message_authenticated(
                &mut writer,
                &Message::Ready,
                &agent_key,
                &mut send_seq,
            )
            .await
            .unwrap();

            // Start を認証付きで受信
            let msg = protocol::read_message_authenticated(&mut reader, &agent_key, &mut recv_seq)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(msg, Message::Start(_)));

            // Event を認証付きで送信
            protocol::write_message_authenticated(
                &mut writer,
                &Message::Event(test_event_clone),
                &agent_key,
                &mut send_seq,
            )
            .await
            .unwrap();

            // Stop を認証付きで受信
            let msg = protocol::read_message_authenticated(&mut reader, &agent_key, &mut recv_seq)
                .await
                .unwrap();
            match msg {
                Some(Message::Stop) => {}
                other => panic!("expected Stop, got {:?}", other),
            }
        });

        // host 側（認証付き）
        let filter_clone = filter.clone();
        let host_handle = tokio::spawn(async move {
            VmAgentTracer::run_on_stream_authenticated(
                client,
                &filter_clone,
                tx,
                shutdown_rx,
                hmac_key,
            )
            .await
            .unwrap();
        });

        // イベント受信
        let received = rx.recv().await.expect("should receive authenticated event");
        assert_eq!(received.pid, test_event.pid);
        assert_eq!(received.syscall, test_event.syscall);
        assert_eq!(&*received.process_name, &*test_event.process_name);

        // shutdown → Stop 送信
        shutdown_tx.send(()).unwrap();

        agent_handle.await.unwrap();
        host_handle.await.unwrap();
    }

    /// set_token で設定したトークンが Hello メッセージに含まれることを確認。
    #[tokio::test]
    async fn run_on_stream_sends_token_in_hello() {
        let (client, server) = tokio::io::duplex(8192);
        let (tx, _rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        // agent が Start を受信したら通知する
        let ready = Arc::new(tokio::sync::Notify::new());
        let ready_clone = ready.clone();

        let agent_handle = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);

            // Hello を受信してトークンを検証
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            match msg {
                Message::Hello { token, .. } => {
                    assert_eq!(token.as_deref(), Some("my-token-hash"));
                }
                other => panic!("expected Hello, got {:?}", other),
            }

            // Hello 返信
            protocol::write_message(
                &mut writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();

            // Ready
            protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();

            // Start を受信 → shutdown 可能を通知
            let _ = protocol::read_message(&mut reader).await.unwrap();
            ready_clone.notify_one();

            // Stop を待つ
            let _ = protocol::read_message(&mut reader).await;
        });

        let host_handle = tokio::spawn(async move {
            VmAgentTracer::run_on_stream_inner(
                client,
                &filter,
                tx,
                shutdown_rx,
                None,
                Some("my-token-hash".to_string()),
            )
            .await
            .unwrap();
        });

        // agent が Start を受信するまで待ってから shutdown
        ready.notified().await;
        shutdown_tx.send(()).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), agent_handle)
            .await
            .expect("agent timed out")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), host_handle)
            .await
            .expect("host timed out")
            .unwrap();
    }

    /// agent が Hello の代わりに Error を返した場合のエラーハンドリング。
    #[tokio::test]
    async fn run_on_stream_agent_hello_error() {
        let (client, server) = tokio::io::duplex(8192);
        let (tx, _rx) = mpsc::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        // agent: Hello を受信した後 Error を返す
        let agent_handle = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);
            let _ = protocol::read_message(&mut reader).await;
            protocol::write_message(&mut writer, &Message::Error("auth failed".to_string()))
                .await
                .unwrap();
        });

        let result = VmAgentTracer::run_on_stream(client, &filter, tx, shutdown_rx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("auth failed"));

        agent_handle.await.unwrap();
    }

    /// agent が接続を閉じた場合のエラーハンドリング。
    #[tokio::test]
    async fn run_on_stream_agent_closes_during_handshake() {
        let (client, server) = tokio::io::duplex(8192);
        let (tx, _rx) = mpsc::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        // agent: Hello を受信した後すぐ接続を閉じる
        let agent_handle = tokio::spawn(async move {
            let (mut reader, _writer) = tokio::io::split(server);
            let _ = protocol::read_message(&mut reader).await;
            // writer をドロップして接続を閉じる
        });

        let result = VmAgentTracer::run_on_stream(client, &filter, tx, shutdown_rx).await;
        assert!(result.is_err());

        agent_handle.await.unwrap();
    }

    /// shutdown シグナルで Stop メッセージが送信されることを確認。
    #[tokio::test]
    async fn run_on_stream_sends_stop_on_shutdown() {
        let (client, server) = tokio::io::duplex(8192);
        let (tx, _rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        // agent が Start を受信したら通知する
        let ready = Arc::new(tokio::sync::Notify::new());
        let ready_clone = ready.clone();

        // agent 側: Hello → Ready を送り、Stop を待つ
        let agent_handle = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);

            // Hello ハンドシェイク
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(
                msg,
                Message::Hello {
                    authenticated: false,
                    ..
                }
            ));
            protocol::write_message(
                &mut writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();

            // Ready を送信
            protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();

            // Start を受信 → shutdown 可能を通知
            let _msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            ready_clone.notify_one();

            // Stop メッセージを待つ
            let msg = protocol::read_message(&mut reader).await.unwrap();
            match msg {
                Some(Message::Stop) => {} // 期待通り
                other => panic!("expected Stop, got {:?}", other),
            }
        });

        // host 側
        let host_handle = tokio::spawn(async move {
            VmAgentTracer::run_on_stream(client, &filter, tx, shutdown_rx)
                .await
                .unwrap();
        });

        // agent が Start を受信するまで待ってから shutdown
        ready.notified().await;
        shutdown_tx.send(()).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), agent_handle)
            .await
            .expect("agent timed out")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), host_handle)
            .await
            .expect("host timed out")
            .unwrap();
    }

    /// TCP 経由で Tracer::start() / stop() の全ライフサイクルをテスト。
    ///
    /// ローカルの TCP リスナーで agent をシミュレートし、
    /// VmAgentTracer が TCP 接続→ハンドシェイク→イベント受信→停止
    /// まで正しく動作することを確認する。
    /// macOS でも TCP 経由の通信パスが動作することの検証を兼ねる。
    #[tokio::test]
    async fn tracer_start_stop_over_tcp() {
        use tokio::net::TcpListener;

        // OS が空きポートを割り当てる
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let test_event = SyscallEvent {
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            pid: 300,
            tgid: 0,
            process_name: "tcp-agent".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![SyscallArg::Fd(7)],
            result: SyscallResult::Ok(0),
        };
        let test_event_clone = test_event.clone();

        // agent 側: TCP accept → Hello → Ready → Start 受信 → Event 送信 → Stop 受信
        let agent_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);

            // Hello ハンドシェイク
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(
                msg,
                Message::Hello {
                    authenticated: false,
                    ..
                }
            ));
            protocol::write_message(
                &mut writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();

            // Ready
            protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();

            // Start 受信
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(msg, Message::Start(_)));

            // Event 送信
            protocol::write_message(&mut writer, &Message::Event(test_event_clone))
                .await
                .unwrap();

            // Stop 受信を待つ
            let msg = protocol::read_message(&mut reader).await.unwrap();
            match msg {
                Some(Message::Stop) => {}
                other => panic!("expected Stop, got {:?}", other),
            }
        });

        // host 側: Tracer trait 経由で start/stop
        let tracer = VmAgentTracer::new(VmAgentConfig { port: port as u32 });
        let filter = TraceFilter {
            categories: vec![crate::event::SyscallCategory::File],
            pids: None,
        };

        let mut rx = tracer.start(&filter).await.unwrap();

        // イベント受信
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("event recv timed out")
            .expect("channel closed before event");
        assert_eq!(received.pid, test_event.pid);
        assert_eq!(received.syscall, test_event.syscall);
        assert_eq!(&*received.process_name, &*test_event.process_name);

        // 停止
        tracer.stop().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), agent_handle)
            .await
            .expect("agent timed out")
            .unwrap();
    }

    /// Tracer::start() を二重に呼ぶとエラーになることを確認。
    #[tokio::test]
    async fn tracer_start_twice_fails() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // agent が Start を受信したことを通知するチャネル
        let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();

        // agent 側: Hello → Ready → Start 受信(通知) → Stop 受信
        let agent_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);

            // Hello ハンドシェイク
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(msg, Message::Hello { .. }));
            protocol::write_message(
                &mut writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();
            protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();

            // Start 受信
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(msg, Message::Start(_)));
            let _ = start_tx.send(());

            // Stop を待つ
            let msg = protocol::read_message(&mut reader).await.unwrap();
            assert!(matches!(msg, Some(Message::Stop)));
        });

        let tracer = VmAgentTracer::new(VmAgentConfig { port: port as u32 });
        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        let _rx = tracer.start(&filter).await.unwrap();

        // agent が Start を受信するまで待ってから二回目を試行
        tokio::time::timeout(std::time::Duration::from_secs(5), start_rx)
            .await
            .expect("start_rx timed out")
            .unwrap();

        // 二回目の start はエラー
        let result = tracer.start(&filter).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already running"));

        tracer.stop().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), agent_handle)
            .await
            .expect("agent timed out")
            .unwrap();
    }

    /// TCP 接続失敗時に shutdown_tx がロールバックされ、再度 start() できることを確認。
    #[tokio::test]
    async fn start_rollback_on_connection_failure() {
        use tokio::net::TcpListener;

        // 到達不可能なポートで start() → 失敗 → ロールバック → 再度 start() 成功
        let tracer = VmAgentTracer::new(VmAgentConfig { port: 1 }); // port 1 は通常接続不可
        let filter = TraceFilter {
            categories: vec![crate::event::SyscallCategory::File],
            pids: None,
        };

        // 1回目: 接続失敗
        let result = tracer.start(&filter).await;
        assert!(result.is_err(), "到達不可能なポートへの接続は失敗すべき");

        // 2回目: ロールバックされているので "already running" にならない
        // 正しいポートを設定して再度 start()
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tracer.set_agent_port(port);

        let agent_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let _msg = protocol::read_message(&mut reader).await.unwrap();
            protocol::write_message(
                &mut writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();
            protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();
            let _msg = protocol::read_message(&mut reader).await.unwrap();
            let _ = protocol::read_message(&mut reader).await;
        });

        let _rx = tracer
            .start(&filter)
            .await
            .expect("ロールバック後の start() は成功すべき");
        tracer.stop().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), agent_handle)
            .await
            .expect("agent timed out")
            .unwrap();
    }

    /// set_agent_port() で設定したポートが config.port より優先されることを確認。
    #[tokio::test]
    async fn set_agent_port_overrides_config() {
        use tokio::net::TcpListener;

        // config.port とは異なるポートでリッスン
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let actual_port = listener.local_addr().unwrap().port();

        let agent_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);

            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(msg, Message::Hello { .. }));
            protocol::write_message(
                &mut writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();
            protocol::write_message(&mut writer, &Message::Ready)
                .await
                .unwrap();

            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(msg, Message::Start(_)));

            let msg = protocol::read_message(&mut reader).await.unwrap();
            assert!(matches!(msg, Some(Message::Stop)));
        });

        // config.port は 99 (使われないポート) だが、set_agent_port で actual_port を設定
        let tracer = VmAgentTracer::new(VmAgentConfig { port: 99 });
        tracer.set_agent_port(actual_port);

        let filter = TraceFilter {
            categories: vec![crate::event::SyscallCategory::File],
            pids: None,
        };

        // config.port=99 ではなく actual_port に接続されることを検証
        let _rx = tracer.start(&filter).await.unwrap();
        tracer.stop().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), agent_handle)
            .await
            .expect("agent timed out")
            .unwrap();
    }
}
