//! Fail-closed startup and runtime monitoring behavior against real TCP peers.
use izanagi::{
    detector::Detector,
    engine::Engine,
    protocol::Message,
    protocol_client::ProtocolClient,
    sandbox::{ExecOutput, Sandbox, SandboxConfig, SandboxStatus, ShareConfig},
    tracer::{TraceFilter, Tracer},
    vm_agent_tracer::{VmAgentConfig, VmAgentTracer},
};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

// Isolate fixtures from a developer's configured agent authentication.
struct TestAuthentication {
    previous_path: Option<std::ffi::OsString>,
    previous_key_env: Option<std::ffi::OsString>,
    path: Option<std::path::PathBuf>,
}
impl TestAuthentication {
    fn new(auth_key: Option<&[u8]>) -> Self {
        let previous_path = std::env::var_os("IZANAGI_SECRET_FILE");
        let previous_key_env = std::env::var_os("IZANAGI_SHARED_SECRET");
        let path = auth_key.map(|key| {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let path = std::env::temp_dir()
                .join(format!("izanagi-monitor-test-{}", rand::random::<u64>()));
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
                .write_all(key)
                .unwrap();
            path
        });
        // These tests are serialized; only test-process environment is changed.
        unsafe {
            std::env::remove_var("IZANAGI_SHARED_SECRET");
            if let Some(path) = &path {
                std::env::set_var("IZANAGI_SECRET_FILE", path);
            } else {
                std::env::remove_var("IZANAGI_SECRET_FILE");
            }
        }
        Self {
            previous_path,
            previous_key_env,
            path,
        }
    }
}
impl Drop for TestAuthentication {
    fn drop(&mut self) {
        unsafe {
            for (name, value) in [
                ("IZANAGI_SECRET_FILE", &self.previous_path),
                ("IZANAGI_SHARED_SECRET", &self.previous_key_env),
            ] {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        if let Some(path) = &self.path {
            std::fs::remove_file(path).unwrap();
        }
    }
}

struct SandboxProbe {
    port: u16,
    status: SandboxStatus,
    down: Arc<AtomicBool>,
    executions: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl Sandbox for SandboxProbe {
    async fn up(&mut self, _: &SandboxConfig) -> anyhow::Result<()> {
        self.status = SandboxStatus::Running;
        Ok(())
    }
    async fn down(&mut self) -> anyhow::Result<()> {
        self.status = SandboxStatus::Stopped;
        self.down.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn status(&self) -> SandboxStatus {
        self.status
    }
    fn agent_host_port(&self) -> Option<u16> {
        Some(self.port)
    }
    async fn exec(&self, _: &[String], _: &HashMap<String, String>) -> anyhow::Result<ExecOutput> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
    async fn shell(&self) -> anyhow::Result<()> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}
fn configuration() -> SandboxConfig {
    SandboxConfig::Landlock {
        share: ShareConfig {
            host_paths: vec![],
            mount_point: "/workspace".into(),
        },
    }
}
fn filter() -> TraceFilter {
    TraceFilter {
        categories: vec![],
        pids: None,
    }
}

async fn fake_agent(
    listener: tokio::net::TcpListener,
    auth_key: Option<Vec<u8>>,
    mode: &'static str,
    release: tokio::sync::oneshot::Receiver<()>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let (reader, writer) = stream.into_split();
    let authenticated = auth_key.is_some();
    let mut peer = ProtocolClient::new(reader, writer, auth_key);
    assert!(matches!(
        peer.recv_message().await.unwrap(),
        Some(Message::Hello { .. })
    ));
    if mode == "hello-disconnect" {
        return;
    }
    if mode == "hello-error" {
        peer.send_message(&Message::Error("authentication rejected".into()))
            .await
            .unwrap();
        return;
    }
    peer.send_message(&Message::Hello {
        authenticated,
        token: None,
    })
    .await
    .unwrap();
    peer.send_message(&Message::Ready).await.unwrap();
    assert!(matches!(
        peer.recv_message().await.unwrap(),
        Some(Message::Start(_))
    ));
    if mode == "start-error" {
        peer.send_message(&Message::Error("eBPF initialization failed".into()))
            .await
            .unwrap();
        return;
    }
    peer.send_message(&Message::TraceStarted).await.unwrap();
    let _ = release.await;
    if mode == "runtime-error" {
        peer.send_message(&Message::Error("eBPF event stream failed".into()))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[serial_test::serial]
async fn startup_failures_stop_sandbox_before_exec_or_shell() {
    let _isolation = TestAuthentication::new(None);
    for authenticated in [false, true] {
        for mode in ["hello-disconnect", "hello-error", "start-error"] {
            for shell in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let down = Arc::new(AtomicBool::new(false));
                let executions = Arc::new(AtomicUsize::new(0));
                let tracer = VmAgentTracer::new(VmAgentConfig::default());
                let auth_key =
                    authenticated.then(|| hex::encode(rand::random::<[u8; 32]>()).into_bytes());
                let _authentication = TestAuthentication::new(auth_key.as_deref());
                if let Some(key) = &auth_key {
                    tracer.set_secret(key.clone());
                }
                let mut engine = Engine::new(
                    Box::new(SandboxProbe {
                        port,
                        status: SandboxStatus::Stopped,
                        down: down.clone(),
                        executions: executions.clone(),
                    }),
                    Box::new(tracer),
                    Detector::new(vec![]),
                );
                let (_release, rx) = tokio::sync::oneshot::channel();
                let agent = tokio::spawn(fake_agent(listener, auth_key, mode, rx));
                let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    engine
                        .start(&configuration(), &filter(), Box::new(|_| {}))
                        .await?;
                    if shell {
                        engine.shell().await
                    } else {
                        engine
                            .exec(&["command".into()], &HashMap::new())
                            .await
                            .map(|_| ())
                    }
                })
                .await
                .unwrap();
                assert!(result.is_err(), "{mode} must fail before execution");
                assert!(down.load(Ordering::SeqCst));
                assert_eq!(executions.load(Ordering::SeqCst), 0);
                assert_eq!(engine.sandbox().status(), SandboxStatus::Stopped);
                agent.await.unwrap();
            }
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn runtime_failure_interrupts_work_and_is_reported_to_caller() {
    let _isolation = TestAuthentication::new(None);
    for mode in ["runtime-error", "runtime-disconnect"] {
        for shell in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let down = Arc::new(AtomicBool::new(false));
            let executions = Arc::new(AtomicUsize::new(0));
            let mut engine = Engine::new(
                Box::new(SandboxProbe {
                    port,
                    status: SandboxStatus::Stopped,
                    down: down.clone(),
                    executions: executions.clone(),
                }),
                Box::new(VmAgentTracer::new(VmAgentConfig::default())),
                Detector::new(vec![]),
            );
            let (release, rx) = tokio::sync::oneshot::channel();
            let agent = tokio::spawn(fake_agent(listener, None, mode, rx));
            engine
                .start(&configuration(), &filter(), Box::new(|_| {}))
                .await
                .unwrap();
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let operation = async {
                    if shell { engine.shell().await } else { engine.exec(&["command".into()], &HashMap::new()).await.map(|_| ()) }
                };
                tokio::pin!(operation);
                tokio::select! { result = &mut operation => panic!("execution unexpectedly completed: {result:?}"),
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {} }
                assert_eq!(executions.load(Ordering::SeqCst), 1);
                release.send(()).unwrap();
                operation.await
            }).await.unwrap();
            let error = result.unwrap_err().to_string();
            assert!(error.contains("monitoring failed"), "{error}");
            if mode == "runtime-error" {
                assert!(error.contains("eBPF event stream failed"));
            }
            // A failed monitor also rejects subsequent commands.
            assert!(
                engine
                    .exec(&["second".into()], &HashMap::new())
                    .await
                    .is_err()
            );
            assert_eq!(executions.load(Ordering::SeqCst), 1);
            engine.stop().await.unwrap();
            assert!(down.load(Ordering::SeqCst));
            agent.await.unwrap();
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn start_waits_for_ack_and_can_retry_after_connection_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tracer = Arc::new(VmAgentTracer::new(VmAgentConfig { port: port.into() }));
    let (ack, ack_rx) = tokio::sync::oneshot::channel();
    let agent = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let mut peer = ProtocolClient::new(reader, writer, None);
        peer.recv_message().await.unwrap();
        peer.send_message(&Message::Hello {
            authenticated: false,
            token: None,
        })
        .await
        .unwrap();
        peer.send_message(&Message::Ready).await.unwrap();
        peer.recv_message().await.unwrap();
        ack_rx.await.unwrap();
        peer.send_message(&Message::TraceStarted).await.unwrap();
        assert!(matches!(
            peer.recv_message().await.unwrap(),
            Some(Message::Stop)
        ));
    });
    let trace_filter = filter();
    let setup = tracer.start(&trace_filter);
    tokio::pin!(setup);
    tokio::select! { _ = &mut setup => panic!("start returned before ACK"),
    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {} }
    ack.send(()).unwrap();
    let _events = setup.await.unwrap();
    tracer.stop().await.unwrap();
    agent.await.unwrap();
    // Failure is rolled back instead of leaving 'already running'.
    tracer.set_agent_port(1);
    for _ in 0..2 {
        assert!(
            !tracer
                .start(&filter())
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("already running")
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn cancelling_start_rolls_back_reservation_and_closes_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tracer = Arc::new(VmAgentTracer::new(VmAgentConfig { port: port.into() }));
    let (waiting, waiting_rx) = tokio::sync::oneshot::channel();
    let agent = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let mut peer = ProtocolClient::new(reader, writer, None);
        peer.recv_message().await.unwrap();
        peer.send_message(&Message::Hello {
            authenticated: false,
            token: None,
        })
        .await
        .unwrap();
        peer.send_message(&Message::Ready).await.unwrap();
        assert!(matches!(
            peer.recv_message().await.unwrap(),
            Some(Message::Start(_))
        ));
        waiting.send(()).unwrap();
        assert!(peer.recv_message().await.unwrap().is_none());
    });
    let startup_tracer = tracer.clone();
    let startup = tokio::spawn(async move { startup_tracer.start(&filter()).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), waiting_rx)
        .await
        .unwrap()
        .unwrap();
    startup.abort();
    assert!(startup.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(5), agent)
        .await
        .unwrap()
        .unwrap();
    tracer.set_agent_port(1);
    assert!(
        !tracer
            .start(&filter())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("already running")
    );
}

#[tokio::test]
#[serial_test::serial]
async fn dropping_tracer_stops_receiver_task_and_closes_stream() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let agent = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let mut peer = ProtocolClient::new(reader, writer, None);
        peer.recv_message().await.unwrap();
        peer.send_message(&Message::Hello {
            authenticated: false,
            token: None,
        })
        .await
        .unwrap();
        peer.send_message(&Message::Ready).await.unwrap();
        peer.recv_message().await.unwrap();
        peer.send_message(&Message::TraceStarted).await.unwrap();
        assert!(matches!(
            peer.recv_message().await.unwrap(),
            Some(Message::Stop)
        ));
        assert!(peer.recv_message().await.unwrap().is_none());
    });
    let tracer = VmAgentTracer::new(VmAgentConfig { port: port.into() });
    let mut events = tracer.start(&filter()).await.unwrap();
    drop(tracer);
    tokio::time::timeout(std::time::Duration::from_secs(5), agent)
        .await
        .unwrap()
        .unwrap();
    assert!(events.recv().await.is_none());
}
