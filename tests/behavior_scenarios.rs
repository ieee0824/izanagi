//! Additional behavioral QA for issues #30/#31, including fragmented transport.
use izanagi::{
    protocol::{self, Message},
    protocol_client::ProtocolClient,
    tracer::TraceFilter,
};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, duplex};

fn filter() -> TraceFilter {
    TraceFilter {
        categories: vec![],
        pids: None,
    }
}

async fn shell_frame(authenticated: bool) -> (Vec<u8>, Option<Vec<u8>>) {
    let message = Message::ShellData {
        stream: 1,
        data: b"fragmented-output".to_vec(),
    };
    let key = authenticated.then(|| hex::encode(rand::random::<[u8; 32]>()).into_bytes());
    let mut bytes = Vec::new();
    if let Some(key) = &key {
        protocol::write_message_authenticated(&mut bytes, &message, key, &mut 0)
            .await
            .unwrap();
    } else {
        protocol::write_message(&mut bytes, &message).await.unwrap();
    }
    (bytes, key)
}

#[tokio::test]
async fn fragmented_shell_output_without_cancellation_is_received() {
    for authenticated in [false, true] {
        let (frame, key) = shell_frame(authenticated).await;
        let (host, mut peer) = duplex(4096);
        let (reader, writer) = tokio::io::split(host);
        let mut client = ProtocolClient::new(reader, writer, key);
        let sender = tokio::spawn(async move {
            for byte in frame {
                peer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let message = tokio::time::timeout(Duration::from_secs(1), client.recv_message())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(message, Some(Message::ShellData { data, .. }) if data == b"fragmented-output")
        );
        sender.await.unwrap();
    }
}

// The shell's select drops recv_message when input or SIGWINCH wins.
// Exercise every frame boundary rather than assuming TCP preserves message boundaries.
#[tokio::test]
async fn fragmented_shell_receive_survives_input_or_resize_cancellation() {
    let mut failures = Vec::new();
    for authenticated in [false, true] {
        let (frame, key) = shell_frame(authenticated).await;
        for boundary in 1..frame.len() {
            let (host, mut peer) = duplex(4096);
            let (reader, writer) = tokio::io::split(host);
            let mut client = ProtocolClient::new(reader, writer, key.clone());
            peer.write_all(&frame[..boundary]).await.unwrap();
            // No suffix exists yet, so the first poll consumes the available prefix
            // and this timeout cancels the pending receive, exactly as shell select does.
            assert!(
                tokio::time::timeout(Duration::from_millis(1), client.recv_message())
                    .await
                    .is_err()
            );
            peer.write_all(&frame[boundary..]).await.unwrap();
            drop(peer);
            let result = client.recv_message().await;
            if !matches!(&result, Ok(Some(Message::ShellData { data, .. })) if data == b"fragmented-output")
            {
                failures.push(format!(
                    "auth={authenticated}, boundary={boundary}: {result:?}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cancelled receives lost frame state; first: {}",
        failures.len(),
        failures.first().map(String::as_str).unwrap_or("")
    );
}

#[tokio::test]
async fn repeated_receive_cancellation_preserves_frame_and_next_message() {
    for authenticated in [false, true] {
        let (frame, key) = shell_frame(authenticated).await;
        let (host, mut peer) = duplex(4096);
        let (reader, writer) = tokio::io::split(host);
        let mut client = ProtocolClient::new(reader, writer, key.clone());
        for byte in &frame[..frame.len() - 1] {
            peer.write_all(&[*byte]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(1), client.recv_message())
                    .await
                    .is_err()
            );
        }
        peer.write_all(&frame[frame.len() - 1..]).await.unwrap();
        assert!(
            matches!(client.recv_message().await.unwrap(), Some(Message::ShellData { data, .. }) if data == b"fragmented-output")
        );
        let next = Message::ShellClose { exit_code: 42 };
        match key {
            Some(key) => protocol::write_message_authenticated(&mut peer, &next, &key, &mut 1)
                .await
                .unwrap(),
            None => protocol::write_message(&mut peer, &next).await.unwrap(),
        }
        drop(peer);
        assert!(matches!(
            client.recv_message().await.unwrap(),
            Some(Message::ShellClose { exit_code: 42 })
        ));
        assert!(client.recv_message().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn tracing_requires_exact_acknowledgement_in_both_authentication_modes() {
    for authenticated in [false, true] {
        for response in [
            Some(Message::TraceStarted),
            Some(Message::Ready),
            Some(Message::Error("initialization failed".into())),
            Some(Message::ShellClose { exit_code: 0 }),
            None,
        ] {
            let success = matches!(response, Some(Message::TraceStarted));
            let key = authenticated.then(|| hex::encode(rand::random::<[u8; 32]>()).into_bytes());
            let (host, peer) = duplex(4096);
            let (reader, writer) = tokio::io::split(host);
            let mut host = ProtocolClient::new(reader, writer, key.clone());
            let agent = tokio::spawn(async move {
                let (reader, writer) = tokio::io::split(peer);
                let mut peer = ProtocolClient::new(reader, writer, key);
                assert!(matches!(
                    peer.recv_message().await.unwrap(),
                    Some(Message::Start(_))
                ));
                if let Some(response) = response {
                    peer.send_message(&response).await.unwrap();
                }
            });
            let result =
                tokio::time::timeout(Duration::from_secs(1), host.start_tracing(&filter()))
                    .await
                    .unwrap();
            assert_eq!(result.is_ok(), success, "{result:?}");
            agent.await.unwrap();
        }
    }
}

#[tokio::test]
async fn truncated_shell_frames_are_rejected_in_both_authentication_modes() {
    for authenticated in [false, true] {
        let (frame, key) = shell_frame(authenticated).await;
        for boundary in 1..frame.len() {
            let (host, mut peer) = duplex(4096);
            let (reader, writer) = tokio::io::split(host);
            let mut client = ProtocolClient::new(reader, writer, key.clone());
            peer.write_all(&frame[..boundary]).await.unwrap();
            drop(peer);
            assert!(
                client.recv_message().await.is_err(),
                "auth={authenticated}, boundary={boundary}"
            );
        }
    }
}

#[tokio::test]
async fn silent_agent_is_bounded_at_hello_ready_and_trace_ack() {
    let mut scenarios = tokio::task::JoinSet::new();
    for phase in ["hello", "ready", "ack"] {
        for authenticated in [false, true] {
            scenarios.spawn(async move {
                let key =
                    authenticated.then(|| hex::encode(rand::random::<[u8; 32]>()).into_bytes());
                let (host, peer) = duplex(4096);
                let agent_key = key.clone();
                let agent = tokio::spawn(async move {
                    let (reader, writer) = tokio::io::split(peer);
                    let mut peer = ProtocolClient::new(reader, writer, agent_key);
                    assert!(matches!(
                        peer.recv_message().await.unwrap(),
                        Some(Message::Hello { .. })
                    ));
                    if phase != "hello" {
                        peer.send_message(&Message::Hello {
                            authenticated,
                            token: None,
                        })
                        .await
                        .unwrap();
                    }
                    if phase == "ack" {
                        peer.send_message(&Message::Ready).await.unwrap();
                        assert!(matches!(
                            peer.recv_message().await.unwrap(),
                            Some(Message::Start(_))
                        ));
                    }
                    assert!(peer.recv_message().await.unwrap().is_none());
                });
                let (tx, _events) = tokio::sync::mpsc::channel(1);
                let (_stop, shutdown) = tokio::sync::oneshot::channel();
                let started = std::time::Instant::now();
                let result = match key {
                    Some(key) => {
                        izanagi::vm_agent_tracer::VmAgentTracer::run_on_stream_authenticated(
                            host,
                            &filter(),
                            tx,
                            shutdown,
                            &key,
                        )
                        .await
                    }
                    None => {
                        izanagi::vm_agent_tracer::VmAgentTracer::run_on_stream(
                            host,
                            &filter(),
                            tx,
                            shutdown,
                        )
                        .await
                    }
                };
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("timed out waiting for agent tracing readiness"),
                    "phase={phase}, auth={authenticated}"
                );
                assert!(started.elapsed() < Duration::from_secs(17));
                agent.await.unwrap();
            });
        }
    }
    while let Some(result) = scenarios.join_next().await {
        result.unwrap();
    }
}

#[tokio::test]
async fn stop_during_start_closes_peer_and_allows_retry() {
    use izanagi::{
        tracer::Tracer,
        vm_agent_tracer::{VmAgentConfig, VmAgentTracer},
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tracer = std::sync::Arc::new(VmAgentTracer::new(VmAgentConfig {
        port: listener.local_addr().unwrap().port().into(),
    }));
    let (waiting, waiting_rx) = tokio::sync::oneshot::channel();
    let agent = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let mut peer = ProtocolClient::new(reader, writer, None);
        assert!(matches!(
            peer.recv_message().await.unwrap(),
            Some(Message::Hello { .. })
        ));
        waiting.send(()).unwrap();
        assert!(peer.recv_message().await.unwrap().is_none());
    });
    let startup_tracer = tracer.clone();
    let startup = tokio::spawn(async move { startup_tracer.start(&filter()).await });
    tokio::time::timeout(Duration::from_secs(1), waiting_rx)
        .await
        .unwrap()
        .unwrap();
    tracer.stop().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), startup)
        .await
        .unwrap()
        .unwrap();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("startup cancelled")
    );
    agent.await.unwrap();
    tracer.set_agent_port(1);
    assert!(
        !tracer
            .start(&filter())
            .await
            .unwrap_err()
            .to_string()
            .contains("already running")
    );
    tracer.stop().await.unwrap();
}

#[tokio::test]
async fn saturated_event_channel_does_not_prevent_shutdown() {
    use izanagi::{
        event::{Syscall, SyscallEvent, SyscallResult},
        vm_agent_tracer::VmAgentTracer,
    };
    let (host, peer) = duplex(8192);
    let (tx, _events) = tokio::sync::mpsc::channel(1);
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let (sent, sent_rx) = tokio::sync::oneshot::channel();
    let agent = tokio::spawn(async move {
        let (reader, writer) = tokio::io::split(peer);
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
        for _ in 0..3 {
            peer.send_message(&Message::Event(SyscallEvent {
                timestamp: std::time::SystemTime::UNIX_EPOCH,
                pid: 1,
                tgid: 1,
                process_name: "qa".into(),
                syscall: Syscall::Open,
                args: smallvec::smallvec![],
                result: SyscallResult::Ok(0),
            }))
            .await
            .unwrap();
        }
        sent.send(()).unwrap();
        let result = peer.recv_message().await.unwrap();
        assert!(matches!(result, None | Some(Message::Stop)));
    });
    let host =
        tokio::spawn(
            async move { VmAgentTracer::run_on_stream(host, &filter(), tx, shutdown).await },
        );
    sent_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), host)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), agent)
        .await
        .unwrap()
        .unwrap();
}
