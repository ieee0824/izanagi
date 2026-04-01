//! ProtocolClient の統合テスト。
//!
//! handshake → Ready → Start → Event → Stop のフルフローを
//! クライアント/サーバーペアで検証する。

use std::sync::Arc;

use izanagi::event::{Syscall, SyscallArg, SyscallEvent, SyscallResult};
use izanagi::protocol::{self, Message};
use izanagi::protocol_client::ProtocolClient;
use izanagi::tracer::TraceFilter;

use smallvec::smallvec;
use tokio::io::duplex;

/// 非認証モードでの handshake → Ready → Start → Event → Stop フルフロー。
#[tokio::test]
async fn full_flow_unauthenticated() {
    let (client_stream, server_stream) = duplex(8192);
    let (server_reader, mut server_writer) = tokio::io::split(server_stream);
    let (client_reader, client_writer) = tokio::io::split(client_stream);

    let mut client = ProtocolClient::new(client_reader, client_writer, None);

    let test_event = SyscallEvent {
        timestamp: std::time::SystemTime::UNIX_EPOCH,
        pid: 42,
        tgid: 0,
        process_name: Arc::from("test-proc"),
        syscall: Syscall::Open,
        args: smallvec![SyscallArg::Path("/etc/passwd".into())],
        result: SyscallResult::Ok(3),
    };
    let test_event_clone = test_event.clone();

    // サーバー側
    let server = tokio::spawn(async move {
        let mut reader = server_reader;

        // Hello を受信して Hello を返す
        let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
        assert!(matches!(
            msg,
            Message::Hello {
                authenticated: false,
                ..
            }
        ));
        protocol::write_message(
            &mut server_writer,
            &Message::Hello {
                authenticated: false,
                token: None,
            },
        )
        .await
        .unwrap();

        // Ready を送信
        protocol::write_message(&mut server_writer, &Message::Ready)
            .await
            .unwrap();

        // Start を受信
        let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
        assert!(matches!(msg, Message::Start(_)));

        // Event を送信
        protocol::write_message(&mut server_writer, &Message::Event(test_event_clone))
            .await
            .unwrap();

        // Stop を受信
        let msg = protocol::read_message(&mut reader).await.unwrap();
        assert!(matches!(msg, Some(Message::Stop)));
    });

    // クライアント側: handshake + Ready 待ち
    client.handshake_and_wait_ready(None).await.unwrap();

    // Start 送信
    let filter = TraceFilter {
        categories: vec![izanagi::event::SyscallCategory::File],
        pids: None,
    };
    client.send_message(&Message::Start(filter)).await.unwrap();

    // Event 受信
    let event_msg = client.recv_message().await.unwrap().unwrap();
    match event_msg {
        Message::Event(event) => {
            assert_eq!(event.pid, 42);
            assert_eq!(&*event.process_name, "test-proc");
        }
        other => panic!("expected Event, got {:?}", other),
    }

    // Stop 送信
    client.send_message(&Message::Stop).await.unwrap();

    server.await.unwrap();
}

/// 認証モードでの handshake フルフロー。
#[tokio::test]
async fn full_flow_authenticated() {
    let secret = b"integration-test-secret-key!!!!!!".to_vec();
    let (client_stream, server_stream) = duplex(8192);
    let (server_reader, mut server_writer) = tokio::io::split(server_stream);
    let (client_reader, client_writer) = tokio::io::split(client_stream);

    let mut client = ProtocolClient::new(client_reader, client_writer, Some(secret.clone()));

    let server = tokio::spawn(async move {
        let mut reader = server_reader;
        let mut recv_seq = 0u64;
        let mut send_seq = 0u64;

        // Hello (HMAC 認証付き)
        let msg = protocol::read_message_authenticated(&mut reader, &secret, &mut recv_seq)
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
            &mut server_writer,
            &Message::Hello {
                authenticated: true,
                token: None,
            },
            &secret,
            &mut send_seq,
        )
        .await
        .unwrap();

        // Ready
        protocol::write_message_authenticated(
            &mut server_writer,
            &Message::Ready,
            &secret,
            &mut send_seq,
        )
        .await
        .unwrap();
    });

    client.handshake_and_wait_ready(None).await.unwrap();

    server.await.unwrap();
}
