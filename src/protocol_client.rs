//! プロトコルクライアント: HMAC 認証の分岐を隠蔽する高レベルラッパー。
//!
//! `vm_agent_tracer`, `qemu_sandbox`, `commands/*` に散在していた
//! handshake/send_message/recv_message の重複ロジックを統合する。

use tokio::io::{AsyncRead, AsyncWrite};

use crate::protocol::{self, Message};

/// HMAC 認証の有無を透過的に扱うプロトコルクライアント。
///
/// `secret` が `Some` の場合はシーケンス番号付き HMAC-SHA256 認証を行い、
/// `None` の場合は非認証モードでメッセージを送受信する。
pub struct ProtocolClient<R, W> {
    reader: R,
    writer: W,
    secret: Option<Vec<u8>>,
    send_seq: u64,
    recv_seq: u64,
}

impl<R, W> ProtocolClient<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// reader/writer と認証情報から ProtocolClient を構築する。
    /// handshake は行わない。呼び出し側で `handshake()` を別途呼ぶこと。
    pub fn new(reader: R, writer: W, secret: Option<Vec<u8>>) -> Self {
        Self {
            reader,
            writer,
            secret,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// Hello ハンドシェイクを実行し、認証モードの一致を確認する。
    pub async fn handshake(&mut self, token: Option<String>) -> anyhow::Result<()> {
        let authenticated = self.secret.is_some();

        let hello = Message::Hello {
            authenticated,
            token,
        };
        self.send_message(&hello).await?;

        match self.recv_message().await? {
            Some(Message::Hello {
                authenticated: agent_auth,
                ..
            }) => {
                if agent_auth != authenticated {
                    anyhow::bail!(
                        "authentication mode mismatch: host={}, agent={}",
                        authenticated,
                        agent_auth
                    );
                }
            }
            Some(Message::Error(e)) => anyhow::bail!("agent error on hello: {}", e),
            Some(other) => anyhow::bail!("expected Hello message, got {:?}", other),
            None => anyhow::bail!(
                "agent disconnected before Hello; possible incompatible protocol version: upgrade host and agent together"
            ),
        }

        Ok(())
    }

    /// Hello ハンドシェイク + Ready 待ちを一括で行う。
    /// 多くの呼び出し元で handshake() + recv_message(Ready) が重複していたため、
    /// この convenience メソッドで統合する。
    pub async fn handshake_and_wait_ready(&mut self, token: Option<String>) -> anyhow::Result<()> {
        self.handshake(token).await?;
        match self.recv_message().await? {
            Some(Message::Ready) => Ok(()),
            Some(Message::Error(e)) => anyhow::bail!("agent error on connect: {}", e),
            Some(other) => anyhow::bail!("expected Ready message, got {:?}", other),
            None => anyhow::bail!("agent disconnected before Ready"),
        }
    }

    /// メッセージを送信する。認証モードに応じて HMAC 署名を付与する。
    pub async fn send_message(&mut self, msg: &Message) -> anyhow::Result<()> {
        match self.secret.as_deref() {
            Some(s) => {
                protocol::write_message_authenticated(&mut self.writer, msg, s, &mut self.send_seq)
                    .await
            }
            None => protocol::write_message(&mut self.writer, msg).await,
        }
    }

    /// メッセージを受信する。認証モードに応じて HMAC 検証を行う。
    pub async fn recv_message(&mut self) -> anyhow::Result<Option<Message>> {
        match self.secret.as_deref() {
            Some(s) => {
                protocol::read_message_authenticated(&mut self.reader, s, &mut self.recv_seq).await
            }
            None => protocol::read_message(&mut self.reader).await,
        }
    }

    /// 現在の認証状態を返す。
    #[cfg(test)]
    pub(crate) fn is_authenticated(&self) -> bool {
        self.secret.is_some()
    }

    /// 現在のシーケンス番号を返す (テスト用)。
    #[cfg(test)]
    pub(crate) fn sequences(&self) -> (u64, u64) {
        (self.send_seq, self.recv_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn unauthenticated_handshake() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        // サーバー側: Hello を受信して Hello を返す
        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            match msg {
                Message::Hello { authenticated, .. } => {
                    assert!(!authenticated);
                }
                _ => panic!("expected Hello"),
            }
            let reply = Message::Hello {
                authenticated: false,
                token: None,
            };
            protocol::write_message(&mut server_writer, &reply)
                .await
                .unwrap();
        });

        client.handshake(None).await.unwrap();
        server_handle.await.unwrap();

        assert!(!client.is_authenticated());
        // 非認証モードではシーケンス番号はインクリメントされない
        assert_eq!(client.sequences(), (0, 0));
    }

    #[tokio::test]
    async fn authenticated_handshake() {
        let secret = b"test-secret-key-32bytes-long!!!!!".to_vec();
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, Some(secret.clone()));

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let mut recv_seq = 0u64;
            let msg = protocol::read_message_authenticated(&mut reader, &secret, &mut recv_seq)
                .await
                .unwrap()
                .unwrap();
            match msg {
                Message::Hello { authenticated, .. } => assert!(authenticated),
                _ => panic!("expected Hello"),
            }
            let reply = Message::Hello {
                authenticated: true,
                token: None,
            };
            let mut send_seq = 0u64;
            protocol::write_message_authenticated(
                &mut server_writer,
                &reply,
                &secret,
                &mut send_seq,
            )
            .await
            .unwrap();
        });

        client.handshake(None).await.unwrap();
        server_handle.await.unwrap();

        assert!(client.is_authenticated());
    }

    #[tokio::test]
    async fn handshake_with_token() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            match msg {
                Message::Hello { token, .. } => {
                    assert_eq!(token.as_deref(), Some("my-token-hash"));
                }
                _ => panic!("expected Hello"),
            }
            let reply = Message::Hello {
                authenticated: false,
                token: None,
            };
            protocol::write_message(&mut server_writer, &reply)
                .await
                .unwrap();
        });

        client
            .handshake(Some("my-token-hash".to_string()))
            .await
            .unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_and_wait_ready_success() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let _hello = protocol::read_message(&mut reader).await.unwrap();
            protocol::write_message(
                &mut server_writer,
                &Message::Hello {
                    authenticated: false,
                    token: None,
                },
            )
            .await
            .unwrap();
            protocol::write_message(&mut server_writer, &Message::Ready)
                .await
                .unwrap();
        });

        client.handshake_and_wait_ready(None).await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_auth_mismatch_fails() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        // クライアントは非認証、サーバーが認証モードで応答
        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let _msg = protocol::read_message(&mut reader).await.unwrap();
            let reply = Message::Hello {
                authenticated: true, // mismatch
                token: None,
            };
            protocol::write_message(&mut server_writer, &reply)
                .await
                .unwrap();
        });

        let result = client.handshake(None).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authentication mode mismatch")
        );

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn send_recv_unauthenticated() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            // クライアントからのメッセージ受信
            let msg = protocol::read_message(&mut reader).await.unwrap().unwrap();
            assert!(matches!(msg, Message::Ready));

            // 応答送信
            protocol::write_message(&mut server_writer, &Message::Ready)
                .await
                .unwrap();
        });

        client.send_message(&Message::Ready).await.unwrap();
        let reply = client.recv_message().await.unwrap().unwrap();
        assert!(matches!(reply, Message::Ready));

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn send_recv_authenticated() {
        let secret = b"test-secret-key-32bytes-long!!!!!".to_vec();
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, Some(secret.clone()));

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let mut recv_seq = 0u64;
            let msg = protocol::read_message_authenticated(&mut reader, &secret, &mut recv_seq)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(msg, Message::Ready));

            let mut send_seq = 0u64;
            protocol::write_message_authenticated(
                &mut server_writer,
                &Message::Ready,
                &secret,
                &mut send_seq,
            )
            .await
            .unwrap();
        });

        client.send_message(&Message::Ready).await.unwrap();
        let reply = client.recv_message().await.unwrap().unwrap();
        assert!(matches!(reply, Message::Ready));

        // 認証モードではシーケンス番号がインクリメントされる
        let (send_seq, recv_seq) = client.sequences();
        assert!(send_seq > 0, "send_seq should be incremented");
        assert!(recv_seq > 0, "recv_seq should be incremented");

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_disconnect_returns_none() {
        let (client_stream, server_stream) = duplex(4096);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        // サーバー側を即座にドロップ
        drop(server_stream);

        let result = client.recv_message().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn handshake_server_error() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let _msg = protocol::read_message(&mut reader).await.unwrap();
            let reply = Message::Error("test error".to_string());
            protocol::write_message(&mut server_writer, &reply)
                .await
                .unwrap();
        });

        let result = client.handshake(None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_server_disconnect() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_reader, server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let mut client = ProtocolClient::new(client_reader, client_writer, None);

        let server_handle = tokio::spawn(async move {
            let mut reader = server_reader;
            let _msg = protocol::read_message(&mut reader).await.unwrap();
            // 応答を返さずに切断
            drop(server_writer);
        });

        let result = client.handshake(None).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("disconnected before Hello")
        );

        server_handle.await.unwrap();
    }
}
