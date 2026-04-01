//! agent で whoami を実行してユーザーを確認するテスト
//! Usage: IZANAGI_SHARED_SECRET=test123 cargo run --example check_user

use izanagi::protocol::{self, Message};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:9001").await?;
    let (mut reader, mut writer) = stream.into_split();

    let secret = protocol::load_shared_secret_from_env()?;

    // Hello ハンドシェイク（シークレット設定時は HMAC 保護）
    let mut send_seq = 0u64;
    let mut recv_seq = 0u64;
    let hello = Message::Hello {
        authenticated: secret.is_some(),
        token: None,
    };
    send(&mut writer, &hello, secret.as_deref(), &mut send_seq).await?;
    recv(&mut reader, secret.as_deref(), &mut recv_seq).await?; // Hello response

    // Ready
    recv(&mut reader, secret.as_deref(), &mut recv_seq).await?;

    // Exec: whoami
    let exec = Message::Exec {
        cmd: vec!["whoami".to_string()],
        env: std::collections::HashMap::new(),
    };
    send(&mut writer, &exec, secret.as_deref(), &mut send_seq).await?;

    match recv(&mut reader, secret.as_deref(), &mut recv_seq).await? {
        Some(Message::ExecResult {
            exit_code,
            stdout,
            stderr,
        }) => {
            println!("Exit code: {}", exit_code);
            println!("User: {}", String::from_utf8_lossy(&stdout).trim());
            if !stderr.is_empty() {
                println!("Stderr: {}", String::from_utf8_lossy(&stderr));
            }
        }
        Some(msg) => println!("Unexpected: {:?}", msg),
        None => println!("Connection closed"),
    }
    Ok(())
}

async fn send<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    msg: &Message,
    s: Option<&[u8]>,
    send_seq: &mut u64,
) -> anyhow::Result<()> {
    match s {
        Some(s) => protocol::write_message_authenticated(w, msg, s, send_seq).await,
        None => protocol::write_message(w, msg).await,
    }
}

async fn recv<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    s: Option<&[u8]>,
    recv_seq: &mut u64,
) -> anyhow::Result<Option<Message>> {
    match s {
        Some(s) => protocol::read_message_authenticated(r, s, recv_seq).await,
        None => protocol::read_message(r).await,
    }
}
