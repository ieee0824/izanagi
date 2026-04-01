//! 手動起動した izanagi-agent に接続するテストツール。
//! Usage: cargo run --example connect_agent
//!
//! 認証付きで試す場合は agent/ホスト両方で同じ IZANAGI_SHARED_SECRET を設定してください:
//!   IZANAGI_SHARED_SECRET=test123 cargo run --example connect_agent

use izanagi::protocol::{self, Message};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = "127.0.0.1:9001";
    println!("Connecting to agent at {}...", addr);

    let stream = TcpStream::connect(addr).await?;
    let (mut reader, mut writer) = stream.into_split();
    println!("Connected!");

    // シークレットを環境変数から取得
    let secret = protocol::load_shared_secret_from_env()?;
    let authenticated = secret.is_some();
    if authenticated {
        println!("Using HMAC authentication");
    } else {
        println!("WARNING: No authentication (IZANAGI_SHARED_SECRET not set)");
    }

    // Hello ハンドシェイク（シークレット設定時は HMAC 保護）
    let mut send_seq = 0u64;
    let mut recv_seq = 0u64;
    let hello = Message::Hello {
        authenticated,
        token: None,
    };
    println!("Sending: {:?}", hello);
    send(&mut writer, &hello, secret.as_deref(), &mut send_seq).await?;

    match recv(&mut reader, secret.as_deref(), &mut recv_seq).await? {
        Some(msg) => println!("Received: {:?}", msg),
        None => {
            println!("Connection closed by agent");
            return Ok(());
        }
    }

    // Ready を受信
    let ready = recv(&mut reader, secret.as_deref(), &mut recv_seq).await?;
    match ready {
        Some(Message::Ready) => println!("Agent is ready"),
        Some(msg) => println!("Expected Ready, got: {:?}", msg),
        None => {
            println!("Connection closed by agent");
            return Ok(());
        }
    }

    // Exec コマンドを送信
    let exec = Message::Exec {
        cmd: vec!["/bin/echo".to_string(), "hello from izanagi!".to_string()],
        env: std::collections::HashMap::new(),
    };
    println!("Sending: {:?}", exec);
    send(&mut writer, &exec, secret.as_deref(), &mut send_seq).await?;

    // レスポンスを受信
    match recv(&mut reader, secret.as_deref(), &mut recv_seq).await? {
        Some(Message::ExecResult {
            exit_code,
            stdout,
            stderr,
        }) => {
            println!("Exit code: {}", exit_code);
            if !stdout.is_empty() {
                print!("Stdout: {}", String::from_utf8_lossy(&stdout));
            }
            if !stderr.is_empty() {
                print!("Stderr: {}", String::from_utf8_lossy(&stderr));
            }
        }
        Some(Message::Error(e)) => {
            println!("Agent error: {}", e);
        }
        Some(msg) => {
            println!("Unexpected: {:?}", msg);
        }
        None => {
            println!("Connection closed");
        }
    }

    println!("Done!");
    Ok(())
}

async fn send<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
    secret: Option<&[u8]>,
    send_seq: &mut u64,
) -> anyhow::Result<()> {
    match secret {
        Some(s) => protocol::write_message_authenticated(writer, msg, s, send_seq).await,
        None => protocol::write_message(writer, msg).await,
    }
}

async fn recv<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    secret: Option<&[u8]>,
    recv_seq: &mut u64,
) -> anyhow::Result<Option<Message>> {
    match secret {
        Some(s) => protocol::read_message_authenticated(reader, s, recv_seq).await,
        None => protocol::read_message(reader).await,
    }
}
