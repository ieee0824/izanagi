//! Authenticated agent connections shared by sandbox and session clients.

use crate::protocol::Message;
use crate::protocol_client::ProtocolClient;
use crate::sandbox::ExecOutput;
use anyhow::Context;
use std::collections::HashMap;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub type AgentClient = ProtocolClient<OwnedReadHalf, OwnedWriteHalf>;

pub async fn connect(
    host_port: u16,
    auth_key: Option<Vec<u8>>,
    token_hash: Option<String>,
) -> anyhow::Result<AgentClient> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", host_port))
        .await
        .context("agent への接続に失敗")?;
    let (reader, writer) = stream.into_split();
    let mut client = ProtocolClient::new(reader, writer, auth_key);
    client.handshake_and_wait_ready(token_hash).await?;
    Ok(client)
}

pub async fn execute<R, W>(
    client: &mut ProtocolClient<R, W>,
    cmd: &[String],
    env: &HashMap<String, String>,
) -> anyhow::Result<ExecOutput>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    client
        .send_message(&Message::Exec {
            cmd: cmd.to_vec(),
            env: env.clone(),
        })
        .await?;
    receive_exec_result(client).await
}

pub async fn execute_with_environment<R, W>(
    client: &mut ProtocolClient<R, W>,
    cmd: &[String],
    env: &HashMap<String, String>,
    inherit: &[String],
) -> anyhow::Result<ExecOutput>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    client
        .send_message(&Message::ExecWithEnvironment {
            cmd: cmd.to_vec(),
            env: env.clone(),
            inherit: inherit.to_vec(),
        })
        .await?;
    receive_exec_result(client).await
}

async fn receive_exec_result<R, W>(client: &mut ProtocolClient<R, W>) -> anyhow::Result<ExecOutput>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    match client.recv_message().await? {
        Some(Message::ExecResult {
            exit_code,
            stdout,
            stderr,
        }) => Ok(ExecOutput {
            exit_code,
            stdout,
            stderr,
        }),
        Some(Message::Error(error)) => anyhow::bail!("exec error: {}", error),
        _ => anyhow::bail!("unexpected agent exec response"),
    }
}
