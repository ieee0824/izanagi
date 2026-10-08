//! Authenticated QEMU protocol smoke test. Uses snapshot mode and always stops its VM.
//! Usage: IZANAGI_SECRET_FILE=... cargo run --example qemu_protocol_smoke -- CONFIG
use anyhow::Context;
use izanagi::sandbox::Sandbox;
use izanagi::{
    event::{Syscall, SyscallArg},
    protocol::Message,
    protocol_client::ProtocolClient,
    tracer::TraceFilter,
};
use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: qemu_protocol_smoke CONFIG")?;
    let config = izanagi::config::Config::load(std::path::Path::new(&path))?;
    let secret =
        izanagi::protocol::load_shared_secret_from_env()?.context("authentication required")?;
    let mut sandbox = izanagi::qemu_sandbox::QemuSandbox::new();
    sandbox.up(&config.to_sandbox_config()?).await?;
    let result = async {
        let port = sandbox.agent_host_port().context("no agent port")?;
        let token = sandbox.session_token().context("no token")?;
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        let (reader, writer) = stream.into_split();
        let mut client = ProtocolClient::new(reader, writer, Some(secret));
        client.handshake_and_wait_ready(Some(token_hash)).await?;
        client
            .start_tracing(&TraceFilter {
                categories: vec![izanagi::event::SyscallCategory::File],
                pids: None,
            })
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let path = "/tmp/izanagi-protocol-path-smoke";
        let output = sandbox
            .exec(
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("printf '%s\\n' $$; printf v2-event-generator > {path}; rm {path}"),
                ],
                &Default::default(),
            )
            .await?;
        anyhow::ensure!(output.exit_code == 0, "Exec failed");
        let pid: u32 = String::from_utf8(output.stdout)?.trim().parse()?;
        // An arbitrary background event is insufficient: require the pathname
        // from this command's actual openat, with no trailing NUL.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match client.recv_message().await? {
                    Some(Message::Event(event)) => {
                        if event.pid == pid
                            && event.syscall == Syscall::OpenAt
                            && event.args.iter().any(
                                |arg| matches!(arg, SyscallArg::Path(value) if value == std::path::Path::new(path)),
                            )
                        {
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                    Some(Message::Error(error)) => anyhow::bail!("agent rejected tracing: {error}"),
                    None => anyhow::bail!("agent disconnected before pathname Event"),
                    other => anyhow::bail!("unexpected message instead of Event: {other:?}"),
                }
            }
        })
        .await
        .context("timed out waiting for command's pathname Event")??;
        println!("authenticated v2 Exec and matching PID/path Event received");
        client.send_message(&Message::Stop).await?;
        Ok(())
    }
    .await;
    sandbox.down().await?;
    result
}
