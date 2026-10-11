use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

pub(crate) const MAX_CONNECTIONS: usize = 64;

/// Reject excess connections immediately. Keep a slot until the session ends,
/// including authentication failures, timeouts and task cancellation.
pub(crate) fn spawn_connection<S>(
    stream: S,
    authentication_key: Option<Vec<u8>>,
    expected_session: Arc<Option<String>>,
    slots: &Arc<Semaphore>,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(permit) = Arc::clone(slots).try_acquire_owned() else {
        return false;
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(error) = crate::connection::handle_connection(
            stream,
            authentication_key.as_deref(),
            &expected_session,
        )
        .await
        {
            eprintln!("connection error: {error}");
        }
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn failed_authentication_releases_connection_slot() {
        let slots = Arc::new(Semaphore::new(1));
        let (mut host, agent) = tokio::io::duplex(4096);
        assert!(spawn_connection(
            agent,
            None,
            Arc::new(Some("fixture-session".into())),
            &slots
        ));
        izanagi::protocol::write_message(
            &mut host,
            &izanagi::protocol::Message::Hello {
                authenticated: false,
                token: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            izanagi::protocol::read_message(&mut host).await.unwrap(),
            Some(izanagi::protocol::Message::Error(_))
        ));
        assert_eq!(host.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn excess_connections_close_and_partial_hello_timeout_releases_slot() {
        let slots = Arc::new(Semaphore::new(1));
        let expected = Arc::new(None);
        let (mut slow, agent) = tokio::io::duplex(4096);
        assert!(spawn_connection(agent, None, expected.clone(), &slots));
        slow.write_all(&[0xff]).await.unwrap();
        tokio::task::yield_now().await;
        let (mut excess, agent) = tokio::io::duplex(4096);
        assert!(!spawn_connection(agent, None, expected.clone(), &slots));
        assert_eq!(excess.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(slots.available_permits(), 0);
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        tokio::task::yield_now().await;
        assert_eq!(slow.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(slots.available_permits(), 1);
        let (host, agent) = tokio::io::duplex(4096);
        assert!(spawn_connection(agent, None, expected, &slots));
        drop(host);
        tokio::task::yield_now().await;
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_hello_times_out_but_authenticated_session_outlives_deadline() {
        let (mut idle, agent) = tokio::io::duplex(4096);
        let slots = Arc::new(Semaphore::new(1));
        let expected = Arc::new(Some("fixture-session".into()));
        assert!(spawn_connection(agent, None, expected.clone(), &slots));
        assert_eq!(idle.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(slots.available_permits(), 1);
        let (host, agent) = tokio::io::duplex(4096);
        assert!(spawn_connection(agent, None, expected, &slots));
        let (reader, writer) = tokio::io::split(host);
        let mut client = izanagi::protocol_client::ProtocolClient::new(reader, writer, None);
        client
            .handshake_and_wait_ready(Some(crate::crypto::sha256_hex("fixture-session")))
            .await
            .unwrap();
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        tokio::task::yield_now().await;
        assert_eq!(slots.available_permits(), 0);
        drop(client);
        tokio::task::yield_now().await;
        assert_eq!(slots.available_permits(), 1);
    }
}
