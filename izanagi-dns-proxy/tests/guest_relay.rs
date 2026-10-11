use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use izanagi::guest_dns::DnsRelay;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn query() -> Vec<u8> {
    let mut message = Message::new(65, MessageType::Query, OpCode::Query);
    let mut question = Query::new();
    question.set_name(Name::from_ascii("denied.example.").unwrap());
    question.set_query_type(RecordType::A);
    message.add_query(question);
    message.to_vec().unwrap()
}

fn assert_blocked(bytes: &[u8]) {
    let response = Message::from_bytes(bytes).unwrap();
    assert_eq!(response.id, 65);
    assert_eq!(response.answers.len(), 1);
    assert!(matches!(&response.answers[0].data, RData::A(a) if a.0 == Ipv4Addr::LOCALHOST));
}

async fn exchange_tcp(address: SocketAddr, query: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_u16(query.len() as u16).await.unwrap();
    stream.write_all(query).await.unwrap();
    let size = stream.read_u16().await.unwrap();
    let mut response = vec![0; size as usize];
    stream.read_exact(&mut response).await.unwrap();
    response
}

fn proxy_config_fixture() -> Fixture {
    let directory =
        std::env::temp_dir().join(format!("izanagi-dns-relay-test-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let fixture = Fixture(directory);
    let config = fixture.0.join("izanagi.toml");
    std::fs::write(
        &config,
        "[sandbox]\nbackend=\"native\"\ntracer=\"none\"\n[share]\npaths=[]\nmount_point=\"/workspace\"\n[monitor]\nsyscalls=[]\n[detect]\nsuspicious_paths=[]\nallowed_hosts=[\"allowed.example\"]\n",
    )
    .unwrap();
    fixture
}

async fn start_proxy() -> (
    Fixture,
    tokio::process::Child,
    SocketAddr,
    std::path::PathBuf,
) {
    let fixture = proxy_config_fixture();
    let config = fixture.0.join("izanagi.toml");
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host = reservation.local_addr().unwrap();
    drop(reservation);
    let log = fixture.0.join("proxy.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_izanagi-dns-proxy"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--listen",
            &host.to_string(),
            "--upstream",
            "127.0.0.1:9",
            "--ready-stdout",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut ready = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ready.trim(),
        "IZANAGI_PROXY_READY",
        "{}",
        std::fs::read_to_string(&log).unwrap()
    );
    (fixture, child, host, log)
}

#[tokio::test]
async fn guest_udp_and_tcp_queries_reach_real_proxy_and_log_blocked() {
    let (_fixture, mut child, host, log) = start_proxy().await;
    let relay = DnsRelay::bind("127.0.0.1:0".parse().unwrap(), host)
        .await
        .unwrap();
    let address = relay.local_addr().unwrap();
    let task = tokio::spawn(relay.run());
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&query(), address).await.unwrap();
    let mut response = [0; 4096];
    let (size, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_blocked(&response[..size]);
    assert_blocked(
        &tokio::time::timeout(Duration::from_secs(5), exchange_tcp(address, &query()))
            .await
            .unwrap(),
    );
    task.abort();
    let _ = task.await;
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(
        log.matches("[BLOCKED] denied.example from").count(),
        2,
        "{log}"
    );
}

#[tokio::test]
async fn relay_startup_rejects_unreachable_upstream_and_releases_both_listeners() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    assert!(DnsRelay::bind(address, dead).await.is_err());
    let _udp = UdpSocket::bind(address).await.unwrap();
    let _tcp = tokio::net::TcpListener::bind(address).await.unwrap();
}
