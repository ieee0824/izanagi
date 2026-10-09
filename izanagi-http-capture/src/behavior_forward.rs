//! Metadata-only explicit HTTP proxy for the opt-in behavior PoC.
//! No request body, arbitrary header, URL path or credentials enter telemetry.
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use izanagi_telemetry::{
    DestinationNovelty, HttpMethod, PolicyAllowed, QualityIssue, SidecarRecord, SocketTuple,
    TelemetryPayload, TransferOutcome,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{Semaphore, mpsc};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: u64 = 1024 * 1024;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const EMITTER_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct ForwardConfig {
    pub listen: SocketAddr,
    pub allowed_hosts: HashSet<String>,
    /// An explicit exact loopback receiver, for isolated fixtures only.
    pub fixture_endpoint: Option<SocketAddr>,
    pub timeout: Duration,
    pub max_connections: usize,
}

struct Request {
    method: String,
    host: String,
    port: u16,
    path: String,
    headers: Vec<(String, String)>,
    content_length: u64,
    body: Vec<u8>,
    received_bytes: u64,
    close: bool,
}

fn authority(value: &str) -> anyhow::Result<(String, u16)> {
    if value.is_empty() || value.contains(['@', '%', '/', '\\', '#', '?']) || !value.is_ascii() {
        bail!("invalid authority");
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            (host, port.parse::<u16>().context("invalid port")?)
        }
        None => (value, 80),
        _ => bail!("invalid authority"),
    };
    if host.is_empty()
        || port == 0
        || !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
    {
        bail!("invalid host");
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn parse_header(bytes: &[u8]) -> anyhow::Result<Request> {
    let text = std::str::from_utf8(bytes).context("invalid header encoding")?;
    if text
        .bytes()
        .any(|b| (b < 32 && b != b'\r' && b != b'\n') || b == 127)
    {
        bail!("invalid header character");
    }
    let mut lines = text.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let target = parse_request_target(request_line)?;
    let (host, port, path) = (target.host, target.port, target.path);
    let ParsedHeaders {
        headers,
        seen,
        length,
        host_header,
        close,
    } = parse_request_headers(lines)?;
    if host_header != Some((host.clone(), port)) {
        bail!("Host and absolute target differ");
    }
    let length = length.unwrap_or(0);
    if matches!(target.method, "POST" | "PUT" | "PATCH") && !seen.contains("content-length") {
        bail!("content length is required");
    }
    if length > MAX_BODY {
        bail!("request body exceeds limit");
    }
    Ok(Request {
        method: target.method.to_owned(),
        host,
        port,
        path: path.to_owned(),
        headers,
        content_length: length,
        body: Vec::new(),
        received_bytes: 0,
        close,
    })
}

struct RequestTarget<'a> {
    method: &'a str,
    host: String,
    port: u16,
    path: &'a str,
}

fn parse_request_target(request_line: &str) -> anyhow::Result<RequestTarget<'_>> {
    let parts: Vec<_> = request_line.split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        bail!("unsupported request line");
    }
    if !matches!(
        parts[0],
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
    ) {
        bail!("unsupported method");
    }
    let target = parts[1]
        .strip_prefix("http://")
        .context("only absolute-form HTTP is supported")?;
    let (auth, path) = match target.find('/') {
        Some(i) => (&target[..i], &target[i..]),
        None => (target, "/"),
    };
    if path.len() > 4096 || path.contains('#') {
        bail!("invalid target");
    }
    let (host, port) = authority(auth)?;
    Ok(RequestTarget {
        method: parts[0],
        host,
        port,
        path,
    })
}

struct ParsedHeaders {
    headers: Vec<(String, String)>,
    seen: HashSet<String>,
    length: Option<u64>,
    host_header: Option<(String, u16)>,
    close: bool,
}

fn parse_request_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> anyhow::Result<ParsedHeaders> {
    let mut headers = Vec::new();
    let mut seen = HashSet::new();
    let mut length = None;
    let mut host_header = None;
    let mut close = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, value) = parse_request_header_field(line)?;
        if !seen.insert(key.clone()) {
            bail!("duplicate header");
        }
        match key.as_str() {
            "host" => host_header = Some(authority(&value)?),
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    bail!("invalid content length");
                }
                length = Some(value.parse::<u64>().context("invalid content length")?);
            }
            "transfer-encoding" | "expect" | "upgrade" | "trailer" => bail!("unsupported framing"),
            "connection" => {
                if !value.eq_ignore_ascii_case("close") && !value.eq_ignore_ascii_case("keep-alive")
                {
                    bail!("unsupported connection options");
                }
                close = value.eq_ignore_ascii_case("close");
            }
            _ => {}
        }
        headers.push((key, value));
    }
    Ok(ParsedHeaders {
        headers,
        seen,
        length,
        host_header,
        close,
    })
}

fn parse_request_header_field(line: &str) -> anyhow::Result<(String, String)> {
    if line.starts_with([' ', '\t']) {
        bail!("folded header is unsupported");
    }
    let (key, value) = line.split_once(':').context("malformed header")?;
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        bail!("invalid header name");
    }
    let key = key.to_ascii_lowercase();
    let value = value.trim().to_owned();
    Ok((key, value))
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<Option<Request>> {
    let mut buffer = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(i) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buffer.len() >= MAX_HEADER {
            bail!("header exceeds limit");
        }
        let mut chunk = [0; 2048];
        let n = stream
            .read(&mut chunk[..(MAX_HEADER - buffer.len()).min(2048)])
            .await?;
        if n == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            bail!("incomplete header");
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let mut request = parse_header(&buffer[..header_end])?;
    let prefix = &buffer[header_end + 4..];
    if prefix.len() as u64 > request.content_length {
        bail!("pipelined or surplus input is unsupported");
    }
    request.body.extend_from_slice(prefix);
    request.body.resize(request.content_length as usize, 0);
    stream
        .read_exact(&mut request.body[prefix.len()..])
        .await
        .context("incomplete body")?;
    request.received_bytes = (header_end + 4) as u64 + request.content_length;
    Ok(Some(request))
}

fn method(value: &str) -> HttpMethod {
    match value {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "PATCH" => HttpMethod::Patch,
        _ => HttpMethod::Other,
    }
}

fn monotonic_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } != 0 {
        return 0;
    }
    (t.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(t.tv_nsec as u64)
}

fn emit(tx: &mpsc::Sender<SidecarRecord>, payload: TelemetryPayload) {
    // Never block the network path on the optional telemetry channel.
    static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dropped = DROPPED.swap(0, std::sync::atomic::Ordering::Relaxed);
    if dropped > 0
        && tx
            .try_send(SidecarRecord {
                observed_monotonic_ns: monotonic_ns(),
                payload: TelemetryPayload::ObservationGap {
                    dropped,
                    reason: QualityIssue::EventLoss,
                },
            })
            .is_err()
    {
        DROPPED.fetch_add(dropped, std::sync::atomic::Ordering::Relaxed);
    }
    if tx
        .try_send(SidecarRecord {
            observed_monotonic_ns: monotonic_ns(),
            payload,
        })
        .is_err()
    {
        DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn connect_upstream(config: &ForwardConfig, request: &Request) -> anyhow::Result<TcpStream> {
    if !config.allowed_hosts.contains(&request.host) {
        bail!("destination denied");
    }
    if let Some(endpoint) = config.fixture_endpoint {
        if request.host.parse::<std::net::IpAddr>().ok() == Some(endpoint.ip())
            && request.port == endpoint.port()
        {
            return Ok(TcpStream::connect(endpoint).await?);
        }
    }
    // Resolve once and connect to the validated numeric address; never resolve
    // again between validation and connect (DNS rebinding).
    let addresses = tokio::net::lookup_host((request.host.as_str(), request.port)).await?;
    for address in addresses {
        if crate::ip_filter::is_private_ip(address.ip()) {
            continue;
        }
        if let Ok(stream) = TcpStream::connect(address).await {
            return Ok(stream);
        }
    }
    bail!("no allowed upstream address")
}

#[derive(Default)]
struct ForwardCounts {
    written: u64,
    received: u64,
}

async fn forward(
    config: &ForwardConfig,
    request: &Request,
    client: &mut TcpStream,
    counts: &mut ForwardCounts,
) -> anyhow::Result<u16> {
    let mut upstream = connect_upstream(config, request).await?;
    let bytes = upstream_request_bytes(request);
    while (counts.written as usize) < bytes.len() {
        let n = upstream.write(&bytes[counts.written as usize..]).await?;
        if n == 0 {
            bail!("upstream write stopped");
        }
        counts.written += n as u64;
    }
    let response = read_forward_response(&mut upstream, counts).await?;
    write_client_response(client, request, &response).await
}

fn upstream_request_bytes(request: &Request) -> Vec<u8> {
    let host = if request.port == 80 {
        request.host.clone()
    } else {
        format!("{}:{}", request.host, request.port)
    };
    let mut bytes = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        request.method, request.path, host, request.content_length
    )
    .into_bytes();
    for (key, value) in &request.headers {
        if matches!(
            key.as_str(),
            "host"
                | "connection"
                | "content-length"
                | "proxy-authorization"
                | "proxy-connection"
                | "keep-alive"
        ) {
            continue;
        }
        bytes.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&request.body);
    bytes
}

async fn read_forward_response(
    upstream: &mut TcpStream,
    counts: &mut ForwardCounts,
) -> anyhow::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let n = upstream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if response.len() + n > MAX_RESPONSE {
            bail!("response exceeds limit");
        }
        counts.received += n as u64;
        response.extend_from_slice(&chunk[..n]);
    }
    Ok(response)
}

struct ResponseHead {
    status: u16,
    length: Option<usize>,
    output: Vec<String>,
}

fn parse_response_head(header: &str) -> anyhow::Result<ResponseHead> {
    let line = header.split("\r\n").next().context("missing response")?;
    let status: u16 = line.split(' ').nth(1).context("missing status")?.parse()?;
    if !line.starts_with("HTTP/1.") || !(200..600).contains(&status) {
        bail!("unsupported response");
    }
    let mut length = None;
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for line in header.split("\r\n").skip(1) {
        let (key, value) = line.split_once(':').context("malformed response")?;
        let key = key.to_ascii_lowercase();
        let value = value.trim();
        if !seen.insert(key.clone()) {
            bail!("duplicate response header");
        }
        if key == "transfer-encoding" {
            bail!("unsupported response framing");
        }
        if key == "content-length" {
            length = Some(value.parse::<usize>()?);
        }
        if !matches!(
            key.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "content-length"
        ) {
            output.push(format!("{}: {}\r\n", key, value));
        }
    }
    Ok(ResponseHead {
        status,
        length,
        output,
    })
}

async fn write_client_response(
    client: &mut TcpStream,
    request: &Request,
    response: &[u8],
) -> anyhow::Result<u16> {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("incomplete response")?;
    let header = std::str::from_utf8(&response[..end]).context("invalid response")?;
    let ResponseHead {
        status,
        length,
        output,
    } = parse_response_head(header)?;
    let body = &response[end + 4..];
    if request.method != "HEAD" && length.is_some_and(|n| n != body.len()) {
        bail!("incomplete or surplus response body");
    }
    let close = if request.close { "close" } else { "keep-alive" };
    client
        .write_all(
            format!(
                "HTTP/1.1 {} Response\r\nConnection: {}\r\nContent-Length: {}\r\n{}\r\n",
                status,
                close,
                if request.method == "HEAD" {
                    length.unwrap_or(0)
                } else {
                    body.len()
                },
                output.join("")
            )
            .as_bytes(),
        )
        .await?;
    client.write_all(body).await?;
    Ok(status)
}

async fn reject(client: &mut TcpStream, code: u16) {
    let _ = client
        .write_all(
            format!(
                "HTTP/1.1 {} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                code
            )
            .as_bytes(),
        )
        .await;
}

async fn handle(
    mut client: TcpStream,
    config: Arc<ForwardConfig>,
    tx: mpsc::Sender<SidecarRecord>,
    connection_id: String,
) {
    let Some(tuple) = connection_tuple(&client) else {
        return;
    };
    for sequence in 0..128u64 {
        let request = match tokio::time::timeout(config.timeout, read_request(&mut client)).await {
            Ok(Ok(Some(r))) => r,
            Ok(Ok(None)) => break,
            _ => {
                reject(&mut client, 400).await;
                break;
            }
        };
        let id = format!("{}:{}", connection_id, sequence);
        emit_request(&tx, &config, &request, &connection_id, &id, &tuple);
        let mut counts = ForwardCounts::default();
        let result = tokio::time::timeout(
            config.timeout,
            forward(&config, &request, &mut client, &mut counts),
        )
        .await;
        let success = match result {
            Ok(Ok(value)) => Some(value),
            _ => None,
        };
        emit_outcome(&tx, &config, &request, id, &counts, success);
        if success.is_none() {
            reject(&mut client, 502).await;
            break;
        }
        if request.close {
            break;
        }
    }
}

fn connection_tuple(client: &TcpStream) -> Option<SocketTuple> {
    let peer = client.peer_addr().ok()?;
    let local = client.local_addr().ok()?;
    let namespace = std::fs::read_link("/proc/self/ns/net")
        .ok()
        .and_then(|p| {
            p.to_str().and_then(|s| {
                s.trim_start_matches("net:[")
                    .trim_end_matches(']')
                    .parse()
                    .ok()
            })
        })
        .unwrap_or(0);
    Some(SocketTuple {
        net_namespace: namespace,
        client: peer,
        local,
    })
}

fn emit_request(
    tx: &mpsc::Sender<SidecarRecord>,
    config: &ForwardConfig,
    request: &Request,
    connection_id: &str,
    id: &str,
    tuple: &SocketTuple,
) {
    emit(
        tx,
        TelemetryPayload::HttpRequest {
            connection_id: connection_id.to_owned(),
            request_id: id.to_owned(),
            tuple: tuple.clone(),
            method: method(&request.method),
            policy: if config.allowed_hosts.contains(&request.host) {
                PolicyAllowed::Allowed
            } else {
                PolicyAllowed::Denied
            },
            novelty: DestinationNovelty::Unknown,
            declared_content_length: Some(request.content_length),
            raw_host: Some(request.host.clone()),
        },
    );
}

fn emit_outcome(
    tx: &mpsc::Sender<SidecarRecord>,
    config: &ForwardConfig,
    request: &Request,
    id: String,
    counts: &ForwardCounts,
    success: Option<u16>,
) {
    emit(
        tx,
        TelemetryPayload::HttpOutcome {
            request_id: id,
            client_bytes_received: request.received_bytes,
            upstream_bytes_written: counts.written,
            response_bytes_received: counts.received,
            status: success,
            outcome: if success.is_some() {
                TransferOutcome::Completed
            } else if !config.allowed_hosts.contains(&request.host) {
                TransferOutcome::Rejected
            } else {
                TransferOutcome::Failed
            },
        },
    );
}

pub async fn run(config: ForwardConfig, telemetry_socket: &Path) -> anyhow::Result<()> {
    validate_forward_config(&config)?;
    let socket = UnixStream::connect(telemetry_socket)
        .await
        .context("telemetry collector unavailable")?;
    let listener = TcpListener::bind(config.listen).await?;
    let (tx, mut rx) = mpsc::channel::<SidecarRecord>(EMITTER_CAPACITY);
    let emitter = tokio::spawn(async move {
        let mut socket = socket;
        while let Some(record) = rx.recv().await {
            let mut line = serde_json::to_vec(&record)?;
            line.push(b'\n');
            tokio::time::timeout(Duration::from_secs(1), socket.write_all(&line)).await??;
        }
        Ok::<_, anyhow::Error>(())
    });
    println!(
        "{}",
        serde_json::json!({"ready":true,"listen":listener.local_addr()?.to_string()})
    );
    let config = Arc::new(config);
    let sem = Arc::new(Semaphore::new(config.max_connections));
    let mut sequence = 0u64;
    let mut emitter_warned = false;
    loop {
        tokio::select! {
            accepted=listener.accept() => {
                let (client, _) = accepted?; let Ok(permit)=sem.clone().try_acquire_owned() else { drop(client); continue; };
                sequence+=1; let id=format!("{}:{}",std::process::id(),sequence); let config=config.clone(); let tx=tx.clone();
                tokio::spawn(async move { let _permit=permit;handle(client,config,tx,id).await; });
            }
            _=tokio::signal::ctrl_c() => break,
        }
        if emitter.is_finished() && !emitter_warned {
            // Optional metadata loss is explicit. Do not print arbitrary request data.
            eprintln!("behavior telemetry emitter unavailable");
            emitter_warned = true;
        }
    }
    emitter.abort();
    let _ = emitter.await;
    Ok(())
}

fn validate_forward_config(config: &ForwardConfig) -> anyhow::Result<()> {
    if !config.listen.ip().is_loopback()
        || config.max_connections == 0
        || config.max_connections > 1024
        || config.timeout.is_zero()
    {
        bail!("invalid behavior proxy configuration");
    }
    if config
        .fixture_endpoint
        .is_some_and(|a| !a.ip().is_loopback() || a.port() == 0)
    {
        bail!("fixture endpoint must be exact loopback receiver");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[test]
    fn response_headers_reject_ambiguous_framing_and_preserve_forwarded_fields() {
        let head = parse_response_head(
            "HTTP/1.1 201 Created\r\nContent-Length: 3\r\nConnection: close\r\nX-Result: ok",
        )
        .unwrap();
        assert_eq!(head.status, 201);
        assert_eq!(head.length, Some(3));
        assert_eq!(head.output, ["x-result: ok\r\n"]);
        for header in [
            "HTTP/1.1 100 Continue",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\ncontent-length: 3",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
            "HTTP/1.1 200 OK\r\nContent-Length: invalid",
        ] {
            assert!(parse_response_head(header).is_err());
        }
    }

    #[tokio::test]
    async fn response_body_validation_preserves_head_length_and_rejects_get_before_writing() {
        let (mut client, mut server) = tcp_pair().await;
        let mut request =
            parse_header(b"HEAD http://example.com/ HTTP/1.1\r\nHost: example.com").unwrap();
        let upstream = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n";
        assert_eq!(
            write_client_response(&mut server, &request, upstream)
                .await
                .unwrap(),
            200
        );
        let expected =
            b"HTTP/1.1 200 Response\r\nConnection: keep-alive\r\nContent-Length: 9\r\n\r\n";
        let mut actual = vec![0; expected.len()];
        client.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        request.method = "GET".into();
        assert!(
            write_client_response(&mut server, &request, upstream)
                .await
                .is_err()
        );
        assert_eq!(
            client.try_read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn failed_transfer_keeps_partial_counts_and_policy_classification() {
        let request =
            parse_header(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com").unwrap();
        let mut config = ForwardConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            allowed_hosts: HashSet::new(),
            fixture_endpoint: None,
            timeout: Duration::from_secs(1),
            max_connections: 1,
        };
        let (tx, mut rx) = mpsc::channel(2);
        let counts = ForwardCounts {
            written: 43,
            received: 12,
        };
        emit_outcome(&tx, &config, &request, "denied".into(), &counts, None);
        config.allowed_hosts.insert("example.com".into());
        emit_outcome(&tx, &config, &request, "failed".into(), &counts, None);
        for expected in [TransferOutcome::Rejected, TransferOutcome::Failed] {
            let record = rx.recv().await.unwrap();
            assert!(matches!(record.payload, TelemetryPayload::HttpOutcome {
                upstream_bytes_written: 43, response_bytes_received: 12, status: None,
                outcome, ..
            } if outcome == expected));
        }
    }

    #[test]
    fn framing_is_strict_and_has_no_secret_error_echo() {
        let valid = b"POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3";
        assert_eq!(parse_header(valid).unwrap().content_length, 3);
        for bad in [
            "POST http://example.com/x HTTP/1.1\r\nHost: other.com\r\nContent-Length: 0",
            "POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nContent-Length: 0",
            "POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 0",
            "POST http://example.com/x HTTP/1.1\r\nHost: example.com",
            "POST http://secret@example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0",
            "POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1048577",
            "POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length : 0",
        ] {
            let err = parse_header(bad.as_bytes()).err().unwrap();
            assert!(!err.to_string().contains("secret"));
        }
    }
    async fn response(client: &mut TcpStream) -> Vec<u8> {
        let mut value = Vec::new();
        loop {
            let mut byte = [0; 1];
            client.read_exact(&mut byte).await.unwrap();
            value.push(byte[0]);
            if value.ends_with(b"\r\n\r\n") {
                break;
            }
            assert!(value.len() < MAX_HEADER);
        }
        let header = std::str::from_utf8(&value).unwrap();
        let length = header
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut body = vec![0; length];
        client.read_exact(&mut body).await.unwrap();
        value.extend(body);
        value
    }

    #[tokio::test]
    async fn forwards_keep_alive_requests_with_exact_metadata_without_body_leaks() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    bytes.push(byte[0]);
                }
                let length = std::str::from_utf8(&bytes)
                    .unwrap()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    )
                    .await
                    .unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(ForwardConfig {
            listen: address,
            allowed_hosts: HashSet::from(["127.0.0.1".into()]),
            fixture_endpoint: Some(endpoint),
            timeout: Duration::from_secs(2),
            max_connections: 2,
        });
        let (tx, mut rx) = mpsc::channel(16);
        let worker = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            handle(client, config, tx, "connection1".into()).await;
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        let canary = "CANARY-SECRET-DO-NOT-LOG";
        let first = format!(
            "POST http://{endpoint}/CANARY-PATH?canary=CANARY-QUERY HTTP/1.1\r\nHost: {endpoint}\r\nContent-Length: {}\r\nAuthorization: Bearer CANARY-HEADER\r\n\r\n{canary}",
            canary.len()
        );
        client.write_all(first.as_bytes()).await.unwrap();
        assert!(response(&mut client).await.ends_with(b"hello"));
        let second = format!(
            "GET http://{endpoint}/two HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(second.as_bytes()).await.unwrap();
        assert!(response(&mut client).await.ends_with(b"hello"));
        worker.await.unwrap();
        upstream_task.await.unwrap();
        let mut records = Vec::new();
        while let Some(r) = rx.recv().await {
            records.push(r);
        }
        assert_eq!(records.len(), 4);
        assert!(
            matches!(&records[1].payload,TelemetryPayload::HttpOutcome{client_bytes_received,outcome:TransferOutcome::Completed,..} if *client_bytes_received==first.len() as u64)
        );
        let json = serde_json::to_string(&records).unwrap();
        assert!(!json.contains("CANARY"));
        assert!(json.contains("connection1:0") && json.contains("connection1:1"));
    }

    #[tokio::test]
    async fn ordinary_allowlist_does_not_disable_private_ip_protection() {
        let request =
            parse_header(b"GET http://127.0.0.1:1234/x HTTP/1.1\r\nHost: 127.0.0.1:1234").unwrap();
        let config = ForwardConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            allowed_hosts: HashSet::from(["127.0.0.1".into()]),
            fixture_endpoint: None,
            timeout: Duration::from_secs(1),
            max_connections: 1,
        };
        assert!(connect_upstream(&config, &request).await.is_err());
    }

    #[tokio::test]
    async fn incomplete_body_and_surplus_requests_are_rejected() {
        for bytes in [
            b"POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nx".as_slice(),
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGET /extra HTTP/1.1".as_slice(),
        ] {
            let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
            let task=tokio::spawn(async move{let(mut client,_)=listener.accept().await.unwrap();read_request(&mut client).await.is_err()});
            let mut client=TcpStream::connect(addr).await.unwrap();client.write_all(bytes).await.unwrap();client.shutdown().await.unwrap();assert!(task.await.unwrap());
        }
    }
}
