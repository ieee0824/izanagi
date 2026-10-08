//! Root-owned sidecar lifecycle. Unprivileged applications cannot submit metadata.
use izanagi::protocol::BehaviorStartConfig;
use izanagi_telemetry::schema::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::mpsc;

const BINARY: &str = "/usr/local/bin/izanagi-http-capture";
const MAX_RECORD: u64 = 16 * 1024;
static ACTIVE: OnceLock<Mutex<Option<(String, String)>>> = OnceLock::new();

pub(crate) fn proxy_environment() -> Option<String> {
    ACTIVE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("proxy state poisoned")
        .as_ref()
        .map(|(_, url)| url.clone())
}

pub(crate) struct Sidecar {
    child: tokio::process::Child,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    directory: PathBuf,
    id: String,
}

struct Source {
    session: String,
    boot: String,
    instance: String,
    sequence: u64,
}
impl Source {
    fn envelope(
        &mut self,
        time: u64,
        payload: TelemetryPayload,
        issues: Vec<QualityIssue>,
    ) -> TelemetryEnvelope {
        self.sequence += 1;
        TelemetryEnvelope {
            schema_version: 1,
            session_id: self.session.clone(),
            guest_boot_id: self.boot.clone(),
            source_instance_id: self.instance.clone(),
            source_seq: self.sequence,
            event_id: format!("{}:{}:{}", self.session, self.instance, self.sequence),
            observed_monotonic_ns: time,
            clock_domain: format!("linux-monotonic:{}", self.boot),
            clock_uncertainty_ns: 0,
            host_received_at_unix_ns: None,
            process: None,
            tid: None,
            quality: ObservationQuality { issues },
            payload,
        }
    }
}

impl Sidecar {
    pub(crate) async fn start(
        config: &BehaviorStartConfig,
    ) -> anyhow::Result<(Self, mpsc::Receiver<TelemetryEnvelope>)> {
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "behavior sidecar requires root collector"
        );
        let listen: std::net::SocketAddr = config.proxy_listen.parse()?;
        anyhow::ensure!(
            listen.ip().is_loopback() && listen.port() != 0,
            "behavior proxy must use a fixed guest loopback port"
        );
        let metadata = std::fs::metadata(BINARY)?;
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0 && metadata.is_file(),
            "sidecar binary must be a root-owned regular file without group/world write permission"
        );
        let id = format!("{:032x}", rand::random::<u128>());
        let directory = PathBuf::from(format!("/run/izanagi-behavior-{id}"));
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let socket = directory.join("telemetry.sock");
        let listener = match tokio::net::UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = std::fs::remove_dir(&directory);
                return Err(error.into());
            }
        };
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let mut command = tokio::process::Command::new(BINARY);
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .args([
                "--behavior-forward",
                "--listen-http",
                &config.proxy_listen,
                "--telemetry-socket",
            ])
            .arg(&socket)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for host in &config.allowed_hosts {
            command.arg("--allowed-host").arg(host);
        }
        if let Some(endpoint) = &config.fixture_endpoint {
            command.arg("--fixture-endpoint").arg(endpoint);
        }
        let child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                let _ = std::fs::remove_file(&socket);
                let _ = std::fs::remove_dir(&directory);
                anyhow::bail!("behavior proxy could not start");
            }
        };
        let mut sidecar = Self {
            child,
            tasks: Vec::new(),
            directory,
            id: id.clone(),
        };
        if let Some(mut stderr) = sidecar.child.stderr.take() {
            sidecar.tasks.push(tokio::spawn(async move {
                let mut buffer = [0; 4096];
                while let Ok(n) = stderr.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                }
            }));
        }
        let stdout = sidecar
            .child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("sidecar stdout unavailable"))?;
        let mut stdout = BufReader::new(stdout);
        let mut ready = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            (&mut stdout).take(4097).read_until(b'\n', &mut ready),
        )
        .await;
        anyhow::ensure!(
            matches!(result, Ok(Ok(_))) && ready.len() <= 4096 && ready.ends_with(b"\n"),
            "behavior proxy readiness failed"
        );
        let ready: serde_json::Value = serde_json::from_slice(&ready)
            .map_err(|_| anyhow::anyhow!("invalid proxy readiness"))?;
        anyhow::ensure!(
            ready.get("ready").and_then(serde_json::Value::as_bool) == Some(true)
                && ready.get("listen").and_then(serde_json::Value::as_str)
                    == Some(config.proxy_listen.as_str()),
            "behavior proxy readiness mismatch"
        );
        sidecar.tasks.push(tokio::spawn(async move {
            let mut buffer = [0; 4096];
            while let Ok(n) = stdout.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
            }
        }));
        let (tx, rx) = mpsc::channel(256);
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        let mut source = Source {
            session: config.session_id.clone(),
            boot,
            instance: format!("http-{id}"),
            sequence: 0,
        };
        sidecar.tasks.push(tokio::spawn(async move {
            let mut lost = 0u64;
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(value) => value,
                    Err(_) => break,
                };
                if !stream.peer_cred().is_ok_and(|cred| cred.uid() == 0) {
                    continue;
                }
                let mut reader = BufReader::new(stream);
                loop {
                    let mut bytes = Vec::new();
                    let read = (&mut reader)
                        .take(MAX_RECORD + 1)
                        .read_until(b'\n', &mut bytes)
                        .await;
                    if !matches!(read,Ok(n) if n>0) {
                        break;
                    }
                    if bytes.len() as u64 > MAX_RECORD || !bytes.ends_with(b"\n") {
                        lost += 1;
                        break;
                    }
                    let record: SidecarRecord = match serde_json::from_slice(&bytes) {
                        Ok(value) => value,
                        Err(_) => {
                            lost += 1;
                            continue;
                        }
                    };
                    // The executable can submit only proxy observations, never
                    // process/PID/envelope/session identities.
                    if !allowed_payload(&record.payload) {
                        lost += 1;
                        continue;
                    }
                    if lost > 0 {
                        let event = source.envelope(
                            monotonic_ns(),
                            TelemetryPayload::ObservationGap {
                                dropped: lost,
                                reason: QualityIssue::EventLoss,
                            },
                            vec![QualityIssue::EventLoss],
                        );
                        if tx.try_send(event).is_ok() {
                            lost = 0;
                        }
                    }
                    let issues = if matches!(record.payload, TelemetryPayload::HttpRequest { .. }) {
                        vec![QualityIssue::MissingWriter]
                    } else {
                        vec![]
                    };
                    let event =
                        source.envelope(record.observed_monotonic_ns, record.payload, issues);
                    if tx.try_send(event).is_err() {
                        lost += 1;
                    }
                }
                let event = source.envelope(
                    monotonic_ns(),
                    TelemetryPayload::CollectorHealth { healthy: false },
                    vec![QualityIssue::SourceUnavailable],
                );
                if tx.try_send(event).is_err() {
                    lost += 1;
                }
                if tx.is_closed() {
                    return;
                }
            }
        }));
        let mut active = ACTIVE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("proxy state poisoned");
        anyhow::ensure!(active.is_none(), "a behavior proxy is already active");
        *active = Some((id, format!("http://{}", config.proxy_listen)));
        Ok((sidecar, rx))
    }

    pub(crate) fn failed(&mut self) -> bool {
        self.child
            .try_wait()
            .map(|status| status.is_some())
            .unwrap_or(true)
    }
}
impl Drop for Sidecar {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE.get_or_init(|| Mutex::new(None)).lock()
            && active.as_ref().is_some_and(|(id, _)| id == &self.id)
        {
            *active = None;
        }
        let _ = self.child.start_kill();
        for task in &self.tasks {
            task.abort();
        }
        let _ = std::fs::remove_file(self.directory.join("telemetry.sock"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}
fn allowed_payload(payload: &TelemetryPayload) -> bool {
    matches!(
        payload,
        TelemetryPayload::HttpRequest { .. }
            | TelemetryPayload::HttpOutcome { .. }
            | TelemetryPayload::ObservationGap { .. }
            | TelemetryPayload::CollectorHealth { .. }
    )
}
fn monotonic_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return 0;
    }
    value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}
use std::os::unix::fs::DirBuilderExt;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_cannot_supply_process_events_or_envelope_identity() {
        assert!(!allowed_payload(&TelemetryPayload::ProcessStart));
        assert!(!allowed_payload(&TelemetryPayload::ProcessExit));
        assert!(allowed_payload(&TelemetryPayload::CollectorHealth {
            healthy: true
        }));
        let mut source = Source {
            session: "trusted-session".into(),
            boot: "trusted-boot".into(),
            instance: "collector".into(),
            sequence: 0,
        };
        let event = source.envelope(
            1,
            TelemetryPayload::CollectorHealth { healthy: true },
            vec![],
        );
        assert_eq!(event.event_id, "trusted-session:collector:1");
        assert!(event.process.is_none());
    }
}
