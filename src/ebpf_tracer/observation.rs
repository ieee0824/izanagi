//! Conversion keeps missing identity and actual syscall outcomes explicit.
use izanagi_common::*;
use izanagi_telemetry::schema::*;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(crate) struct Collector {
    session: String,
    boot: String,
    source: String,
    pid_namespace: u64,
    net_namespace: u64,
    sequence: u64,
    seen: BTreeSet<ProcessKey>,
    sockets: BTreeMap<(u64, u64), u64>,
    socket_sequence: u64,
}

impl Collector {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(session: String) -> anyhow::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        // bpf_get_current_pid_tgid / sched PIDs use the initial PID namespace.
        // Run only in that namespace; no race-prone per-process /proc lookup.
        let initial = std::fs::metadata("/proc/1/ns/pid")?.ino();
        anyhow::ensure!(
            initial == std::fs::metadata("/proc/self/ns/pid")?.ino(),
            "collector must run in the initial PID namespace"
        );
        Ok(Self {
            session,
            boot,
            source: format!("ebpf-{:032x}", rand::random::<u128>()),
            pid_namespace: initial,
            net_namespace: std::fs::metadata("/proc/self/ns/net")?.ino(),
            sequence: 0,
            seen: BTreeSet::new(),
            sockets: BTreeMap::new(),
            socket_sequence: 0,
        })
    }

    fn key(&self, tgid: u32, start: u64) -> Option<ProcessKey> {
        if tgid == 0 || start == 0 {
            return None;
        }
        Some(ProcessKey {
            session_id: self.session.clone(),
            guest_boot_id: self.boot.clone(),
            pid_namespace: self.pid_namespace,
            tgid,
            started_monotonic_ns: start,
        })
    }

    pub(crate) fn envelope(
        &mut self,
        timestamp: u64,
        process: Option<ProcessKey>,
        tid: Option<u32>,
        payload: TelemetryPayload,
        mut issues: Vec<QualityIssue>,
    ) -> TelemetryEnvelope {
        if process.is_none()
            && !matches!(
                payload,
                TelemetryPayload::CollectorHealth { .. } | TelemetryPayload::ObservationGap { .. }
            )
        {
            issues.push(QualityIssue::MissingProcessIdentity);
        }
        self.sequence += 1;
        TelemetryEnvelope {
            schema_version: 1,
            session_id: self.session.clone(),
            guest_boot_id: self.boot.clone(),
            source_instance_id: self.source.clone(),
            source_seq: self.sequence,
            event_id: format!("{}:{}:{}", self.session, self.source, self.sequence),
            observed_monotonic_ns: timestamp,
            clock_domain: format!("linux-monotonic:{}", self.boot),
            clock_uncertainty_ns: 0,
            host_received_at_unix_ns: None,
            process,
            tid,
            quality: ObservationQuality { issues },
            payload,
        }
    }

    pub(crate) fn convert(&mut self, raw: &RawSyscallEvent) -> Vec<TelemetryEnvelope> {
        let mut result = Vec::new();
        if raw.abi_version != RAW_ABI_VERSION {
            return result;
        }
        let process = self.key(raw.tgid, raw.process_start_ns);
        self.record_process_identity(raw, &process, &mut result);
        let mut issues = Vec::new();
        let payload = match raw.kind {
            KIND_ENTER if raw.syscall_id == SyscallId::OpenAt as u32 => {
                self.open_attempt(raw, &mut issues)
            }
            KIND_OPEN_EXIT => self.open_outcome(raw, &mut issues),
            KIND_EXEC => TelemetryPayload::ProcessExec {
                exec_generation: raw.exec_generation,
            },
            KIND_EXIT => {
                if let Some(key) = &process {
                    self.seen.remove(key);
                }
                TelemetryPayload::ProcessExit
            }
            KIND_SOCKET => {
                let socket = self.record_socket_identity(raw, &mut result);
                let Some(payload) = self.socket_payload(raw, socket, &mut issues) else {
                    return result;
                };
                payload
            }
            _ => return result,
        };
        result.push(self.envelope(raw.timestamp_ns, process, Some(raw.pid), payload, issues));
        result
    }

    fn record_process_identity(
        &mut self,
        raw: &RawSyscallEvent,
        process: &Option<ProcessKey>,
        result: &mut Vec<TelemetryEnvelope>,
    ) {
        // The first TGID-bearing event confirms that sched_process_fork's child
        // was a process, rather than a thread. Preexisting processes remain None.
        if let Some(key) = process.as_ref()
            && !self.seen.contains(key)
        {
            if self.seen.len() >= 4096 {
                self.seen.clear();
                result.push(self.envelope(
                    raw.timestamp_ns,
                    None,
                    None,
                    TelemetryPayload::ObservationGap {
                        dropped: 1,
                        reason: QualityIssue::StateEvicted,
                    },
                    vec![QualityIssue::StateEvicted],
                ));
            }
            self.seen.insert(key.clone());
            result.push(self.envelope(
                raw.process_start_ns,
                process.clone(),
                Some(raw.pid),
                TelemetryPayload::ProcessStart,
                vec![],
            ));
            if let Some(parent) = self.key(raw.parent_tgid, raw.parent_start_ns) {
                result.push(self.envelope(
                    raw.process_start_ns,
                    process.clone(),
                    Some(raw.pid),
                    TelemetryPayload::ProcessFork {
                        parent,
                        child: key.clone(),
                    },
                    vec![],
                ));
            }
        }
    }

    fn open_attempt(
        &self,
        raw: &RawSyscallEvent,
        issues: &mut Vec<QualityIssue>,
    ) -> TelemetryPayload {
        let length = (raw.path_len as usize).min(PATH_BUF_SIZE);
        if raw.flags & FLAG_PATH_FAILED != 0 || length == 0 {
            issues.push(QualityIssue::PathUnresolved);
        }
        if raw.flags & FLAG_PATH_TRUNCATED != 0 || raw.path_len as usize > PATH_BUF_SIZE {
            issues.push(QualityIssue::PathTruncated);
        }
        let path = std::str::from_utf8(&raw.path_buf[..length])
            .ok()
            .filter(|s| !s.is_empty());
        if path.is_some_and(|s| !s.starts_with('/')) {
            issues.push(QualityIssue::PathUnresolved);
        }
        let role = path.map(file_role).unwrap_or(FileRole::Unknown);
        TelemetryPayload::FileAccessAttempt {
            attempt_id: self.attempt(raw.pid, raw.timestamp_ns),
            role,
            path: path.map(str::to_owned),
        }
    }

    fn open_outcome(
        &self,
        raw: &RawSyscallEvent,
        issues: &mut Vec<QualityIssue>,
    ) -> TelemetryPayload {
        if raw.flags & FLAG_STATE_MISSING != 0 {
            issues.push(QualityIssue::MissingOutcome);
        }
        let outcome = if raw.flags & FLAG_STATE_MISSING != 0 {
            OpenOutcome::Unknown
        } else if raw.result < 0 {
            OpenOutcome::Failed {
                errno: (-raw.result).min(i32::MAX as i64) as i32,
            }
        } else if raw.result <= i32::MAX as i64 {
            OpenOutcome::Succeeded {
                fd: raw.result as i32,
            }
        } else {
            issues.push(QualityIssue::InvalidEvent);
            OpenOutcome::Unknown
        };
        TelemetryPayload::FileOpenOutcome {
            attempt_id: self.attempt(raw.pid, raw.attempt_ns),
            outcome,
        }
    }

    fn record_socket_identity(
        &mut self,
        raw: &RawSyscallEvent,
        result: &mut Vec<TelemetryEnvelope>,
    ) -> SocketIdentity {
        let key = (raw.socket_address, raw.socket_generation);
        if !self.sockets.contains_key(&key) && self.sockets.len() >= 4096 {
            self.sockets.clear();
            result.push(self.envelope(
                raw.timestamp_ns,
                None,
                None,
                TelemetryPayload::ObservationGap {
                    dropped: 1,
                    reason: QualityIssue::StateEvicted,
                },
                vec![QualityIssue::StateEvicted],
            ));
        }
        let identity = *self.sockets.entry(key).or_insert_with(|| {
            self.socket_sequence += 1;
            self.socket_sequence
        });
        let socket = SocketIdentity {
            net_namespace: self.net_namespace,
            kernel_identity: identity,
            generation: raw.socket_generation,
            kind: SocketIdentityKind::OpaqueKernelIdentity,
        };
        if raw.socket_state == 7 {
            self.sockets.remove(&key);
        }
        socket
    }

    fn socket_payload(
        &self,
        raw: &RawSyscallEvent,
        socket: SocketIdentity,
        issues: &mut Vec<QualityIssue>,
    ) -> Option<TelemetryPayload> {
        // inet_sock_set_state has no namespace ID. This PoC is initial
        // namespace scoped; unproven namespace/writer attribution remains unknown.
        issues.push(QualityIssue::SocketAmbiguous);
        Some(match raw.socket_state {
            // SYN_SENT can be emitted before the kernel assigns the
            // ephemeral port. The established transition retains the
            // original connector and supplies the completed tuple.
            1 | 2 if raw.source_port != 0 => {
                let client = address(raw.family, raw.source_address, raw.source_port)?;
                let local = address(raw.family, raw.destination_address, raw.destination_port)?;
                issues.push(QualityIssue::MissingWriter);
                TelemetryPayload::SocketConnect {
                    socket,
                    tuple: SocketTuple {
                        net_namespace: self.net_namespace,
                        client,
                        local,
                    },
                    binding: ProcessBinding::Connector,
                }
            }
            1 => TelemetryPayload::SocketLifecycle {
                socket,
                state: SocketState::Connected,
            },
            7 => TelemetryPayload::SocketLifecycle {
                socket,
                state: SocketState::Closed,
            },
            _ => return None,
        })
    }

    fn attempt(&self, tid: u32, time: u64) -> String {
        format!("{}:{}:open:{}:{}", self.session, self.source, tid, time)
    }
}

fn address(family: u16, bytes: [u8; 16], port: u16) -> Option<SocketAddr> {
    let ip = match family {
        2 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        10 => IpAddr::V6(Ipv6Addr::from(bytes)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn file_role(path: &str) -> FileRole {
    if path.ends_with("/.npmrc")
        || path.ends_with("/.env")
        || path.contains("/.aws/")
        || path.contains("/.ssh/")
        || path.contains("credentials")
    {
        FileRole::Credential
    } else if path.contains("/node_modules/") || path.contains("/target/") {
        FileRole::Build
    } else if path.contains("/.cache/") {
        FileRole::Cache
    } else {
        FileRole::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn collector() -> Collector {
        Collector {
            session: "s".into(),
            boot: "b".into(),
            source: "c".into(),
            pid_namespace: 1,
            net_namespace: 2,
            sequence: 0,
            seen: BTreeSet::new(),
            sockets: BTreeMap::new(),
            socket_sequence: 0,
        }
    }
    fn raw() -> RawSyscallEvent {
        let mut raw: RawSyscallEvent = unsafe { std::mem::zeroed() };
        raw.abi_version = RAW_ABI_VERSION;
        raw.timestamp_ns = 50;
        raw.pid = 42;
        raw.tgid = 42;
        raw
    }
    #[test]
    fn preexisting_identity_is_missing_and_open_is_only_an_attempt() {
        let events = collector().convert(&raw());
        assert_eq!(events.len(), 1);
        assert!(events[0].process.is_none());
        assert!(
            events[0]
                .quality
                .issues
                .contains(&QualityIssue::MissingProcessIdentity)
        );
        assert!(matches!(
            events[0].payload,
            TelemetryPayload::FileAccessAttempt { .. }
        ));
    }
    #[test]
    fn actual_open_outcomes_share_attempt_id_and_pid_reuse_is_distinct() {
        let mut c = collector();
        let mut entry = raw();
        entry.process_start_ns = 10;
        let first = c.convert(&entry);
        let TelemetryPayload::FileAccessAttempt { attempt_id, .. } = &first.last().unwrap().payload
        else {
            panic!()
        };
        let mut exit = entry;
        exit.kind = KIND_OPEN_EXIT;
        exit.attempt_ns = entry.timestamp_ns;
        exit.result = -13;
        let outcome = c.convert(&exit);
        assert!(
            matches!(&outcome[0].payload,TelemetryPayload::FileOpenOutcome{attempt_id:id,outcome:OpenOutcome::Failed{errno:13}} if id==attempt_id)
        );
        entry.process_start_ns = 80;
        let reused = c.convert(&entry);
        assert_ne!(first[0].process, reused[0].process);
    }
    #[test]
    fn unknown_parent_and_connector_are_never_invented() {
        let mut c = collector();
        let mut event = raw();
        event.process_start_ns = 10;
        event.parent_tgid = 3;
        event.kind = KIND_SOCKET;
        event.socket_state = 2;
        event.family = 2;
        event.source_port = 50000;
        event.destination_port = 18080;
        event.socket_generation = 30;
        event.socket_address = 30;
        let events = c.convert(&event);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.payload, TelemetryPayload::ProcessFork { .. }))
        );
        let socket = events.last().unwrap();
        assert!(matches!(
            socket.payload,
            TelemetryPayload::SocketConnect {
                binding: ProcessBinding::Connector,
                ..
            }
        ));
        assert!(socket.quality.issues.contains(&QualityIssue::MissingWriter));
    }
}
