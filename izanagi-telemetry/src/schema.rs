use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessKey {
    pub session_id: String,
    pub guest_boot_id: String,
    pub pid_namespace: u64,
    pub tgid: u32,
    pub started_monotonic_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketIdentity {
    pub net_namespace: u64,
    pub kernel_identity: u64,
    pub generation: u64,
    pub kind: SocketIdentityKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketIdentityKind {
    Cookie,
    OpaqueKernelIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketTuple {
    pub net_namespace: u64,
    pub client: SocketAddr,
    pub local: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessBinding {
    Connector,
    ConfirmedWriter,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    Credential,
    Build,
    Cache,
    Other,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAllowed {
    Allowed,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationNovelty {
    Known,
    Novel,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferOutcome {
    Completed,
    Rejected,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenOutcome {
    Succeeded { fd: i32 },
    Failed { errno: i32 },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityIssue {
    MissingProcessIdentity,
    MissingWriter,
    SocketAmbiguous,
    SocketShared,
    ClockUnknown,
    ClockUncertain,
    EventLoss,
    SourceRestart,
    SourceUnavailable,
    PathUnresolved,
    PathTruncated,
    UnsupportedProtocol,
    StateEvicted,
    WindowTruncated,
    StorageGap,
    InvalidEvent,
    MissingOutcome,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationQuality {
    pub issues: Vec<QualityIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketState {
    Connected,
    Closed,
    Shared,
    Transferred,
}

/// No argv, environment, header or body field exists in this schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TelemetryPayload {
    ProcessStart,
    ProcessFork {
        parent: ProcessKey,
        child: ProcessKey,
    },
    ProcessExec {
        exec_generation: u64,
    },
    ProcessExit,
    FileAccessAttempt {
        attempt_id: String,
        role: FileRole,
        path: Option<String>,
    },
    FileOpenOutcome {
        attempt_id: String,
        outcome: OpenOutcome,
    },
    SocketConnect {
        socket: SocketIdentity,
        tuple: SocketTuple,
        binding: ProcessBinding,
    },
    SocketLifecycle {
        socket: SocketIdentity,
        state: SocketState,
    },
    HttpRequest {
        connection_id: String,
        request_id: String,
        tuple: SocketTuple,
        method: HttpMethod,
        policy: PolicyAllowed,
        novelty: DestinationNovelty,
        declared_content_length: Option<u64>,
        raw_host: Option<String>,
    },
    HttpOutcome {
        request_id: String,
        client_bytes_received: u64,
        upstream_bytes_written: u64,
        response_bytes_received: u64,
        status: Option<u16>,
        outcome: TransferOutcome,
    },
    ObservationGap {
        dropped: u64,
        reason: QualityIssue,
    },
    CollectorHealth {
        healthy: bool,
    },
    RuleMatch {
        rule_code: String,
    },
    /// Successful TCP sends, scoped to one kernel socket incarnation. Byte
    /// offsets count stream data from the completed handshake, excluding SYN.
    SocketWrite {
        socket: SocketIdentity,
        tuple: SocketTuple,
        stream_start: u64,
        stream_end: u64,
    },
    /// Proxy-parsed request bounds; separate variant preserves existing wire
    /// discriminants and layouts for legacy HttpRequest / HttpOutcome records.
    HttpStreamRange {
        connection_id: String,
        request_id: String,
        stream_start: u64,
        stream_end: u64,
    },
}

/// A credential-checked sidecar cannot choose envelope or process identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarRecord {
    pub observed_monotonic_ns: u64,
    pub payload: TelemetryPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEnvelope {
    pub schema_version: u16,
    pub session_id: String,
    pub guest_boot_id: String,
    pub source_instance_id: String,
    pub source_seq: u64,
    pub event_id: String,
    pub observed_monotonic_ns: u64,
    pub clock_domain: String,
    pub clock_uncertainty_ns: u64,
    pub host_received_at_unix_ns: Option<u64>,
    pub process: Option<ProcessKey>,
    pub tid: Option<u32>,
    pub quality: ObservationQuality,
    pub payload: TelemetryPayload,
}

impl TelemetryEnvelope {
    pub fn expected_event_id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.session_id, self.source_instance_id, self.source_seq
        )
    }
    pub fn validate(&self) -> Result<(), crate::TelemetryError> {
        use crate::{SCHEMA_VERSION, TelemetryError};
        if self.schema_version != SCHEMA_VERSION
            || !valid_id(&self.session_id)
            || !valid_id(&self.guest_boot_id)
            || !valid_id(&self.source_instance_id)
            || !valid_id(&self.clock_domain)
            || self.event_id != self.expected_event_id()
            || self.quality.issues.len() > 32
        {
            return Err(TelemetryError::InvalidEvent);
        }
        if self
            .process
            .as_ref()
            .is_some_and(|p| !self.valid_process(p))
        {
            return Err(TelemetryError::InvalidEvent);
        }
        self.validate_payload()
    }

    fn valid_process(&self, p: &ProcessKey) -> bool {
        p.session_id == self.session_id
            && p.guest_boot_id == self.guest_boot_id
            && p.tgid > 0
            && p.started_monotonic_ns <= self.observed_monotonic_ns
    }

    fn validate_payload(&self) -> Result<(), crate::TelemetryError> {
        use crate::TelemetryError;
        self.validate_stream_payload()?;
        match &self.payload {
            TelemetryPayload::ProcessFork { parent, child }
                if !self.valid_process(parent)
                    || !self.valid_process(child)
                    || parent.pid_namespace != child.pid_namespace
                    || parent == child =>
            {
                return Err(TelemetryError::InvalidEvent);
            }
            TelemetryPayload::FileAccessAttempt {
                attempt_id, path, ..
            } if !valid_id(attempt_id) || path.as_ref().is_some_and(|p| p.len() > 4096) => {
                return Err(TelemetryError::InvalidEvent);
            }
            TelemetryPayload::FileOpenOutcome { attempt_id, .. } if !valid_id(attempt_id) => {
                return Err(TelemetryError::InvalidEvent);
            }
            TelemetryPayload::HttpRequest {
                connection_id,
                request_id,
                raw_host,
                ..
            } if !valid_id(connection_id)
                || !valid_id(request_id)
                || raw_host.as_ref().is_some_and(|h| h.len() > 1024) =>
            {
                return Err(TelemetryError::InvalidEvent);
            }
            TelemetryPayload::HttpOutcome {
                request_id, status, ..
            } if !valid_id(request_id) || status.is_some_and(|s| !(100..=599).contains(&s)) => {
                return Err(TelemetryError::InvalidEvent);
            }
            TelemetryPayload::RuleMatch { rule_code } if rule_code.len() > 1024 => {
                return Err(TelemetryError::InvalidEvent);
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_stream_payload(&self) -> Result<(), crate::TelemetryError> {
        use crate::TelemetryError;
        let range = match &self.payload {
            TelemetryPayload::SocketWrite {
                socket,
                tuple,
                stream_start,
                stream_end,
            } => {
                if socket.net_namespace == 0
                    || socket.net_namespace != tuple.net_namespace
                    || socket.generation == 0
                    || socket.kernel_identity == 0
                {
                    return Err(TelemetryError::InvalidEvent);
                }
                Some((*stream_start, *stream_end))
            }
            TelemetryPayload::HttpStreamRange {
                connection_id,
                request_id,
                stream_start,
                stream_end,
            } => {
                if !valid_id(connection_id) || !valid_id(request_id) {
                    return Err(TelemetryError::InvalidEvent);
                }
                Some((*stream_start, *stream_end))
            }
            _ => None,
        };
        if range.is_some_and(|(start, end)| start >= end || end > crate::MAX_STREAM_BYTES) {
            return Err(TelemetryError::InvalidEvent);
        }
        Ok(())
    }
}

// Envelope IDs have a stricter size cap than persisted local audit IDs.
fn valid_id(s: &str) -> bool {
    s.len() <= 160 && crate::privacy::valid_local_id(s)
}
