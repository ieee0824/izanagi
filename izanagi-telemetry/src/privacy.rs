use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatClass {
    Normal,
    AccessPostSuspected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureMode {
    Correlated,
    NetworkOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSnapshot {
    pub feature_version: u16,
    pub session_id: String,
    pub window_id: String,
    pub revision: u32,
    pub supersedes: Option<String>,
    pub process: Option<ProcessKey>,
    pub binding: ProcessBinding,
    pub started_monotonic_ns: u64,
    pub ended_monotonic_ns: u64,
    pub clock_domain: String,
    pub credential_access_attempts: u32,
    pub credential_open_succeeded: u32,
    pub credential_open_failed: u32,
    pub access_to_post_ns: Option<u64>,
    pub method: HttpMethod,
    pub policy: PolicyAllowed,
    pub novelty: DestinationNovelty,
    pub declared_content_length: Option<u64>,
    pub client_bytes_received: Option<u64>,
    pub upstream_bytes_written: Option<u64>,
    pub response_bytes_received: Option<u64>,
    pub transfer_outcome: TransferOutcome,
    pub rule_matches: Vec<String>,
    pub quality: ObservationQuality,
    pub evidence_event_ids: Vec<String>,
}

/// Explicit allowlist projection: no raw strings or local event/process IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureProjection {
    pub feature_version: u16,
    pub mode: FeatureMode,
    pub binding: ProcessBinding,
    pub credential_access_attempts: Option<u32>,
    pub credential_open_succeeded: Option<u32>,
    pub credential_open_failed: Option<u32>,
    pub access_to_post_ns: Option<u64>,
    pub method: HttpMethod,
    pub policy: PolicyAllowed,
    pub novelty: DestinationNovelty,
    pub declared_content_length: Option<u64>,
    pub client_bytes_received: Option<u64>,
    pub upstream_bytes_written: Option<u64>,
    pub response_bytes_received: Option<u64>,
    pub transfer_outcome: TransferOutcome,
    pub quality: ObservationQuality,
}

impl FeatureSnapshot {
    pub fn projection(&self, mode: FeatureMode) -> FeatureProjection {
        let correlated = mode == FeatureMode::Correlated;
        FeatureProjection {
            feature_version: self.feature_version,
            mode,
            binding: if correlated {
                self.binding
            } else {
                ProcessBinding::Unknown
            },
            credential_access_attempts: correlated.then_some(self.credential_access_attempts),
            credential_open_succeeded: correlated.then_some(self.credential_open_succeeded),
            credential_open_failed: correlated.then_some(self.credential_open_failed),
            access_to_post_ns: if correlated {
                self.access_to_post_ns
            } else {
                None
            },
            method: self.method,
            policy: self.policy,
            novelty: self.novelty,
            declared_content_length: self.declared_content_length,
            client_bytes_received: self.client_bytes_received,
            upstream_bytes_written: self.upstream_bytes_written,
            response_bytes_received: self.response_bytes_received,
            transfer_outcome: self.transfer_outcome,
            quality: self.quality.clone(),
        }
    }
}

impl FeatureProjection {
    pub fn to_json(&self) -> Result<Vec<u8>, TelemetryError> {
        if self.feature_version != FEATURE_VERSION || self.quality.issues.len() > 32 {
            return Err(TelemetryError::InvalidEvent);
        }
        if self.mode == FeatureMode::NetworkOnly
            && (self.binding != ProcessBinding::Unknown
                || self.credential_access_attempts.is_some()
                || self.credential_open_succeeded.is_some()
                || self.credential_open_failed.is_some()
                || self.access_to_post_ns.is_some())
        {
            return Err(TelemetryError::InvalidEvent);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| TelemetryError::InvalidEvent)?;
        if bytes.len() > MAX_PROJECTION_BYTES {
            return Err(TelemetryError::Oversize);
        }
        Ok(bytes)
    }
    /// Digest identifies this typed, canonical serializer output; it is not a
    /// secret-masking mechanism and contains no event or process identifiers.
    pub fn digest(&self) -> Result<String, TelemetryError> {
        use sha2::{Digest, Sha256};
        Ok(hex::encode(Sha256::digest(self.to_json()?)))
    }
    pub fn eligible(&self) -> bool {
        if self.to_json().is_err()
            || self.method != HttpMethod::Post
            || self.policy == PolicyAllowed::Unknown
            || self.novelty == DestinationNovelty::Unknown
            || self.transfer_outcome == TransferOutcome::Unknown
        {
            return false;
        }
        match self.mode {
            FeatureMode::Correlated => {
                self.binding == ProcessBinding::ConfirmedWriter
                    && self.credential_access_attempts.is_some()
                    && self.quality.issues.is_empty()
            }
            FeatureMode::NetworkOnly => self.quality.issues.iter().all(|issue| {
                matches!(
                    issue,
                    QualityIssue::MissingProcessIdentity
                        | QualityIssue::MissingWriter
                        | QualityIssue::SocketAmbiguous
                        | QualityIssue::SocketShared
                        | QualityIssue::PathUnresolved
                        | QualityIssue::PathTruncated
                )
            }),
        }
    }
}

/// Local storage uses an allowlist transformation, not secret-pattern guessing.
pub fn sanitize_event(event: &TelemetryEnvelope) -> Result<TelemetryEnvelope, TelemetryError> {
    event.validate()?;
    let mut sanitized = event.clone();
    match &mut sanitized.payload {
        TelemetryPayload::FileAccessAttempt { path, .. } => *path = None,
        TelemetryPayload::HttpRequest { raw_host, .. } => *raw_host = None,
        TelemetryPayload::RuleMatch { rule_code } => *rule_code = sanitize_rule_code(rule_code),
        _ => {}
    }
    Ok(sanitized)
}

pub fn sanitize_rule_code(code: &str) -> String {
    match code {
        "suspicious-path"
        | "network-allowlist"
        | "unexpected-exec"
        | "env-access"
        | "process-baseline"
        | "access-post-sequence" => code.to_owned(),
        _ => "other-rule".to_owned(),
    }
}

pub(crate) fn valid_local_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

pub fn sanitize_snapshot(snapshot: &FeatureSnapshot) -> Result<FeatureSnapshot, TelemetryError> {
    if snapshot.feature_version != FEATURE_VERSION
        || !valid_local_id(&snapshot.session_id)
        || !valid_local_id(&snapshot.window_id)
        || !valid_local_id(&snapshot.clock_domain)
        || snapshot.evidence_event_ids.len() > 128
        || snapshot.rule_matches.len() > 128
        || snapshot.quality.issues.len() > 32
        || snapshot
            .evidence_event_ids
            .iter()
            .any(|s| !valid_local_id(s))
        || snapshot
            .supersedes
            .as_ref()
            .is_some_and(|s| !valid_local_id(s))
        || snapshot.started_monotonic_ns > snapshot.ended_monotonic_ns
        || snapshot.process.as_ref().is_some_and(|p| {
            p.session_id != snapshot.session_id || !valid_local_id(&p.guest_boot_id) || p.tgid == 0
        })
    {
        return Err(TelemetryError::InvalidEvent);
    }
    let mut sanitized = snapshot.clone();
    sanitized.rule_matches = sanitized
        .rule_matches
        .iter()
        .map(|s| sanitize_rule_code(s))
        .collect();
    Ok(sanitized)
}
