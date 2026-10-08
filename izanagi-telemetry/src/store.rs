//! Sanitized, bounded JSONL audit persistence.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

type AuditSegment = (u64, PathBuf, u64);

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub max_session_bytes: u64,
    pub max_segment_bytes: u64,
    pub retention_secs: u64,
    pub max_record_bytes: usize,
}
impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_session_bytes: 100 * 1024 * 1024,
            max_segment_bytes: 10 * 1024 * 1024,
            retention_secs: 7 * 24 * 60 * 60,
            max_record_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AuditPayload {
    Event(TelemetryEnvelope),
    Assessment {
        snapshot: FeatureSnapshot,
        projection_digest: String,
        rule_class: ThreatClass,
    },
    Classification(ClassificationAudit),
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub stored_at_unix_secs: u64,
    /// Records discarded by retention/budget before this append, including the
    /// first retained record after rotation. Never silently reported as complete.
    pub storage_gap: bool,
    pub payload: AuditPayload,
}

impl AuditRecord {
    fn validate(&self) -> Result<(), TelemetryError> {
        match &self.payload {
            AuditPayload::Event(event) => {
                if sanitize_event(event)? != *event {
                    return Err(TelemetryError::MalformedRecord);
                }
            }
            AuditPayload::Assessment {
                snapshot,
                projection_digest,
                rule_class,
            } => {
                if sanitize_snapshot(snapshot)? != *snapshot
                    || snapshot.projection(FeatureMode::Correlated).digest()? != *projection_digest
                    || deterministic_rule(snapshot) != *rule_class
                {
                    return Err(TelemetryError::MalformedRecord);
                }
            }
            AuditPayload::Classification(record) => record.validate()?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationStatus {
    Classified,
    Abstained,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationReason {
    UnknownClass,
    LowConfidence,
    InsufficientObservation,
    ApiError,
    McpError,
    Timeout,
    InvalidResponse,
    ModelMismatch,
    Disabled,
    ExportForbidden,
    QueueFull,
    Oversize,
    Stale,
    SessionEnded,
}

/// Host normalizes classifier replies into this allowlisted audit record.
/// No provider explanation, stderr, generic JSON, or prompt text is accepted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationAudit {
    pub session_id: String,
    pub window_id: String,
    pub revision: u32,
    pub projection_digest: String,
    pub feature_version: u16,
    pub question_version: u16,
    pub host_policy_version: u16,
    pub question_digest: String,
    pub mcp_commit: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub status: ClassificationStatus,
    pub class: Option<ThreatClass>,
    pub reason: Option<ClassificationReason>,
    pub requested_model: String,
    pub returned_model: Option<String>,
    /// In fixed order: normal, access_post_suspected, unknown.
    pub probabilities: Option<[f64; 3]>,
    pub confidence: Option<f64>,
    pub evidence_event_ids: Vec<String>,
    pub queued_ns: Option<u64>,
    pub elapsed_ns: Option<u64>,
}

impl ClassificationAudit {
    pub fn validate(&self) -> Result<(), TelemetryError> {
        self.validate_metadata()?;
        self.validate_probabilities()?;
        self.validate_status()
    }

    fn validate_metadata(&self) -> Result<(), TelemetryError> {
        if !valid_local_id(&self.session_id)
            || !valid_local_id(&self.window_id)
            || self.projection_digest.len() != 64
            || !self
                .projection_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || self.feature_version != crate::FEATURE_VERSION
            || self.question_version != 1
            || self.host_policy_version != 1
            || self.question_digest.len() != 64
            || !self.question_digest.bytes().all(|b| b.is_ascii_hexdigit())
            || self.mcp_commit.as_ref().is_some_and(|commit| {
                commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit())
            })
            || !valid_model(&self.requested_model)
            || self
                .returned_model
                .as_ref()
                .is_some_and(|m| !valid_model(m))
            || self.evidence_event_ids.len() > 128
            || self.evidence_event_ids.iter().any(|id| !valid_local_id(id))
            || self
                .confidence
                .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
        {
            return Err(TelemetryError::InvalidEvent);
        }
        Ok(())
    }

    fn validate_probabilities(&self) -> Result<(), TelemetryError> {
        if let Some(probabilities) = self.probabilities
            && (probabilities
                .iter()
                .any(|v| !v.is_finite() || !(0.0..=1.0).contains(v))
                || (probabilities.iter().sum::<f64>() - 1.0).abs() > 0.001)
        {
            return Err(TelemetryError::InvalidEvent);
        }
        if let (Some(probabilities), Some(class)) = (self.probabilities, self.class) {
            let index = match class {
                ThreatClass::Normal => 0,
                ThreatClass::AccessPostSuspected => 1,
                ThreatClass::Unknown => 2,
            };
            let selected = probabilities[index];
            if probabilities
                .iter()
                .any(|p| *p > selected + f64::EPSILON * 8.0)
                || self
                    .confidence
                    .is_some_and(|c| ((selected - 1.0 / 3.0) / (1.0 - 1.0 / 3.0) - c).abs() > 0.01)
            {
                return Err(TelemetryError::InvalidEvent);
            }
        }
        Ok(())
    }

    fn validate_status(&self) -> Result<(), TelemetryError> {
        match self.status {
            ClassificationStatus::Classified
                if self.class.is_none()
                    || self.class == Some(ThreatClass::Unknown)
                    || self.reason.is_some()
                    || self.returned_model.as_ref() != Some(&self.requested_model)
                    || self.probabilities.is_none()
                    || self.confidence.is_none() =>
            {
                Err(TelemetryError::InvalidEvent)
            }
            ClassificationStatus::Abstained if self.reason.is_none() => {
                Err(TelemetryError::InvalidEvent)
            }
            ClassificationStatus::Failed | ClassificationStatus::Skipped
                if self.reason.is_none()
                    || self.class.is_some()
                    || self.probabilities.is_some()
                    || self.confidence.is_some() =>
            {
                Err(TelemetryError::InvalidEvent)
            }
            _ => Ok(()),
        }
    }
}

fn valid_model(model: &str) -> bool {
    model == "mock"
        || model == "mock-v1"
        || model == "recorded"
        || model == "recorded-v1"
        || model.strip_prefix("jev-").is_some_and(|v| {
            let parts: Vec<_> = v.split('.').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreWrite {
    pub storage_gap: bool,
    pub removed_segments: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAvailability {
    Available,
    EvidenceExpired,
}

/// One directory per session. Every record is sanitized again at this boundary.
pub struct AuditStore {
    dir: PathBuf,
    config: StoreConfig,
    session_id: Option<String>,
    segment_newest: BTreeMap<u64, u64>,
}

impl AuditStore {
    pub fn new(dir: impl AsRef<Path>, config: StoreConfig) -> Result<Self, TelemetryError> {
        if config.max_session_bytes == 0
            || config.max_segment_bytes == 0
            || config.max_segment_bytes > config.max_session_bytes
            || config.retention_secs == 0
            || config.max_record_bytes == 0
            || config.max_record_bytes as u64 > config.max_segment_bytes
        {
            return Err(TelemetryError::InvalidConfiguration);
        }
        let dir = dir.as_ref();
        if fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink() || !m.is_dir()) {
            return Err(TelemetryError::Io);
        }
        fs::create_dir_all(dir).map_err(|_| TelemetryError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::symlink_metadata(dir).map_err(|_| TelemetryError::Io)?;
            if metadata.file_type().is_symlink() || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(TelemetryError::Io);
            }
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| TelemetryError::Io)?;
        }
        let mut store = Self {
            dir: dir.to_owned(),
            config,
            session_id: None,
            segment_newest: BTreeMap::new(),
        };
        // Refuse to append another session to an existing session directory.
        for record in store.read_records()? {
            let session = match record.payload {
                AuditPayload::Event(e) => e.session_id,
                AuditPayload::Assessment { snapshot, .. } => snapshot.session_id,
                AuditPayload::Classification(record) => record.session_id,
            };
            store.check_session(&session)?;
        }
        Ok(store)
    }

    pub fn append_event(
        &mut self,
        event: &TelemetryEnvelope,
        now_unix_secs: u64,
    ) -> Result<StoreWrite, TelemetryError> {
        let sanitized = sanitize_event(event)?;
        self.check_session(&sanitized.session_id)?;
        self.append(AuditPayload::Event(sanitized), now_unix_secs)
    }

    pub fn append_snapshot(
        &mut self,
        snapshot: &FeatureSnapshot,
        now_unix_secs: u64,
    ) -> Result<StoreWrite, TelemetryError> {
        let sanitized = sanitize_snapshot(snapshot)?;
        self.check_session(&sanitized.session_id)?;
        let digest = sanitized.projection(FeatureMode::Correlated).digest()?;
        let class = deterministic_rule(&sanitized);
        self.append(
            AuditPayload::Assessment {
                snapshot: sanitized,
                projection_digest: digest,
                rule_class: class,
            },
            now_unix_secs,
        )
    }

    pub fn append_classification(
        &mut self,
        record: &ClassificationAudit,
        now_unix_secs: u64,
    ) -> Result<StoreWrite, TelemetryError> {
        record.validate()?;
        self.check_session(&record.session_id)?;
        self.append(AuditPayload::Classification(record.clone()), now_unix_secs)
    }

    pub fn read_records(&self) -> Result<Vec<AuditRecord>, TelemetryError> {
        let mut records = Vec::new();
        let segments = self.segments()?;
        let total: u64 = segments.iter().map(|(_, _, size)| size).sum();
        if total > self.config.max_session_bytes {
            return Err(TelemetryError::Oversize);
        }
        for (_, path, _) in segments {
            let file = open_private(&path, false)?;
            let mut reader = BufReader::new(file);
            loop {
                let mut line = Vec::new();
                let count = reader
                    .by_ref()
                    .take(self.config.max_record_bytes as u64 + 1)
                    .read_until(b'\n', &mut line)
                    .map_err(|_| TelemetryError::Io)?;
                if count == 0 {
                    break;
                }
                if count > self.config.max_record_bytes || line.last() != Some(&b'\n') {
                    return Err(TelemetryError::MalformedRecord);
                }
                let record: AuditRecord =
                    serde_json::from_slice(&line).map_err(|_| TelemetryError::MalformedRecord)?;
                record.validate()?;
                records.push(record);
            }
        }
        Ok(records)
    }

    pub fn evidence_availability(
        &self,
        event_ids: &[String],
    ) -> Result<EvidenceAvailability, TelemetryError> {
        let available: BTreeSet<_> = self
            .read_records()?
            .into_iter()
            .filter_map(|r| {
                if let AuditPayload::Event(event) = r.payload {
                    Some(event.event_id)
                } else {
                    None
                }
            })
            .collect();
        Ok(if event_ids.iter().all(|id| available.contains(id)) {
            EvidenceAvailability::Available
        } else {
            EvidenceAvailability::EvidenceExpired
        })
    }

    /// Explicit expiration uses caller wall time, allowing deterministic tests.
    pub fn expire(&mut self, now_unix_secs: u64) -> Result<usize, TelemetryError> {
        let mut removed = 0;
        for (generation, path, _) in self.segments()? {
            let newest = if let Some(newest) = self.segment_newest.get(&generation) {
                *newest
            } else {
                let file = open_private(&path, false)?;
                let mut reader = BufReader::new(file);
                let mut newest = 0;
                loop {
                    let mut line = Vec::new();
                    let count = reader
                        .by_ref()
                        .take(self.config.max_record_bytes as u64 + 1)
                        .read_until(b'\n', &mut line)
                        .map_err(|_| TelemetryError::Io)?;
                    if count == 0 {
                        break;
                    }
                    if count > self.config.max_record_bytes || line.last() != Some(&b'\n') {
                        return Err(TelemetryError::MalformedRecord);
                    }
                    let record: AuditRecord = serde_json::from_slice(&line)
                        .map_err(|_| TelemetryError::MalformedRecord)?;
                    newest = newest.max(record.stored_at_unix_secs);
                }
                self.segment_newest.insert(generation, newest);
                newest
            };
            if now_unix_secs.saturating_sub(newest) > self.config.retention_secs {
                fs::remove_file(path).map_err(|_| TelemetryError::Io)?;
                self.segment_newest.remove(&generation);
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn clear(&mut self) -> Result<(), TelemetryError> {
        for (_, path, _) in self.segments()? {
            fs::remove_file(path).map_err(|_| TelemetryError::Io)?;
        }
        self.session_id = None;
        self.segment_newest.clear();
        Ok(())
    }

    fn check_session(&mut self, id: &str) -> Result<(), TelemetryError> {
        if !valid_local_id(id) {
            return Err(TelemetryError::InvalidEvent);
        }
        match &self.session_id {
            Some(existing) if existing != id => Err(TelemetryError::InvalidEvent),
            None => {
                self.session_id = Some(id.to_owned());
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn append(&mut self, payload: AuditPayload, now: u64) -> Result<StoreWrite, TelemetryError> {
        let mut removed = self.expire(now)?;
        let mut record = AuditRecord {
            stored_at_unix_secs: now,
            storage_gap: removed > 0,
            payload,
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|_| TelemetryError::InvalidEvent)?;
        bytes.push(b'\n');
        if bytes.len() > self.config.max_record_bytes {
            return Err(TelemetryError::Oversize);
        }
        let (segments, capacity_removed) = self.make_record_room(bytes.len())?;
        removed += capacity_removed;
        if removed > 0 && !record.storage_gap {
            record.storage_gap = true;
            bytes = serde_json::to_vec(&record).map_err(|_| TelemetryError::InvalidEvent)?;
            bytes.push(b'\n');
        }
        self.write_record(&segments, &bytes, now)?;
        Ok(StoreWrite {
            storage_gap: record.storage_gap,
            removed_segments: removed,
        })
    }

    fn make_record_room(
        &mut self,
        record_bytes: usize,
    ) -> Result<(Vec<AuditSegment>, usize), TelemetryError> {
        let mut removed = 0;
        let mut segments = self.segments()?;
        let mut total: u64 = segments.iter().map(|(_, _, size)| size).sum();
        // Remove old complete segments before writing. Retention guarantees a
        // bounded directory, and storage_gap persists in the new retained record.
        while total.saturating_add(record_bytes as u64) > self.config.max_session_bytes {
            let Some((generation, path, size)) = segments.first().cloned() else {
                return Err(TelemetryError::Oversize);
            };
            fs::remove_file(path).map_err(|_| TelemetryError::Io)?;
            self.segment_newest.remove(&generation);
            total = total.saturating_sub(size);
            segments.remove(0);
            removed += 1;
        }
        Ok((segments, removed))
    }

    fn write_record(
        &mut self,
        segments: &[AuditSegment],
        bytes: &[u8],
        now: u64,
    ) -> Result<(), TelemetryError> {
        let path = match segments.last() {
            Some((_, path, size))
                if size.saturating_add(bytes.len() as u64) <= self.config.max_segment_bytes =>
            {
                path.clone()
            }
            Some((generation, _, _)) => {
                self.dir.join(format!("audit-{:016}.jsonl", generation + 1))
            }
            None => self.dir.join("audit-0000000000000001.jsonl"),
        };
        let mut file = open_private(&path, true)?;
        file.write_all(bytes)
            .and_then(|_| file.flush())
            .map_err(|_| TelemetryError::Io)?;
        let generation = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("audit-"))
            .and_then(|n| n.strip_suffix(".jsonl"))
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or(TelemetryError::MalformedRecord)?;
        let newest = self.segment_newest.entry(generation).or_default();
        *newest = (*newest).max(now);
        Ok(())
    }

    fn segments(&self) -> Result<Vec<AuditSegment>, TelemetryError> {
        let mut segments = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|_| TelemetryError::Io)? {
            let entry = entry.map_err(|_| TelemetryError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(digits) = name
                .strip_prefix("audit-")
                .and_then(|n| n.strip_suffix(".jsonl"))
            else {
                continue;
            };
            if digits.len() != 16 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(TelemetryError::MalformedRecord);
            }
            let generation = digits
                .parse()
                .map_err(|_| TelemetryError::MalformedRecord)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| TelemetryError::Io)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(TelemetryError::Io);
            }
            segments.push((generation, entry.path(), metadata.len()));
        }
        segments.sort_by_key(|(generation, _, _)| *generation);
        Ok(segments)
    }
}

fn open_private(path: &Path, append: bool) -> Result<File, TelemetryError> {
    let mut options = OpenOptions::new();
    options.read(true);
    if append {
        options.create(true).append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path).map_err(|_| TelemetryError::Io)?;
        if !file.metadata().map_err(|_| TelemetryError::Io)?.is_file() {
            return Err(TelemetryError::Io);
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| TelemetryError::Io)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        options.open(path).map_err(|_| TelemetryError::Io)
    }
}
