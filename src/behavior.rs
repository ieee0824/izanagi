//! Bounded advisory workers; telemetry and existing syscall rules never await inference.
use crate::{
    behavior_classifier::{
        AbstentionReason, ClassificationOutcome, Classifier, JevMcpClassifier, MockClassifier,
        SkipReason,
    },
    behavior_config::BehaviorSection,
    protocol::BehaviorStartConfig,
};
use izanagi_telemetry::*;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

#[derive(Default)]
struct Counters {
    requested_model: String,
    mcp_commit: Option<String>,
    events: AtomicU64,
    invalid: AtomicU64,
    storage_failed: AtomicU64,
    storage_gap: AtomicU64,
    windows: AtomicU64,
    classified: AtomicU64,
    abstained: AtomicU64,
    failed: AtomicU64,
    skipped: AtomicU64,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct BehaviorStats {
    pub events: u64,
    pub invalid: u64,
    pub storage_failed: u64,
    pub storage_gap: u64,
    pub windows: u64,
    pub classified: u64,
    pub abstained: u64,
    pub failed: u64,
    pub skipped: u64,
}
impl Counters {
    fn snapshot(&self) -> BehaviorStats {
        let read = |v: &AtomicU64| v.load(Ordering::Relaxed);
        BehaviorStats {
            events: read(&self.events),
            invalid: read(&self.invalid),
            storage_failed: read(&self.storage_failed),
            storage_gap: read(&self.storage_gap),
            windows: read(&self.windows),
            classified: read(&self.classified),
            abstained: read(&self.abstained),
            failed: read(&self.failed),
            skipped: read(&self.skipped),
        }
    }
}
struct Pending {
    snapshot: FeatureSnapshot,
    digest: String,
    created: Instant,
}
#[derive(Default)]
struct Latest {
    values: HashMap<String, (u32, String)>,
    order: VecDeque<String>,
}
impl Latest {
    fn put(&mut self, snapshot: &FeatureSnapshot, digest: &str) {
        if !self.values.contains_key(&snapshot.window_id) {
            self.order.push_back(snapshot.window_id.clone());
        }
        self.values.insert(
            snapshot.window_id.clone(),
            (snapshot.revision, digest.into()),
        );
        while self.values.len() > 256 {
            if let Some(id) = self.order.pop_front() {
                self.values.remove(&id);
            }
        }
    }
    fn current(&self, pending: &Pending) -> bool {
        self.values
            .get(&pending.snapshot.window_id)
            .is_some_and(|(revision, digest)| {
                *revision == pending.snapshot.revision && *digest == pending.digest
            })
    }
}

pub struct BehaviorRuntime {
    start: BehaviorStartConfig,
    sender: mpsc::Sender<TelemetryEnvelope>,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    counters: Arc<Counters>,
    session_dir: PathBuf,
    shutdown_limit: Duration,
}
impl BehaviorRuntime {
    pub fn spawn(
        config: &BehaviorSection,
        allowed_hosts: Vec<String>,
        audit_root: PathBuf,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(config.enabled, "behavior analysis is disabled");
        config.validate()?;
        let classifier: Arc<dyn Classifier> = match config.classifier.provider.as_str() {
            "mock" => Arc::new(MockClassifier),
            "jev-mcp" => Arc::new(JevMcpClassifier::new(config.classifier.runtime())?),
            _ => anyhow::bail!("unsupported behavior classifier"),
        };
        Self::spawn_with_classifier(config, allowed_hosts, audit_root, classifier)
    }
    pub fn spawn_with_classifier(
        config: &BehaviorSection,
        allowed_hosts: Vec<String>,
        audit_root: PathBuf,
        classifier: Arc<dyn Classifier>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(config.enabled, "behavior analysis is disabled");
        config.validate()?;
        let session_id = new_session_id();
        let session_dir = audit_root.join(&session_id);
        let store = runtime_store(config, &session_dir)?;
        let counters = runtime_counters(config);
        let latest = Arc::new(Mutex::new(Latest::default()));
        let (sender, rx) = mpsc::channel(config.limits.telemetry_queue);
        let (queue, windows) = mpsc::channel(config.limits.queue_windows);
        let (stop, stop_rx) = watch::channel(false);
        let ingestion = tokio::spawn(ingest(
            rx,
            queue,
            stop_rx.clone(),
            session_id.clone(),
            config.baseline_hosts.clone(),
            store.clone(),
            latest.clone(),
            counters.clone(),
        ));
        let worker = tokio::spawn(classify(
            windows,
            stop_rx,
            classifier,
            config.clone(),
            store,
            latest,
            counters.clone(),
        ));
        eprintln!(
            "behavior audit started (advisory, classifier={})",
            config.classifier.provider
        );
        Ok(Self {
            start: guest_start_config(config, session_id, allowed_hosts),
            sender,
            stop,
            tasks: vec![ingestion, worker],
            counters,
            session_dir,
            shutdown_limit: Duration::from_secs(config.limits.shutdown_secs),
        })
    }
    pub fn start_config(&self) -> &BehaviorStartConfig {
        &self.start
    }
    pub fn sender(&self) -> mpsc::Sender<TelemetryEnvelope> {
        self.sender.clone()
    }
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }
    pub fn stats(&self) -> BehaviorStats {
        self.counters.snapshot()
    }
    pub async fn shutdown(&mut self) {
        self.stop.send_replace(true);
        let deadline = tokio::time::Instant::now() + self.shutdown_limit;
        for mut task in self.tasks.drain(..) {
            if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        if let Ok(json) = serde_json::to_string(&self.stats()) {
            eprintln!("behavior counters: {json}");
        }
    }
}
impl Drop for BehaviorRuntime {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}
fn runtime_store(
    config: &BehaviorSection,
    session_dir: &Path,
) -> anyhow::Result<Arc<Mutex<AuditStore>>> {
    let store = AuditStore::new(
        session_dir,
        StoreConfig {
            max_session_bytes: config.limits.max_store_bytes,
            max_segment_bytes: (10 * 1024 * 1024).min(config.limits.max_store_bytes),
            retention_secs: config.limits.retention_days * 86400,
            ..Default::default()
        },
    )?;
    let store = Arc::new(Mutex::new(store));
    Ok(store)
}

fn runtime_counters(config: &BehaviorSection) -> Arc<Counters> {
    Arc::new(Counters {
        mcp_commit: config.classifier.mcp_commit.clone(),
        requested_model: if config.classifier.provider == "mock" {
            "mock-v1".into()
        } else {
            config.classifier.model.clone()
        },
        ..Default::default()
    })
}

fn guest_start_config(
    config: &BehaviorSection,
    session_id: String,
    allowed_hosts: Vec<String>,
) -> BehaviorStartConfig {
    BehaviorStartConfig {
        session_id,
        proxy_listen: config.proxy_listen.clone(),
        allowed_hosts,
        fixture_endpoint: config.fixture_endpoint.clone(),
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn stored(result: Result<StoreWrite, TelemetryError>, counters: &Counters) {
    match result {
        Ok(write) if write.storage_gap => {
            counters.storage_gap.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) if counters.storage_failed.fetch_add(1, Ordering::Relaxed) == 0 => {
            eprintln!("behavior audit unavailable; optional analysis is degraded");
        }
        _ => {}
    }
}

// Independent worker channels and immutable session configuration are explicit
// here so ownership and shutdown paths remain visible at the spawn boundary.
#[allow(clippy::too_many_arguments)]
async fn ingest(
    mut rx: mpsc::Receiver<TelemetryEnvelope>,
    queue: mpsc::Sender<Pending>,
    mut stop: watch::Receiver<bool>,
    session: String,
    baseline: Vec<String>,
    store: Arc<Mutex<AuditStore>>,
    latest: Arc<Mutex<Latest>>,
    counters: Arc<Counters>,
) {
    let mut state = IngestionState::new(baseline);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut closing = false;
    loop {
        let snapshots = tokio::select! {
            biased;
            _ = stop.changed(), if !closing => { rx.close(); closing = true; Vec::new() },
            _ = tick.tick(), if !closing => state.advance_clocks(),
            event = rx.recv() => {
                let Some(event) = event else { break; };
                let Some(snapshots) = state.receive_event(event, &session, &store, &counters) else { continue; };
                snapshots
            },
        };
        for snapshot in snapshots {
            enqueue(snapshot, &queue, &store, &latest, &counters);
        }
    }
    // Final snapshots remain audit records; stopped sessions cannot start new inference.
    for snapshot in state.correlator.flush() {
        stored(
            store
                .lock()
                .expect("audit lock")
                .append_snapshot(&snapshot, unix_secs()),
            &counters,
        );
        record(
            &snapshot,
            ClassificationOutcome::Skipped {
                reason: SkipReason::SessionEnded,
            },
            &store,
            &counters,
        );
    }
}

struct IngestionState {
    correlator: Correlator,
    baseline: Vec<String>,
    clocks: HashMap<String, (u64, Instant, u64)>,
    pending_gap: bool,
}
impl IngestionState {
    fn new(baseline: Vec<String>) -> Self {
        Self {
            correlator: Correlator::new(Default::default())
                .expect("fixed bounded correlation configuration"),
            baseline: baseline
                .into_iter()
                .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                .collect(),
            clocks: HashMap::new(),
            pending_gap: false,
        }
    }

    fn advance_clocks(&mut self) -> Vec<FeatureSnapshot> {
        let mut snapshots = Vec::new();
        for (domain, (observed, received, uncertainty)) in &self.clocks {
            // Advance only by elapsed host duration since an actual same-domain guest event.
            let elapsed = received.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            snapshots.extend(self.correlator.advance_clock_uncertain(
                domain,
                observed.saturating_add(elapsed),
                uncertainty.saturating_add(5_000_000),
            ));
        }
        snapshots
    }

    fn receive_event(
        &mut self,
        mut event: TelemetryEnvelope,
        session: &str,
        store: &Arc<Mutex<AuditStore>>,
        counters: &Counters,
    ) -> Option<Vec<FeatureSnapshot>> {
        if event.session_id != session || event.validate().is_err() {
            counters.invalid.fetch_add(1, Ordering::Relaxed);
            self.pending_gap = true;
            return None;
        }
        counters.events.fetch_add(1, Ordering::Relaxed);
        event.host_received_at_unix_ns = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .min(u64::MAX as u128) as u64,
        );
        self.assign_novelty(&mut event);
        // Invalid envelopes have no trustworthy scope/time: coverage stays degraded for this session.
        if self.pending_gap {
            event.quality.issues.push(QualityIssue::EventLoss);
        }
        self.update_clock(&mut event);
        let result = store
            .lock()
            .expect("audit lock")
            .append_event(&event, unix_secs());
        let storage_bad = !result.as_ref().is_ok_and(|r| !r.storage_gap);
        stored(result, counters);
        if storage_bad {
            event.quality.issues.push(QualityIssue::StorageGap);
        }
        Some(match self.correlator.ingest(event) {
            Ok(snapshots) => snapshots,
            Err(_) => {
                counters.invalid.fetch_add(1, Ordering::Relaxed);
                self.pending_gap = true;
                Vec::new()
            }
        })
    }

    fn assign_novelty(&self, event: &mut TelemetryEnvelope) {
        if let TelemetryPayload::HttpRequest {
            raw_host, novelty, ..
        } = &mut event.payload
        {
            *novelty = match raw_host {
                Some(host) => {
                    if self
                        .baseline
                        .iter()
                        .any(|b| b == &host.trim_end_matches('.').to_ascii_lowercase())
                    {
                        DestinationNovelty::Known
                    } else {
                        DestinationNovelty::Novel
                    }
                }
                None => DestinationNovelty::Unknown,
            };
        }
    }

    fn update_clock(&mut self, event: &mut TelemetryEnvelope) {
        if self.clocks.len() < 16 || self.clocks.contains_key(&event.clock_domain) {
            let clock = self.clocks.entry(event.clock_domain.clone()).or_insert((
                event.observed_monotonic_ns,
                Instant::now(),
                event.clock_uncertainty_ns,
            ));
            // Delayed source events must not reset the live estimate backwards.
            let estimate = clock
                .0
                .saturating_add(clock.1.elapsed().as_nanos().min(u64::MAX as u128) as u64);
            if event.observed_monotonic_ns >= estimate {
                *clock = (
                    event.observed_monotonic_ns,
                    Instant::now(),
                    event.clock_uncertainty_ns,
                );
            } else {
                clock.2 = clock.2.max(event.clock_uncertainty_ns);
            }
        } else {
            event.quality.issues.push(QualityIssue::ClockUnknown);
        }
    }
}

fn enqueue(
    snapshot: FeatureSnapshot,
    queue: &mpsc::Sender<Pending>,
    store: &Arc<Mutex<AuditStore>>,
    latest: &Arc<Mutex<Latest>>,
    counters: &Counters,
) {
    counters.windows.fetch_add(1, Ordering::Relaxed);
    stored(
        store
            .lock()
            .expect("audit lock")
            .append_snapshot(&snapshot, unix_secs()),
        counters,
    );
    let projection = snapshot.projection(FeatureMode::Correlated);
    let Ok(digest) = projection.digest() else {
        record(
            &snapshot,
            ClassificationOutcome::Skipped {
                reason: SkipReason::Oversize,
            },
            store,
            counters,
        );
        return;
    };
    latest.lock().expect("latest lock").put(&snapshot, &digest);
    if !projection.eligible() {
        record(
            &snapshot,
            ClassificationOutcome::Abstained {
                reason: AbstentionReason::IncompleteObservation,
                answer: None,
            },
            store,
            counters,
        );
        return;
    }
    queue_pending(snapshot, digest, queue, store, counters);
}

fn queue_pending(
    snapshot: FeatureSnapshot,
    digest: String,
    queue: &mpsc::Sender<Pending>,
    store: &Arc<Mutex<AuditStore>>,
    counters: &Counters,
) {
    let pending = Pending {
        snapshot,
        digest,
        created: Instant::now(),
    };
    if let Err(error) = queue.try_send(pending) {
        let reason = if matches!(error, mpsc::error::TrySendError::Closed(_)) {
            SkipReason::SessionEnded
        } else {
            SkipReason::QueueFull
        };
        record(
            &error.into_inner().snapshot,
            ClassificationOutcome::Skipped { reason },
            store,
            counters,
        );
    }
}
async fn classify(
    mut rx: mpsc::Receiver<Pending>,
    mut stop: watch::Receiver<bool>,
    classifier: Arc<dyn Classifier>,
    config: BehaviorSection,
    store: Arc<Mutex<AuditStore>>,
    latest: Arc<Mutex<Latest>>,
    counters: Arc<Counters>,
) {
    loop {
        let pending = tokio::select! { biased; _=stop.changed()=>break,pending=rx.recv()=>{let Some(p)=pending else{break}; p} };
        let current = latest.lock().expect("latest lock").current(&pending);
        let outcome = if !current
            || pending.created.elapsed() > Duration::from_secs(config.limits.max_queue_age_secs)
        {
            ClassificationOutcome::Skipped {
                reason: SkipReason::Stale,
            }
        } else if config.classifier.provider == "jev-mcp" && !config.classifier.allow_export {
            ClassificationOutcome::Skipped {
                reason: SkipReason::ExportDenied,
            }
        } else {
            let Some(outcome) =
                invoke_classifier(&pending, &classifier, &config, &mut stop, &store, &counters)
                    .await
            else {
                break;
            };
            outcome
        };
        let outcome = if pending.created.elapsed()
            > Duration::from_secs(config.limits.max_result_age_secs)
            || !latest.lock().expect("latest lock").current(&pending)
        {
            ClassificationOutcome::Skipped {
                reason: SkipReason::Stale,
            }
        } else {
            outcome
        };
        record(&pending.snapshot, outcome, &store, &counters);
    }
    discard_pending(&mut rx, &store, &counters);
}

fn discard_pending(
    rx: &mut mpsc::Receiver<Pending>,
    store: &Arc<Mutex<AuditStore>>,
    counters: &Counters,
) {
    rx.close();
    while let Ok(pending) = rx.try_recv() {
        record(
            &pending.snapshot,
            ClassificationOutcome::Skipped {
                reason: SkipReason::SessionEnded,
            },
            store,
            counters,
        );
    }
}

fn new_session_id() -> String {
    (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

async fn invoke_classifier(
    pending: &Pending,
    classifier: &Arc<dyn Classifier>,
    config: &BehaviorSection,
    stop: &mut watch::Receiver<bool>,
    store: &Arc<Mutex<AuditStore>>,
    counters: &Counters,
) -> Option<ClassificationOutcome> {
    let projection = pending.snapshot.projection(FeatureMode::Correlated);
    let classifier = classifier.clone();
    // JoinSet aborts its invocation on timeout, shutdown, or worker drop.
    // A provider panic becomes an audit failure; ingestion keeps running.
    let mut invocation = tokio::task::JoinSet::new();
    invocation.spawn(async move { classifier.classify(&projection).await });
    Some(tokio::select! { biased;
        _=stop.changed()=> { record(&pending.snapshot,ClassificationOutcome::Skipped{reason:SkipReason::SessionEnded},store,counters); return None; },
        outcome=tokio::time::timeout(Duration::from_secs(config.classifier.deadline_secs),invocation.join_next())=>match outcome {
            Ok(Some(Ok(outcome)))=>outcome,
            Ok(_)=>ClassificationOutcome::Failed{kind:crate::behavior_classifier::ClassificationErrorKind::Panicked},
            Err(_)=>ClassificationOutcome::Failed{kind:crate::behavior_classifier::ClassificationErrorKind::Timeout},
        },
    })
}

fn record(
    snapshot: &FeatureSnapshot,
    outcome: ClassificationOutcome,
    store: &Arc<Mutex<AuditStore>>,
    counters: &Counters,
) {
    match &outcome {
        ClassificationOutcome::Classified { answer } => {
            counters.classified.fetch_add(1, Ordering::Relaxed);
            if answer.class == ThreatClass::AccessPostSuspected {
                eprintln!(
                    "behavior warning: access_post_suspected window={} revision={} evidence={} (advisory)",
                    snapshot.window_id,
                    snapshot.revision,
                    snapshot.evidence_event_ids.len()
                );
            }
        }
        ClassificationOutcome::Abstained { .. } => {
            counters.abstained.fetch_add(1, Ordering::Relaxed);
        }
        ClassificationOutcome::Failed { .. } => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
        }
        ClassificationOutcome::Skipped { .. } => {
            counters.skipped.fetch_add(1, Ordering::Relaxed);
        }
    }
    // The shared store accepts a closed, sanitized classification record. The
    // provider response and free-form explanation never enter persistence.
    persist_classification(snapshot, &outcome, store, counters);
}

fn persist_classification(
    snapshot: &FeatureSnapshot,
    outcome: &ClassificationOutcome,
    store: &Arc<Mutex<AuditStore>>,
    counters: &Counters,
) {
    let Some(audit) = classification_audit(snapshot, outcome, counters) else {
        return;
    };
    stored(
        store
            .lock()
            .expect("audit lock")
            .append_classification(&audit, unix_secs()),
        counters,
    );
}

fn audit_status(
    outcome: &ClassificationOutcome,
) -> (ClassificationStatus, Option<ClassificationReason>) {
    use crate::behavior_classifier::ClassificationErrorKind as Error;
    match outcome {
        ClassificationOutcome::Classified { .. } => (ClassificationStatus::Classified, None),
        ClassificationOutcome::Abstained { reason, .. } => (
            ClassificationStatus::Abstained,
            Some(match reason {
                AbstentionReason::IncompleteObservation => {
                    ClassificationReason::InsufficientObservation
                }
                AbstentionReason::UnknownChoice => ClassificationReason::UnknownClass,
                AbstentionReason::LowConfidence => ClassificationReason::LowConfidence,
            }),
        ),
        ClassificationOutcome::Failed { kind } => (
            ClassificationStatus::Failed,
            Some(match kind {
                Error::Timeout => ClassificationReason::Timeout,
                Error::ModelMismatch => ClassificationReason::ModelMismatch,
                Error::InvalidResponse | Error::Validation => ClassificationReason::InvalidResponse,
                Error::ResponseTooLarge | Error::StderrTooLarge => ClassificationReason::Oversize,
                Error::Authentication | Error::RateLimit | Error::Network | Error::Http => {
                    ClassificationReason::ApiError
                }
                _ => ClassificationReason::McpError,
            }),
        ),
        ClassificationOutcome::Skipped { reason } => (
            ClassificationStatus::Skipped,
            Some(match reason {
                SkipReason::Disabled => ClassificationReason::Disabled,
                SkipReason::ExportDenied => ClassificationReason::ExportForbidden,
                SkipReason::QueueFull => ClassificationReason::QueueFull,
                SkipReason::Oversize => ClassificationReason::Oversize,
                SkipReason::Stale => ClassificationReason::Stale,
                SkipReason::SessionEnded => ClassificationReason::SessionEnded,
                SkipReason::MissingRecording => ClassificationReason::McpError,
            }),
        ),
    }
}

fn classification_audit(
    snapshot: &FeatureSnapshot,
    outcome: &ClassificationOutcome,
    counters: &Counters,
) -> Option<ClassificationAudit> {
    let (status, reason) = audit_status(outcome);
    let Ok(projection_digest) = snapshot.projection(FeatureMode::Correlated).digest() else {
        counters.storage_failed.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let answer = outcome.answer();
    Some(ClassificationAudit {
        session_id: snapshot.session_id.clone(),
        window_id: snapshot.window_id.clone(),
        revision: snapshot.revision,
        projection_digest,
        feature_version: snapshot.feature_version,
        question_version: crate::behavior_classifier::QUESTION_VERSION,
        host_policy_version: 1,
        question_digest: crate::behavior_classifier::question_digest(),
        mcp_commit: answer
            .and_then(|a| a.mcp_commit.clone())
            .or_else(|| counters.mcp_commit.clone()),
        input_tokens: answer.map(|a| a.input_tokens),
        output_tokens: answer.map(|a| a.output_tokens),
        status,
        class: answer.map(|a| a.class),
        reason,
        requested_model: answer.map_or_else(
            || counters.requested_model.clone(),
            |a| a.requested_model.clone(),
        ),
        returned_model: answer.map(|a| a.returned_model.clone()),
        probabilities: answer.map(|a| {
            [
                a.probabilities["normal"],
                a.probabilities["access_post_suspected"],
                a.probabilities["unknown"],
            ]
        }),
        confidence: answer.map(|a| a.confidence),
        evidence_event_ids: snapshot.evidence_event_ids.clone(),
        queued_ns: None,
        elapsed_ns: answer.map(|a| a.elapsed_ms.saturating_mul(1_000_000)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir()
                .join(format!("izanagi-worker-{:032x}", rand::random::<u128>()));
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn snapshot() -> FeatureSnapshot {
        crate::behavior_evaluation::replay_file(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/behavior/access-post.jsonl"),
        )
        .unwrap()
        .remove(0)
    }
    fn state(dir: &Temp) -> (Arc<Mutex<AuditStore>>, Arc<Mutex<Latest>>, Arc<Counters>) {
        (
            Arc::new(Mutex::new(
                AuditStore::new(&dir.0, Default::default()).unwrap(),
            )),
            Arc::new(Mutex::new(Latest::default())),
            Arc::new(Counters {
                requested_model: "mock-v1".into(),
                ..Default::default()
            }),
        )
    }
    #[tokio::test]
    async fn queue_saturation_is_recorded_and_latest_index_stays_bounded() {
        let dir = Temp::new();
        let (store, latest, counters) = state(&dir);
        let (tx, _rx) = mpsc::channel(1);
        for i in 0..300 {
            let mut s = snapshot();
            s.window_id = format!("window-{i}");
            enqueue(s, &tx, &store, &latest, &counters);
        }
        assert_eq!(counters.skipped.load(Ordering::Relaxed), 299);
        assert_eq!(latest.lock().unwrap().values.len(), 256);
        let records = store.lock().unwrap().read_records().unwrap();
        assert!(records.iter().any(|r|matches!(&r.payload,AuditPayload::Classification(a) if a.reason==Some(ClassificationReason::QueueFull))));
    }
    #[tokio::test]
    async fn expired_queue_item_never_runs_provider() {
        let dir = Temp::new();
        let (store, latest, counters) = state(&dir);
        let (tx, rx) = mpsc::channel(1);
        let (_stop, stop) = watch::channel(false);
        let snapshot = snapshot();
        let digest = snapshot
            .projection(FeatureMode::Correlated)
            .digest()
            .unwrap();
        latest.lock().unwrap().put(&snapshot, &digest);
        tx.send(Pending {
            snapshot,
            digest,
            created: Instant::now() - Duration::from_secs(16),
        })
        .await
        .unwrap();
        drop(tx);
        classify(
            rx,
            stop,
            Arc::new(MockClassifier),
            BehaviorSection::default(),
            store.clone(),
            latest,
            counters.clone(),
        )
        .await;
        assert_eq!(counters.classified.load(Ordering::Relaxed), 0);
        assert!(store.lock().unwrap().read_records().unwrap().iter().any(|r|matches!(&r.payload,AuditPayload::Classification(a) if a.reason==Some(ClassificationReason::Stale))));
    }
    struct Delayed {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }
    #[async_trait]
    impl Classifier for Delayed {
        async fn classify(&self, p: &FeatureProjection) -> ClassificationOutcome {
            self.entered.notify_one();
            self.release.notified().await;
            MockClassifier.classify(p).await
        }
    }
    #[tokio::test]
    async fn superseded_inflight_result_is_saved_as_stale() {
        let dir = Temp::new();
        let (store, latest, counters) = state(&dir);
        let (tx, rx) = mpsc::channel(1);
        let (_stop, stop) = watch::channel(false);
        let snapshot = snapshot();
        let digest = snapshot
            .projection(FeatureMode::Correlated)
            .digest()
            .unwrap();
        latest.lock().unwrap().put(&snapshot, &digest);
        tx.send(Pending {
            snapshot: snapshot.clone(),
            digest: digest.clone(),
            created: Instant::now(),
        })
        .await
        .unwrap();
        drop(tx);
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let worker = tokio::spawn(classify(
            rx,
            stop,
            Arc::new(Delayed {
                entered: entered.clone(),
                release: release.clone(),
            }),
            BehaviorSection::default(),
            store.clone(),
            latest.clone(),
            counters.clone(),
        ));
        entered.notified().await;
        let mut revised = snapshot;
        revised.revision += 1;
        latest.lock().unwrap().put(&revised, &digest);
        release.notify_one();
        worker.await.unwrap();
        assert_eq!(counters.classified.load(Ordering::Relaxed), 0);
        assert_eq!(counters.skipped.load(Ordering::Relaxed), 1);
    }
}
