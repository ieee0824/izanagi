//! Offline event-time replay and paired A/B/C/D evaluation. No live freshness clock is used.
use crate::behavior_classifier::{
    ClassificationOutcome, Classifier, PINNED_MODEL, QUESTION_VERSION,
};
use anyhow::{Result, bail};
use izanagi_telemetry::{
    AuditPayload, AuditRecord, CorrelationConfig, Correlator, FeatureMode, FeatureSnapshot,
    QualityIssue, TelemetryEnvelope, ThreatClass, deterministic_rule,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

const MAX_REPLAY_BYTES: u64 = 100 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SCENARIOS: usize = 256;
const MAX_REPLAY_WINDOWS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedLabel {
    Normal,
    Suspicious,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationSplit {
    Development,
    HeldOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowLabel {
    pub window_id: String,
    pub expected: ExpectedLabel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationScenario {
    pub id: String,
    pub family: String,
    pub split: EvaluationSplit,
    pub events: PathBuf,
    pub events_sha256: String,
    pub routine_workload: bool,
    pub labels: Vec<WindowLabel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationManifest {
    pub schema_version: u16,
    pub feature_version: u16,
    pub host_policy_version: u16,
    /// The PoC remains advisory regardless of measured classification accuracy.
    pub promotion_policy: String,
    pub seed: u64,
    pub source_commit: String,
    pub collector_commit: String,
    pub vm_image_sha256: String,
    pub scenario_version: String,
    pub baseline_version: String,
    pub model: String,
    /// Operator-declared MCP revision; null records that it was not independently verified.
    pub mcp_commit: Option<String>,
    pub question_version: u16,
    pub min_confidence: f64,
    pub distribution_tolerance: f64,
    pub confidence_tolerance: f64,
    /// Exactly these eligibility/mask definitions apply in every paired run.
    pub correlated_eligibility: String,
    pub network_eligibility: String,
    pub scenarios: Vec<EvaluationScenario>,
}

impl EvaluationManifest {
    pub fn validate(&self) -> Result<()> {
        let hex = |value: &str, len: usize| {
            value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
        };
        if self.schema_version != 1
            || self.feature_version != izanagi_telemetry::FEATURE_VERSION
            || self.host_policy_version != 1
            || self.promotion_policy != "audit_only_no_automatic_promotion_v1"
            || self.model != PINNED_MODEL
            || self.mcp_commit.as_ref().is_some_and(|commit| {
                commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit())
            })
            || self.question_version != QUESTION_VERSION
            || !hex(&self.source_commit, 40)
            || !hex(&self.collector_commit, 40)
            || !hex(&self.vm_image_sha256, 64)
            || !safe_id(&self.scenario_version)
            || !safe_id(&self.baseline_version)
            || !self.min_confidence.is_finite()
            || !(0.0..=1.0).contains(&self.min_confidence)
            || !self.distribution_tolerance.is_finite()
            || !(0.0..=0.01).contains(&self.distribution_tolerance)
            || !self.confidence_tolerance.is_finite()
            || !(0.0..=0.05).contains(&self.confidence_tolerance)
            || self.correlated_eligibility != "confirmed_writer_complete_v1"
            || self.network_eligibility != "network_complete_mask_v1"
            || self.scenarios.is_empty()
            || self.scenarios.len() > MAX_SCENARIOS
        {
            bail!("invalid evaluation manifest");
        }
        let mut ids = BTreeSet::new();
        let mut families = BTreeMap::new();
        for scenario in &self.scenarios {
            if !safe_id(&scenario.id)
                || !safe_id(&scenario.family)
                || !ids.insert(scenario.id.clone())
                || scenario.events.is_absolute()
                || scenario
                    .events
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || !hex(&scenario.events_sha256, 64)
                || scenario.labels.is_empty()
                || scenario.labels.len() > 256
            {
                bail!("invalid evaluation scenario");
            }
            if families
                .insert(scenario.family.clone(), scenario.split)
                .is_some_and(|split| split != scenario.split)
            {
                bail!("scenario family crosses development and held-out splits");
            }
            let mut windows = BTreeSet::new();
            for label in &scenario.labels {
                if !safe_id(&label.window_id)
                    || !windows.insert(label.window_id.clone())
                    || (scenario.routine_workload && label.expected != ExpectedLabel::Normal)
                {
                    bail!("invalid independent window labels");
                }
            }
        }
        Ok(())
    }
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

pub fn load_manifest(path: &Path) -> Result<EvaluationManifest> {
    let metadata =
        std::fs::metadata(path).map_err(|_| anyhow::anyhow!("cannot read evaluation manifest"))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        bail!("evaluation manifest size limit exceeded");
    }
    let bytes =
        std::fs::read(path).map_err(|_| anyhow::anyhow!("cannot read evaluation manifest"))?;
    let manifest: EvaluationManifest = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid evaluation manifest JSON"))?;
    manifest.validate()?;
    Ok(manifest)
}

/// Accepts arbitrary arrival order; the correlator uses only recorded monotonic event time.
/// Only the last explicit revision of each window participates in paired evaluation.
pub fn replay<R: BufRead>(
    mut reader: R,
    config: CorrelationConfig,
) -> Result<Vec<FeatureSnapshot>> {
    let mut correlator = Correlator::new(config)
        .map_err(|_| anyhow::anyhow!("invalid replay correlation configuration"))?;
    let mut latest = BTreeMap::<String, FeatureSnapshot>::new();
    let mut total = 0u64;
    loop {
        let mut line = Vec::new();
        // Bound a line before parsing or allocation of an arbitrarily long JSON object.
        loop {
            let available = reader
                .fill_buf()
                .map_err(|_| anyhow::anyhow!("replay input I/O failed"))?;
            if available.is_empty() {
                break;
            }
            let len = available
                .iter()
                .position(|c| *c == b'\n')
                .map_or(available.len(), |index| index + 1);
            if line.len().saturating_add(len) > MAX_EVENT_BYTES {
                bail!("replay event size limit exceeded");
            }
            line.extend_from_slice(&available[..len]);
            let ended = available[len - 1] == b'\n';
            reader.consume(len);
            if ended {
                break;
            }
        }
        if line.is_empty() {
            break;
        }
        total = total.saturating_add(line.len() as u64);
        if total > MAX_REPLAY_BYTES {
            bail!("replay input size limit exceeded");
        }
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            bail!("blank replay event");
        }
        let event: TelemetryEnvelope = match serde_json::from_slice(&line) {
            Ok(event) => event,
            Err(_) => {
                let record: AuditRecord = serde_json::from_slice(&line)
                    .map_err(|_| anyhow::anyhow!("invalid replay event JSON"))?;
                let AuditPayload::Event(mut event) = record.payload else {
                    continue;
                };
                if record.storage_gap && !event.quality.issues.contains(&QualityIssue::StorageGap) {
                    event.quality.issues.push(QualityIssue::StorageGap);
                }
                event
            }
        };
        event
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid replay event"))?;
        for snapshot in correlator
            .ingest(event)
            .map_err(|_| anyhow::anyhow!("replay correlation failed"))?
        {
            keep_latest(&mut latest, snapshot);
            if latest.len() > MAX_REPLAY_WINDOWS {
                bail!("replay window count limit exceeded");
            }
        }
    }
    for snapshot in correlator.flush() {
        keep_latest(&mut latest, snapshot);
        if latest.len() > MAX_REPLAY_WINDOWS {
            bail!("replay window count limit exceeded");
        }
    }
    Ok(latest.into_values().collect())
}

fn keep_latest(latest: &mut BTreeMap<String, FeatureSnapshot>, snapshot: FeatureSnapshot) {
    if latest
        .get(&snapshot.window_id)
        .is_none_or(|previous| snapshot.revision > previous.revision)
    {
        latest.insert(snapshot.window_id.clone(), snapshot);
    }
}

pub fn replay_file(path: &Path) -> Result<Vec<FeatureSnapshot>> {
    let file =
        std::fs::File::open(path).map_err(|_| anyhow::anyhow!("cannot open replay input"))?;
    replay(BufReader::new(file), CorrelationConfig::default())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvaluationMethod {
    A,
    B,
    C,
    D,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesDecision {
    NotApplied,
    Normal,
    Suspicious,
    Unknown,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationWindowResult {
    pub scenario_id: String,
    pub split: EvaluationSplit,
    pub window_id: String,
    pub revision: u32,
    pub expected: ExpectedLabel,
    pub method: EvaluationMethod,
    pub existing_rule_alert: bool,
    pub series_decision: SeriesDecision,
    pub detected: bool,
    pub projection_digest: Option<String>,
    pub classifier: Option<ClassificationOutcome>,
    /// Includes failures/abstentions; does not remove slow failing requests from latency statistics.
    pub classifier_elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvaluationMetrics {
    pub total_windows: u64,
    pub positive_windows: u64,
    pub negative_windows: u64,
    pub indeterminate_windows: u64,
    pub true_positives: u64,
    pub false_positives: u64,
    pub true_negatives: u64,
    pub false_negatives: u64,
    pub classified_windows: u64,
    pub abstained_windows: u64,
    pub failed_windows: u64,
    pub skipped_windows: u64,
    pub existing_rule_alerts: u64,
    pub additional_series_alerts: u64,
    pub routine_workloads: u64,
    pub routine_false_alerts: u64,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
    pub coverage: f64,
    pub abstention_rate: f64,
    pub error_rate: f64,
    pub additional_false_alerts_per_routine_workload: Option<f64>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub p50_elapsed_ms: Option<u64>,
    pub p95_elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub schema_version: u16,
    pub provider: String,
    pub simulated: bool,
    pub manifest: EvaluationManifest,
    pub returned_models: Vec<String>,
    pub methods: BTreeMap<EvaluationMethod, EvaluationMetrics>,
    pub windows: Vec<EvaluationWindowResult>,
}

fn decision(outcome: &ClassificationOutcome) -> SeriesDecision {
    match outcome {
        ClassificationOutcome::Classified { answer } => match answer.class {
            ThreatClass::Normal => SeriesDecision::Normal,
            ThreatClass::AccessPostSuspected => SeriesDecision::Suspicious,
            ThreatClass::Unknown => SeriesDecision::Unknown,
        },
        ClassificationOutcome::Abstained { .. } => SeriesDecision::Unknown,
        ClassificationOutcome::Failed { .. } => SeriesDecision::Failed,
        ClassificationOutcome::Skipped { .. } => SeriesDecision::Skipped,
    }
}

/// The same candidate windows and independent labels are evaluated by all methods.
/// B's intentional mask preserves network observations and is not a collector gap.
pub async fn evaluate_manifest(
    manifest: &EvaluationManifest,
    base_dir: &Path,
    classifier: &dyn Classifier,
    provider: &str,
) -> Result<EvaluationReport> {
    manifest.validate()?;
    if !matches!(provider, "mock" | "recorded" | "jev-mcp") {
        bail!("invalid evaluation provider");
    }
    if let Some(config) = classifier.configuration()
        && (config.model != manifest.model
            || config.mcp_commit != manifest.mcp_commit
            || config.min_confidence != manifest.min_confidence
            || config.confidence_tolerance != manifest.confidence_tolerance
            || config.distribution_tolerance != manifest.distribution_tolerance)
    {
        bail!("classifier configuration does not match evaluation manifest");
    }
    let base = base_dir
        .canonicalize()
        .map_err(|_| anyhow::anyhow!("invalid evaluation base directory"))?;
    let mut results = Vec::new();
    let mut models = BTreeSet::new();
    let mut metrics: BTreeMap<_, _> = [
        EvaluationMethod::A,
        EvaluationMethod::B,
        EvaluationMethod::C,
        EvaluationMethod::D,
    ]
    .into_iter()
    .map(|method| (method, EvaluationMetrics::default()))
    .collect();
    let mut elapsed = BTreeMap::<EvaluationMethod, Vec<u64>>::new();
    for scenario in &manifest.scenarios {
        let path = base
            .join(&scenario.events)
            .canonicalize()
            .map_err(|_| anyhow::anyhow!("cannot open evaluation fixture"))?;
        if !path.starts_with(&base) {
            bail!("evaluation fixture escapes manifest directory");
        }
        let file = std::fs::File::open(&path)
            .map_err(|_| anyhow::anyhow!("cannot open evaluation fixture"))?;
        if file
            .metadata()
            .map_err(|_| anyhow::anyhow!("cannot read evaluation fixture"))?
            .len()
            > MAX_REPLAY_BYTES
        {
            bail!("evaluation fixture size limit exceeded");
        }
        // Read and hash the exact immutable bytes which will be replayed, avoiding a reopen race.
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(file, MAX_REPLAY_BYTES + 1),
            &mut bytes,
        )
        .map_err(|_| anyhow::anyhow!("cannot read evaluation fixture"))?;
        if bytes.len() as u64 > MAX_REPLAY_BYTES {
            bail!("evaluation fixture size limit exceeded");
        }
        if hex::encode(Sha256::digest(&bytes)) != scenario.events_sha256 {
            bail!("evaluation fixture does not match manifest digest");
        }
        let snapshots = replay(std::io::Cursor::new(bytes), CorrelationConfig::default())?;
        let mut labels: BTreeMap<_, _> = scenario
            .labels
            .iter()
            .map(|label| (label.window_id.clone(), label.expected))
            .collect();
        if snapshots.len() != labels.len() {
            bail!("replayed candidate windows do not match independent labels");
        }
        for method in metrics.values_mut() {
            if scenario.routine_workload {
                method.routine_workloads += 1;
            }
        }
        for snapshot in snapshots {
            let expected = labels
                .remove(&snapshot.window_id)
                .ok_or_else(|| anyhow::anyhow!("replayed window has no independent label"))?;
            let existing = !snapshot.rule_matches.is_empty();
            for method in [
                EvaluationMethod::A,
                EvaluationMethod::B,
                EvaluationMethod::C,
                EvaluationMethod::D,
            ] {
                let request_started = std::time::Instant::now();
                let (series_decision, assessment, digest) = match method {
                    EvaluationMethod::A => (SeriesDecision::NotApplied, None, None),
                    EvaluationMethod::D => (
                        match deterministic_rule(&snapshot) {
                            ThreatClass::Normal => SeriesDecision::Normal,
                            ThreatClass::AccessPostSuspected => SeriesDecision::Suspicious,
                            ThreatClass::Unknown => SeriesDecision::Unknown,
                        },
                        None,
                        Some(
                            snapshot
                                .projection(FeatureMode::Correlated)
                                .digest()
                                .map_err(|_| anyhow::anyhow!("invalid replay projection"))?,
                        ),
                    ),
                    EvaluationMethod::B | EvaluationMethod::C => {
                        let projection = snapshot.projection(if method == EvaluationMethod::B {
                            FeatureMode::NetworkOnly
                        } else {
                            FeatureMode::Correlated
                        });
                        let digest = projection
                            .digest()
                            .map_err(|_| anyhow::anyhow!("invalid replay projection"))?;
                        let outcome = classifier.classify(&projection).await;
                        if let Some(answer) = outcome.answer() {
                            if answer.input_digest != digest
                                || answer.question_version != manifest.question_version
                                || (provider != "mock"
                                    && (answer.requested_model != manifest.model
                                        || answer.returned_model != manifest.model))
                            {
                                bail!("classifier output does not match evaluation manifest");
                            }
                            models.insert(answer.returned_model.clone());
                        }
                        (decision(&outcome), Some(outcome), Some(digest))
                    }
                };
                let result = EvaluationWindowResult {
                    scenario_id: scenario.id.clone(),
                    split: scenario.split,
                    window_id: snapshot.window_id.clone(),
                    revision: snapshot.revision,
                    expected,
                    method,
                    existing_rule_alert: existing,
                    series_decision,
                    detected: existing || series_decision == SeriesDecision::Suspicious,
                    projection_digest: digest,
                    classifier_elapsed_ms: assessment.as_ref().map(|_| {
                        request_started
                            .elapsed()
                            .as_millis()
                            .min(u128::from(u64::MAX)) as u64
                    }),
                    classifier: assessment,
                };
                let stats = metrics
                    .get_mut(&method)
                    .expect("all comparison methods exist");
                stats.total_windows += 1;
                if existing {
                    stats.existing_rule_alerts += 1;
                }
                if series_decision == SeriesDecision::Suspicious {
                    stats.additional_series_alerts += 1;
                }
                match series_decision {
                    SeriesDecision::Normal
                    | SeriesDecision::Suspicious
                    | SeriesDecision::NotApplied => stats.classified_windows += 1,
                    SeriesDecision::Unknown => stats.abstained_windows += 1,
                    SeriesDecision::Failed => stats.failed_windows += 1,
                    SeriesDecision::Skipped => stats.skipped_windows += 1,
                }
                match expected {
                    ExpectedLabel::Normal => {
                        stats.negative_windows += 1;
                        if result.detected {
                            stats.false_positives += 1;
                        } else {
                            stats.true_negatives += 1;
                        }
                    }
                    ExpectedLabel::Suspicious => {
                        stats.positive_windows += 1;
                        if result.detected {
                            stats.true_positives += 1;
                        } else {
                            stats.false_negatives += 1;
                        }
                    }
                    ExpectedLabel::Indeterminate => stats.indeterminate_windows += 1,
                }
                if scenario.routine_workload && series_decision == SeriesDecision::Suspicious {
                    stats.routine_false_alerts += 1;
                }
                if let Some(answer) = result
                    .classifier
                    .as_ref()
                    .and_then(ClassificationOutcome::answer)
                {
                    stats.input_tokens = stats.input_tokens.saturating_add(answer.input_tokens);
                    stats.output_tokens = stats.output_tokens.saturating_add(answer.output_tokens);
                }
                if let Some(duration) = result.classifier_elapsed_ms {
                    elapsed.entry(method).or_default().push(duration);
                }
                results.push(result);
            }
        }
    }
    for (method, stats) in &mut metrics {
        stats.precision = ratio(
            stats.true_positives,
            stats.true_positives + stats.false_positives,
        );
        stats.recall = ratio(stats.true_positives, stats.positive_windows);
        stats.f1 = ratio(
            2 * stats.true_positives,
            2 * stats.true_positives + stats.false_positives + stats.false_negatives,
        );
        stats.coverage = ratio(stats.classified_windows, stats.total_windows).unwrap_or(0.0);
        stats.abstention_rate = ratio(stats.abstained_windows, stats.total_windows).unwrap_or(0.0);
        stats.error_rate = ratio(stats.failed_windows, stats.total_windows).unwrap_or(0.0);
        stats.additional_false_alerts_per_routine_workload =
            ratio(stats.routine_false_alerts, stats.routine_workloads);
        let mut times = elapsed.remove(method).unwrap_or_default();
        times.sort_unstable();
        stats.p50_elapsed_ms = percentile(&times, 50);
        stats.p95_elapsed_ms = percentile(&times, 95);
    }
    Ok(EvaluationReport {
        schema_version: 1,
        provider: provider.into(),
        simulated: provider == "mock",
        manifest: manifest.clone(),
        returned_models: models.into_iter().collect(),
        methods: metrics,
        windows: results,
    })
}

fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}
fn percentile(values: &[u64], percent: usize) -> Option<u64> {
    if values.is_empty() {
        None
    } else {
        Some(values[(values.len() * percent).div_ceil(100).saturating_sub(1)])
    }
}
