//! Advisory classifiers. Only the closed telemetry projection may cross the provider boundary.
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use izanagi_telemetry::{FeatureProjection, TelemetryError, ThreatClass};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{ChildStdin, Command},
};

pub const PINNED_MODEL: &str = "jev-1.13.0";
pub const QUESTION_VERSION: u16 = 1;
const CLASSES: [&str; 3] = ["normal", "access_post_suspected", "unknown"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationErrorKind {
    Configuration,
    Spawn,
    Transport,
    Capability,
    InvalidResponse,
    ModelMismatch,
    Timeout,
    ResponseTooLarge,
    StderrTooLarge,
    Validation,
    Authentication,
    RateLimit,
    Network,
    Http,
    Panicked,
}

impl std::fmt::Display for ClassificationErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "behavior classifier {self:?}")
    }
}
impl std::error::Error for ClassificationErrorKind {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstentionReason {
    IncompleteObservation,
    UnknownChoice,
    LowConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Disabled,
    ExportDenied,
    QueueFull,
    Oversize,
    Stale,
    SessionEnded,
    MissingRecording,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationAnswer {
    pub class: ThreatClass,
    pub probabilities: BTreeMap<String, f64>,
    pub selected_probability: f64,
    pub confidence: f64,
    pub requested_model: String,
    pub returned_model: String,
    pub input_digest: String,
    pub question_version: u16,
    pub feature_version: u16,
    pub host_policy_version: u16,
    pub question_digest: String,
    pub mcp_commit: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClassificationOutcome {
    Classified {
        answer: ClassificationAnswer,
    },
    Abstained {
        reason: AbstentionReason,
        answer: Option<ClassificationAnswer>,
    },
    Failed {
        kind: ClassificationErrorKind,
    },
    Skipped {
        reason: SkipReason,
    },
}

impl ClassificationOutcome {
    pub fn answer(&self) -> Option<&ClassificationAnswer> {
        match self {
            Self::Classified { answer } => Some(answer),
            Self::Abstained { answer, .. } => answer.as_ref(),
            _ => None,
        }
    }
    pub fn class(&self) -> Option<ThreatClass> {
        match self {
            Self::Classified { answer } => Some(answer.class),
            _ => None,
        }
    }
    pub fn failed(kind: ClassificationErrorKind) -> Self {
        Self::Failed { kind }
    }
}

#[async_trait]
pub trait Classifier: Send + Sync {
    async fn classify(&self, projection: &FeatureProjection) -> ClassificationOutcome;
    fn configuration(&self) -> Option<&ClassifierConfig> {
        None
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JevProfile {
    Reliable,
    Interactive,
}
impl JevProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reliable => "reliable",
            Self::Interactive => "interactive",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub credential_env: String,
    pub model: String,
    /// Operator-declared server revision; None means unverified/unknown.
    pub mcp_commit: Option<String>,
    pub profile: JevProfile,
    pub deadline: Duration,
    pub min_confidence: f64,
    pub distribution_tolerance: f64,
    pub confidence_tolerance: f64,
    pub max_projection_bytes: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            command: PathBuf::from("jev-mcp"),
            args: vec![],
            credential_env: "TYPESAFE_API_KEY".into(),
            model: PINNED_MODEL.into(),
            mcp_commit: None,
            profile: JevProfile::Reliable,
            deadline: Duration::from_secs(65),
            min_confidence: 0.6,
            distribution_tolerance: 0.001,
            confidence_tolerance: 0.01,
            max_projection_bytes: 8192,
            max_request_bytes: 16384,
            max_response_bytes: 65536,
            max_stderr_bytes: 65536,
        }
    }
}

impl ClassifierConfig {
    pub fn validate(&self) -> Result<(), ClassificationErrorKind> {
        let variable_ok = self.credential_env.starts_with("TYPESAFE_")
            && self
                .credential_env
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_');
        if self.command.as_os_str().is_empty()
            || !variable_ok
            || self.model != PINNED_MODEL
            || self.mcp_commit.as_ref().is_some_and(|commit| {
                commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit())
            })
            || self.deadline.is_zero()
            || self.deadline > Duration::from_secs(65)
            || !unit(self.min_confidence)
            || !(0.0..=0.01).contains(&self.distribution_tolerance)
            || !(0.0..=0.05).contains(&self.confidence_tolerance)
            || self.max_projection_bytes == 0
            || self.max_projection_bytes > 8192
            || self.max_request_bytes == 0
            || self.max_request_bytes > 16384
            || self.max_response_bytes == 0
            || self.max_response_bytes > 65536
            || self.max_stderr_bytes == 0
            || self.max_stderr_bytes > 65536
        {
            return Err(ClassificationErrorKind::Configuration);
        }
        Ok(())
    }
}

pub struct JevMcpClassifier {
    config: ClassifierConfig,
}
impl JevMcpClassifier {
    pub fn new(config: ClassifierConfig) -> Result<Self, ClassificationErrorKind> {
        config.validate()?;
        Ok(Self { config })
    }
    pub fn config(&self) -> &ClassifierConfig {
        &self.config
    }

    async fn evaluate(
        &self,
        projection: &FeatureProjection,
    ) -> Result<Value, ClassificationErrorKind> {
        let mut child = self.spawn_process()?;
        let (mut transport, stderr) = McpExchange::take(&mut child, &self.config)?;
        let stderr_drain = drain_stderr(stderr, self.config.max_stderr_bytes);
        let exchange = transport.exchange(projection, &self.config);
        tokio::pin!(exchange, stderr_drain);
        let (mut result, stderr_finished) = tokio::select! {
            result = &mut exchange => (result, false),
            result = &mut stderr_drain => (match result { Ok(()) => exchange.await, Err(error) => Err(error) }, true),
        };
        // A provider has no authority to outlive the request or the sandbox session.
        let _ = child.start_kill();
        let _ = child.wait().await;
        if !stderr_finished {
            // Account for buffered stderr even if a successful stdout response won the select.
            // A descendant holding the pipe open cannot extend the request indefinitely.
            if let Ok(Err(error)) =
                tokio::time::timeout(Duration::from_millis(100), &mut stderr_drain).await
            {
                result = Err(error);
            }
        }
        result
    }

    fn spawn_process(&self) -> Result<tokio::process::Child, ClassificationErrorKind> {
        let mut command = Command::new(&self.config.command);
        command
            .args(&self.config.args)
            .env_clear()
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // No generic inheritance: sandbox secrets and unrelated provider credentials never reach MCP.
        for name in [
            "PATH",
            "LANG",
            "LC_ALL",
            "TZ",
            self.config.credential_env.as_str(),
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.spawn().map_err(|_| ClassificationErrorKind::Spawn)
    }
}

struct McpExchange {
    stdin: tokio::process::ChildStdin,
    reader: CappedLines<tokio::process::ChildStdout>,
    max_request_bytes: usize,
}
impl McpExchange {
    fn take(
        child: &mut tokio::process::Child,
        config: &ClassifierConfig,
    ) -> Result<(Self, tokio::process::ChildStderr), ClassificationErrorKind> {
        let stdin = child
            .stdin
            .take()
            .ok_or(ClassificationErrorKind::Transport)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ClassificationErrorKind::Transport)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(ClassificationErrorKind::Transport)?;
        let reader = CappedLines::new(stdout, config.max_response_bytes);
        Ok((
            Self {
                stdin,
                reader,
                max_request_bytes: config.max_request_bytes,
            },
            stderr,
        ))
    }

    async fn initialize(&mut self) -> Result<(), ClassificationErrorKind> {
        send(&mut self.stdin, &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"izanagi-behavior","version":"1"}}}), self.max_request_bytes).await?;
        let initialized = self.reader.response(1).await?;
        let protocol = initialized
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or(ClassificationErrorKind::Capability)?;
        if !matches!(protocol, "2024-11-05" | "2025-03-26" | "2025-06-18")
            || !initialized
                .pointer("/capabilities/tools")
                .is_some_and(Value::is_object)
        {
            return Err(ClassificationErrorKind::Capability);
        }
        send(
            &mut self.stdin,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            self.max_request_bytes,
        )
        .await?;
        Ok(())
    }

    async fn discover_choice(&mut self) -> Result<(), ClassificationErrorKind> {
        send(
            &mut self.stdin,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            self.max_request_bytes,
        )
        .await?;
        let listing = self.reader.response(2).await?;
        let tools = listing
            .get("tools")
            .and_then(Value::as_array)
            .ok_or(ClassificationErrorKind::Capability)?;
        let choice = tools
            .iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some("jev.choice"))
            .ok_or(ClassificationErrorKind::Capability)?;
        if !choice.get("inputSchema").is_some_and(Value::is_object) {
            return Err(ClassificationErrorKind::Capability);
        }
        Ok(())
    }

    async fn exchange(
        &mut self,
        projection: &FeatureProjection,
        config: &ClassifierConfig,
    ) -> Result<Value, ClassificationErrorKind> {
        self.initialize().await?;
        self.discover_choice().await?;
        send(
            &mut self.stdin,
            &choice_request(projection, config),
            self.max_request_bytes,
        )
        .await?;
        let result = self.reader.response(3).await?;
        extract_evaluation(result)
    }
}

// Never retain or echo stderr: it can contain features or credentials.
async fn drain_stderr(
    mut stderr: tokio::process::ChildStderr,
    stderr_limit: usize,
) -> Result<(), ClassificationErrorKind> {
    let mut total = 0usize;
    let mut buffer = [0u8; 4096];
    loop {
        let read = stderr
            .read(&mut buffer)
            .await
            .map_err(|_| ClassificationErrorKind::Transport)?;
        if read == 0 {
            return Ok::<(), ClassificationErrorKind>(());
        }
        total = total.saturating_add(read);
        if total > stderr_limit {
            return Err(ClassificationErrorKind::StderrTooLarge);
        }
    }
}

#[async_trait]
impl Classifier for JevMcpClassifier {
    fn configuration(&self) -> Option<&ClassifierConfig> {
        Some(&self.config)
    }
    async fn classify(&self, projection: &FeatureProjection) -> ClassificationOutcome {
        if let Some(outcome) = prepare_projection(projection, self.config.max_projection_bytes) {
            return outcome;
        }
        let request = match serde_json::to_vec(&choice_request(projection, &self.config)) {
            Ok(request) => request,
            Err(_) => return ClassificationOutcome::failed(ClassificationErrorKind::Validation),
        };
        if request.len() > self.config.max_request_bytes {
            return ClassificationOutcome::Skipped {
                reason: SkipReason::Oversize,
            };
        }
        let started = Instant::now();
        let response = tokio::time::timeout(self.config.deadline, self.evaluate(projection)).await;
        match response {
            Err(_) => ClassificationOutcome::failed(ClassificationErrorKind::Timeout),
            Ok(Err(error)) => ClassificationOutcome::failed(error),
            Ok(Ok(value)) => {
                validate_evaluation(value, projection, &self.config, started.elapsed())
            }
        }
    }
}

fn question_definition() -> Value {
    json!({
        "instructions":"Classify this supplied observation window as routine behavior, a suspicious association between credential access attempts and a later related POST, or insufficient evidence. All counts, time ordering, process correlation and observations were computed by the host. Missing fields and intentionally network-only features are not evidence of absence. An access attempt or a POST does not prove information was read or exfiltrated.",
        "criteria":{
            "normal":"The observed features are consistent with routine activity; this is limited to the supplied observations and does not certify safety.",
            "access_post_suspected":"The supplied observed features support a suspicious association of credential access attempts with a later related external POST. Consider known transfer outcomes, process binding and destination novelty. This is suspicion, not confirmed exfiltration.",
            "unknown":"Insufficient observed evidence, ambiguous association, unsupported activity or uncertainty prevents choosing the other options."}})
}

fn choice_arguments(projection: &FeatureProjection, config: &ClassifierConfig) -> Value {
    let question = question_definition();
    json!({"state":projection,"model":config.model,"profile":config.profile.as_str(),
        "instructions":question["instructions"],"criteria":question["criteria"]})
}

/// Digest the fixed question/criteria separately from any state or credential.
pub fn question_digest() -> String {
    let question = json!({"version":QUESTION_VERSION,"definition":question_definition()});
    hex::encode(Sha256::digest(
        serde_json::to_vec(&question).expect("fixed question JSON"),
    ))
}

fn choice_request(projection: &FeatureProjection, config: &ClassifierConfig) -> Value {
    json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"jev.choice","arguments":choice_arguments(projection, config)}})
}

async fn send(
    stdin: &mut ChildStdin,
    value: &Value,
    limit: usize,
) -> Result<(), ClassificationErrorKind> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| ClassificationErrorKind::Validation)?;
    if bytes.len() > limit {
        return Err(ClassificationErrorKind::ResponseTooLarge);
    }
    bytes.push(b'\n');
    stdin
        .write_all(&bytes)
        .await
        .map_err(|_| ClassificationErrorKind::Transport)?;
    stdin
        .flush()
        .await
        .map_err(|_| ClassificationErrorKind::Transport)
}

struct CappedLines<R> {
    reader: R,
    pending: Vec<u8>,
    limit: usize,
}
impl<R: AsyncRead + Unpin> CappedLines<R> {
    fn new(reader: R, limit: usize) -> Self {
        Self {
            reader,
            pending: Vec::new(),
            limit,
        }
    }
    async fn line(&mut self) -> Result<Value, ClassificationErrorKind> {
        loop {
            if let Some(index) = self.pending.iter().position(|c| *c == b'\n') {
                if index > self.limit {
                    return Err(ClassificationErrorKind::ResponseTooLarge);
                }
                let bytes: Vec<_> = self.pending.drain(..=index).collect();
                return serde_json::from_slice(&bytes)
                    .map_err(|_| ClassificationErrorKind::InvalidResponse);
            }
            if self.pending.len() > self.limit {
                return Err(ClassificationErrorKind::ResponseTooLarge);
            }
            let mut buffer = [0u8; 4096];
            let count = self
                .reader
                .read(&mut buffer)
                .await
                .map_err(|_| ClassificationErrorKind::Transport)?;
            if count == 0 {
                return Err(ClassificationErrorKind::Transport);
            }
            self.pending.extend_from_slice(&buffer[..count]);
        }
    }
    async fn response(&mut self, id: u64) -> Result<Value, ClassificationErrorKind> {
        for _ in 0..32 {
            let value = self.line().await?;
            if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return Err(ClassificationErrorKind::InvalidResponse);
            }
            if value.get("id").is_none() && value.get("method").is_some() {
                continue;
            }
            if value.get("id").and_then(Value::as_u64) != Some(id) || value.get("error").is_some() {
                return Err(ClassificationErrorKind::InvalidResponse);
            }
            return value
                .get("result")
                .cloned()
                .ok_or(ClassificationErrorKind::InvalidResponse);
        }
        Err(ClassificationErrorKind::InvalidResponse)
    }
}

fn extract_evaluation(result: Value) -> Result<Value, ClassificationErrorKind> {
    if result.get("isError").is_some_and(|flag| !flag.is_boolean()) {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        let kind = match result
            .pointer("/structuredContent/error/kind")
            .and_then(Value::as_str)
        {
            Some("validation") => ClassificationErrorKind::Validation,
            Some("authentication") => ClassificationErrorKind::Authentication,
            Some("rate_limit") => ClassificationErrorKind::RateLimit,
            Some("timeout") => ClassificationErrorKind::Timeout,
            Some("network") => ClassificationErrorKind::Network,
            Some("http") => ClassificationErrorKind::Http,
            _ => ClassificationErrorKind::InvalidResponse,
        };
        return Err(kind);
    }
    if let Some(value) = result.get("structuredContent") {
        return Ok(value.clone());
    }
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .ok_or(ClassificationErrorKind::InvalidResponse)?;
    if content.len() != 1 || content[0].get("type").and_then(Value::as_str) != Some("text") {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    serde_json::from_str(
        content[0]
            .get("text")
            .and_then(Value::as_str)
            .ok_or(ClassificationErrorKind::InvalidResponse)?,
    )
    .map_err(|_| ClassificationErrorKind::InvalidResponse)
}

fn unit(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn prepare_projection(
    projection: &FeatureProjection,
    max_bytes: usize,
) -> Option<ClassificationOutcome> {
    let encoded = match projection.to_json() {
        Ok(encoded) => encoded,
        Err(TelemetryError::Oversize) => {
            return Some(ClassificationOutcome::Skipped {
                reason: SkipReason::Oversize,
            });
        }
        Err(_) => {
            return Some(ClassificationOutcome::failed(
                ClassificationErrorKind::Validation,
            ));
        }
    };
    if encoded.len() > max_bytes {
        return Some(ClassificationOutcome::Skipped {
            reason: SkipReason::Oversize,
        });
    }
    if !projection.eligible() {
        return Some(ClassificationOutcome::Abstained {
            reason: AbstentionReason::IncompleteObservation,
            answer: None,
        });
    }
    None
}

pub fn validate_evaluation(
    value: Value,
    projection: &FeatureProjection,
    config: &ClassifierConfig,
    elapsed: Duration,
) -> ClassificationOutcome {
    if let Err(kind) = config.validate() {
        return ClassificationOutcome::failed(kind);
    }
    let answer = match decode_evaluation(&value, projection, config, elapsed) {
        Ok(answer) => answer,
        Err(kind) => return ClassificationOutcome::failed(kind),
    };
    if answer.class == ThreatClass::Unknown {
        ClassificationOutcome::Abstained {
            reason: AbstentionReason::UnknownChoice,
            answer: Some(answer),
        }
    } else if answer.confidence < config.min_confidence {
        ClassificationOutcome::Abstained {
            reason: AbstentionReason::LowConfidence,
            answer: Some(answer),
        }
    } else {
        ClassificationOutcome::Classified { answer }
    }
}

fn decode_evaluation(
    value: &Value,
    projection: &FeatureProjection,
    config: &ClassifierConfig,
    elapsed: Duration,
) -> Result<ClassificationAnswer, ClassificationErrorKind> {
    let model = response_model(value, config)?;
    let (choice, class, answer) = response_choice(value)?;
    let confidence = response_confidence(answer, choice, config)?;
    let Some(input_tokens) = value.pointer("/usage/input_tokens").and_then(Value::as_u64) else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    let Some(output_tokens) = value
        .pointer("/usage/output_tokens")
        .and_then(Value::as_u64)
    else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    let Ok(input_digest) = projection.digest() else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    Ok(ClassificationAnswer {
        class,
        probabilities: confidence.probabilities,
        selected_probability: confidence.selected_probability,
        confidence: confidence.confidence,
        requested_model: config.model.clone(),
        returned_model: model.into(),
        input_digest,
        question_version: QUESTION_VERSION,
        feature_version: projection.feature_version,
        host_policy_version: 1,
        question_digest: question_digest(),
        mcp_commit: config.mcp_commit.clone(),
        input_tokens,
        output_tokens,
        elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
    })
}

fn response_model<'a>(
    value: &'a Value,
    config: &ClassifierConfig,
) -> Result<&'a str, ClassificationErrorKind> {
    let Some(model) = value.get("model").and_then(Value::as_str) else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    if model != config.model {
        return Err(ClassificationErrorKind::ModelMismatch);
    }
    Ok(model)
}

fn response_choice(value: &Value) -> Result<(&str, ThreatClass, &Value), ClassificationErrorKind> {
    let Some(answers) = value.get("answers").and_then(Value::as_object) else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    if answers.len() != 1 {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    let Some(answer) = answers.get("result") else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    if answer.get("type").and_then(Value::as_str) != Some("choice") {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    let Some(choice) = answer.get("choice").and_then(Value::as_str) else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    let class = match choice {
        "normal" => ThreatClass::Normal,
        "access_post_suspected" => ThreatClass::AccessPostSuspected,
        "unknown" => ThreatClass::Unknown,
        _ => return Err(ClassificationErrorKind::InvalidResponse),
    };
    Ok((choice, class, answer))
}

struct ResponseConfidence {
    probabilities: BTreeMap<String, f64>,
    selected_probability: f64,
    confidence: f64,
}

fn response_confidence(
    answer: &Value,
    choice: &str,
    config: &ClassifierConfig,
) -> Result<ResponseConfidence, ClassificationErrorKind> {
    let Some(distribution) = answer.get("probabilities").and_then(Value::as_object) else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    if distribution.len() != CLASSES.len() || CLASSES.iter().any(|c| !distribution.contains_key(*c))
    {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    let mut probabilities = BTreeMap::new();
    for (name, probability) in distribution {
        let Some(probability) = probability.as_f64() else {
            return Err(ClassificationErrorKind::InvalidResponse);
        };
        if !unit(probability) {
            return Err(ClassificationErrorKind::InvalidResponse);
        }
        probabilities.insert(name.clone(), probability);
    }
    let sum: f64 = probabilities.values().sum();
    if (sum - 1.0).abs() > config.distribution_tolerance {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    let selected_probability = probabilities[choice];
    if probabilities
        .values()
        .any(|p| *p > selected_probability + f64::EPSILON * 8.0)
    {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    let Some(confidence) = answer.get("confidence").and_then(Value::as_f64) else {
        return Err(ClassificationErrorKind::InvalidResponse);
    };
    let expected_confidence = (selected_probability - 1.0 / 3.0) / (1.0 - 1.0 / 3.0);
    if !unit(confidence) || (expected_confidence - confidence).abs() > config.confidence_tolerance {
        return Err(ClassificationErrorKind::InvalidResponse);
    }
    Ok(ResponseConfidence {
        probabilities,
        selected_probability,
        confidence,
    })
}

/// Recorded responses are keyed by a closed projection digest, never a raw log or secret.
pub struct RecordedClassifier {
    pub responses: BTreeMap<String, Value>,
    pub config: ClassifierConfig,
}
#[async_trait]
impl Classifier for RecordedClassifier {
    fn configuration(&self) -> Option<&ClassifierConfig> {
        Some(&self.config)
    }
    async fn classify(&self, projection: &FeatureProjection) -> ClassificationOutcome {
        if let Err(kind) = self.config.validate() {
            return ClassificationOutcome::failed(kind);
        }
        if let Some(outcome) = prepare_projection(projection, self.config.max_projection_bytes) {
            return outcome;
        }
        let Ok(digest) = projection.digest() else {
            return ClassificationOutcome::failed(ClassificationErrorKind::Validation);
        };
        match self.responses.get(&digest) {
            Some(response) => {
                validate_evaluation(response.clone(), projection, &self.config, Duration::ZERO)
            }
            None => ClassificationOutcome::Skipped {
                reason: SkipReason::MissingRecording,
            },
        }
    }
}

/// Deterministic testing classifier. Its output is explicitly not a Jev quality measurement.
#[derive(Default)]
pub struct MockClassifier;
#[async_trait]
impl Classifier for MockClassifier {
    async fn classify(&self, projection: &FeatureProjection) -> ClassificationOutcome {
        if let Some(outcome) = prepare_projection(projection, 8192) {
            return outcome;
        }
        let choice = if projection.credential_access_attempts.is_some_and(|n| n > 0)
            && projection.access_to_post_ns.is_some()
        {
            "access_post_suspected"
        } else if projection.credential_access_attempts == Some(0) {
            "normal"
        } else {
            "unknown"
        };
        let probabilities: BTreeMap<_, _> = CLASSES
            .iter()
            .map(|name| ((*name).to_string(), if *name == choice { 1.0 } else { 0.0 }))
            .collect();
        let config = ClassifierConfig::default();
        let mut outcome = validate_evaluation(
            json!({"model":PINNED_MODEL,"answers":{"result":{"type":"choice","choice":choice,"probabilities":probabilities,"confidence":1.0}},"usage":{"input_tokens":0,"output_tokens":0}}),
            projection,
            &config,
            Duration::ZERO,
        );
        match &mut outcome {
            ClassificationOutcome::Classified { answer }
            | ClassificationOutcome::Abstained {
                answer: Some(answer),
                ..
            } => {
                answer.requested_model = "mock-v1".into();
                answer.returned_model = "mock-v1".into();
            }
            _ => {}
        }
        outcome
    }
}
