//! Offline behavior commands do not start a sandbox or require its authentication secrets.
use crate::behavior_classifier::{
    ClassificationOutcome, Classifier, ClassifierConfig, JevMcpClassifier, JevProfile,
    MockClassifier, PINNED_MODEL, RecordedClassifier,
};
use crate::behavior_evaluation::{
    EvaluationManifest, evaluate_manifest, load_manifest, replay_file,
};
use anyhow::{Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use izanagi_telemetry::{
    AuditPayload, AuditRecord, AuditStore, EvidenceAvailability, FeatureMode, FeatureSnapshot,
    StoreConfig, ThreatClass, deterministic_rule,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Provider {
    Mock,
    Recorded,
    JevMcp,
}
impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Recorded => "recorded",
            Self::JevMcp => "jev-mcp",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct ProviderOptions {
    /// mock は通信なし。jev-mcp は TypeSafe API へ特徴量を送信します。
    #[arg(long, alias = "provider", value_enum, default_value = "mock")]
    pub classifier: Provider,
    /// Jev への外部送信を明示的に許可
    #[arg(long)]
    pub allow_export: bool,
    /// digest → 検証対象 API 応答の JSON object
    #[arg(long)]
    pub recorded_responses: Option<PathBuf>,
    #[arg(long, default_value = "jev-mcp")]
    pub mcp_command: PathBuf,
    /// MCP 子プロセスの固定引数。shell 展開はしません。
    #[arg(long, allow_hyphen_values = true)]
    pub mcp_arg: Vec<String>,
    #[arg(long, default_value = PINNED_MODEL)]
    pub model: String,
    /// Operator-declared Jev MCP git revision, if verified separately.
    #[arg(long)]
    pub mcp_commit: Option<String>,
    #[arg(long, default_value = "reliable", value_parser = ["reliable", "interactive"])]
    pub profile: String,
    #[arg(long, default_value = "TYPESAFE_API_KEY")]
    pub credential_env: String,
}

#[derive(Debug, Subcommand)]
pub enum BehaviorAction {
    /// immutable JSONL の記録イベント時刻で相関・分類を再生
    Replay {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        provider: ProviderOptions,
    },
    /// 保存した根拠・分類・観測欠損を表示
    Show {
        #[arg(long)]
        session: String,
        /// 対象 session の audit ディレクトリ (未指定時はこの project のログ)
        #[arg(long, alias = "audit-dir")]
        directory: Option<PathBuf>,
    },
    /// 指定 session の行動監査レコードを削除（通常 syscall ログは対象外）
    Clear {
        #[arg(long)]
        session: String,
        #[arg(long, alias = "audit-dir")]
        directory: Option<PathBuf>,
    },
    /// 固定 manifest と独立ラベルで A/B/C/D を比較
    Evaluate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        provider: ProviderOptions,
    },
}

#[derive(Debug, Serialize)]
pub struct ReplayAssessment {
    pub snapshot: FeatureSnapshot,
    pub projection_digest: String,
    pub deterministic_class: ThreatClass,
    pub classifier: ClassificationOutcome,
}

#[derive(Serialize)]
struct ShownRecord<'a> {
    record: &'a AuditRecord,
    evidence_availability: Option<EvidenceAvailability>,
}

/// Runtime config is intentionally not loaded: these commands need no VM or shared secret.
pub async fn run(action: BehaviorAction, default_audit_root: &Path) -> Result<u8> {
    match action {
        BehaviorAction::Replay {
            input,
            output,
            provider,
        } => {
            let classifier = build_classifier(&provider, None)?;
            let snapshots = replay_file(&input)?;
            let mut assessments = Vec::new();
            for snapshot in snapshots {
                let projection = snapshot.projection(FeatureMode::Correlated);
                let projection_digest = projection.digest()?;
                let outcome = classifier.classify(&projection).await;
                assessments.push(ReplayAssessment {
                    deterministic_class: deterministic_rule(&snapshot),
                    snapshot,
                    projection_digest,
                    classifier: outcome,
                });
            }
            let mut bytes = Vec::new();
            for assessment in assessments {
                serde_json::to_writer(&mut bytes, &assessment)?;
                bytes.push(b'\n');
            }
            write_output(output.as_deref(), &bytes)?;
        }
        BehaviorAction::Evaluate {
            manifest: path,
            output,
            provider,
        } => {
            let manifest = load_manifest(&path)?;
            let classifier = build_classifier(&provider, Some(&manifest))?;
            let base = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let report = evaluate_manifest(
                &manifest,
                base,
                classifier.as_ref(),
                provider.classifier.name(),
            )
            .await?;
            let mut bytes = serde_json::to_vec_pretty(&report)?;
            bytes.push(b'\n');
            write_output(output.as_deref(), &bytes)?;
        }
        BehaviorAction::Clear { session, directory } => {
            validate_session(&session)?;
            let directory = directory.unwrap_or_else(|| default_audit_root.join(&session));
            if !directory.is_dir() {
                bail!("behavior session audit directory does not exist");
            }
            let mut store = AuditStore::new(directory, StoreConfig::default())?;
            for record in store.read_records()? {
                let id = match record.payload {
                    AuditPayload::Event(e) => e.session_id,
                    AuditPayload::Assessment { snapshot, .. } => snapshot.session_id,
                    AuditPayload::Classification(c) => c.session_id,
                };
                if id != session {
                    bail!("audit directory does not match requested session");
                }
            }
            store.clear()?;
        }
        BehaviorAction::Show { session, directory } => {
            if session.is_empty()
                || session.len() > 160
                || !session
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
            {
                bail!("invalid behavior session ID");
            }
            let directory = directory.unwrap_or_else(|| default_audit_root.join(&session));
            if !directory.is_dir() {
                bail!("behavior session audit directory does not exist");
            }
            let mut store = AuditStore::new(directory, StoreConfig::default())?;
            // Verify the requested identity before applying retention to the
            // selected directory, including when every record is already old.
            for record in store.read_records()? {
                let id = match record.payload {
                    AuditPayload::Event(e) => e.session_id,
                    AuditPayload::Assessment { snapshot, .. } => snapshot.session_id,
                    AuditPayload::Classification(c) => c.session_id,
                };
                if id != session {
                    bail!("audit directory does not match requested session");
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            store.expire(now)?;
            let records = store.read_records()?;
            let mut events = BTreeSet::new();
            for record in &records {
                let id = match &record.payload {
                    AuditPayload::Event(event) => {
                        events.insert(event.event_id.clone());
                        &event.session_id
                    }
                    AuditPayload::Assessment { snapshot, .. } => &snapshot.session_id,
                    AuditPayload::Classification(classification) => &classification.session_id,
                };
                if id != &session {
                    bail!("audit directory does not match requested session");
                }
            }
            let mut stdout = std::io::stdout().lock();
            for record in &records {
                let refs = match &record.payload {
                    AuditPayload::Assessment { snapshot, .. } => Some(&snapshot.evidence_event_ids),
                    AuditPayload::Classification(classification) => {
                        Some(&classification.evidence_event_ids)
                    }
                    _ => None,
                };
                let evidence_availability = refs.map(|refs| {
                    if refs.iter().all(|id| events.contains(id)) {
                        EvidenceAvailability::Available
                    } else {
                        EvidenceAvailability::EvidenceExpired
                    }
                });
                serde_json::to_writer(
                    &mut stdout,
                    &ShownRecord {
                        record,
                        evidence_availability,
                    },
                )?;
                stdout.write_all(b"\n")?;
            }
        }
    }
    Ok(0)
}

fn validate_session(session: &str) -> Result<()> {
    if session.is_empty()
        || session.len() > 160
        || !session
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
    {
        bail!("invalid behavior session ID");
    }
    Ok(())
}

fn build_classifier(
    options: &ProviderOptions,
    manifest: Option<&EvaluationManifest>,
) -> Result<Box<dyn Classifier>> {
    if matches!(options.classifier, Provider::JevMcp) && !options.allow_export {
        bail!("jev-mcp sends sanitized features to TypeSafe API; --allow-export is required");
    }
    if options.model != PINNED_MODEL {
        bail!("behavior evaluation requires pinned model jev-1.13.0");
    }
    let mut config = ClassifierConfig {
        command: options.mcp_command.clone(),
        args: options.mcp_arg.clone(),
        credential_env: options.credential_env.clone(),
        model: options.model.clone(),
        mcp_commit: options.mcp_commit.clone(),
        profile: if options.profile == "reliable" {
            JevProfile::Reliable
        } else {
            JevProfile::Interactive
        },
        ..Default::default()
    };
    if let Some(manifest) = manifest {
        if options.mcp_commit.is_some() && options.mcp_commit != manifest.mcp_commit {
            bail!("MCP revision does not match evaluation manifest");
        }
        config.mcp_commit = manifest.mcp_commit.clone();
        config.min_confidence = manifest.min_confidence;
        config.distribution_tolerance = manifest.distribution_tolerance;
        config.confidence_tolerance = manifest.confidence_tolerance;
    }
    config.validate()?;
    match options.classifier {
        Provider::Mock => {
            if options.recorded_responses.is_some() {
                bail!("recorded responses require recorded classifier");
            }
            Ok(Box::new(MockClassifier))
        }
        Provider::Recorded => {
            let path = options.recorded_responses.as_deref().ok_or_else(|| {
                anyhow::anyhow!("recorded classifier requires --recorded-responses")
            })?;
            let file = std::fs::File::open(path)
                .map_err(|_| anyhow::anyhow!("cannot read recorded classifier responses"))?;
            let mut bytes = Vec::new();
            file.take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow::anyhow!("cannot read recorded classifier responses"))?;
            if bytes.len() > 8 * 1024 * 1024 {
                bail!("recorded classifier response file size limit exceeded");
            }
            let responses: BTreeMap<String, Value> = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid recorded classifier response JSON"))?;
            if responses.len() > 4096
                || responses
                    .keys()
                    .any(|key| key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                bail!("invalid recorded classifier projection digests");
            }
            Ok(Box::new(RecordedClassifier { responses, config }))
        }
        Provider::JevMcp => {
            if options.recorded_responses.is_some() {
                bail!("recorded responses require recorded classifier");
            }
            Ok(Box::new(JevMcpClassifier::new(config)?))
        }
    }
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = path {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(path)
            .map_err(|_| anyhow::anyhow!("cannot create behavior output; choose a new file"))?;
        file.write_all(bytes)
            .map_err(|_| anyhow::anyhow!("behavior output I/O failed"))?;
    } else {
        std::io::stdout()
            .lock()
            .write_all(bytes)
            .map_err(|_| anyhow::anyhow!("behavior output I/O failed"))?;
    }
    Ok(())
}
