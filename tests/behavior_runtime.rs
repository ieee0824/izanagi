use async_trait::async_trait;
use izanagi::{
    behavior::BehaviorRuntime, behavior_classifier::*, behavior_config::BehaviorSection,
};
use izanagi_telemetry::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "izanagi-behavior-runtime-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config() -> BehaviorSection {
    BehaviorSection {
        enabled: true,
        ..Default::default()
    }
}
fn fixture(session: &str) -> Vec<TelemetryEnvelope> {
    include_str!("fixtures/behavior/access-post.jsonl")
        .replace("fixture-access-post", session)
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
async fn settle(runtime: &BehaviorRuntime) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let stats = runtime.stats();
            if stats.classified + stats.abstained + stats.skipped + stats.failed > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn live_projection_is_sanitized_and_has_typed_audit_evidence() {
    let dir = Temp::new();
    let mut runtime = BehaviorRuntime::spawn(&config(), vec![], dir.path().into()).unwrap();
    for e in fixture(&runtime.start_config().session_id) {
        runtime.sender().send(e).await.unwrap();
    }
    settle(&runtime).await;
    assert_eq!(runtime.stats().classified, 1);
    runtime.shutdown().await;
    let store = AuditStore::new(runtime.session_dir(), Default::default()).unwrap();
    let records = store.read_records().unwrap();
    let rendered = serde_json::to_string(&records).unwrap();
    assert!(!rendered.contains("DO_NOT_LOG_CANARY"));
    assert_eq!(runtime.stats().storage_failed, 0);
    assert!(records.iter().any(|r|matches!(&r.payload,AuditPayload::Classification(a) if a.class==Some(ThreatClass::AccessPostSuspected) && a.requested_model=="mock-v1")));
    for record in records {
        if let AuditPayload::Assessment { snapshot, .. } = record.payload {
            assert_eq!(
                store
                    .evidence_availability(&snapshot.evidence_event_ids)
                    .unwrap(),
                EvidenceAvailability::Available
            );
        }
    }
}
#[tokio::test]
async fn connector_only_and_source_loss_abstain_without_inference() {
    for source_loss in [false, true] {
        let dir = Temp::new();
        let calls = Arc::new(AtomicU64::new(0));
        let mut runtime = BehaviorRuntime::spawn_with_classifier(
            &config(),
            vec![],
            dir.path().into(),
            Arc::new(Counted(calls.clone())),
        )
        .unwrap();
        for mut e in fixture(&runtime.start_config().session_id) {
            if source_loss {
                e.quality.issues.push(QualityIssue::EventLoss);
            } else if let TelemetryPayload::SocketConnect { binding, .. } = &mut e.payload {
                *binding = ProcessBinding::Connector;
            }
            runtime.sender().send(e).await.unwrap();
        }
        settle(&runtime).await;
        assert_eq!(runtime.stats().abstained, 1);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        runtime.shutdown().await;
    }
}
struct Counted(Arc<AtomicU64>);
#[async_trait]
impl Classifier for Counted {
    async fn classify(&self, p: &FeatureProjection) -> ClassificationOutcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        MockClassifier.classify(p).await
    }
}
#[tokio::test]
async fn real_provider_requires_export_opt_in_and_invalid_session_is_reported() {
    let dir = Temp::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut cfg = config();
    cfg.classifier.provider = "jev-mcp".into();
    let mut runtime = BehaviorRuntime::spawn_with_classifier(
        &cfg,
        vec![],
        dir.path().into(),
        Arc::new(Counted(calls.clone())),
    )
    .unwrap();
    runtime
        .sender()
        .send(fixture("wrong-session").remove(0))
        .await
        .unwrap();
    for e in fixture(&runtime.start_config().session_id) {
        runtime.sender().send(e).await.unwrap();
    }
    settle(&runtime).await;
    assert_eq!(runtime.stats().invalid, 1);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    // Invalid source data poisons coverage, rather than being silently ignored.
    assert_eq!(runtime.stats().abstained, 1);
    runtime.shutdown().await;
    let dir2 = Temp::new();
    let mut runtime = BehaviorRuntime::spawn_with_classifier(
        &cfg,
        vec![],
        dir2.path().into(),
        Arc::new(Counted(calls.clone())),
    )
    .unwrap();
    for e in fixture(&runtime.start_config().session_id) {
        runtime.sender().send(e).await.unwrap();
    }
    settle(&runtime).await;
    assert_eq!(runtime.stats().skipped, 1);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    runtime.shutdown().await;
}
struct Slow {
    calls: Arc<AtomicU64>,
}
#[async_trait]
impl Classifier for Slow {
    async fn classify(&self, _: &FeatureProjection) -> ClassificationOutcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        std::future::pending().await
    }
}
#[tokio::test]
async fn slow_classifier_does_not_stop_ingestion_and_shutdown_cancels_it() {
    let dir = Temp::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut runtime = BehaviorRuntime::spawn_with_classifier(
        &config(),
        vec![],
        dir.path().into(),
        Arc::new(Slow {
            calls: calls.clone(),
        }),
    )
    .unwrap();
    let events = fixture(&runtime.start_config().session_id);
    for e in events.clone() {
        runtime.sender().send(e).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while calls.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let count = runtime.stats().events;
    let mut e = events[0].clone();
    e.source_seq = 100;
    e.event_id = e.expected_event_id();
    e.observed_monotonic_ns += 10_000_000_000;
    runtime.sender().send(e).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.stats().events == count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), runtime.shutdown())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}
