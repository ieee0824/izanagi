use izanagi_telemetry::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "izanagi-telemetry-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn event(seq: u64) -> TelemetryEnvelope {
    let mut e = TelemetryEnvelope {
        schema_version: SCHEMA_VERSION,
        session_id: "session".into(),
        guest_boot_id: "boot".into(),
        source_instance_id: "collector".into(),
        source_seq: seq,
        event_id: String::new(),
        observed_monotonic_ns: seq,
        clock_domain: "guest-monotonic".into(),
        clock_uncertainty_ns: 0,
        host_received_at_unix_ns: None,
        process: None,
        tid: None,
        quality: ObservationQuality::default(),
        payload: TelemetryPayload::FileAccessAttempt {
            attempt_id: format!("attempt-{seq}"),
            role: FileRole::Credential,
            path: Some("/credentials/CANARY-api-secret".into()),
        },
    };
    e.event_id = e.expected_event_id();
    e
}

#[test]
fn audit_scrubs_canary_and_reopens_only_same_session() {
    let dir = Temp::new();
    let mut store = AuditStore::new(&dir.0, StoreConfig::default()).unwrap();
    store.append_event(&event(1), 100).unwrap();
    let records = store.read_records().unwrap();
    let text = serde_json::to_string(&records).unwrap();
    assert!(!text.contains("CANARY"));
    drop(store);
    let mut store = AuditStore::new(&dir.0, StoreConfig::default()).unwrap();
    let mut other = event(2);
    other.session_id = "other-session".into();
    other.event_id = other.expected_event_id();
    assert_eq!(
        store.append_event(&other, 101),
        Err(TelemetryError::InvalidEvent)
    );
    assert_eq!(
        store.evidence_availability(&[event(1).event_id]).unwrap(),
        EvidenceAvailability::Available
    );
}

#[test]
fn capacity_rotation_reports_gap_and_expired_evidence() {
    let dir = Temp::new();
    let config = StoreConfig {
        max_session_bytes: 4096,
        max_segment_bytes: 2048,
        max_record_bytes: 2048,
        retention_secs: 20,
    };
    let mut store = AuditStore::new(&dir.0, config).unwrap();
    let mut gaps = 0;
    for seq in 1..20 {
        gaps += usize::from(store.append_event(&event(seq), seq).unwrap().storage_gap);
    }
    assert!(gaps > 0);
    let total: u64 = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum();
    assert!(total <= 4096);
    assert_eq!(
        store.evidence_availability(&[event(1).event_id]).unwrap(),
        EvidenceAvailability::EvidenceExpired
    );
    assert_eq!(
        store.evidence_availability(&[event(19).event_id]).unwrap(),
        EvidenceAvailability::Available
    );
    assert!(
        store
            .read_records()
            .unwrap()
            .iter()
            .any(|record| record.storage_gap)
    );
    assert!(store.append_event(&event(20), 100).unwrap().storage_gap);
    assert_eq!(
        store.evidence_availability(&[event(19).event_id]).unwrap(),
        EvidenceAvailability::EvidenceExpired
    );
}

#[test]
fn malformed_oversize_and_secret_record_cannot_be_replayed() {
    let dir = Temp::new();
    fs::write(dir.0.join("audit-0000000000000001.jsonl"), b"{broken\n").unwrap();
    assert!(matches!(
        AuditStore::new(&dir.0, StoreConfig::default()),
        Err(TelemetryError::MalformedRecord)
    ));
    let record = AuditRecord {
        stored_at_unix_secs: 1,
        storage_gap: false,
        payload: AuditPayload::Event(event(1)),
    };
    let mut bytes = serde_json::to_vec(&record).unwrap();
    bytes.push(b'\n');
    fs::write(dir.0.join("audit-0000000000000001.jsonl"), bytes).unwrap();
    assert!(matches!(
        AuditStore::new(&dir.0, StoreConfig::default()),
        Err(TelemetryError::MalformedRecord)
    ));
}

#[test]
fn identity_injection_never_gets_written() {
    let dir = Temp::new();
    let mut store = AuditStore::new(&dir.0, StoreConfig::default()).unwrap();
    let mut e = event(1);
    e.source_instance_id = "../../CANARY\nAuthorization".into();
    e.event_id = e.expected_event_id();
    let error = store.append_event(&e, 1).unwrap_err();
    assert_eq!(error, TelemetryError::InvalidEvent);
    assert!(!error.to_string().contains("CANARY"));
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn classification_audit_rejects_provider_text_and_invalid_distributions() {
    let dir = Temp::new();
    let mut store = AuditStore::new(&dir.0, StoreConfig::default()).unwrap();
    let mut record = ClassificationAudit {
        session_id: "session".into(),
        window_id: "session:http:1".into(),
        revision: 0,
        projection_digest: "0".repeat(64),
        feature_version: FEATURE_VERSION,
        question_version: 1,
        host_policy_version: 1,
        question_digest: "0".repeat(64),
        mcp_commit: None,
        input_tokens: Some(10),
        output_tokens: Some(3),
        status: ClassificationStatus::Classified,
        class: Some(ThreatClass::Normal),
        reason: None,
        requested_model: "jev-1.13.0".into(),
        returned_model: Some("jev-1.13.0".into()),
        probabilities: Some([1.0, 0.0, 0.0]),
        confidence: Some(1.0),
        evidence_event_ids: vec![],
        queued_ns: Some(10),
        elapsed_ns: Some(100),
    };
    store.append_classification(&record, 1).unwrap();
    assert!(matches!(
        store.read_records().unwrap()[0].payload,
        AuditPayload::Classification(_)
    ));
    record.returned_model = Some("CANARY-api-secret".into());
    assert_eq!(
        store.append_classification(&record, 2),
        Err(TelemetryError::InvalidEvent)
    );
    record.returned_model = Some("jev-1.13.0".into());
    record.probabilities = Some([f64::NAN, 0.0, 1.0]);
    assert_eq!(
        store.append_classification(&record, 2),
        Err(TelemetryError::InvalidEvent)
    );
    record.probabilities = Some([0.1, 0.1, 0.1]);
    assert_eq!(
        store.append_classification(&record, 2),
        Err(TelemetryError::InvalidEvent)
    );
    assert!(
        !serde_json::to_string(&store.read_records().unwrap())
            .unwrap()
            .contains("CANARY")
    );
}

#[cfg(unix)]
#[test]
fn permissions_and_symlink_protection() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Temp::new();
    let mut store = AuditStore::new(&dir.0, StoreConfig::default()).unwrap();
    store.append_event(&event(1), 1).unwrap();
    assert_eq!(
        fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let file = dir.0.join("audit-0000000000000001.jsonl");
    assert_eq!(
        fs::metadata(file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let victim = Temp::new();
    let link = dir.0.join("audit-0000000000000002.jsonl");
    symlink(victim.0.join("victim"), link).unwrap();
    assert!(store.append_event(&event(2), 2).is_err());
    assert!(!victim.0.join("victim").exists());
    let linked_dir = dir.0.join("linked-dir");
    symlink(&victim.0, &linked_dir).unwrap();
    assert!(AuditStore::new(linked_dir, StoreConfig::default()).is_err());
}
