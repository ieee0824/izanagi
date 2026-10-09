use izanagi::behavior_classifier::PINNED_MODEL;
use izanagi::behavior_evaluation::{EvaluationMethod, EvaluationReport, replay_file};
use izanagi_telemetry::{AuditStore, StoreConfig, TelemetryEnvelope};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, process::Command};

mod support;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/behavior")
}
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_izanagi"));
    command
        .arg("--config")
        .arg("/configuration-not-needed.toml")
        .env("IZANAGI_SECRET_FILE", "/sandbox-secret-must-not-be-read");
    command
}
fn temporary() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "izanagi-behavior-cli-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[test]
fn replay_and_evaluation_work_without_vm_config_or_sandbox_credentials() {
    let input = fixtures().join("access-post.jsonl");
    let original = std::fs::read(&input).unwrap();
    let output = command()
        .args(["behavior", "replay", "--input"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["deterministic_class"], "access_post_suspected");
    assert_eq!(record["classifier"]["status"], "classified");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DO_NOT_LOG_CANARY"));
    assert_eq!(std::fs::read(input).unwrap(), original);
    let output = command()
        .args(["behavior", "evaluate", "--manifest"])
        .arg(fixtures().join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: EvaluationReport = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.simulated);
    assert_eq!(report.methods[&EvaluationMethod::C].recall, Some(0.5));
}

#[test]
fn remote_export_requires_explicit_flag_and_uses_closed_projection() {
    let input = fixtures().join("normal.jsonl");
    let denied = command()
        .args(["behavior", "replay", "--input"])
        .arg(&input)
        .args([
            "--classifier",
            "jev-mcp",
            "--mcp-command",
            "/provider-must-not-be-started",
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("--allow-export is required"));
    let granted = command()
        .args(["behavior", "replay", "--input"])
        .arg(input)
        .args(["--classifier", "jev-mcp", "--allow-export", "--mcp-command"])
        .arg(support::python())
        .arg("--mcp-arg")
        .arg(fixtures().join("mock_mcp.py"))
        .args(["--mcp-arg", "normal"])
        .output()
        .unwrap();
    assert!(
        granted.status.success(),
        "{}",
        String::from_utf8_lossy(&granted.stderr)
    );
    let result: Value = serde_json::from_slice(&granted.stdout).unwrap();
    assert_eq!(
        result["classifier"]["answer"]["returned_model"],
        PINNED_MODEL
    );
    assert_eq!(result["classifier"]["answer"]["class"], "normal");
}

#[test]
fn recorded_response_cli_is_offline_and_pinned_model_alias_is_rejected() {
    let dir = temporary();
    let input = fixtures().join("normal.jsonl");
    let snapshot = replay_file(&input).unwrap().remove(0);
    let digest = snapshot
        .projection(izanagi_telemetry::FeatureMode::Correlated)
        .digest()
        .unwrap();
    let recorded = dir.join("recorded.json");
    std::fs::write(&recorded, serde_json::to_vec(&BTreeMap::from([(digest, json!({"model":PINNED_MODEL,"answers":{"result":{"type":"choice","choice":"normal","probabilities":{"normal":1.0,"access_post_suspected":0.0,"unknown":0.0},"confidence":1.0}},"usage":{"input_tokens":1,"output_tokens":1}}))])).unwrap()).unwrap();
    let output = command()
        .args(["behavior", "replay", "--input"])
        .arg(&input)
        .args(["--classifier", "recorded", "--recorded-responses"])
        .arg(recorded)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["classifier"]["status"], "classified");
    let alias = command()
        .args(["behavior", "replay", "--input"])
        .arg(input)
        .args(["--model", "jev-latest"])
        .output()
        .unwrap();
    assert!(!alias.status.success());
    assert!(String::from_utf8_lossy(&alias.stderr).contains("pinned model"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn output_is_private_and_never_overwrites_the_immutable_input() {
    let dir = temporary();
    let output_path = dir.join("output.jsonl");
    let output = command()
        .args(["behavior", "replay", "--input"])
        .arg(fixtures().join("normal.jsonl"))
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let bytes = std::fs::read(&output_path).unwrap();
    let again = command()
        .args(["behavior", "replay", "--input"])
        .arg(fixtures().join("access-post.jsonl"))
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert_eq!(std::fs::read(output_path).unwrap(), bytes);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn show_reports_expired_evidence_and_rejects_a_different_session() {
    let dir = temporary();
    let snapshot = replay_file(&fixtures().join("access-post.jsonl"))
        .unwrap()
        .remove(0);
    let mut store = AuditStore::new(&dir, StoreConfig::default()).unwrap();
    store
        .append_snapshot(
            &snapshot,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
    let shown = command()
        .args(["behavior", "show", "--session"])
        .arg(&snapshot.session_id)
        .arg("--directory")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let value: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(value["evidence_availability"], "evidence_expired");
    let mismatched = command()
        .args([
            "behavior",
            "show",
            "--session",
            "another-session",
            "--directory",
        ])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!mismatched.status.success());
    assert!(String::from_utf8_lossy(&mismatched.stderr).contains("does not match"));
    let traversal = command()
        .args(["behavior", "show", "--session", "../escaped"])
        .output()
        .unwrap();
    assert!(!traversal.status.success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn persisted_audit_events_replay_while_saved_assessments_are_not_reingested() {
    let dir = temporary();
    let input = fixtures().join("access-post.jsonl");
    let mut store = AuditStore::new(&dir, StoreConfig::default()).unwrap();
    for line in std::fs::read_to_string(&input).unwrap().lines() {
        let event: TelemetryEnvelope = serde_json::from_str(line).unwrap();
        store
            .append_event(
                &event,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap();
    }
    let snapshot = replay_file(&input).unwrap().remove(0);
    store
        .append_snapshot(
            &snapshot,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
    let persisted = dir.join("audit-0000000000000001.jsonl");
    let original = std::fs::read(&persisted).unwrap();
    let output = command()
        .args(["behavior", "replay", "--input"])
        .arg(&persisted)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["snapshot"]["window_id"], snapshot.window_id);
    assert_eq!(result["classifier"]["status"], "classified");
    assert_eq!(std::fs::read(persisted).unwrap(), original);
    let shown = command()
        .args(["behavior", "show", "--session"])
        .arg(snapshot.session_id)
        .arg("--directory")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(shown.status.success());
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains("\"evidence_availability\":\"available\"")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn documented_default_settings_keep_behavior_and_export_disabled() {
    let source = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("configs/default.toml"),
    )
    .unwrap();
    let config = izanagi::config::Config::from_toml(&source).unwrap();
    assert!(!config.behavior.enabled);
    assert!(!config.behavior.classifier.allow_export);
    assert_eq!(config.behavior.classifier.model, PINNED_MODEL);
    config.validate().unwrap();
}

#[test]
fn retention_and_manual_clear_verify_session_before_removing_records() {
    let dir = temporary();
    let snapshot = replay_file(&fixtures().join("access-post.jsonl"))
        .unwrap()
        .remove(0);
    AuditStore::new(&dir, Default::default())
        .unwrap()
        .append_snapshot(&snapshot, 1)
        .unwrap();
    for action in ["show", "clear"] {
        let output = command()
            .args([
                "behavior",
                action,
                "--session",
                "wrong-session",
                "--directory",
            ])
            .arg(&dir)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            AuditStore::new(&dir, Default::default())
                .unwrap()
                .read_records()
                .unwrap()
                .len(),
            1
        );
    }
    let output = command()
        .args(["behavior", "show", "--session"])
        .arg(&snapshot.session_id)
        .arg("--directory")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    AuditStore::new(&dir, Default::default())
        .unwrap()
        .append_snapshot(&snapshot, now)
        .unwrap();
    let output = command()
        .args(["behavior", "clear", "--session"])
        .arg(&snapshot.session_id)
        .arg("--directory")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        AuditStore::new(&dir, Default::default())
            .unwrap()
            .read_records()
            .unwrap()
            .is_empty()
    );
    std::fs::remove_dir_all(dir).unwrap();
}
