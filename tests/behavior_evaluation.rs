use async_trait::async_trait;
use izanagi::behavior_classifier::*;
use izanagi::behavior_evaluation::*;
use izanagi_telemetry::*;
use std::{io::Cursor, path::PathBuf};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/behavior")
}

#[tokio::test]
async fn paired_comparison_preserves_all_windows_and_mask_is_not_observation_loss() {
    let dir = fixtures();
    let manifest = load_manifest(&dir.join("manifest.json")).unwrap();
    let report = evaluate_manifest(&manifest, &dir, &MockClassifier, "mock")
        .await
        .unwrap();
    assert!(report.simulated);
    assert_eq!(report.windows.len(), 12);
    for method in report.methods.values() {
        assert_eq!(method.total_windows, 3);
    }
    let correlated = &report.methods[&EvaluationMethod::C];
    assert_eq!(correlated.true_positives, 1);
    assert_eq!(correlated.false_negatives, 1);
    assert_eq!(correlated.abstained_windows, 1);
    assert_eq!(correlated.recall, Some(0.5));
    assert_eq!(correlated.false_positives, 0);
    assert_eq!(report.methods[&EvaluationMethod::B].abstained_windows, 3);
    assert_eq!(report.methods[&EvaluationMethod::D].true_positives, 1);
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("DO_NOT_LOG_CANARY"));
    assert!(rendered.contains("mock-v1"));
    for result in &report.windows {
        if result.method == EvaluationMethod::B && result.scenario_id != "event-loss" {
            assert!(matches!(
                result.classifier,
                Some(ClassificationOutcome::Abstained {
                    reason: AbstentionReason::UnknownChoice,
                    ..
                })
            ));
        }
    }
}

struct FailedClassifier;
#[async_trait]
impl Classifier for FailedClassifier {
    async fn classify(&self, _: &FeatureProjection) -> ClassificationOutcome {
        ClassificationOutcome::Failed {
            kind: ClassificationErrorKind::Timeout,
        }
    }
}

#[tokio::test]
async fn failures_are_separate_from_normal_and_remain_in_recall_denominator() {
    let dir = fixtures();
    let manifest = load_manifest(&dir.join("manifest.json")).unwrap();
    let report = evaluate_manifest(&manifest, &dir, &FailedClassifier, "recorded")
        .await
        .unwrap();
    let stats = &report.methods[&EvaluationMethod::C];
    assert_eq!(stats.total_windows, 3);
    assert_eq!(stats.failed_windows, 3);
    assert_eq!(stats.false_negatives, 2);
    assert_eq!(stats.error_rate, 1.0);
    assert_eq!(stats.recall, Some(0.0));
    assert!(
        report
            .windows
            .iter()
            .filter(|r| r.method == EvaluationMethod::C)
            .all(|r| r.series_decision == SeriesDecision::Failed)
    );
}

#[test]
fn historical_event_time_replay_is_deterministic_and_immutable() {
    let path = fixtures().join("access-post.jsonl");
    let bytes = std::fs::read(&path).unwrap();
    let first = replay(Cursor::new(&bytes), CorrelationConfig::default()).unwrap();
    let second = replay(Cursor::new(&bytes), CorrelationConfig::default()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].ended_monotonic_ns, 4_000_000_000);
    assert_eq!(first[0].credential_access_attempts, 1);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn manifest_rejects_leakage_duplicate_labels_aliases_and_unbounded_input() {
    let original = load_manifest(&fixtures().join("manifest.json")).unwrap();
    let mut split = original.clone();
    split.scenarios[1].family = split.scenarios[0].family.clone();
    assert!(split.validate().is_err());
    let mut labels = original.clone();
    let duplicate = labels.scenarios[0].labels[0].clone();
    labels.scenarios[0].labels.push(duplicate);
    assert!(labels.validate().is_err());
    let mut alias = original.clone();
    alias.model = "jev-latest".into();
    assert!(alias.validate().is_err());
    let mut policy = original.clone();
    policy.promotion_policy = "enable_automatic_blocking".into();
    assert!(policy.validate().is_err());
    let mut revision = original.clone();
    revision.mcp_commit = Some("unverified-server-description".into());
    assert!(revision.validate().is_err());
    let mut escaping = original;
    escaping.scenarios[0].events = "../private.jsonl".into();
    assert!(escaping.validate().is_err());
    assert!(
        replay(
            Cursor::new(vec![b'x'; 70_000]),
            CorrelationConfig::default()
        )
        .is_err()
    );
    assert!(replay(Cursor::new(b"\n"), CorrelationConfig::default()).is_err());
}

#[tokio::test]
async fn independent_labels_must_match_every_candidate_window() {
    let dir = fixtures();
    let mut manifest = load_manifest(&dir.join("manifest.json")).unwrap();
    manifest.scenarios[0].labels[0].window_id = "unobserved-window".into();
    assert!(
        evaluate_manifest(&manifest, &dir, &MockClassifier, "mock")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn captured_real_responses_keep_abstentions_and_validation_failures() {
    let dir = fixtures();
    let manifest = load_manifest(&dir.join("manifest.json")).unwrap();
    let responses =
        serde_json::from_slice(&std::fs::read(dir.join("jev-responses.json")).unwrap()).unwrap();
    let classifier = RecordedClassifier {
        responses,
        config: Default::default(),
    };
    let report = evaluate_manifest(&manifest, &dir, &classifier, "recorded")
        .await
        .unwrap();
    assert!(!report.simulated);
    let correlated = &report.methods[&EvaluationMethod::C];
    assert_eq!(correlated.classified_windows, 1);
    assert_eq!(correlated.abstained_windows, 2);
    assert_eq!(correlated.true_positives, 0);
    assert_eq!(correlated.recall, Some(0.0));
    assert_eq!(report.methods[&EvaluationMethod::B].failed_windows, 1);
    assert_eq!(report.methods[&EvaluationMethod::D].true_positives, 1);
    assert!(
        report
            .windows
            .iter()
            .filter_map(|w| w.classifier.as_ref())
            .filter_map(|o| o.answer())
            .all(|a| a.returned_model == PINNED_MODEL)
    );
}

#[tokio::test]
async fn boundary_contracts_cover_routine_workloads_and_incomplete_observation() {
    let dir = fixtures();
    let manifest = load_manifest(&dir.join("boundary-manifest.json")).unwrap();
    let report = evaluate_manifest(&manifest, &dir, &MockClassifier, "mock")
        .await
        .unwrap();
    assert_eq!(report.methods[&EvaluationMethod::D].total_windows, 21);
    assert_eq!(report.methods[&EvaluationMethod::D].true_positives, 7);
    assert_eq!(report.methods[&EvaluationMethod::D].false_positives, 0);
    assert_eq!(report.methods[&EvaluationMethod::D].abstained_windows, 5);
    assert_eq!(report.methods[&EvaluationMethod::D].routine_workloads, 4);
    for window in report
        .windows
        .iter()
        .filter(|w| w.method == EvaluationMethod::D)
    {
        let expected = match window.expected {
            ExpectedLabel::Normal => SeriesDecision::Normal,
            ExpectedLabel::Suspicious => SeriesDecision::Suspicious,
            ExpectedLabel::Indeterminate => SeriesDecision::Unknown,
        };
        assert_eq!(window.series_decision, expected, "{}", window.scenario_id);
    }
    // The deliberately simple mock does not establish real model performance:
    // it over-alerts on a legitimate credential upload to a known destination.
    let mock_upload = report
        .windows
        .iter()
        .find(|w| w.method == EvaluationMethod::C && w.scenario_id == "legitimate-upload")
        .unwrap();
    assert_eq!(mock_upload.expected, ExpectedLabel::Normal);
    assert_eq!(mock_upload.series_decision, SeriesDecision::Suspicious);
    assert_eq!(report.methods[&EvaluationMethod::C].false_positives, 1);
    assert_eq!(
        report.methods[&EvaluationMethod::C].additional_false_alerts_per_routine_workload,
        Some(0.25)
    );
}

#[tokio::test]
async fn additional_real_response_does_not_over_alert_on_known_credential_upload() {
    let dir = fixtures();
    let manifest = load_manifest(&dir.join("boundary-manifest.json")).unwrap();
    let responses =
        serde_json::from_slice(&std::fs::read(dir.join("jev-boundary-responses.json")).unwrap())
            .unwrap();
    let classifier = RecordedClassifier {
        responses,
        config: Default::default(),
    };
    let report = evaluate_manifest(&manifest, &dir, &classifier, "recorded")
        .await
        .unwrap();
    let upload = report
        .windows
        .iter()
        .find(|w| w.method == EvaluationMethod::C && w.scenario_id == "legitimate-upload")
        .unwrap();
    assert_eq!(upload.series_decision, SeriesDecision::Normal);
    assert_eq!(
        upload
            .classifier
            .as_ref()
            .unwrap()
            .answer()
            .unwrap()
            .returned_model,
        "jev-1.13.0"
    );
    assert_eq!(
        upload
            .classifier
            .as_ref()
            .unwrap()
            .answer()
            .unwrap()
            .input_tokens,
        632
    );
    assert_eq!(report.methods[&EvaluationMethod::C].total_windows, 21);
    // Unmeasured projections stay explicitly skipped, not filled with mock answers.
    assert_eq!(report.methods[&EvaluationMethod::C].skipped_windows, 15);
    assert_eq!(report.methods[&EvaluationMethod::C].abstained_windows, 5);
}

#[tokio::test]
async fn confident_wrong_answers_are_counted_against_independent_labels() {
    let dir = fixtures();
    let manifest = load_manifest(&dir.join("manifest.json")).unwrap();
    let mut responses: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&std::fs::read(dir.join("jev-responses.json")).unwrap()).unwrap();
    for response in responses.values_mut() {
        response["answers"]["result"] = serde_json::json!({"type":"choice","choice":"normal","probabilities":{"normal":1.0,"access_post_suspected":0.0,"unknown":0.0},"confidence":1.0});
    }
    let classifier = RecordedClassifier {
        responses,
        config: Default::default(),
    };
    let report = evaluate_manifest(&manifest, &dir, &classifier, "recorded")
        .await
        .unwrap();
    let metrics = &report.methods[&EvaluationMethod::C];
    assert_eq!(metrics.total_windows, 3);
    assert_eq!(metrics.false_negatives, 2);
    assert_eq!(metrics.true_positives, 0);
    assert_eq!(metrics.recall, Some(0.0));
    let wrong = report
        .windows
        .iter()
        .find(|w| w.method == EvaluationMethod::C && w.scenario_id == "access-post")
        .unwrap();
    assert_eq!(wrong.expected, ExpectedLabel::Suspicious);
    assert_eq!(wrong.series_decision, SeriesDecision::Normal);
    assert_eq!(
        wrong
            .classifier
            .as_ref()
            .unwrap()
            .answer()
            .unwrap()
            .confidence,
        1.0
    );
}

struct NoInvocation;
#[async_trait]
impl Classifier for NoInvocation {
    async fn classify(&self, _: &FeatureProjection) -> ClassificationOutcome {
        panic!("invalid fixture must be rejected before classification")
    }
}

#[tokio::test]
async fn fixture_digest_mismatch_prevents_classification() {
    let dir = fixtures();
    let mut manifest = load_manifest(&dir.join("manifest.json")).unwrap();
    manifest.scenarios[0].events_sha256 = "0".repeat(64);
    let error = evaluate_manifest(&manifest, &dir, &NoInvocation, "mock")
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "evaluation fixture does not match manifest digest"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn canonical_fixture_symlink_escape_prevents_classification() {
    let dir = fixtures();
    let manifest = load_manifest(&dir.join("manifest.json")).unwrap();
    let base = std::env::temp_dir().join(format!("izanagi-eval-{}", rand::random::<u64>()));
    std::fs::create_dir(&base).unwrap();
    std::os::unix::fs::symlink(
        dir.join(&manifest.scenarios[0].events),
        base.join(&manifest.scenarios[0].events),
    )
    .unwrap();
    let result = evaluate_manifest(&manifest, &base, &NoInvocation, "mock").await;
    std::fs::remove_dir_all(base).unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "evaluation fixture escapes manifest directory"
    );
}
