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
