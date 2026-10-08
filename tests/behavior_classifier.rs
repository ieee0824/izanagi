use izanagi::behavior_classifier::*;
use izanagi_telemetry::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

fn projection() -> FeatureProjection {
    FeatureProjection {
        feature_version: FEATURE_VERSION,
        mode: FeatureMode::Correlated,
        binding: ProcessBinding::ConfirmedWriter,
        credential_access_attempts: Some(0),
        credential_open_succeeded: Some(0),
        credential_open_failed: Some(0),
        access_to_post_ns: None,
        method: HttpMethod::Post,
        policy: PolicyAllowed::Allowed,
        novelty: DestinationNovelty::Known,
        declared_content_length: Some(3),
        client_bytes_received: Some(3),
        upstream_bytes_written: Some(3),
        response_bytes_received: Some(0),
        transfer_outcome: TransferOutcome::Completed,
        quality: ObservationQuality::default(),
    }
}

fn config(mode: &str) -> ClassifierConfig {
    ClassifierConfig {
        command: PathBuf::from("python3"),
        args: vec![
            format!(
                "{}/tests/fixtures/behavior/mock_mcp.py",
                env!("CARGO_MANIFEST_DIR")
            ),
            mode.into(),
        ],
        deadline: Duration::from_secs(2),
        ..Default::default()
    }
}

fn response(choice: &str, probabilities: [f64; 3], confidence: f64) -> Value {
    json!({"model":PINNED_MODEL,"answers":{"result":{"type":"choice","choice":choice,
        "probabilities":{"normal":probabilities[0],"access_post_suspected":probabilities[1],"unknown":probabilities[2]},
        "confidence":confidence}},"usage":{"input_tokens":30,"output_tokens":4}})
}

#[tokio::test]
async fn authenticated_shape_is_validated_and_text_fallback_is_success_only() {
    for mode in ["normal", "text"] {
        let classifier = JevMcpClassifier::new(config(mode)).unwrap();
        let outcome = classifier.classify(&projection()).await;
        assert_eq!(outcome.class(), Some(ThreatClass::Normal), "{outcome:?}");
        let answer = outcome.answer().unwrap();
        assert_eq!(answer.input_tokens, 17);
        assert_eq!(answer.input_digest, projection().digest().unwrap());
    }
    assert_eq!(
        JevMcpClassifier::new(config("call_error"))
            .unwrap()
            .classify(&projection())
            .await,
        ClassificationOutcome::Failed {
            kind: ClassificationErrorKind::RateLimit
        }
    );
}

#[tokio::test]
async fn uncertain_observation_and_high_confidence_unknown_never_become_normal() {
    let classifier = JevMcpClassifier::new(config("unknown")).unwrap();
    let outcome = classifier.classify(&projection()).await;
    assert!(matches!(
        outcome,
        ClassificationOutcome::Abstained {
            reason: AbstentionReason::UnknownChoice,
            answer: Some(_)
        }
    ));
    assert_eq!(outcome.answer().unwrap().confidence, 1.0);
    let mut incomplete = projection();
    incomplete.quality.issues.push(QualityIssue::EventLoss);
    let no_spawn = JevMcpClassifier::new(ClassifierConfig {
        command: PathBuf::from("/not/a/program"),
        ..config("normal")
    })
    .unwrap();
    assert_eq!(
        no_spawn.classify(&incomplete).await,
        ClassificationOutcome::Abstained {
            reason: AbstentionReason::IncompleteObservation,
            answer: None
        }
    );
}

#[tokio::test]
async fn protocol_failures_are_bounded_and_do_not_echo_remote_data() {
    for (mode, expected) in [
        ("overloaded", ClassificationErrorKind::Http),
        ("stopped", ClassificationErrorKind::Transport),
        ("wrong_id", ClassificationErrorKind::InvalidResponse),
        ("duplicate", ClassificationErrorKind::InvalidResponse),
        ("missing_tool", ClassificationErrorKind::Capability),
        ("model_mismatch", ClassificationErrorKind::ModelMismatch),
        ("oversize", ClassificationErrorKind::ResponseTooLarge),
        ("malformed", ClassificationErrorKind::InvalidResponse),
        ("stderr", ClassificationErrorKind::StderrTooLarge),
    ] {
        let outcome = JevMcpClassifier::new(config(mode))
            .unwrap()
            .classify(&projection())
            .await;
        assert_eq!(
            outcome,
            ClassificationOutcome::Failed { kind: expected },
            "{mode}"
        );
        assert!(
            !serde_json::to_string(&outcome)
                .unwrap()
                .contains("DO_NOT_LOG_CANARY")
        );
    }
    let started = std::time::Instant::now();
    let outcome = JevMcpClassifier::new(ClassifierConfig {
        deadline: Duration::from_millis(100),
        ..config("timeout")
    })
    .unwrap()
    .classify(&projection())
    .await;
    assert_eq!(
        outcome,
        ClassificationOutcome::Failed {
            kind: ClassificationErrorKind::Timeout
        }
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn strict_semantics_reject_wrong_question_distribution_selection_and_model() {
    let config = ClassifierConfig::default();
    let good = response("normal", [1.0, 0.0, 0.0], 1.0);
    for mutation in [
        "question",
        "missing_probability",
        "unknown_probability",
        "negative_probability",
        "sum",
        "selection",
        "confidence",
        "usage",
    ] {
        let mut value = good.clone();
        match mutation {
            "question" => {
                value["answers"]["extra"] = value["answers"]["result"].clone();
            }
            "missing_probability" => {
                value["answers"]["result"]["probabilities"]
                    .as_object_mut()
                    .unwrap()
                    .remove("unknown");
            }
            "unknown_probability" => {
                value["answers"]["result"]["probabilities"]["injected"] = json!(0.0);
            }
            "negative_probability" => {
                value["answers"]["result"]["probabilities"]["unknown"] = json!(-0.1);
            }
            "sum" => {
                value["answers"]["result"]["probabilities"]["unknown"] = json!(0.1);
            }
            "selection" => {
                value["answers"]["result"]["choice"] = json!("unknown");
            }
            "confidence" => {
                value["answers"]["result"]["confidence"] = json!(0.4);
            }
            "usage" => {
                value["usage"]["input_tokens"] = json!(-1);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            validate_evaluation(value, &projection(), &config, Duration::ZERO),
            ClassificationOutcome::Failed {
                kind: ClassificationErrorKind::InvalidResponse
            },
            "{mutation}"
        );
    }
    let mut value = good;
    value["model"] = json!("jev-latest");
    assert_eq!(
        validate_evaluation(value, &projection(), &config, Duration::ZERO),
        ClassificationOutcome::Failed {
            kind: ClassificationErrorKind::ModelMismatch
        }
    );
}

#[test]
fn rounded_confidence_and_tied_probabilities_follow_official_choice_semantics() {
    let config = ClassifierConfig {
        min_confidence: 0.4,
        ..Default::default()
    };
    assert_eq!(
        validate_evaluation(
            response("access_post_suspected", [0.04, 0.61, 0.35], 0.42),
            &projection(),
            &config,
            Duration::ZERO
        )
        .class(),
        Some(ThreatClass::AccessPostSuspected)
    );
    assert!(matches!(
        validate_evaluation(
            response("normal", [0.5, 0.5, 0.0], 0.25),
            &projection(),
            &config,
            Duration::ZERO
        ),
        ClassificationOutcome::Abstained {
            reason: AbstentionReason::LowConfidence,
            ..
        }
    ));
}

#[tokio::test]
async fn closed_projection_size_is_checked_before_starting_provider() {
    let classifier = JevMcpClassifier::new(ClassifierConfig {
        max_projection_bytes: 1,
        command: PathBuf::from("/not/a/program"),
        ..config("normal")
    })
    .unwrap();
    assert_eq!(
        classifier.classify(&projection()).await,
        ClassificationOutcome::Skipped {
            reason: SkipReason::Oversize
        }
    );
    assert!(
        JevMcpClassifier::new(ClassifierConfig {
            model: "jev-latest".into(),
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        JevMcpClassifier::new(ClassifierConfig {
            credential_env: "IZANAGI_SECRET_FILE".into(),
            ..Default::default()
        })
        .is_err()
    );
}

#[tokio::test]
async fn recorded_responses_revalidate_against_the_requested_projection() {
    let p = projection();
    let classifier = RecordedClassifier {
        responses: BTreeMap::from([(
            p.digest().unwrap(),
            response("normal", [1.0, 0.0, 0.0], 1.0),
        )]),
        config: ClassifierConfig::default(),
    };
    assert_eq!(
        classifier.classify(&p).await.class(),
        Some(ThreatClass::Normal)
    );
    let mut different = p;
    different.client_bytes_received = Some(4);
    assert_eq!(
        classifier.classify(&different).await,
        ClassificationOutcome::Skipped {
            reason: SkipReason::MissingRecording
        }
    );
}
