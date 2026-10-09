use izanagi_telemetry::*;
use std::collections::BTreeMap;

fn process(pid: u32, start: u64) -> ProcessKey {
    ProcessKey {
        session_id: "session".into(),
        guest_boot_id: "boot".into(),
        pid_namespace: 1,
        tgid: pid,
        started_monotonic_ns: start,
    }
}
fn tuple() -> SocketTuple {
    SocketTuple {
        net_namespace: 7,
        client: "127.0.0.1:4242".parse().unwrap(),
        local: "127.0.0.1:18080".parse().unwrap(),
    }
}
fn socket(generation: u64) -> SocketIdentity {
    SocketIdentity {
        net_namespace: 7,
        kernel_identity: 123,
        generation,
        kind: SocketIdentityKind::Cookie,
    }
}
fn event(
    source: &str,
    seq: u64,
    time: u64,
    process: Option<ProcessKey>,
    payload: TelemetryPayload,
) -> TelemetryEnvelope {
    let mut event = TelemetryEnvelope {
        schema_version: SCHEMA_VERSION,
        session_id: "session".into(),
        guest_boot_id: "boot".into(),
        source_instance_id: source.into(),
        source_seq: seq,
        event_id: String::new(),
        observed_monotonic_ns: time,
        clock_domain: "guest-monotonic".into(),
        clock_uncertainty_ns: 0,
        host_received_at_unix_ns: None,
        process,
        tid: None,
        quality: ObservationQuality::default(),
        payload,
    };
    event.event_id = event.expected_event_id();
    event
}
fn fixture(binding: ProcessBinding) -> Vec<TelemetryEnvelope> {
    let p = process(42, 1);
    vec![
        event(
            "ebpf",
            1,
            1,
            Some(p.clone()),
            TelemetryPayload::ProcessStart,
        ),
        event(
            "ebpf",
            2,
            1_000_000_000,
            Some(p.clone()),
            TelemetryPayload::FileAccessAttempt {
                attempt_id: "open-1".into(),
                role: FileRole::Credential,
                path: Some("/secret/CANARY-token".into()),
            },
        ),
        event(
            "ebpf",
            3,
            1_100_000_000,
            Some(p.clone()),
            TelemetryPayload::FileOpenOutcome {
                attempt_id: "open-1".into(),
                outcome: OpenOutcome::Succeeded { fd: 3 },
            },
        ),
        event(
            "ebpf",
            4,
            2_000_000_000,
            Some(p),
            TelemetryPayload::SocketConnect {
                socket: socket(2),
                tuple: tuple(),
                binding,
            },
        ),
        event(
            "http",
            1,
            3_000_000_000,
            None,
            TelemetryPayload::HttpRequest {
                connection_id: "connection-1".into(),
                request_id: "request-1".into(),
                tuple: tuple(),
                method: HttpMethod::Post,
                policy: PolicyAllowed::Allowed,
                novelty: DestinationNovelty::Novel,
                declared_content_length: Some(8),
                raw_host: Some("CANARY-token.example".into()),
            },
        ),
        event(
            "http",
            2,
            3_100_000_000,
            None,
            TelemetryPayload::HttpOutcome {
                request_id: "request-1".into(),
                client_bytes_received: 8,
                upstream_bytes_written: 8,
                response_bytes_received: 100,
                status: Some(200),
                outcome: TransferOutcome::Completed,
            },
        ),
    ]
}
fn replay(events: Vec<TelemetryEnvelope>, config: CorrelationConfig) -> FeatureSnapshot {
    let mut correlator = Correlator::new(config).unwrap();
    let mut results = BTreeMap::new();
    for event in events {
        for snapshot in correlator.ingest(event).unwrap() {
            results.insert(snapshot.window_id.clone(), snapshot);
        }
    }
    for snapshot in correlator.flush() {
        results.insert(snapshot.window_id.clone(), snapshot);
    }
    results.into_values().last().unwrap()
}

#[test]
fn transfer_interval_gaps_and_socket_sharing_remain_in_evidence() {
    for payload in [
        TelemetryPayload::ObservationGap {
            reason: QualityIssue::EventLoss,
            dropped: 1,
        },
        TelemetryPayload::CollectorHealth { healthy: false },
        TelemetryPayload::SocketLifecycle {
            socket: socket(2),
            state: SocketState::Shared,
        },
    ] {
        let mut events = fixture(ProcessBinding::ConfirmedWriter);
        let gap = event("health", 1, 3_050_000_000, None, payload);
        let gap_id = gap.event_id.clone();
        events.push(gap);
        let snapshot = replay(events, CorrelationConfig::default());
        assert_eq!(deterministic_rule(&snapshot), ThreatClass::Unknown);
        assert!(snapshot.evidence_event_ids.contains(&gap_id));
        assert_eq!(snapshot.transfer_outcome, TransferOutcome::Completed);
    }
}

#[test]
fn conflicting_open_outcomes_preserve_counts_and_degrade_quality() {
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    events.push(event(
        "ebpf",
        5,
        1_200_000_000,
        Some(process(42, 1)),
        TelemetryPayload::FileOpenOutcome {
            attempt_id: "open-1".into(),
            outcome: OpenOutcome::Failed { errno: 13 },
        },
    ));
    let snapshot = replay(events, CorrelationConfig::default());
    assert_eq!(snapshot.credential_open_succeeded, 1);
    assert_eq!(snapshot.credential_open_failed, 1);
    assert!(
        snapshot
            .quality
            .issues
            .contains(&QualityIssue::MissingOutcome)
    );
    assert_eq!(deterministic_rule(&snapshot), ThreatClass::Unknown);
}

#[test]
fn evidence_truncation_is_stable_under_arrival_reordering() {
    let events = fixture(ProcessBinding::ConfirmedWriter);
    let mut reversed = events.clone();
    reversed.reverse();
    let config = CorrelationConfig {
        max_events_per_window: 2,
        ..Default::default()
    };
    let first = replay(events, config.clone());
    let second = replay(reversed, config);
    // Revisions reflect arrival history; the semantic snapshot remains identical.
    assert_eq!(first.evidence_event_ids, second.evidence_event_ids);
    assert_eq!(first.quality, second.quality);
    assert_eq!(first.evidence_event_ids.len(), 2);
    assert!(
        first
            .quality
            .issues
            .contains(&QualityIssue::WindowTruncated)
    );
    assert_eq!(deterministic_rule(&first), ThreatClass::Unknown);
}

#[test]
fn confirmed_attempt_and_post_is_warning_not_confirmed_read() {
    let snapshot = replay(
        fixture(ProcessBinding::ConfirmedWriter),
        CorrelationConfig::default(),
    );
    assert_eq!(
        deterministic_rule(&snapshot),
        ThreatClass::AccessPostSuspected
    );
    assert_eq!(snapshot.credential_access_attempts, 1);
    assert_eq!(snapshot.credential_open_succeeded, 1);
    assert_eq!(snapshot.access_to_post_ns, Some(2_000_000_000));
    assert!(snapshot.quality.issues.is_empty());
    let json = String::from_utf8(
        snapshot
            .projection(FeatureMode::Correlated)
            .to_json()
            .unwrap(),
    )
    .unwrap();
    assert!(!json.contains("CANARY"));
    assert!(!json.contains("read_completed"));
    assert!(!json.contains("session"));
    assert!(!json.contains("127.0.0.1"));
}

#[test]
fn connector_is_not_writer_and_network_mask_is_not_source_loss() {
    let snapshot = replay(
        fixture(ProcessBinding::Connector),
        CorrelationConfig::default(),
    );
    assert_eq!(deterministic_rule(&snapshot), ThreatClass::Unknown);
    assert!(!snapshot.projection(FeatureMode::Correlated).eligible());
    let network = snapshot.projection(FeatureMode::NetworkOnly);
    assert!(network.eligible());
    assert_eq!(network.credential_access_attempts, None);
    assert!(
        network
            .quality
            .issues
            .contains(&QualityIssue::MissingWriter)
    );
}

#[test]
fn unsuccessful_open_and_post_are_known_attempts_not_success() {
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    events[2].payload = TelemetryPayload::FileOpenOutcome {
        attempt_id: "open-1".into(),
        outcome: OpenOutcome::Failed { errno: 13 },
    };
    if let TelemetryPayload::HttpOutcome {
        outcome,
        upstream_bytes_written,
        ..
    } = &mut events[5].payload
    {
        *outcome = TransferOutcome::Failed;
        *upstream_bytes_written = 0;
    }
    let snapshot = replay(events, CorrelationConfig::default());
    assert_eq!(snapshot.credential_open_failed, 1);
    assert_eq!(snapshot.credential_open_succeeded, 0);
    assert_eq!(snapshot.upstream_bytes_written, Some(0));
    assert_eq!(
        deterministic_rule(&snapshot),
        ThreatClass::AccessPostSuspected
    );
}

#[test]
fn missing_open_or_http_outcome_is_unknown() {
    for index in [2, 5] {
        let mut events = fixture(ProcessBinding::ConfirmedWriter);
        events.remove(index);
        let snapshot = replay(events, CorrelationConfig::default());
        assert!(
            snapshot
                .quality
                .issues
                .contains(&QualityIssue::MissingOutcome)
        );
        assert_eq!(deterministic_rule(&snapshot), ThreatClass::Unknown);
    }
}

#[test]
fn unrelated_pid_and_pid_reuse_do_not_inherit_access() {
    for p in [process(43, 1), process(42, 1_500_000_000)] {
        let mut events = fixture(ProcessBinding::ConfirmedWriter);
        events[3].process = Some(p);
        let snapshot = replay(events, CorrelationConfig::default());
        assert_eq!(snapshot.credential_access_attempts, 0);
        assert_eq!(deterministic_rule(&snapshot), ThreatClass::Normal);
        assert!(
            !snapshot
                .evidence_event_ids
                .contains(&"session:ebpf:2".to_string())
        );
    }
}

#[test]
fn verified_parent_child_edge_is_in_evidence() {
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    let parent = process(42, 1);
    let child = process(43, 1_500_000_000);
    events[3].process = Some(child.clone());
    events[3].source_seq = 5;
    events[3].event_id = events[3].expected_event_id();
    events.push(event(
        "ebpf",
        4,
        1_500_000_000,
        Some(parent.clone()),
        TelemetryPayload::ProcessFork { parent, child },
    ));
    let snapshot = replay(events, CorrelationConfig::default());
    assert_eq!(snapshot.credential_access_attempts, 1);
    assert!(
        snapshot
            .evidence_event_ids
            .contains(&"session:ebpf:4".into())
    );
    assert_eq!(
        deterministic_rule(&snapshot),
        ThreatClass::AccessPostSuspected
    );
}

#[test]
fn ambiguous_or_shared_socket_does_not_get_single_writer() {
    for payload in [
        TelemetryPayload::SocketConnect {
            socket: socket(3),
            tuple: tuple(),
            binding: ProcessBinding::ConfirmedWriter,
        },
        TelemetryPayload::SocketLifecycle {
            socket: socket(2),
            state: SocketState::Shared,
        },
        TelemetryPayload::SocketLifecycle {
            socket: socket(2),
            state: SocketState::Transferred,
        },
    ] {
        let mut events = fixture(ProcessBinding::ConfirmedWriter);
        events.push(event(
            "ebpf",
            5,
            2_500_000_000,
            Some(process(43, 1)),
            payload,
        ));
        let snapshot = replay(events, CorrelationConfig::default());
        assert_eq!(deterministic_rule(&snapshot), ThreatClass::Unknown);
        assert!(snapshot.quality.issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::SocketShared | QualityIssue::SocketAmbiguous
        )));
    }
}

#[test]
fn closed_socket_incarnation_does_not_bind_port_reuse_to_old_pid() {
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    events.push(event(
        "ebpf",
        5,
        2_200_000_000,
        Some(process(42, 1)),
        TelemetryPayload::SocketLifecycle {
            socket: socket(2),
            state: SocketState::Closed,
        },
    ));
    events.push(event(
        "ebpf",
        6,
        2_500_000_000,
        Some(process(43, 1)),
        TelemetryPayload::SocketConnect {
            socket: socket(3),
            tuple: tuple(),
            binding: ProcessBinding::ConfirmedWriter,
        },
    ));
    let snapshot = replay(events, CorrelationConfig::default());
    assert_eq!(snapshot.process.unwrap().tgid, 43);
    assert_eq!(snapshot.credential_access_attempts, 0);
}

#[test]
fn shuffled_duplicate_input_has_identical_features() {
    let original = fixture(ProcessBinding::ConfirmedWriter);
    let expected = replay(original.clone(), CorrelationConfig::default());
    let mut shuffled = original.clone();
    shuffled.reverse();
    shuffled.extend(original);
    let actual = replay(shuffled, CorrelationConfig::default());
    assert_eq!(
        actual.projection(FeatureMode::Correlated),
        expected.projection(FeatureMode::Correlated)
    );
    assert_eq!(actual.evidence_event_ids, expected.evidence_event_ids);
}

#[test]
fn gaps_and_cross_clock_observations_cannot_become_normal() {
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    events.push(event(
        "ebpf",
        5,
        2_500_000_000,
        None,
        TelemetryPayload::ObservationGap {
            dropped: 2,
            reason: QualityIssue::EventLoss,
        },
    ));
    let snapshot = replay(events, CorrelationConfig::default());
    assert_eq!(deterministic_rule(&snapshot), ThreatClass::Unknown);
    assert!(!snapshot.projection(FeatureMode::NetworkOnly).eligible());
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    events[1].clock_domain = "other-clock".into();
    let snapshot = replay(events, CorrelationConfig::default());
    assert!(
        snapshot
            .quality
            .issues
            .contains(&QualityIssue::ClockUnknown)
    );
}

#[test]
fn restarted_proxy_cannot_reuse_an_old_request_outcome() {
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    events[5].source_instance_id = "old-http".into();
    events[5].event_id = events[5].expected_event_id();
    let snapshot = replay(events, CorrelationConfig::default());
    assert_eq!(snapshot.transfer_outcome, TransferOutcome::Unknown);
}

#[test]
fn state_limits_and_late_revisions_are_explicit() {
    let config = CorrelationConfig {
        max_events: 3,
        ..CorrelationConfig::default()
    };
    let mut correlator = Correlator::new(config).unwrap();
    for event in fixture(ProcessBinding::ConfirmedWriter) {
        correlator.ingest(event).unwrap();
    }
    assert!(correlator.retained_events() <= 3);
    assert!(
        correlator.flush()[0]
            .quality
            .issues
            .contains(&QualityIssue::StateEvicted)
    );

    let events = fixture(ProcessBinding::ConfirmedWriter);
    let mut correlator = Correlator::new(CorrelationConfig::default()).unwrap();
    for i in [0, 3, 4, 5] {
        correlator.ingest(events[i].clone()).unwrap();
    }
    let first = correlator
        .advance_clock("guest-monotonic", 6_000_000_000)
        .pop()
        .unwrap();
    assert_eq!(first.credential_access_attempts, 0);
    let mut revisions = correlator.ingest(events[1].clone()).unwrap();
    revisions.extend(correlator.ingest(events[2].clone()).unwrap());
    let last = revisions.last().unwrap();
    assert_eq!(last.credential_access_attempts, 1);
    assert!(last.revision > first.revision);
    assert!(last.supersedes.is_some());
}

#[test]
fn identity_injection_and_cross_session_process_are_rejected() {
    let mut events = fixture(ProcessBinding::ConfirmedWriter);
    events[0].source_instance_id = "../../root/CANARY".into();
    events[0].event_id = events[0].expected_event_id();
    assert_eq!(events[0].validate(), Err(TelemetryError::InvalidEvent));
    events[1].process.as_mut().unwrap().session_id = "other-session".into();
    assert_eq!(events[1].validate(), Err(TelemetryError::InvalidEvent));
}

#[test]
fn equivocation_and_uncertain_order_cannot_produce_a_normal_class() {
    let events = fixture(ProcessBinding::ConfirmedWriter);
    let mut correlator = Correlator::new(CorrelationConfig::default()).unwrap();
    for event in events.clone() {
        correlator.ingest(event).unwrap();
    }
    let mut changed = events[3].clone();
    changed.process = Some(process(43, 1));
    assert_eq!(
        correlator.ingest(changed),
        Err(TelemetryError::InvalidEvent)
    );
    assert_eq!(
        deterministic_rule(&correlator.flush()[0]),
        ThreatClass::Unknown
    );

    let mut uncertain = events.clone();
    uncertain[1].clock_uncertainty_ns = 1_200_000_000;
    uncertain[4].clock_uncertainty_ns = 1_200_000_000;
    assert_eq!(
        deterministic_rule(&replay(uncertain, CorrelationConfig::default())),
        ThreatClass::Unknown
    );

    let mut correlator = Correlator::new(CorrelationConfig::default()).unwrap();
    for event in &events {
        correlator.ingest(event.clone()).unwrap();
    }
    correlator.advance_clock_uncertain("guest-monotonic", 6_000_000_000, 3_000_000_000);
    // Host uncertainty annotations must not alter immutable source envelopes.
    assert!(correlator.ingest(events[0].clone()).unwrap().is_empty());
}

#[test]
fn projection_rejects_generic_fields_and_correlation_fields_in_network_mask() {
    let snapshot = replay(
        fixture(ProcessBinding::ConfirmedWriter),
        CorrelationConfig::default(),
    );
    let projection = snapshot.projection(FeatureMode::Correlated);
    let mut value = serde_json::to_value(&projection).unwrap();
    value["instructions"] = serde_json::json!("CANARY-secret");
    assert!(serde_json::from_value::<FeatureProjection>(value).is_err());
    let mut network = snapshot.projection(FeatureMode::NetworkOnly);
    network.credential_access_attempts = Some(1);
    assert_eq!(network.to_json(), Err(TelemetryError::InvalidEvent));
}

#[test]
fn serialized_state_budget_includes_scope_and_snapshot_indexes() {
    let config = CorrelationConfig {
        max_state_bytes: 16 * 1024,
        ..CorrelationConfig::default()
    };
    let mut correlator = Correlator::new(config).unwrap();
    for index in 0..200 {
        let mut event = fixture(ProcessBinding::Connector).remove(1);
        event.session_id = format!("session-{index}");
        event.process = None;
        event.event_id = event.expected_event_id();
        correlator.ingest(event).unwrap();
        assert!(correlator.retained_bytes() <= 16 * 1024);
    }
    assert!(correlator.take_evicted_events() > 0);
    assert_eq!(correlator.take_evicted_events(), 0);
}
