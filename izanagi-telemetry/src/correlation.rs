use crate::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    pub window_ns: u64,
    pub lateness_ns: u64,
    pub idle_ttl_ns: u64,
    pub max_processes: usize,
    pub max_events: usize,
    pub max_windows: usize,
    pub max_state_bytes: usize,
    pub max_events_per_window: usize,
}
impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            window_ns: 30_000_000_000,
            lateness_ns: 2_000_000_000,
            idle_ttl_ns: 60_000_000_000,
            max_processes: 4096,
            max_events: 16384,
            max_windows: 256,
            max_state_bytes: 64 * 1024 * 1024,
            max_events_per_window: 128,
        }
    }
}

/// Arithmetic event-time correlation. No wall-clock reads or classifier I/O.
/// Call flush at the end of immutable replay; live callers advance by events.
pub struct Correlator {
    config: CorrelationConfig,
    events: VecDeque<TelemetryEnvelope>,
    seen: BTreeSet<String>,
    emitted: BTreeMap<String, FeatureSnapshot>,
    watermarks: BTreeMap<(String, String, String), u64>,
    clock_uncertainties: BTreeMap<(String, String, String), u64>,
    state_bytes: usize,
    state_gaps: BTreeSet<(String, String, String)>,
    global_state_gap: bool,
    evicted_events: u64,
}

impl Correlator {
    pub fn new(config: CorrelationConfig) -> Result<Self, TelemetryError> {
        if config.window_ns == 0
            || config.idle_ttl_ns < config.window_ns
            || config.max_events == 0
            || config.max_windows == 0
            || config.max_processes == 0
            || config.max_state_bytes == 0
            || config.max_events_per_window == 0
        {
            return Err(TelemetryError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            events: VecDeque::new(),
            seen: BTreeSet::new(),
            emitted: BTreeMap::new(),
            watermarks: BTreeMap::new(),
            clock_uncertainties: BTreeMap::new(),
            state_bytes: 0,
            state_gaps: BTreeSet::new(),
            global_state_gap: false,
            evicted_events: 0,
        })
    }

    pub fn ingest(
        &mut self,
        event: TelemetryEnvelope,
    ) -> Result<Vec<FeatureSnapshot>, TelemetryError> {
        event.validate()?;
        let mut event = sanitize_event(&event)?;
        // Host receive times legitimately differ for duplicate source events;
        // they are never part of source identity or event-time arithmetic.
        event.host_received_at_unix_ns = None;
        if self.seen.contains(&event.event_id) {
            if self
                .events
                .iter()
                .any(|old| old.event_id == event.event_id && old != &event)
            {
                self.state_gaps.insert(scope(&event));
                return Err(TelemetryError::InvalidEvent);
            }
            return Ok(Vec::new());
        }
        let scope = scope(&event);
        let watermark = self.watermarks.entry(scope.clone()).or_default();
        *watermark = (*watermark).max(event.observed_monotonic_ns);
        let size = serde_json::to_vec(&event)
            .map_err(|_| TelemetryError::InvalidEvent)?
            .len();
        if size > self.config.max_state_bytes {
            self.state_gaps.insert(scope);
            self.prune();
            return Err(TelemetryError::Oversize);
        }
        self.seen.insert(event.event_id.clone());
        self.events.push_back(event);
        self.refresh_state_bytes();
        self.prune();
        Ok(self.assess(false))
    }

    pub fn flush(&mut self) -> Vec<FeatureSnapshot> {
        self.assess(true)
    }
    /// Advance a known source clock (live heartbeat or replay virtual time).
    /// Arrival-clock estimates must use advance_clock_uncertain instead.
    pub fn advance_clock(&mut self, clock_domain: &str, now_ns: u64) -> Vec<FeatureSnapshot> {
        self.advance_clock_uncertain(clock_domain, now_ns, 0)
    }
    pub fn advance_clock_uncertain(
        &mut self,
        clock_domain: &str,
        now_ns: u64,
        uncertainty_ns: u64,
    ) -> Vec<FeatureSnapshot> {
        for (scope, watermark) in &mut self.watermarks {
            if scope.2 == clock_domain {
                *watermark = (*watermark).max(now_ns);
                let uncertainty = self.clock_uncertainties.entry(scope.clone()).or_default();
                *uncertainty = (*uncertainty).max(uncertainty_ns);
            }
        }
        self.prune();
        self.assess(false)
    }
    pub fn retained_events(&self) -> usize {
        self.events.len()
    }
    pub fn retained_bytes(&self) -> usize {
        self.state_bytes
    }
    /// Both idle expiry and capacity eviction are visible to callers; the latter
    /// additionally marks retained candidate windows with StateEvicted.
    pub fn take_evicted_events(&mut self) -> u64 {
        std::mem::take(&mut self.evicted_events)
    }

    fn prune(&mut self) {
        // Scope count is bounded too: adversarial session IDs cannot grow maps.
        while self.watermarks.len() > self.config.max_processes {
            let Some(oldest) = self
                .watermarks
                .iter()
                .min_by_key(|(_, t)| *t)
                .map(|(s, _)| s.clone())
            else {
                break;
            };
            self.watermarks.remove(&oldest);
            self.clock_uncertainties.remove(&oldest);
            self.state_gaps.remove(&oldest);
            self.global_state_gap = true;
            self.remove_scope(&oldest);
        }
        let expired: BTreeSet<_> = self
            .events
            .iter()
            .filter(|event| {
                self.watermarks.get(&scope(event)).is_some_and(|watermark| {
                    watermark.saturating_sub(event.observed_monotonic_ns) > self.config.idle_ttl_ns
                })
            })
            .map(|e| e.event_id.clone())
            .collect();
        self.remove_events(&expired);
        loop {
            let mut processes: BTreeSet<_> = self
                .events
                .iter()
                .filter_map(|e| e.process.as_ref())
                .collect();
            for event in &self.events {
                if let TelemetryPayload::ProcessFork { parent, child } = &event.payload {
                    processes.insert(parent);
                    processes.insert(child);
                }
            }
            let windows = self
                .events
                .iter()
                .filter(|e| {
                    matches!(
                        e.payload,
                        TelemetryPayload::HttpRequest {
                            method: HttpMethod::Post,
                            ..
                        }
                    )
                })
                .count();
            if self.events.len() <= self.config.max_events
                && self.state_bytes <= self.config.max_state_bytes
                && processes.len() <= self.config.max_processes
                && windows <= self.config.max_windows
            {
                break;
            }
            let Some(event) = self.events.front() else {
                break;
            };
            self.state_gaps.insert(scope(event));
            let id = event.event_id.clone();
            self.remove_events(&BTreeSet::from([id]));
        }
        let retained: BTreeSet<_> = self.events.iter().map(|e| &e.event_id).collect();
        self.emitted.retain(|id, _| retained.contains(id));
        self.refresh_state_bytes();
        // Empty scopes/gap indexes also consume budget. If their history cannot
        // be retained, report degraded coverage globally rather than silently
        // forgetting a dropped credential attempt when that session returns.
        while self.state_bytes > self.config.max_state_bytes {
            let Some(oldest) = self
                .watermarks
                .iter()
                .min_by_key(|(_, t)| *t)
                .map(|(s, _)| s.clone())
            else {
                break;
            };
            self.watermarks.remove(&oldest);
            self.clock_uncertainties.remove(&oldest);
            self.state_gaps.remove(&oldest);
            self.global_state_gap = true;
            self.remove_scope(&oldest);
            self.refresh_state_bytes();
        }
    }

    fn remove_scope(&mut self, target: &(String, String, String)) {
        let ids = self
            .events
            .iter()
            .filter(|e| scope(e) == *target)
            .map(|e| e.event_id.clone())
            .collect();
        self.remove_events(&ids);
    }
    fn remove_events(&mut self, ids: &BTreeSet<String>) {
        self.evicted_events = self.evicted_events.saturating_add(ids.len() as u64);
        self.events.retain(|e| !ids.contains(&e.event_id));
        self.seen.retain(|id| !ids.contains(id));
        self.emitted.retain(|id, _| !ids.contains(id));
        self.refresh_state_bytes();
    }
    fn refresh_state_bytes(&mut self) {
        // Include retained snapshots, duplicate ID indexes and clock scopes;
        // count caps additionally bound allocator/container overhead.
        let events = self
            .events
            .iter()
            .map(|e| {
                serde_json::to_vec(e).map_or(0, |v| v.len())
                    + std::mem::size_of::<TelemetryEnvelope>()
                    + e.event_id.len()
                    + 64
            })
            .sum::<usize>();
        let snapshots = self
            .emitted
            .iter()
            .map(|(id, snapshot)| {
                serde_json::to_vec(snapshot).map_or(0, |v| v.len())
                    + std::mem::size_of::<FeatureSnapshot>()
                    + id.len()
                    + 64
            })
            .sum::<usize>();
        let scopes = self
            .watermarks
            .keys()
            .map(|(s, b, c)| s.len() + b.len() + c.len() + 256)
            .sum::<usize>();
        let gaps = self
            .state_gaps
            .iter()
            .map(|(s, b, c)| s.len() + b.len() + c.len() + 128)
            .sum::<usize>();
        self.state_bytes = events
            .saturating_add(snapshots)
            .saturating_add(scopes)
            .saturating_add(gaps);
    }

    fn assess(&mut self, force: bool) -> Vec<FeatureSnapshot> {
        let mut posts: Vec<_> = self
            .events
            .iter()
            .filter(|e| {
                matches!(
                    e.payload,
                    TelemetryPayload::HttpRequest {
                        method: HttpMethod::Post,
                        ..
                    }
                )
            })
            .filter(|e| {
                force
                    || self.watermarks.get(&scope(e)).is_some_and(|watermark| {
                        *watermark
                            >= e.observed_monotonic_ns
                                .saturating_add(self.config.lateness_ns)
                    })
            })
            .collect();
        posts.sort_by_key(|e| (scope(e), e.observed_monotonic_ns, &e.event_id));
        let mut output = Vec::new();
        for post in posts {
            let mut snapshot = self.snapshot(post);
            if let Some(previous) = self.emitted.get(&post.event_id) {
                snapshot.revision = previous.revision;
                snapshot.supersedes = previous.supersedes.clone();
                if &snapshot == previous {
                    continue;
                }
                snapshot.revision = previous.revision.saturating_add(1);
                snapshot.supersedes = Some(format!("{}:{}", previous.window_id, previous.revision));
            }
            self.emitted.insert(post.event_id.clone(), snapshot.clone());
            output.push(snapshot);
        }
        self.refresh_state_bytes();
        self.prune();
        output
    }

    fn snapshot(&self, post: &TelemetryEnvelope) -> FeatureSnapshot {
        let TelemetryPayload::HttpRequest {
            request_id,
            tuple,
            method,
            policy,
            novelty,
            declared_content_length,
            ..
        } = &post.payload
        else {
            unreachable!()
        };
        let start = post
            .observed_monotonic_ns
            .saturating_sub(self.config.window_ns);
        let events: Vec<_> = self
            .events
            .iter()
            .filter(|e| scope(e) == scope(post))
            .collect();
        let mut quality = post.quality.clone();
        let mut evidence = BTreeSet::from([post.event_id.clone()]);
        if self.global_state_gap || self.state_gaps.contains(&scope(post)) {
            add_issue(&mut quality, QualityIssue::StateEvicted);
        }
        if self
            .clock_uncertainties
            .get(&scope(post))
            .is_some_and(|u| *u > self.config.lateness_ns)
        {
            add_issue(&mut quality, QualityIssue::ClockUncertain);
        }
        if post.clock_uncertainty_ns > self.config.lateness_ns {
            add_issue(&mut quality, QualityIssue::ClockUncertain);
        }
        // The same exact tuple must identify one live socket incarnation.
        let candidates: Vec<_> = events
            .iter()
            .copied()
            .filter(|e| {
                if e.observed_monotonic_ns > post.observed_monotonic_ns {
                    return false;
                }
                if let TelemetryPayload::SocketConnect {
                    tuple: candidate,
                    socket,
                    ..
                } = &e.payload
                {
                    candidate == tuple
                        && !events.iter().any(|later| {
                            later.observed_monotonic_ns >= e.observed_monotonic_ns
                                && later.observed_monotonic_ns <= post.observed_monotonic_ns
                                && matches!(&later.payload, TelemetryPayload::SocketLifecycle {
                        socket: closed, state: SocketState::Closed } if closed == socket)
                        })
                } else {
                    false
                }
            })
            .collect();
        let (process, binding) = if candidates.len() == 1 {
            let connection = candidates[0];
            evidence.insert(connection.event_id.clone());
            let TelemetryPayload::SocketConnect {
                binding, socket, ..
            } = &connection.payload
            else {
                unreachable!()
            };
            let shared = events.iter().any(|e| {
                e.observed_monotonic_ns >= connection.observed_monotonic_ns
                    && e.observed_monotonic_ns <= post.observed_monotonic_ns
                    && matches!(&e.payload, TelemetryPayload::SocketLifecycle { socket: changed,
                    state: SocketState::Shared | SocketState::Transferred } if changed == socket)
            });
            for issue in &connection.quality.issues {
                add_issue(&mut quality, *issue);
            }
            if shared {
                add_issue(&mut quality, QualityIssue::SocketShared);
            }
            if *binding != ProcessBinding::ConfirmedWriter {
                add_issue(&mut quality, QualityIssue::MissingWriter);
            }
            (
                connection.process.clone(),
                if shared {
                    ProcessBinding::Unknown
                } else {
                    *binding
                },
            )
        } else {
            add_issue(&mut quality, QualityIssue::SocketAmbiguous);
            (None, ProcessBinding::Unknown)
        };
        if process.is_none() {
            add_issue(&mut quality, QualityIssue::MissingProcessIdentity);
        }
        // A proxy-provided process hint is never evidence. Only kernel socket
        // observation above may provide a process binding.
        let mut attempts = BTreeSet::new();
        let mut succeeded = BTreeSet::new();
        let mut failed = BTreeSet::new();
        let mut latest_access = None;
        let mut rules = BTreeSet::new();
        for e in &events {
            if e.observed_monotonic_ns < start
                || e.observed_monotonic_ns > post.observed_monotonic_ns
            {
                continue;
            }
            for issue in &e.quality.issues {
                if matches!(
                    issue,
                    QualityIssue::EventLoss
                        | QualityIssue::SourceRestart
                        | QualityIssue::SourceUnavailable
                        | QualityIssue::StorageGap
                        | QualityIssue::InvalidEvent
                        | QualityIssue::ClockUnknown
                        | QualityIssue::ClockUncertain
                ) {
                    add_issue(&mut quality, *issue);
                    evidence.insert(e.event_id.clone());
                }
            }
            match &e.payload {
                TelemetryPayload::ObservationGap { reason, .. } => {
                    add_issue(&mut quality, *reason);
                    evidence.insert(e.event_id.clone());
                }
                TelemetryPayload::CollectorHealth { healthy: false } => {
                    add_issue(&mut quality, QualityIssue::SourceUnavailable);
                    evidence.insert(e.event_id.clone());
                }
                _ => {}
            }
            let proof = match (&process, &e.process) {
                (Some(p), Some(other)) => {
                    self.related(p, other, &events, post.observed_monotonic_ns)
                }
                _ => None,
            };
            let Some(proof) = proof else {
                continue;
            };
            if let TelemetryPayload::FileAccessAttempt { role, .. } = &e.payload {
                for issue in &e.quality.issues {
                    add_issue(&mut quality, *issue);
                }
                if *role == FileRole::Unknown {
                    add_issue(&mut quality, QualityIssue::PathUnresolved);
                    evidence.insert(e.event_id.clone());
                    evidence.extend(proof.iter().cloned());
                }
            }
            match &e.payload {
                TelemetryPayload::FileAccessAttempt {
                    attempt_id,
                    role: FileRole::Credential,
                    ..
                } => {
                    attempts.insert((e.process.clone(), attempt_id.clone()));
                    latest_access = Some(latest_access.unwrap_or(0).max(e.observed_monotonic_ns));
                    evidence.insert(e.event_id.clone());
                    evidence.extend(proof);
                    for issue in &e.quality.issues {
                        add_issue(&mut quality, *issue);
                    }
                    if e.clock_uncertainty_ns > self.config.lateness_ns {
                        add_issue(&mut quality, QualityIssue::ClockUncertain);
                    }
                    if post
                        .observed_monotonic_ns
                        .saturating_sub(e.observed_monotonic_ns)
                        <= post
                            .clock_uncertainty_ns
                            .saturating_add(e.clock_uncertainty_ns)
                        && (post.clock_uncertainty_ns > 0 || e.clock_uncertainty_ns > 0)
                    {
                        add_issue(&mut quality, QualityIssue::ClockUncertain);
                    }
                }
                TelemetryPayload::RuleMatch { rule_code } => {
                    rules.insert(sanitize_rule_code(rule_code));
                    evidence.insert(e.event_id.clone());
                }
                _ => {}
            }
        }
        for e in &events {
            if e.observed_monotonic_ns < start
                || e.observed_monotonic_ns > post.observed_monotonic_ns
            {
                continue;
            }
            if let TelemetryPayload::FileOpenOutcome {
                attempt_id,
                outcome,
            } = &e.payload
            {
                if !attempts.contains(&(e.process.clone(), attempt_id.clone())) {
                    continue;
                }
                evidence.insert(e.event_id.clone());
                for issue in &e.quality.issues {
                    add_issue(&mut quality, *issue);
                }
                match outcome {
                    OpenOutcome::Succeeded { .. } => {
                        succeeded.insert((e.process.clone(), attempt_id.clone()));
                    }
                    OpenOutcome::Failed { .. } => {
                        failed.insert((e.process.clone(), attempt_id.clone()));
                    }
                    OpenOutcome::Unknown => {
                        add_issue(&mut quality, QualityIssue::MissingOutcome);
                    }
                }
            }
        }
        if attempts
            .iter()
            .any(|id| !succeeded.contains(id) && !failed.contains(id))
            || succeeded.iter().any(|id| failed.contains(id))
        {
            add_issue(&mut quality, QualityIssue::MissingOutcome);
        }
        // A different clock domain is not reconciled using host arrival times.
        if let Some(process) = &process
            && self.events.iter().any(|e| {
                e.session_id == post.session_id
                    && e.guest_boot_id == post.guest_boot_id
                    && e.clock_domain != post.clock_domain
                    && e.process.as_ref() == Some(process)
                    && matches!(
                        e.payload,
                        TelemetryPayload::FileAccessAttempt {
                            role: FileRole::Credential,
                            ..
                        }
                    )
            })
        {
            add_issue(&mut quality, QualityIssue::ClockUnknown);
        }
        let outcomes: Vec<_> = events.iter().copied().filter(|e|
            e.observed_monotonic_ns >= post.observed_monotonic_ns
            && e.source_instance_id == post.source_instance_id
            && matches!(&e.payload, TelemetryPayload::HttpOutcome { request_id: id, .. } if id == request_id))
            .collect();
        let (client, upstream, response, outcome) = if outcomes.len() == 1 {
            let e = outcomes[0];
            evidence.insert(e.event_id.clone());
            for issue in &e.quality.issues {
                add_issue(&mut quality, *issue);
            }
            let TelemetryPayload::HttpOutcome {
                client_bytes_received,
                upstream_bytes_written,
                response_bytes_received,
                outcome,
                ..
            } = &e.payload
            else {
                unreachable!()
            };
            (
                Some(*client_bytes_received),
                Some(*upstream_bytes_written),
                Some(*response_bytes_received),
                *outcome,
            )
        } else {
            add_issue(&mut quality, QualityIssue::MissingOutcome);
            (None, None, None, TransferOutcome::Unknown)
        };
        let observation_end = outcomes
            .iter()
            .map(|e| e.observed_monotonic_ns)
            .max()
            .unwrap_or(post.observed_monotonic_ns);
        for e in &events {
            if e.observed_monotonic_ns <= post.observed_monotonic_ns
                || e.observed_monotonic_ns > observation_end
            {
                continue;
            }
            match &e.payload {
                TelemetryPayload::ObservationGap { reason, .. } => {
                    add_issue(&mut quality, *reason);
                    evidence.insert(e.event_id.clone());
                }
                TelemetryPayload::CollectorHealth { healthy: false } => {
                    add_issue(&mut quality, QualityIssue::SourceUnavailable);
                    evidence.insert(e.event_id.clone());
                }
                TelemetryPayload::SocketLifecycle {
                    socket: changed,
                    state: SocketState::Shared | SocketState::Transferred,
                } if candidates.iter().any(|connection| {
                    matches!(&connection.payload,
                        TelemetryPayload::SocketConnect { socket, .. } if socket == changed)
                }) =>
                {
                    add_issue(&mut quality, QualityIssue::SocketShared);
                    evidence.insert(e.event_id.clone());
                }
                _ => {}
            }
        }
        // Source sequence gaps are checked after sorting; normal arrival reorder
        // does not manufacture a gap. Filters must assign sequence after filtering.
        let mut sequences: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
        for e in &events {
            if e.observed_monotonic_ns >= start
                && e.observed_monotonic_ns <= post.observed_monotonic_ns
            {
                sequences
                    .entry(&e.source_instance_id)
                    .or_default()
                    .push(e.source_seq);
            }
        }
        for seqs in sequences.values_mut() {
            seqs.sort_unstable();
            seqs.dedup();
            if seqs
                .windows(2)
                .any(|pair| pair[1] != pair[0].saturating_add(1))
            {
                add_issue(&mut quality, QualityIssue::EventLoss);
            }
        }
        if evidence.len() > self.config.max_events_per_window {
            add_issue(&mut quality, QualityIssue::WindowTruncated);
            evidence = evidence
                .into_iter()
                .take(self.config.max_events_per_window)
                .collect();
        }
        quality.issues.sort();
        quality.issues.dedup();
        FeatureSnapshot {
            feature_version: FEATURE_VERSION,
            session_id: post.session_id.clone(),
            window_id: post.event_id.clone(),
            revision: 0,
            supersedes: None,
            process,
            binding,
            started_monotonic_ns: start,
            ended_monotonic_ns: post.observed_monotonic_ns,
            clock_domain: post.clock_domain.clone(),
            credential_access_attempts: attempts.len() as u32,
            credential_open_succeeded: succeeded.len() as u32,
            credential_open_failed: failed.len() as u32,
            access_to_post_ns: latest_access.map(|t| post.observed_monotonic_ns.saturating_sub(t)),
            method: *method,
            policy: *policy,
            novelty: *novelty,
            declared_content_length: *declared_content_length,
            client_bytes_received: client,
            upstream_bytes_written: upstream,
            response_bytes_received: response,
            transfer_outcome: outcome,
            rule_matches: rules.into_iter().collect(),
            quality,
            evidence_event_ids: evidence.into_iter().collect(),
        }
    }

    fn related(
        &self,
        first: &ProcessKey,
        second: &ProcessKey,
        events: &[&TelemetryEnvelope],
        at: u64,
    ) -> Option<Vec<String>> {
        if first == second {
            return Some(Vec::new());
        }
        if first.session_id != second.session_id
            || first.guest_boot_id != second.guest_boot_id
            || first.pid_namespace != second.pid_namespace
        {
            return None;
        }
        // Ancestor/descendant only: siblings are not assumed to exchange data.
        let ancestor = |descendant: &ProcessKey, wanted: &ProcessKey| {
            let mut current = descendant.clone();
            let mut visited = BTreeSet::new();
            let mut proof = Vec::new();
            for _ in 0..32 {
                if !visited.insert(current.clone()) {
                    return None;
                }
                let edges: Vec<_> = events
                    .iter()
                    .filter_map(|e| match &e.payload {
                        TelemetryPayload::ProcessFork { parent, child }
                            if child == &current
                                && e.observed_monotonic_ns <= at
                                && e.quality.issues.is_empty()
                                && e.clock_uncertainty_ns == 0 =>
                        {
                            Some((parent, &e.event_id))
                        }
                        _ => None,
                    })
                    .collect();
                if edges.len() != 1 {
                    return None;
                }
                proof.push(edges[0].1.clone());
                if edges[0].0 == wanted {
                    return Some(proof);
                }
                current = edges[0].0.clone();
            }
            None
        };
        ancestor(first, second).or_else(|| ancestor(second, first))
    }
}

fn scope(event: &TelemetryEnvelope) -> (String, String, String) {
    (
        event.session_id.clone(),
        event.guest_boot_id.clone(),
        event.clock_domain.clone(),
    )
}
fn add_issue(quality: &mut ObservationQuality, issue: QualityIssue) {
    if !quality.issues.contains(&issue) {
        quality.issues.push(issue);
    }
}

/// A warning about observed attempts, never a claim of data exfiltration.
pub fn deterministic_rule(snapshot: &FeatureSnapshot) -> ThreatClass {
    let projection = snapshot.projection(FeatureMode::Correlated);
    if !projection.eligible() {
        return ThreatClass::Unknown;
    }
    if snapshot.credential_access_attempts > 0 && snapshot.novelty == DestinationNovelty::Novel {
        ThreatClass::AccessPostSuspected
    } else {
        ThreatClass::Normal
    }
}
