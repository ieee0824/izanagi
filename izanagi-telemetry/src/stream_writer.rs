//! Writer attribution requires complete byte coverage, not a connect caller.
use crate::*;

type Proof = (ProcessKey, Vec<String>);

pub(crate) fn prove(
    post: &TelemetryEnvelope,
    connection: &TelemetryEnvelope,
    events: &[&TelemetryEnvelope],
) -> Result<Option<Proof>, QualityIssue> {
    let TelemetryPayload::HttpRequest { tuple, .. } = &post.payload else {
        return Err(QualityIssue::InvalidEvent);
    };
    let Some(range) = request_range(post, events)? else {
        return Ok(None);
    };
    let TelemetryPayload::HttpStreamRange {
        stream_start,
        stream_end,
        ..
    } = range.payload
    else {
        unreachable!()
    };
    if !range.quality.issues.is_empty() {
        return Err(range.quality.issues[0]);
    }
    let TelemetryPayload::SocketConnect { socket, .. } = &connection.payload else {
        unreachable!()
    };
    let writes = matching_writes(
        post,
        connection,
        events,
        socket,
        tuple,
        stream_start,
        stream_end,
    );
    let (process, mut evidence) = cover(writes, stream_start, stream_end)?;
    evidence.push(range.event_id.clone());
    Ok(Some((process, evidence)))
}

fn request_range<'a>(
    post: &TelemetryEnvelope,
    events: &[&'a TelemetryEnvelope],
) -> Result<Option<&'a TelemetryEnvelope>, QualityIssue> {
    let TelemetryPayload::HttpRequest {
        connection_id,
        request_id,
        ..
    } = &post.payload
    else {
        unreachable!()
    };
    let ranges: Vec<_> = events
        .iter()
        .copied()
        .filter(|e| {
            e.source_instance_id == post.source_instance_id
                && e.observed_monotonic_ns <= post.observed_monotonic_ns
                && matches!(&e.payload, TelemetryPayload::HttpStreamRange {
                connection_id: c, request_id: r, ..
            } if c == connection_id && r == request_id)
        })
        .collect();
    if ranges.is_empty() {
        return Ok(None);
    } // Legacy fixture / audit format.
    if ranges.len() != 1 {
        return Err(QualityIssue::SocketAmbiguous);
    }
    Ok(Some(ranges[0]))
}

fn matching_writes<'a>(
    post: &TelemetryEnvelope,
    connection: &TelemetryEnvelope,
    events: &[&'a TelemetryEnvelope],
    socket: &SocketIdentity,
    tuple: &SocketTuple,
    start: u64,
    end: u64,
) -> Vec<(&'a TelemetryEnvelope, u64, u64)> {
    events
        .iter()
        .copied()
        .filter_map(|e| {
            if e.observed_monotonic_ns < connection.observed_monotonic_ns
                || e.observed_monotonic_ns > post.observed_monotonic_ns
            {
                return None;
            }
            let TelemetryPayload::SocketWrite {
                socket: s,
                tuple: t,
                stream_start,
                stream_end,
            } = &e.payload
            else {
                return None;
            };
            (s == socket && t == tuple && *stream_start < end && *stream_end > start).then_some((
                e,
                (*stream_start).max(start),
                (*stream_end).min(end),
            ))
        })
        .collect()
}

fn cover(
    mut writes: Vec<(&TelemetryEnvelope, u64, u64)>,
    start: u64,
    end: u64,
) -> Result<Proof, QualityIssue> {
    writes.sort_by_key(|(_, start, end)| (*start, *end));
    let mut cursor = start;
    let mut writer = None;
    let mut evidence = Vec::new();
    for (event, start, end) in writes {
        if start != cursor {
            return Err(QualityIssue::SocketAmbiguous);
        }
        if let Some(issue) = event.quality.issues.first() {
            return Err(*issue);
        }
        let process = event
            .process
            .as_ref()
            .ok_or(QualityIssue::MissingProcessIdentity)?;
        if writer.is_some_and(|p| p != process) {
            return Err(QualityIssue::SocketShared);
        }
        writer = Some(process);
        evidence.push(event.event_id.clone());
        cursor = end;
    }
    if cursor != end {
        return Err(QualityIssue::MissingWriter);
    }
    Ok((writer.ok_or(QualityIssue::MissingWriter)?.clone(), evidence))
}
