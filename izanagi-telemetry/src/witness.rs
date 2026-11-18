use crate::{HostWitnessMismatch, SocketIdentity, TelemetryEnvelope, TelemetryPayload};
use std::{collections::BTreeSet, net::SocketAddr};

/// A finalized, single TCP connection observed outside the guest.
/// The caller supplies guest events scoped to the same connection lifetime
/// using independently aligned capture boundaries.
pub struct HostWitnessFlow {
    pub number: u64,
    pub client: SocketAddr,
    pub remote: SocketAddr,
    /// Contiguous outbound stream bytes from offset zero, excluding retransmits.
    pub outbound_bytes: u64,
}

impl HostWitnessFlow {
    pub fn compare(
        &self,
        session: &str,
        events: &[TelemetryEnvelope],
    ) -> Option<HostWitnessMismatch> {
        if self.outbound_bytes == 0 {
            return None;
        }
        let mut connects = BTreeSet::<&SocketIdentity>::new();
        let mut writes = Vec::new();
        for event in events.iter().filter(|event| event.session_id == session) {
            match &event.payload {
                TelemetryPayload::SocketConnect { socket, tuple, .. }
                    if tuple.client == self.client && tuple.local == self.remote =>
                {
                    connects.insert(socket);
                }
                TelemetryPayload::SocketWrite {
                    socket,
                    tuple,
                    stream_start,
                    stream_end,
                } if tuple.client == self.client
                    && tuple.local == self.remote
                    && stream_start < stream_end =>
                {
                    let process = event.process.as_ref().filter(|process| {
                        process.session_id == session
                            && process.guest_boot_id == event.guest_boot_id
                            && event.quality.issues.is_empty()
                    });
                    writes.push((socket, *stream_start, *stream_end, process));
                }
                _ => {}
            }
        }
        let identities: BTreeSet<_> = connects
            .iter()
            .copied()
            .chain(writes.iter().map(|write| write.0))
            .collect();
        let missing_connect = connects.len() != 1 || identities.len() != 1;
        writes.sort_unstable_by_key(|write| (write.1, write.2));
        let missing_write = identities.len() != 1 || !covers(&writes, self.outbound_bytes, false);
        let missing_process = missing_write || !covers(&writes, self.outbound_bytes, true);
        (missing_connect || missing_write || missing_process).then(|| HostWitnessMismatch {
            session_id: session.to_owned(),
            flow_number: self.number,
            missing_connect,
            missing_write,
            missing_process,
        })
    }
}

type WriteEvidence<'a> = (&'a SocketIdentity, u64, u64, Option<&'a crate::ProcessKey>);

fn covers(writes: &[WriteEvidence<'_>], bytes: u64, attributed: bool) -> bool {
    let mut covered = 0;
    for &(_, start, end, process) in writes {
        if start > covered {
            return false;
        }
        if !attributed || process.is_some() {
            covered = covered.max(end);
            if covered >= bytes {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_flow_without_guest_events_reports_all_evidence_missing() {
        let flow = HostWitnessFlow {
            number: 1,
            client: "192.0.2.1:12345".parse().unwrap(),
            remote: "192.0.2.2:443".parse().unwrap(),
            outbound_bytes: 42,
        };
        let mismatch = flow.compare("session", &[]).unwrap();
        assert!(mismatch.missing_connect && mismatch.missing_write && mismatch.missing_process);
    }
}
