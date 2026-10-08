//! Linux probe setup and bounded event forwarding.
use super::{boot_time_offset, convert_raw_event, monotonic_ns, observation, read_raw_event};
use crate::event::SyscallEvent;
use aya::{
    Ebpf,
    maps::{MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
};
use izanagi_telemetry::schema::{QualityIssue, TelemetryEnvelope, TelemetryPayload};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

type RequiredProbe = (
    &'static str,
    &'static str,
    &'static str,
    &'static [(&'static str, usize, usize)],
);
type Observation = Option<(observation::Collector, mpsc::Sender<TelemetryEnvelope>)>;
const REQUIRED: &[RequiredProbe] = &[
    (
        "sys_enter_openat",
        "syscalls",
        "sys_enter_openat",
        &[("dfd", 16, 8), ("filename", 24, 8), ("flags", 32, 8)],
    ),
    (
        "sys_exit_openat",
        "syscalls",
        "sys_exit_openat",
        &[("ret", 16, 8)],
    ),
    (
        "sched_process_fork",
        "sched",
        "sched_process_fork",
        &[("parent_pid", 24, 4), ("child_pid", 44, 4)],
    ),
    ("sched_process_exec", "sched", "sched_process_exec", &[]),
    ("sched_process_exit", "sched", "sched_process_exit", &[]),
    (
        "inet_sock_set_state",
        "sock",
        "inet_sock_set_state",
        &[
            ("skaddr", 8, 8),
            ("newstate", 20, 4),
            ("sport", 24, 2),
            ("dport", 26, 2),
            ("family", 28, 2),
            ("protocol", 30, 2),
        ],
    ),
];

const SYSCALL_PROBES: &[(&str, &str, &str)] = &[
    // (program_name, category, tracepoint_name)
    // File (#22)
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("sys_enter_read", "syscalls", "sys_enter_read"),
    ("sys_enter_write", "syscalls", "sys_enter_write"),
    ("sys_enter_stat", "syscalls", "sys_enter_newstat"),
    ("sys_enter_access", "syscalls", "sys_enter_access"),
    // Network (#23)
    ("sys_enter_connect", "syscalls", "sys_enter_connect"),
    ("sys_enter_sendto", "syscalls", "sys_enter_sendto"),
    ("sys_enter_recvfrom", "syscalls", "sys_enter_recvfrom"),
    ("sys_enter_socket", "syscalls", "sys_enter_socket"),
    ("sys_enter_bind", "syscalls", "sys_enter_bind"),
    // Process (#24)
    ("sys_enter_execve", "syscalls", "sys_enter_execve"),
    ("sys_enter_clone", "syscalls", "sys_enter_clone"),
    ("sys_enter_fork", "syscalls", "sys_enter_fork"),
];

pub(super) fn attach_required(bpf: &mut Ebpf, behavior: bool) -> anyhow::Result<()> {
    if behavior {
        for map in [
            "EVENTS",
            "DROPS",
            "PROCESS_GENERATIONS",
            "OPEN_ATTEMPTS",
            "SOCKET_GENERATIONS",
        ] {
            anyhow::ensure!(bpf.map(map).is_some(), "required eBPF map missing: {map}");
        }
        for &(program, category, name, fields) in REQUIRED {
            super::abi::validate_tracepoint(category, name, fields)?;
            let program: &mut TracePoint = bpf
                .program_mut(program)
                .ok_or_else(|| anyhow::anyhow!("required eBPF probe missing"))?
                .try_into()?;
            program.load()?;
            program.attach(category, name)?;
        }
    } else {
        // Outcomes are also useful in the legacy stream.
        let program: &mut TracePoint = bpf
            .program_mut("sys_exit_openat")
            .ok_or_else(|| anyhow::anyhow!("required open outcome probe missing"))?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_exit_openat")?;
    }

    Ok(())
}

pub(super) fn attach_syscalls(bpf: &mut Ebpf, behavior: bool) -> anyhow::Result<u64> {
    let mut unavailable = 0;
    for &(prog_name, category, tp_name) in SYSCALL_PROBES {
        unavailable += u64::from(attach_optional(
            bpf, behavior, prog_name, category, tp_name,
        )?);
    }
    Ok(unavailable)
}

/// Returns true when an optional probe is unavailable (not when intentionally skipped).
fn attach_optional(
    bpf: &mut Ebpf,
    behavior: bool,
    prog_name: &str,
    category: &str,
    tp_name: &str,
) -> anyhow::Result<bool> {
    if behavior && prog_name == "sys_enter_openat" {
        return Ok(false);
    }
    let program: &mut TracePoint = match bpf.program_mut(prog_name) {
        Some(p) => match p.try_into() {
            Ok(tp) => tp,
            Err(e) => {
                eprintln!("eBPF: skipping '{}' (not a tracepoint: {})", prog_name, e);
                return Ok(true);
            }
        },
        None => {
            eprintln!(
                "eBPF: program '{}' not found in object, skipping",
                prog_name
            );
            return Ok(true);
        }
    };
    program.load()?;
    // tracepoint が存在しない場合はスキップ（aarch64 等で一部の syscall がないため）
    if let Err(e) = program.attach(category, tp_name) {
        eprintln!(
            "eBPF: skipping tracepoint '{}/{}' (not available: {})",
            category, tp_name, e
        );
        return Ok(true);
    }
    Ok(false)
}

pub(super) struct KernelInput {
    ring: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
    boot_offset: Duration,
}
impl KernelInput {
    pub(super) fn take(bpf: &mut Ebpf) -> anyhow::Result<Self> {
        let events_map = bpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("eBPF map 'EVENTS' not found"))?;
        let ring = RingBuf::try_from(events_map)?;
        let drop_map = bpf
            .take_map("DROPS")
            .ok_or_else(|| anyhow::anyhow!("required drop counter missing"))?;
        let drops = PerCpuArray::try_from(drop_map)?;
        let boot_offset = boot_time_offset()?;
        Ok(Self {
            ring,
            drops,
            boot_offset,
        })
    }

    pub(super) async fn run(
        mut self,
        tx: mpsc::Sender<Arc<SyscallEvent>>,
        observation: Observation,
        unavailable: u64,
    ) {
        let mut forwarder = Forwarder {
            observation,
            lost_pending: 0,
            kernel_losses: 0,
        };
        let mut checked = tokio::time::Instant::now();
        forwarder.initial_health(unavailable);
        let mut backoff_ms = 1;
        // Polling remains adaptive (1-10ms) until aya supplies a stable AsyncRingBuf.
        loop {
            let mut got_event = false;
            while let Some(item) = self.ring.next() {
                got_event = true;
                if !forwarder.forward(&item, self.boot_offset, &tx).await {
                    return;
                }
            }
            if checked.elapsed() >= Duration::from_millis(100) {
                checked = tokio::time::Instant::now();
                forwarder.check_losses(&self.drops);
            }
            if tx.is_closed() {
                return;
            }
            backoff_ms = if got_event {
                1
            } else {
                (backoff_ms * 2).min(10)
            };
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
    }
}

struct Forwarder {
    observation: Observation,
    lost_pending: u64,
    kernel_losses: u64,
}
impl Forwarder {
    fn initial_health(&mut self, unavailable: u64) {
        if let Some((collector, tx)) = self.observation.as_mut() {
            let event = collector.envelope(
                0,
                None,
                None,
                TelemetryPayload::CollectorHealth { healthy: true },
                vec![
                    QualityIssue::MissingWriter,
                    QualityIssue::UnsupportedProtocol,
                ],
            );
            if tx.try_send(event).is_err() {
                self.lost_pending += 1;
            }
            if unavailable > 0 {
                self.lost_pending += unavailable;
            }
        }
    }

    async fn forward(
        &mut self,
        data: &[u8],
        boot_offset: Duration,
        tx: &mpsc::Sender<Arc<SyscallEvent>>,
    ) -> bool {
        if data.len() != izanagi_common::RAW_EVENT_SIZE {
            self.lost_pending += 1;
            return true;
        }

        // アライメントを検証してから読み取り (#2)
        let raw = read_raw_event(data);

        if let Some((collector, telemetry)) = self.observation.as_mut()
            && raw.tgid != std::process::id()
        {
            for event in collector.convert(&raw) {
                if telemetry.try_send(event).is_err() {
                    self.lost_pending += 1;
                }
            }
        }
        // RawSyscallEvent → SyscallEvent 変換 (#93)
        let event = match convert_raw_event(&raw, boot_offset) {
            Some(e) => e,
            None => return true,
        };

        // try_send でブロックを回避し、Full の場合のみ await (#8)
        let event = Arc::new(event);
        match tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(event)) => {
                if tx.send(event).await.is_err() {
                    // receiver が drop された → 終了
                    return false;
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // receiver が drop された → 終了
                return false;
            }
        }
        true
    }

    fn check_losses(&mut self, drops: &PerCpuArray<MapData, u64>) {
        match drops.get(&0, 0) {
            Ok(values) => {
                let total = values.iter().copied().sum::<u64>();
                self.lost_pending = self
                    .lost_pending
                    .saturating_add(total.saturating_sub(self.kernel_losses));
                self.kernel_losses = total;
            }
            Err(_) => {
                self.lost_pending += 1;
            }
        }
        self.emit_pending_loss();
    }

    fn emit_pending_loss(&mut self) {
        if self.lost_pending > 0
            && let Some((collector, telemetry)) = self.observation.as_mut()
        {
            let timestamp = monotonic_ns();
            let event = collector.envelope(
                timestamp,
                None,
                None,
                TelemetryPayload::ObservationGap {
                    dropped: self.lost_pending,
                    reason: QualityIssue::EventLoss,
                },
                vec![QualityIssue::EventLoss],
            );
            if telemetry.try_send(event).is_ok() {
                self.lost_pending = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use izanagi_common::{RAW_ABI_VERSION, RAW_EVENT_SIZE, RawSyscallEvent, SyscallId};

    fn open_bytes(tgid: u32) -> Vec<u8> {
        let mut bytes = vec![0; RAW_EVENT_SIZE];
        for (offset, value) in [
            (
                std::mem::offset_of!(RawSyscallEvent, abi_version),
                RAW_ABI_VERSION,
            ),
            (
                std::mem::offset_of!(RawSyscallEvent, syscall_id),
                SyscallId::OpenAt as u32,
            ),
            (std::mem::offset_of!(RawSyscallEvent, tgid), tgid),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        bytes
    }

    #[tokio::test]
    async fn legacy_backpressure_ends_when_receiver_closes() {
        let mut forwarder = Forwarder {
            observation: None,
            lost_pending: 0,
            kernel_losses: 0,
        };
        let (tx, rx) = mpsc::channel(1);
        let bytes = open_bytes(0);
        assert!(forwarder.forward(&bytes, Duration::ZERO, &tx).await);
        let forwarding = forwarder.forward(&bytes, Duration::ZERO, &tx);
        tokio::pin!(forwarding);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut forwarding)
                .await
                .is_err()
        );
        drop(rx);
        assert!(!forwarding.await);
    }

    #[tokio::test]
    async fn lost_observations_are_retained_until_the_gap_can_be_sent() {
        let collector = observation::Collector::new("test-session".into()).unwrap();
        let (telemetry, mut events) = mpsc::channel(1);
        let mut forwarder = Forwarder {
            observation: Some((collector, telemetry)),
            lost_pending: 0,
            kernel_losses: 0,
        };
        forwarder.initial_health(3);
        let (legacy, _rx) = mpsc::channel(1);
        assert!(
            forwarder
                .forward(b"truncated", Duration::ZERO, &legacy)
                .await
        );
        forwarder.emit_pending_loss(); // Health still occupies the only slot.
        assert_eq!(forwarder.lost_pending, 4);
        assert!(matches!(
            events.recv().await.unwrap().payload,
            TelemetryPayload::CollectorHealth { healthy: true }
        ));
        forwarder.emit_pending_loss();
        assert_eq!(forwarder.lost_pending, 0);
        assert!(matches!(
            events.recv().await.unwrap().payload,
            TelemetryPayload::ObservationGap {
                dropped: 4,
                reason: QualityIssue::EventLoss
            }
        ));
    }

    #[tokio::test]
    async fn agent_events_skip_telemetry_but_keep_the_legacy_stream() {
        let collector = observation::Collector::new("test-session".into()).unwrap();
        let (telemetry, mut events) = mpsc::channel(1);
        let mut forwarder = Forwarder {
            observation: Some((collector, telemetry)),
            lost_pending: 0,
            kernel_losses: 0,
        };
        let (legacy, mut rx) = mpsc::channel(1);
        assert!(
            forwarder
                .forward(&open_bytes(std::process::id()), Duration::ZERO, &legacy)
                .await
        );
        assert_eq!(rx.recv().await.unwrap().tgid, std::process::id());
        assert!(events.try_recv().is_err());
    }
}
