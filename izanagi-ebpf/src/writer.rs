//! Metadata-only TCP stream proof. Entry/return sequence deltas must exactly
//! equal successful bytes; lock-dropping interleaved sends remain unproven.
use super::*;
use aya_ebpf::{
    macros::{kprobe, kretprobe},
    maps::Array,
    programs::{ProbeContext, RetProbeContext},
};

#[map]
static SOCKET_LAYOUT: Array<[u32; 4]> = Array::with_max_entries(1, 0);
#[map]
static SOCKET_STREAMS: HashMap<u64, Stream> = HashMap::with_max_entries(4096, 0);
#[map]
static SEND_ATTEMPTS: HashMap<u64, Attempt> = HashMap::with_max_entries(4096, 0);
#[map]
static UNPROVEN_STREAMS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[derive(Clone, Copy)]
struct Stream {
    generation: u64,
    namespace: u64,
    initial_seq: u32,
    family: u16,
    source_port: u16,
    destination_port: u16,
    _pad: u16,
    source: [u8; 16],
    destination: [u8; 16],
}
#[derive(Clone, Copy)]
struct Attempt {
    address: u64,
    generation: u64,
    timestamp: u64,
    requested: u64,
    sequence: u32,
    _pad: u32,
}

#[inline(always)]
fn field<T: Copy>(address: u64, offset: usize) -> Result<T, i64> {
    unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((address + offset as u64) as *const T) }
}

#[inline(always)]
pub(super) unsafe fn socket_state(event: *mut RawSyscallEvent, address: u64, state: u32) {
    let Some(layout) = SOCKET_LAYOUT.get(0) else {
        return;
    };
    if layout[3] != 1 {
        return;
    }
    let net = match field::<u64>(address, layout[1] as usize) {
        Ok(v) => v,
        Err(_) => {
            lost();
            return;
        }
    };
    let namespace = match field::<u32>(net, layout[2] as usize) {
        Ok(v) => v as u64,
        Err(_) => {
            lost();
            return;
        }
    };
    (*event).net_namespace = namespace;
    if state == 1 && namespace != 0 {
        if record_stream(event, address, layout[0] as usize).is_err() {
            lost();
        }
    } else if state == 7 {
        let _ = SOCKET_STREAMS.remove(&address);
        let _ = UNPROVEN_STREAMS.remove(&address);
    }
}

#[inline(always)]
unsafe fn record_stream(
    event: *mut RawSyscallEvent,
    address: u64,
    seq_offset: usize,
) -> Result<(), i64> {
    // Fast Open / pre-handshake writes cannot be renumbered as byte zero.
    if UNPROVEN_STREAMS
        .get(&address)
        .is_some_and(|g| *g == 0 || *g == (*event).socket_generation)
    {
        return Ok(());
    }
    let stream = Stream {
        generation: (*event).socket_generation,
        namespace: (*event).net_namespace,
        initial_seq: field(address, seq_offset)?,
        family: (*event).family,
        source_port: (*event).source_port,
        destination_port: (*event).destination_port,
        _pad: 0,
        source: (*event).source_address,
        destination: (*event).destination_address,
    };
    SOCKET_STREAMS.insert(&address, &stream, 0)
}

#[kprobe]
pub fn tcp_sendmsg_enter(ctx: ProbeContext) -> u32 {
    if send_enter(&ctx).is_err() {
        lost();
    }
    0
}
#[inline(always)]
fn send_enter(ctx: &ProbeContext) -> Result<(), i64> {
    let address: u64 = ctx.arg(0).ok_or(1)?;
    let Some(stream) = (unsafe { SOCKET_STREAMS.get(&address) }) else {
        // A Fast Open send can precede the SYN_SENT tracepoint itself.
        let generation = unsafe { SOCKET_GENERATIONS.get(&address) }
            .map(|g| g.started)
            .unwrap_or(0);
        UNPROVEN_STREAMS.insert(&address, &generation, 0)?;
        return Ok(());
    };
    let layout = SOCKET_LAYOUT.get(0).ok_or(1)?;
    let attempt = Attempt {
        address,
        generation: stream.generation,
        timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        requested: ctx.arg(2).ok_or(1)?,
        sequence: field(address, layout[0] as usize)?,
        _pad: 0,
    };
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    if unsafe { SEND_ATTEMPTS.get(&id).is_some() } {
        lost();
    }
    SEND_ATTEMPTS.insert(&id, &attempt, 0)
}

#[kretprobe]
pub fn tcp_sendmsg_exit(ctx: RetProbeContext) -> u32 {
    if send_exit(&ctx).is_err() {
        lost();
    }
    0
}
#[inline(always)]
fn send_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let Some(attempt) = (unsafe { SEND_ATTEMPTS.get(&id).copied() }) else {
        return Ok(());
    };
    SEND_ATTEMPTS.remove(&id)?;
    let result = ctx.ret::<i32>().ok_or(1)? as i64;
    if result <= 0 {
        return Ok(());
    }
    let stream = unsafe { SOCKET_STREAMS.get(&attempt.address).copied() }.ok_or(1)?;
    let layout = SOCKET_LAYOUT.get(0).ok_or(1)?;
    let end: u32 = field(attempt.address, layout[0] as usize)?;
    if stream.generation != attempt.generation {
        return Err(1);
    }
    let (start, end) = tcp_stream_range(
        stream.initial_seq,
        attempt.sequence,
        end,
        result,
        attempt.requested,
    )
    .ok_or(1)?;
    let Some(mut entry) = EVENTS.reserve::<RawSyscallEvent>(0) else {
        return Err(1);
    };
    unsafe {
        populate_write(entry.as_mut_ptr(), &attempt, &stream, start, end - start);
    }
    entry.submit(0);
    Ok(())
}

#[inline(always)]
unsafe fn populate_write(
    event: *mut RawSyscallEvent,
    attempt: &Attempt,
    stream: &Stream,
    start: u64,
    length: u64,
) {
    initialize(event, KIND_SOCKET_WRITE);
    (*event).timestamp_ns = attempt.timestamp;
    (*event).socket_address = attempt.address;
    (*event).socket_generation = attempt.generation;
    (*event).net_namespace = stream.namespace;
    (*event).family = stream.family;
    (*event).source_port = stream.source_port;
    (*event).destination_port = stream.destination_port;
    (*event).source_address = stream.source;
    (*event).destination_address = stream.destination;
    (*event).stream_start = start;
    (*event).stream_end = start + length;
}

#[inline(always)]
pub(super) fn process_exit(id: u64) {
    if unsafe { SEND_ATTEMPTS.get(&id).is_some() } {
        lost();
        let _ = SEND_ATTEMPTS.remove(&id);
    }
}

#[inline(always)]
pub(super) fn close(address: u64) {
    let _ = SOCKET_STREAMS.remove(&address);
    let _ = UNPROVEN_STREAMS.remove(&address);
}
