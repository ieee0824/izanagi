//! Entry-time address snapshot and per-thread connect syscall outcomes.
use super::{initialize, lost, EVENTS};
use aya_ebpf::{
    helpers::bpf_probe_read_user, macros::map, maps::HashMap, programs::TracePointContext,
};
use izanagi_common::*;

#[derive(Clone, Copy)]
struct Attempt {
    timestamp: u64,
    fd: u64,
    address: [u8; 28],
    valid: bool,
}

#[map]
static CONNECT_ATTEMPTS: HashMap<u64, Attempt> = HashMap::with_max_entries(4096, 0);

pub(super) fn cleanup(id: u64) {
    let _ = CONNECT_ATTEMPTS.remove(&id);
}

fn snapshot(ctx: &TracePointContext) -> Result<Attempt, i64> {
    let mut attempt = Attempt {
        timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        fd: unsafe { ctx.read_at::<u64>(16)? },
        address: [0; 28],
        valid: false,
    };
    let pointer = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    let length = unsafe { ctx.read_at::<i32>(32)? };
    if length < 2 {
        return Ok(attempt);
    }
    let family = unsafe { bpf_probe_read_user(pointer.cast::<u16>()) };
    match family {
        Ok(2) if length >= 16 => {
            if let Ok(bytes) = unsafe { bpf_probe_read_user(pointer.cast::<[u8; 16]>()) } {
                attempt.address[..16].copy_from_slice(&bytes);
                attempt.valid = u16::from_ne_bytes([bytes[0], bytes[1]]) == 2;
            }
        }
        Ok(10) if length >= 28 => {
            if let Ok(bytes) = unsafe { bpf_probe_read_user(pointer.cast::<[u8; 28]>()) } {
                attempt.address = bytes;
                attempt.valid = u16::from_ne_bytes([bytes[0], bytes[1]]) == 10;
            }
        }
        _ => {}
    }
    Ok(attempt)
}

unsafe fn populate(event: *mut RawSyscallEvent, attempt: &Attempt) {
    (*event).attempt_ns = attempt.timestamp;
    (*event).arg0 = attempt.fd;
    if !attempt.valid {
        return;
    }
    let bytes = &attempt.address;
    (*event).family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    (*event).destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match (*event).family {
        2 => (&mut (*event).destination_address)[..4].copy_from_slice(&bytes[4..8]),
        10 => {
            (*event).destination_address.copy_from_slice(&bytes[8..24]);
            // Reuse arg2 for scope ID without expanding the event layout.
            (*event).arg2 = u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as u64;
        }
        _ => return,
    }
    (*event).flags |= FLAG_CONNECT_ADDRESS;
}

pub(super) fn enter(ctx: &TracePointContext) -> u32 {
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    cleanup(id); // Never reuse stale state if this entry cannot be captured.
    let attempt = match snapshot(ctx) {
        Ok(value) => value,
        Err(_) => {
            lost();
            return 1;
        }
    };
    if CONNECT_ATTEMPTS.insert(&id, &attempt, 0).is_err() {
        lost();
    }
    let Some(mut entry) = EVENTS.reserve::<RawSyscallEvent>(0) else {
        lost();
        return 1;
    };
    unsafe {
        let event = entry.as_mut_ptr();
        initialize(event, KIND_ENTER);
        (*event).syscall_id = SyscallId::Connect as u32;
        (*event).category = SyscallCategoryId::Network as u8;
        populate(event, &attempt);
    }
    entry.submit(0);
    0
}

pub(super) fn exit(ctx: &TracePointContext) -> u32 {
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let attempt = unsafe { CONNECT_ATTEMPTS.get(&id).copied() };
    cleanup(id);
    let result = match unsafe { ctx.read_at::<i64>(16) } {
        Ok(value) => value,
        Err(_) => {
            lost();
            return 1;
        }
    };
    let Some(mut entry) = EVENTS.reserve::<RawSyscallEvent>(0) else {
        lost();
        return 1;
    };
    unsafe {
        let event = entry.as_mut_ptr();
        initialize(event, KIND_CONNECT_EXIT);
        (*event).syscall_id = SyscallId::Connect as u32;
        (*event).category = SyscallCategoryId::Network as u8;
        (*event).result = result;
        if let Some(attempt) = attempt {
            populate(event, &attempt);
        } else {
            (*event).flags |= FLAG_STATE_MISSING;
        }
    }
    entry.submit(0);
    0
}
