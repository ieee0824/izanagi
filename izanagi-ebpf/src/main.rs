//! Izanagi eBPF プログラム。
//!
//! syscall の tracepoint にアタッチし、イベントを ring buffer 経由で
//! ユーザー空間に送信する。
//!
//! **注意**: このプログラムは nightly Rust + bpf-linker でのみビルド可能。
//! macOS ではビルドできない。Linux 環境で以下のようにビルドする:
//!
//! ```sh
//! cargo +nightly build --target bpfel-unknown-none -Z build-std=core
//! ```
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use izanagi_common::*;
use izanagi_common::{RawSyscallEvent, SyscallCategoryId, SyscallId};
mod writer;

/// ring buffer マップ。ユーザー空間とイベントデータを共有する。
/// サイズは 256KB (65536 エントリ × 4 ページ)。
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// The loader verifies this immutable ELF section before loading any probe.
#[used]
#[link_section = ".izanagi_abi"]
static RAW_ABI: [u8; 16] = [
    b'I',
    b'Z',
    b'A',
    b'N',
    b'A',
    b'B',
    b'I',
    b'!',
    RAW_ABI_VERSION as u8,
    0,
    0,
    0,
    (RAW_EVENT_SIZE & 255) as u8,
    ((RAW_EVENT_SIZE >> 8) & 255) as u8,
    0,
    0,
];

#[derive(Clone, Copy)]
struct Generation {
    start: u64,
    exec: u64,
    parent_start: u64,
    parent: u32,
    _pad: u32,
}
#[derive(Clone, Copy)]
struct SocketGeneration {
    started: u64,
    opaque: u64,
    process: Generation,
    tgid: u32,
    tid: u32,
}
#[map]
static PROCESS_GENERATIONS: HashMap<u32, Generation> = HashMap::with_max_entries(4096, 0);
#[map]
static OPEN_ATTEMPTS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);
#[map]
static SOCKET_GENERATIONS: HashMap<u64, SocketGeneration> = HashMap::with_max_entries(4096, 0);
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn lost() {
    unsafe {
        if let Some(value) = DROPS.get_ptr_mut(0) {
            *value += 1;
        }
    }
}

#[inline(always)]
unsafe fn initialize(event: *mut RawSyscallEvent, kind: u32) {
    for index in 0..core::mem::size_of::<RawSyscallEvent>() {
        core::ptr::write_volatile(event.cast::<u8>().add(index), 0);
    }
    (*event).abi_version = RAW_ABI_VERSION;
    (*event).kind = kind;
    (*event).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    (*event).pid = pid_tgid as u32;
    (*event).tgid = (pid_tgid >> 32) as u32;
    if let Some(generation) = PROCESS_GENERATIONS.get(&(*event).tgid) {
        (*event).process_start_ns = generation.start;
        (*event).exec_generation = generation.exec;
        (*event).parent_start_ns = generation.parent_start;
        (*event).parent_tgid = generation.parent;
    }
    aya_ebpf::helpers::gen::bpf_get_current_comm(core::ptr::addr_of_mut!((*event).comm).cast(), 16);
}

// ---------------------------------------------------------------------------
// ヘルパー関数
// ---------------------------------------------------------------------------

/// tracepoint コンテキストから RawSyscallEvent を構築し ring buffer に送信する。
///
/// # Safety
/// tracepoint コンテキストのフィールド読み取りは unsafe。
#[inline(always)]
fn emit_event(
    ctx: &TracePointContext,
    syscall_id: SyscallId,
    category: SyscallCategoryId,
) -> Result<(), i64> {
    // ring buffer にエントリを予約
    let mut entry = match EVENTS.reserve::<RawSyscallEvent>(0) {
        Some(entry) => entry,
        None => {
            lost();
            return Err(1);
        } // observable ring reservation loss
    };

    let event = entry.as_mut_ptr();
    unsafe {
        initialize(event, KIND_ENTER);
        (*event).syscall_id = syscall_id as u32;
        (*event).category = category as u8;

        // tracepoint の引数を読み取り (オフセットはフォーマット依存)
        // sys_enter の共通レイアウト: offset 8 = syscall_nr, offset 16~ = args
        (*event).arg0 = ctx.read_at::<u64>(16).unwrap_or(0);
        (*event).arg1 = ctx.read_at::<u64>(24).unwrap_or(0);
        (*event).arg2 = ctx.read_at::<u64>(32).unwrap_or(0);

        // プロセス名を取得
        aya_ebpf::helpers::gen::bpf_get_current_comm(
            core::ptr::addr_of_mut!((*event).comm).cast(),
            16,
        );

        capture_user_path(event, syscall_id);
    }

    if syscall_id == SyscallId::OpenAt {
        let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
        let now = unsafe { (*event).timestamp_ns };
        if OPEN_ATTEMPTS.insert(&id, &now, 0).is_err() {
            lost();
        }
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// File syscall tracepoints (#22)
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::OpenAt, SyscallCategoryId::File) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Read, SyscallCategoryId::File) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Write, SyscallCategoryId::File) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_stat(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Stat, SyscallCategoryId::File) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_access(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Access, SyscallCategoryId::File) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// ---------------------------------------------------------------------------
// Network syscall tracepoints (#23)
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Connect, SyscallCategoryId::Network) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::SendTo, SyscallCategoryId::Network) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_recvfrom(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::RecvFrom, SyscallCategoryId::Network) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_socket(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Socket, SyscallCategoryId::Network) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Bind, SyscallCategoryId::Network) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// ---------------------------------------------------------------------------
// Process syscall tracepoints (#24)
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Execve, SyscallCategoryId::Process) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_clone(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Clone, SyscallCategoryId::Process) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn sys_enter_fork(ctx: TracePointContext) -> u32 {
    match emit_event(&ctx, SyscallId::Fork, SyscallCategoryId::Process) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// sys_exit provides the actual return value; a missing entry is never success.
#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let attempt = unsafe { OPEN_ATTEMPTS.get(&id).copied() };
    let _ = OPEN_ATTEMPTS.remove(&id);
    writer::process_exit(id);
    let Some(mut entry) = EVENTS.reserve::<RawSyscallEvent>(0) else {
        lost();
        return 1;
    };
    unsafe {
        let event = entry.as_mut_ptr();
        initialize(event, KIND_OPEN_EXIT);
        (*event).syscall_id = SyscallId::OpenAt as u32;
        (*event).result = match ctx.read_at::<i64>(16) {
            Ok(value) => value,
            Err(_) => {
                entry.discard(0);
                lost();
                return 1;
            }
        };
        if let Some(attempt) = attempt {
            (*event).attempt_ns = attempt;
        } else {
            (*event).flags |= FLAG_STATE_MISSING;
        }
    }
    entry.submit(0);
    0
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let child = match unsafe { ctx.read_at::<u32>(44) } {
        Ok(value) => value,
        Err(_) => {
            lost();
            return 1;
        }
    };
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let parent = (id >> 32) as u32;
    let parent_start = unsafe {
        PROCESS_GENERATIONS
            .get(&parent)
            .map(|g| g.start)
            .unwrap_or(0)
    };
    let generation = Generation {
        start: now,
        exec: 0,
        parent_start,
        parent,
        _pad: 0,
    };
    if PROCESS_GENERATIONS.insert(&child, &generation, 0).is_err() {
        lost();
    }
    // The child's first event confirms TGID. A fork tracepoint also covers threads;
    // do not manufacture a ProcessKey for a child that is actually a TID.
    0
}

#[tracepoint]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    unsafe {
        if let Some(pointer) = PROCESS_GENERATIONS.get_ptr_mut(&tgid) {
            (*pointer).exec += 1;
        }
    }
    let Some(mut entry) = EVENTS.reserve::<RawSyscallEvent>(0) else {
        lost();
        return 1;
    };
    unsafe {
        initialize(entry.as_mut_ptr(), KIND_EXEC);
    }
    entry.submit(0);
    0
}

#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tid = id as u32;
    let tgid = (id >> 32) as u32;
    if tid == tgid {
        if let Some(mut entry) = EVENTS.reserve::<RawSyscallEvent>(0) {
            unsafe {
                initialize(entry.as_mut_ptr(), KIND_EXIT);
            }
            entry.submit(0);
        } else {
            lost();
        }
        let _ = PROCESS_GENERATIONS.remove(&tgid);
    } else {
        let _ = PROCESS_GENERATIONS.remove(&tid);
    }
    let _ = OPEN_ATTEMPTS.remove(&id);
    0
}

/// TCP SYN_SENT occurs in the connect caller. Other states may run in softirq:
/// preserve the original connector rather than attributing the softirq current task.
#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    let address = match unsafe { ctx.read_at::<u64>(8) } {
        Ok(v) => v,
        Err(_) => {
            lost();
            return 1;
        }
    };
    let state = match unsafe { ctx.read_at::<u32>(20) } {
        Ok(v) => v,
        Err(_) => {
            lost();
            return 1;
        }
    };
    let protocol = unsafe { ctx.read_at::<u16>(30).unwrap_or(0) };
    if protocol != 6 {
        return 0;
    }
    if state == 7 {
        writer::close(address);
    }
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    if state == 2 && record_connector(address, now).is_err() {
        return 1;
    }
    let generation = unsafe { SOCKET_GENERATIONS.get(&address).copied() };
    let Some(generation) = generation else {
        return 0;
    }; // preexisting sockets remain unobserved
    let Some(mut entry) = EVENTS.reserve::<RawSyscallEvent>(0) else {
        lost();
        return 1;
    };
    unsafe {
        let event = entry.as_mut_ptr();
        populate_socket_identity(&ctx, event, &generation, state, now);
        if !read_socket_addresses(&ctx, event) {
            entry.discard(0);
            return 0;
        }
        writer::socket_state(event, address, state);
    }
    entry.submit(0);
    if state == 7 {
        let _ = SOCKET_GENERATIONS.remove(&address);
    }
    0
}

// All helpers inline into their tracepoint to retain the verifier's bounded layout.
/// # Safety
/// `event` must point to an initialized, live ring-buffer reservation.
#[inline(always)]
unsafe fn capture_user_path(event: *mut RawSyscallEvent, syscall_id: SyscallId) {
    unsafe {
        // Read only arguments whose syscall ABI defines a userspace pathname.
        // Never dereference the pointer directly: the helper bounds the copy,
        // omits the trailing NUL, and reports inaccessible memory as an error.
        let path_ptr = match syscall_id {
            SyscallId::OpenAt => Some((*event).arg1),
            SyscallId::Stat | SyscallId::Access | SyscallId::Execve => Some((*event).arg0),
            _ => None,
        };
        if let Some(path_ptr) = path_ptr {
            if let Ok(path) = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
                path_ptr as *const u8,
                &mut (*event).path_buf,
            ) {
                (*event).path_len = path.len() as u32;
                if path.len() >= PATH_BUF_SIZE - 1 {
                    (*event).flags |= FLAG_PATH_TRUNCATED;
                }
            } else {
                (*event).flags |= FLAG_PATH_FAILED;
            }
        }
    }
}

#[inline(always)]
fn record_connector(address: u64, now: u64) -> Result<(), ()> {
    let id = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let process = unsafe { PROCESS_GENERATIONS.get(&tgid).copied() }.unwrap_or(Generation {
        start: 0,
        exec: 0,
        parent_start: 0,
        parent: 0,
        _pad: 0,
    });
    // Opaque correlation ID, generated without exposing the kernel address.
    let generation = SocketGeneration {
        started: now,
        opaque: address,
        process,
        tgid,
        tid: id as u32,
    };
    if SOCKET_GENERATIONS.insert(&address, &generation, 0).is_err() {
        lost();
        return Err(());
    }
    Ok(())
}

/// # Safety
/// `event` must be a live reservation and `ctx` must use inet_sock_set_state layout.
#[inline(always)]
unsafe fn populate_socket_identity(
    ctx: &TracePointContext,
    event: *mut RawSyscallEvent,
    generation: &SocketGeneration,
    state: u32,
    now: u64,
) {
    unsafe {
        initialize(event, KIND_SOCKET);
        (*event).timestamp_ns = now;
        (*event).socket_address = generation.opaque;
        (*event).socket_generation = generation.started;
        (*event).socket_state = state;
        (*event).pid = generation.tid;
        (*event).tgid = generation.tgid;
        (*event).process_start_ns = generation.process.start;
        (*event).exec_generation = generation.process.exec;
        (*event).parent_start_ns = generation.process.parent_start;
        (*event).parent_tgid = generation.process.parent;
        (*event).family = ctx.read_at::<u16>(28).unwrap_or(0);
        (*event).source_port = ctx.read_at::<u16>(24).unwrap_or(0);
        (*event).destination_port = ctx.read_at::<u16>(26).unwrap_or(0);
    }
}

/// # Safety
/// `event` must be a live reservation and `ctx` must use inet_sock_set_state layout.
#[inline(always)]
unsafe fn read_socket_addresses(ctx: &TracePointContext, event: *mut RawSyscallEvent) -> bool {
    unsafe {
        if (*event).family == 2 {
            (&mut (*event).source_address)[..4]
                .copy_from_slice(&ctx.read_at::<[u8; 4]>(32).unwrap_or([0; 4]));
            (&mut (*event).destination_address)[..4]
                .copy_from_slice(&ctx.read_at::<[u8; 4]>(36).unwrap_or([0; 4]));
        } else if (*event).family == 10 {
            // Scalar loads avoid LLVM generating unsupported BPF memset calls
            // for the error branch of a 16-byte array read.
            let source0 = ctx.read_at::<u64>(40).unwrap_or(0).to_ne_bytes();
            let source1 = ctx.read_at::<u64>(48).unwrap_or(0).to_ne_bytes();
            let destination0 = ctx.read_at::<u64>(56).unwrap_or(0).to_ne_bytes();
            let destination1 = ctx.read_at::<u64>(64).unwrap_or(0).to_ne_bytes();
            (&mut (*event).source_address)[..8].copy_from_slice(&source0);
            (&mut (*event).source_address)[8..].copy_from_slice(&source1);
            (&mut (*event).destination_address)[..8].copy_from_slice(&destination0);
            (&mut (*event).destination_address)[8..].copy_from_slice(&destination1);
        } else {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// パニックハンドラ (no_std 環境では必須)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
