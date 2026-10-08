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
    maps::RingBuf,
    programs::TracePointContext,
};
use izanagi_common::{RawSyscallEvent, SyscallCategoryId, SyscallId};

/// ring buffer マップ。ユーザー空間とイベントデータを共有する。
/// サイズは 256KB (65536 エントリ × 4 ページ)。
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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
        None => return Err(1), // ring buffer が満杯
    };

    let event = entry.as_mut_ptr();
    unsafe {
        // Initialize every byte (including padding) with BPF-compatible stores.
        // LLVM must not replace the writes with an unsupported memset call.
        for index in 0..core::mem::size_of::<RawSyscallEvent>() {
            core::ptr::write_volatile(event.cast::<u8>().add(index), 0);
        }
        // bpf_ktime_get_ns() でタイムスタンプを取得
        (*event).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();

        // bpf_get_current_pid_tgid() の上位 32bit が tgid、下位 32bit が pid
        let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
        (*event).pid = pid_tgid as u32;
        (*event).tgid = (pid_tgid >> 32) as u32;

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

        // パスバッファは初期化のみ (tracepoint ごとに個別に読み取る)
        (*event).path_len = 0;
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

// ---------------------------------------------------------------------------
// パニックハンドラ (no_std 環境では必須)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
