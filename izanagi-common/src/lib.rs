//! eBPF プログラムとユーザー空間で共有するイベント構造体。
//!
//! この crate は eBPF (no_std) とユーザー空間 (std) の両方で使用される。
//! `#[repr(C)]` でメモリレイアウトを固定し、ring buffer 経由で安全に受け渡す。

#![cfg_attr(not(feature = "user"), no_std)]

/// syscall のカテゴリを識別する定数。
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallCategoryId {
    File = 0,
    Network = 1,
    Process = 2,
}

/// 監視対象の syscall を識別する定数。
/// eBPF プログラム側で tracepoint ごとに設定する。
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallId {
    // File
    OpenAt = 0,
    Read = 1,
    Write = 2,
    Stat = 3,
    Access = 4,

    // Network
    Connect = 10,
    SendTo = 11,
    RecvFrom = 12,
    Socket = 13,
    Bind = 14,

    // Process
    Execve = 20,
    Clone = 21,
    Fork = 22,
}

impl TryFrom<u32> for SyscallId {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::OpenAt),
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Stat),
            4 => Ok(Self::Access),
            10 => Ok(Self::Connect),
            11 => Ok(Self::SendTo),
            12 => Ok(Self::RecvFrom),
            13 => Ok(Self::Socket),
            14 => Ok(Self::Bind),
            20 => Ok(Self::Execve),
            21 => Ok(Self::Clone),
            22 => Ok(Self::Fork),
            _ => Err(value),
        }
    }
}

/// ring buffer 経由で送信するイベント構造体。
///
/// eBPF プログラム側で構築し、ユーザー空間側で読み取る。
/// `#[repr(C)]` でレイアウトを固定し、両側で同一のメモリ表現を保証する。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawSyscallEvent {
    /// イベント発生時刻 (ktime_ns)。
    pub timestamp_ns: u64,
    /// プロセス ID。
    pub pid: u32,
    /// スレッドグループ ID (通常 pid と同一)。
    pub tgid: u32,
    /// syscall 識別子。
    pub syscall_id: u32,
    /// syscall カテゴリ。
    pub category: u8,
    /// パディング (アライメント調整)。
    pub _pad: [u8; 3],
    /// syscall の第 1 引数。
    pub arg0: u64,
    /// syscall の第 2 引数。
    pub arg1: u64,
    /// syscall の第 3 引数。
    pub arg2: u64,
    /// プロセス名 (comm)。最大 16 バイト (カーネル TASK_COMM_LEN)。
    pub comm: [u8; 16],
    /// ファイルパスバッファ。tracepoint から読み取ったパス文字列。
    pub path_buf: [u8; PATH_BUF_SIZE],
    /// path_buf の有効長。
    pub path_len: u32,
    /// パディング (構造体末尾のアライメント調整)。
    pub _pad2: [u8; 4],
    pub abi_version: u32,
    pub kind: u32,
    /// Kernel sched_process_fork observation generation; zero means unavailable.
    pub process_start_ns: u64,
    pub exec_generation: u64,
    pub parent_start_ns: u64,
    pub parent_tgid: u32,
    pub child_pid: u32,
    pub result: i64,
    pub attempt_ns: u64,
    /// Kernel address (never exported as a socket cookie), paired with generation.
    pub socket_address: u64,
    pub socket_generation: u64,
    pub socket_state: u32,
    pub family: u16,
    pub source_port: u16,
    pub destination_port: u16,
    pub flags: u16,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
}

/// `RawSyscallEvent` のサイズ（バイト数）。
/// ring buffer のエントリサイズとして使用する。
/// `RawSyscallEvent.path_buf` のサイズ。
pub const PATH_BUF_SIZE: usize = 256;

pub const RAW_EVENT_SIZE: usize = core::mem::size_of::<RawSyscallEvent>();

/// Raw ABI is deliberately independent from the authenticated wire version.
pub const RAW_ABI_VERSION: u32 = 1;
pub const ABI_SECTION: &str = ".izanagi_abi";
pub const ABI_MAGIC: [u8; 8] = *b"IZANABI!";
pub const KIND_ENTER: u32 = 0;
pub const KIND_OPEN_EXIT: u32 = 1;
pub const KIND_FORK: u32 = 2;
pub const KIND_EXEC: u32 = 3;
pub const KIND_EXIT: u32 = 4;
pub const KIND_SOCKET: u32 = 5;
pub const FLAG_PATH_FAILED: u16 = 1;
pub const FLAG_PATH_TRUNCATED: u16 = 2;
pub const FLAG_STATE_MISSING: u16 = 4;

/// ユーザー空間の DNS / HTTP 接続先に共通の内部アドレス判定。
#[cfg(feature = "user")]
pub mod ip_filter;
