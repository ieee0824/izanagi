//! eBPF ベースの Tracer 実装。
//!
//! Linux 上で aya クレートを使い、eBPF プログラムをロードして
//! tracepoint にアタッチし、ring buffer 経由でイベントを受信する。
//!
//! macOS など非 Linux 環境では stub 実装となり、`start()` はエラーを返す。

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
#[cfg(feature = "ebpf")]
mod abi;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux;
#[cfg(feature = "ebpf")]
mod observation;

use crate::event::SyscallEvent;
use crate::tracer::{TraceFilter, Tracer};

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use crate::tracer::EVENT_CHANNEL_CAPACITY;

/// デフォルトの eBPF オブジェクトパス。
const DEFAULT_EBPF_OBJ_PATH: &str = "/opt/izanagi/izanagi-ebpf.o";

/// eBPF ベースの Tracer。
///
/// Linux 上でのみ動作する。eBPF プログラムを tracepoint にアタッチし、
/// ring buffer からイベントを受信して `SyscallEvent` に変換する。
pub struct EbpfTracer {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    bpf: std::sync::Mutex<Option<aya::Ebpf>>,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    observation: std::sync::Mutex<
        Option<(
            observation::Collector,
            mpsc::Sender<izanagi_telemetry::schema::TelemetryEnvelope>,
        )>,
    >,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    worker: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// eBPF オブジェクトファイルのパス。Linux 実装でのみ使用。
    #[cfg_attr(not(all(target_os = "linux", feature = "ebpf")), allow(dead_code))]
    ebpf_obj_path: PathBuf,
}

impl Default for EbpfTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfTracer {
    /// 新しい `EbpfTracer` を作成する。
    ///
    /// デフォルトの eBPF オブジェクトパス (`/opt/izanagi/izanagi-ebpf.o`) を使用する。
    /// この時点では eBPF プログラムのロードは行わない。
    /// `start()` で初めてロード・アタッチする。
    pub fn new() -> Self {
        Self::with_ebpf_obj_path(DEFAULT_EBPF_OBJ_PATH)
    }

    /// 指定した eBPF オブジェクトパスで `EbpfTracer` を作成する。
    ///
    /// 開発・テスト環境でカスタムパスを使用する場合に利用する。
    pub fn with_ebpf_obj_path(path: impl Into<PathBuf>) -> Self {
        Self {
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            bpf: std::sync::Mutex::new(None),
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            observation: std::sync::Mutex::new(None),
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            worker: std::sync::Mutex::new(None),
            ebpf_obj_path: path.into(),
        }
    }
}

impl EbpfTracer {
    pub async fn start_observation(
        &self,
        filter: &TraceFilter,
        session_id: String,
    ) -> anyhow::Result<(
        mpsc::Receiver<Arc<SyscallEvent>>,
        mpsc::Receiver<izanagi_telemetry::schema::TelemetryEnvelope>,
    )> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let (tx, rx) = mpsc::channel(256);
            *self.observation.lock().expect("observation lock poisoned") =
                Some((observation::Collector::new(session_id)?, tx));
            match self.start(filter).await {
                Ok(events) => Ok((events, rx)),
                Err(error) => {
                    self.observation
                        .lock()
                        .expect("observation lock poisoned")
                        .take();
                    Err(error)
                }
            }
        }
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            let _ = (filter, session_id);
            anyhow::bail!("Linux eBPF behavior observation is unavailable")
        }
    }
}

// ---------------------------------------------------------------------------
// Linux 実装
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "ebpf"))]
/// `SyscallId` から `Syscall` への変換。
///
/// `ebpf_tracer` モジュール内で一元管理し、手動 match の重複を排除する。
impl TryFrom<izanagi_common::SyscallId> for crate::event::Syscall {
    type Error = anyhow::Error;

    fn try_from(id: izanagi_common::SyscallId) -> Result<Self, Self::Error> {
        use izanagi_common::SyscallId;
        match id {
            SyscallId::OpenAt => Ok(Self::OpenAt),
            SyscallId::Read => Ok(Self::Read),
            SyscallId::Write => Ok(Self::Write),
            SyscallId::Stat => Ok(Self::Stat),
            SyscallId::Access => Ok(Self::Access),
            SyscallId::Connect => Ok(Self::Connect),
            SyscallId::SendTo => Ok(Self::SendTo),
            SyscallId::RecvFrom => Ok(Self::RecvFrom),
            SyscallId::Socket => Ok(Self::Socket),
            SyscallId::Bind => Ok(Self::Bind),
            SyscallId::Execve => Ok(Self::Execve),
            SyscallId::Clone => Ok(Self::Clone),
            SyscallId::Fork => Ok(Self::Fork),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
/// boot time のオフセットを計算する。
///
/// `CLOCK_MONOTONIC` と `CLOCK_REALTIME` の差分から、
/// `bpf_ktime_get_ns()` の値を UNIX epoch ベースに補正するためのオフセットを求める。
fn boot_time_offset() -> anyhow::Result<std::time::Duration> {
    let mut boottime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut realtime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // Safety: libc::clock_gettime は有効な timespec ポインタに対して安全。
    // 戻り値 -1 はエラーを示す (#99)。
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut boottime) == -1 {
            anyhow::bail!(
                "clock_gettime(CLOCK_MONOTONIC) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut realtime) == -1 {
            anyhow::bail!(
                "clock_gettime(CLOCK_REALTIME) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let boot_ns = boottime.tv_sec as u64 * 1_000_000_000 + boottime.tv_nsec as u64;
    let real_ns = realtime.tv_sec as u64 * 1_000_000_000 + realtime.tv_nsec as u64;

    // realtime - boottime = boot epoch からの UNIX epoch オフセット
    Ok(std::time::Duration::from_nanos(
        real_ns.saturating_sub(boot_ns),
    ))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
/// ring buffer データからアライメントを考慮して `RawSyscallEvent` を読み取る。
///
/// ポインタのアライメントが `RawSyscallEvent` の要求に合わない場合は
/// コピーして対応する。
fn read_raw_event(data: &[u8]) -> izanagi_common::RawSyscallEvent {
    let ptr = data.as_ptr();
    let align = core::mem::align_of::<izanagi_common::RawSyscallEvent>();

    if (ptr as usize).is_multiple_of(align) {
        // アライメントが合っている場合は直接読み取り
        // Safety: サイズチェックは呼び出し元で実施済み、アライメントも検証済み。
        unsafe { core::ptr::read(ptr as *const izanagi_common::RawSyscallEvent) }
    } else {
        // アライメントが合わない場合はコピーして読み取り
        let mut event = core::mem::MaybeUninit::<izanagi_common::RawSyscallEvent>::uninit();
        // Safety: サイズチェックは呼び出し元で実施済み。バイト単位コピーなのでアライメント不要。
        unsafe {
            core::ptr::copy_nonoverlapping(
                ptr,
                event.as_mut_ptr() as *mut u8,
                core::mem::size_of::<izanagi_common::RawSyscallEvent>(),
            );
            event.assume_init()
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
/// `RawSyscallEvent` を `SyscallEvent` に変換する。
///
/// `boot_offset` は `boot_time_offset()` で事前計算した値。
/// 変換できない場合（未知の syscall ID 等）は `None` を返す。
fn convert_raw_event(
    raw: &izanagi_common::RawSyscallEvent,
    boot_offset: std::time::Duration,
) -> Option<SyscallEvent> {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::event::Syscall;

    if raw.abi_version != izanagi_common::RAW_ABI_VERSION
        || !matches!(
            raw.kind,
            izanagi_common::KIND_ENTER | izanagi_common::KIND_OPEN_EXIT
        )
    {
        return None;
    }
    // SyscallId → Syscall 変換
    let syscall_id = izanagi_common::SyscallId::try_from(raw.syscall_id).ok()?;
    let syscall = Syscall::try_from(syscall_id).ok()?;

    let process_name = legacy_process_name(raw);

    // タイムスタンプを SystemTime に変換
    let timestamp = UNIX_EPOCH + boot_offset + Duration::from_nanos(raw.timestamp_ns);

    // パスがあれば SyscallArg::Path として引数に追加
    let mut args = smallvec::smallvec![];
    if raw.path_len > 0 {
        let path_len = raw.path_len as usize;
        let path_bytes = &raw.path_buf[..path_len.min(izanagi_common::PATH_BUF_SIZE)];
        let path_str = String::from_utf8_lossy(path_bytes);
        args.push(crate::event::SyscallArg::Path(std::path::PathBuf::from(
            path_str.as_ref(),
        )));
    }

    Some(SyscallEvent {
        timestamp,
        pid: raw.pid,
        tgid: raw.tgid,
        process_name,
        syscall,
        args,
        result: legacy_result(raw),
    })
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn legacy_process_name(raw: &izanagi_common::RawSyscallEvent) -> Arc<str> {
    // comm を文字列に変換
    let comm_len = raw
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw.comm.len());
    String::from_utf8_lossy(&raw.comm[..comm_len]).into()
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn legacy_result(raw: &izanagi_common::RawSyscallEvent) -> crate::event::SyscallResult {
    use crate::event::SyscallResult;
    if raw.kind == izanagi_common::KIND_OPEN_EXIT {
        if raw.result < 0 {
            SyscallResult::Err((-raw.result).min(i32::MAX as i64) as i32)
        } else {
            SyscallResult::Ok(raw.result)
        }
    } else {
        SyscallResult::Unknown
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[async_trait::async_trait]
impl Tracer for EbpfTracer {
    async fn start(
        &self,
        _filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>> {
        let bytes = std::fs::read(&self.ebpf_obj_path)?;
        abi::validate_object(&bytes)?;
        let mut bpf = aya::Ebpf::load(&bytes)?;
        let behavior = self
            .observation
            .lock()
            .expect("observation lock poisoned")
            .is_some();
        linux::attach_required(&mut bpf, behavior)?;
        let unavailable = linux::attach_syscalls(&mut bpf, behavior)?;
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        // Finish all fallible map/clock setup before publishing the loaded object.
        let input = linux::KernelInput::take(&mut bpf)?;
        let observation = self
            .observation
            .lock()
            .expect("observation lock poisoned")
            .take();
        {
            let mut guard = self.bpf.lock().expect("EbpfTracer lock poisoned");
            if guard.is_some() {
                anyhow::bail!("EbpfTracer is already running");
            }
            *guard = Some(bpf);
        }
        let worker = tokio::spawn(input.run(tx, observation, unavailable));
        *self.worker.lock().expect("worker lock poisoned") = Some(worker);
        Ok(rx)
    }

    async fn stop(&self) -> anyhow::Result<()> {
        if let Some(worker) = self.worker.lock().expect("worker lock poisoned").take() {
            worker.abort();
        }
        // Ebpf を drop すると全プログラムがデタッチされる
        self.bpf.lock().expect("EbpfTracer lock poisoned").take();
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn monotonic_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

// ---------------------------------------------------------------------------
// macOS / その他 OS のスタブ実装
// ---------------------------------------------------------------------------

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
#[async_trait::async_trait]
impl Tracer for EbpfTracer {
    async fn start(
        &self,
        _filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>> {
        anyhow::bail!("eBPF is only supported on Linux")
    }

    async fn stop(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_tracer_can_be_constructed() {
        let _tracer = EbpfTracer::new();
    }

    #[test]
    fn ebpf_tracer_with_custom_path() {
        let tracer = EbpfTracer::with_ebpf_obj_path("/tmp/custom.o");
        assert_eq!(
            tracer.ebpf_obj_path,
            std::path::PathBuf::from("/tmp/custom.o")
        );
    }

    #[test]
    fn ebpf_tracer_default_path() {
        let tracer = EbpfTracer::new();
        assert_eq!(
            tracer.ebpf_obj_path,
            std::path::PathBuf::from(DEFAULT_EBPF_OBJ_PATH)
        );
    }

    // --- convert_raw_event テスト (#93) ---
    // Linux + ebpf feature でのみコンパイル可能

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    mod convert_tests {
        use super::super::*;
        use izanagi_common::{PATH_BUF_SIZE, RawSyscallEvent, SyscallId};
        use std::time::Duration;

        fn make_raw_event(syscall_id: u32, comm: &[u8], path: &[u8]) -> RawSyscallEvent {
            let mut event = RawSyscallEvent {
                timestamp_ns: 1_000_000_000,
                pid: 42,
                tgid: 42,
                syscall_id,
                category: 0,
                _pad: [0u8; 3],
                arg0: 0,
                arg1: 0,
                arg2: 0,
                comm: [0u8; 16],
                path_buf: [0u8; PATH_BUF_SIZE],
                path_len: path.len() as u32,
                _pad2: [0u8; 4],
                abi_version: izanagi_common::RAW_ABI_VERSION,
                kind: 0,
                process_start_ns: 0,
                exec_generation: 0,
                parent_start_ns: 0,
                parent_tgid: 0,
                child_pid: 0,
                result: 0,
                attempt_ns: 0,
                socket_address: 0,
                socket_generation: 0,
                socket_state: 0,
                family: 0,
                source_port: 0,
                destination_port: 0,
                flags: 0,
                source_address: [0; 16],
                destination_address: [0; 16],
            };
            let comm_len = comm.len().min(16);
            event.comm[..comm_len].copy_from_slice(&comm[..comm_len]);
            let path_len = path.len().min(PATH_BUF_SIZE);
            event.path_buf[..path_len].copy_from_slice(&path[..path_len]);
            event
        }

        #[test]
        fn convert_valid_openat_event() {
            let raw = make_raw_event(SyscallId::OpenAt as u32, b"bash", b"/etc/passwd");
            let boot_offset = Duration::from_secs(1000);
            let event = convert_raw_event(&raw, boot_offset).unwrap();
            assert_eq!(event.pid, 42);
            assert_eq!(&*event.process_name, "bash");
            assert_eq!(event.syscall, crate::event::Syscall::OpenAt);
            assert_eq!(event.args.len(), 1);
        }

        #[test]
        fn convert_unknown_syscall_returns_none() {
            let raw = make_raw_event(9999, b"test", b"");
            let result = convert_raw_event(&raw, Duration::ZERO);
            assert!(result.is_none());
        }

        #[test]
        fn convert_no_path() {
            let raw = make_raw_event(SyscallId::Connect as u32, b"curl", b"");
            let event = convert_raw_event(&raw, Duration::ZERO).unwrap();
            assert!(event.args.is_empty());
        }

        #[test]
        fn convert_comm_with_null_terminator() {
            let raw = make_raw_event(SyscallId::Read as u32, b"sh\0\0\0\0", b"");
            let event = convert_raw_event(&raw, Duration::ZERO).unwrap();
            assert_eq!(&*event.process_name, "sh");
        }

        #[test]
        fn convert_path_clamped_to_buf_size() {
            // path_len > PATH_BUF_SIZE のケース — min でクランプされる
            let mut raw = make_raw_event(SyscallId::OpenAt as u32, b"test", b"");
            raw.path_len = (PATH_BUF_SIZE + 100) as u32;
            // path_buf は全ゼロだが path_len が大きくても panic しないことを確認
            let event = convert_raw_event(&raw, Duration::ZERO).unwrap();
            assert_eq!(event.args.len(), 1);
        }

        #[test]
        fn convert_timestamp_uses_boot_offset() {
            let raw = make_raw_event(SyscallId::Read as u32, b"test", b"");
            let boot_offset = Duration::from_secs(500);
            let event = convert_raw_event(&raw, boot_offset).unwrap();
            let expected =
                std::time::UNIX_EPOCH + boot_offset + Duration::from_nanos(raw.timestamp_ns);
            assert_eq!(event.timestamp, expected);
        }
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    #[tokio::test]
    async fn ebpf_tracer_start_fails_on_non_linux() {
        let tracer = EbpfTracer::new();
        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };
        let result = tracer.start(&filter).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only supported on Linux")
        );
    }
}
