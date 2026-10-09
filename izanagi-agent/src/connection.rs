use std::sync::Arc;

use izanagi::protocol::{self, Message, MessageReader};
use izanagi::tracer::Tracer;

use crate::crypto::{constant_time_eq, sha256_hex};
use crate::exec::{EXEC_USER, execute_command};
use crate::security::sanitize_anyhow_error;
use crate::shell::{ShellChild, relay_shell};

// Rotate data-source priority while leaving control messages first in the outer select.
async fn next_forwarded<L, T>(
    legacy: &mut tokio::sync::mpsc::Receiver<L>,
    kernel: &mut Option<tokio::sync::mpsc::Receiver<T>>,
    http: &mut Option<tokio::sync::mpsc::Receiver<T>>,
    round: u8,
    kernel_available: bool,
    http_available: bool,
) -> Forwarded<L, T> {
    let legacy_event = legacy.recv();
    let kernel_event = async {
        match kernel.as_mut() {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    };
    let http_event = async {
        match http.as_mut() {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(legacy_event, kernel_event, http_event);
    match round % 3 {
        0 => tokio::select! { biased;
            event = &mut legacy_event => Forwarded::Legacy(event),
            event = &mut kernel_event, if kernel_available => Forwarded::Kernel(event.map(Box::new)),
            event = &mut http_event, if http_available => Forwarded::Http(event.map(Box::new)),
        },
        1 => tokio::select! { biased;
            event = &mut kernel_event, if kernel_available => Forwarded::Kernel(event.map(Box::new)),
            event = &mut http_event, if http_available => Forwarded::Http(event.map(Box::new)),
            event = &mut legacy_event => Forwarded::Legacy(event),
        },
        _ => tokio::select! { biased;
            event = &mut http_event, if http_available => Forwarded::Http(event.map(Box::new)),
            event = &mut legacy_event => Forwarded::Legacy(event),
            event = &mut kernel_event, if kernel_available => Forwarded::Kernel(event.map(Box::new)),
        },
    }
}

enum Forwarded<L, T> {
    Legacy(Option<L>),
    Kernel(Option<Box<T>>),
    Http(Option<Box<T>>),
}

/// 1 つのホスト接続を処理する。
pub(crate) async fn handle_connection<S>(
    stream: S,
    secret: Option<&[u8]>,
    expected_token: &Arc<Option<String>>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut session = Session {
        reader: MessageReader::new(reader),
        writer,
        secret,
        send_seq: 0,
        recv_seq: 0,
    };
    session
        .handshake(expected_token.as_ref().as_deref())
        .await?;
    while let Some(message) = session.recv().await? {
        if !session.dispatch(message).await? {
            break;
        }
    }
    eprintln!("connection closed");
    Ok(())
}

/// Authentication state and sequence counters live as long as the shared reader.
/// In particular, cancelling a receive never creates a fresh frame reader.
struct Session<'a, R, W> {
    reader: MessageReader<R>,
    writer: W,
    secret: Option<&'a [u8]>,
    send_seq: u64,
    recv_seq: u64,
}

type TraceEvents = tokio::sync::mpsc::Receiver<Arc<izanagi::event::SyscallEvent>>;
type TelemetryEvents = tokio::sync::mpsc::Receiver<izanagi_telemetry::TelemetryEnvelope>;
type TraceChannels = (TraceEvents, Option<TelemetryEvents>);
type SidecarChannels = (Option<crate::sidecar::Sidecar>, Option<TelemetryEvents>);

impl<R, W> Session<'_, R, W>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    async fn recv(&mut self) -> anyhow::Result<Option<Message>> {
        recv_message(&mut self.reader, self.secret, &mut self.recv_seq).await
    }

    async fn send(&mut self, message: &Message) -> anyhow::Result<()> {
        send_message(&mut self.writer, message, self.secret, &mut self.send_seq).await
    }

    async fn handshake(&mut self, expected_token: Option<&str>) -> anyhow::Result<()> {
        // Hello is HMAC protected whenever the configured secret requires it.
        let (host_auth, token) = match self.recv().await? {
            Some(Message::Hello {
                authenticated,
                token,
            }) => (authenticated, token),
            Some(_) => anyhow::bail!("expected Hello message"),
            None => anyhow::bail!("host disconnected before Hello"),
        };
        let authenticated = self.secret.is_some();
        if host_auth != authenticated {
            return self
                .reject_hello(format!(
                    "authentication mode mismatch: host={}, agent={}",
                    host_auth, authenticated,
                ))
                .await;
        }
        if let Some(expected) = expected_token {
            if let Err(message) = verify_session_token(expected, token.as_deref()) {
                return self.reject_hello(message.to_owned()).await;
            }
            eprintln!("fw_cfg token verified successfully");
        }
        self.send(&Message::Hello {
            authenticated,
            token: None,
        })
        .await?;
        eprintln!(
            "hello handshake completed (authenticated={})",
            authenticated
        );
        self.send(&Message::Ready).await?;
        eprintln!("sent Ready");
        Ok(())
    }

    async fn reject_hello(&mut self, message: String) -> anyhow::Result<()> {
        // Preserve the unprotected diagnostic on mode/token negotiation failure.
        let _ = protocol::write_message(&mut self.writer, &Message::Error(message.clone())).await;
        anyhow::bail!("{}", message)
    }

    async fn authorize(&mut self, operation: &str) -> anyhow::Result<bool> {
        if self.secret.is_some() {
            return Ok(true);
        }
        self.send(&Message::Error(format!(
            "{operation} requires authenticated session"
        )))
        .await?;
        Ok(false)
    }

    async fn dispatch(&mut self, message: Message) -> anyhow::Result<bool> {
        match message {
            Message::Exec { cmd, env } => {
                if self.authorize("Exec").await? {
                    self.exec(cmd, env).await?;
                }
            }
            Message::Start(filter) => self.trace(filter, None).await?,
            Message::StartBehavior { filter, config } => {
                if self.authorize("behavior").await? {
                    self.trace(filter, Some(config)).await?;
                }
            }
            Message::Shell { rows, cols } => {
                if self.authorize("Shell").await? {
                    eprintln!("received Shell ({}x{})", cols, rows);
                    handle_shell(
                        &mut self.reader,
                        &mut self.writer,
                        self.secret,
                        &mut self.send_seq,
                        &mut self.recv_seq,
                        rows,
                        cols,
                    )
                    .await?;
                }
            }
            Message::Stop => {
                eprintln!("received Stop");
                return Ok(false);
            }
            _ => eprintln!("unexpected message type"),
        }
        Ok(true)
    }

    async fn exec(
        &mut self,
        cmd: Vec<String>,
        mut env: std::collections::HashMap<String, String>,
    ) -> anyhow::Result<()> {
        eprintln!("received Exec");
        if let Some(proxy) = crate::sidecar::proxy_environment() {
            for key in ["http_proxy", "HTTP_PROXY"] {
                env.insert(key.into(), proxy.clone());
            }
            for key in ["no_proxy", "NO_PROXY"] {
                env.insert(key.into(), String::new());
            }
        }
        match execute_command(&cmd, &env).await {
            Ok((exit_code, stdout, stderr)) => {
                self.send(&Message::ExecResult {
                    exit_code,
                    stdout,
                    stderr,
                })
                .await?;
                eprintln!("exec completed with exit code {}", exit_code);
            }
            Err(error) => {
                eprintln!("exec error: {}", sanitize_anyhow_error(&error));
                let sanitized_msg = sanitize_anyhow_error(&error);
                self.send(&Message::ExecResult {
                    exit_code: -1,
                    stdout: Vec::new(),
                    stderr: sanitized_msg.into_bytes(),
                })
                .await?;
            }
        }
        Ok(())
    }

    async fn start_tracer(
        &mut self,
        tracer: &izanagi::ebpf_tracer::EbpfTracer,
        filter: &izanagi::tracer::TraceFilter,
        behavior: Option<&izanagi::protocol::BehaviorStartConfig>,
    ) -> anyhow::Result<Option<TraceChannels>> {
        let start = if let Some(config) = behavior {
            tracer
                .start_observation(filter, config.session_id.clone())
                .await
                .map(|(rx, telemetry)| (rx, Some(telemetry)))
        } else {
            tracer.start(filter).await.map(|rx| (rx, None))
        };
        match start {
            Ok(channels) => Ok(Some(channels)),
            Err(error) => {
                eprintln!("eBPF tracer start failed: {}", error);
                self.send(&Message::Error(format!(
                    "eBPF tracer start failed: {}",
                    error
                )))
                .await?;
                Ok(None)
            }
        }
    }

    async fn start_sidecar(
        &mut self,
        tracer: &izanagi::ebpf_tracer::EbpfTracer,
        behavior: Option<&izanagi::protocol::BehaviorStartConfig>,
    ) -> anyhow::Result<Option<SidecarChannels>> {
        let Some(config) = behavior else {
            return Ok(Some((None, None)));
        };
        match crate::sidecar::Sidecar::start(config).await {
            Ok((sidecar, events)) => Ok(Some((Some(sidecar), Some(events)))),
            Err(_) => {
                tracer.stop().await?;
                self.send(&Message::Error("behavior sidecar startup failed".into()))
                    .await?;
                Ok(None)
            }
        }
    }

    async fn trace(
        &mut self,
        filter: izanagi::tracer::TraceFilter,
        behavior: Option<izanagi::protocol::BehaviorStartConfig>,
    ) -> anyhow::Result<()> {
        eprintln!("received Start");
        let tracer = izanagi::ebpf_tracer::EbpfTracer::new();
        let Some((legacy, kernel)) = self
            .start_tracer(&tracer, &filter, behavior.as_ref())
            .await?
        else {
            return Ok(());
        };
        let Some((mut sidecar, http)) = self.start_sidecar(&tracer, behavior.as_ref()).await?
        else {
            return Ok(());
        };
        let mut streams = TraceStreams::new(legacy, kernel, http);
        // Every forwarding error still passes through the original stop/drop order.
        let transfer_result = self.forward_trace(&mut streams, &mut sidecar).await;
        tracer.stop().await?;
        drop(sidecar);
        transfer_result
    }

    async fn forward_trace(
        &mut self,
        streams: &mut TraceStreams,
        sidecar: &mut Option<crate::sidecar::Sidecar>,
    ) -> anyhow::Result<()> {
        let mut health_tick = tokio::time::interval(std::time::Duration::from_secs(1));
        self.send(&Message::TraceStarted).await?;
        loop {
            streams.refresh_budget();
            tokio::select! {
                biased;
                result = recv_message(&mut self.reader, self.secret, &mut self.recv_seq) => {
                    match result? { Some(Message::Stop) | None => break, Some(_) => {} }
                }
                _ = health_tick.tick() => {
                    if sidecar.as_mut().is_some_and(crate::sidecar::Sidecar::failed) {
                        // No direct-route fallback; applications retain a dead proxy.
                        self.send(&Message::Error("behavior proxy stopped unexpectedly".into())).await?;
                        break;
                    }
                }
                event = streams.next() => {
                    if !self.forward_event(streams, event).await? { break; }
                }
            }
        }
        Ok(())
    }

    async fn forward_event(
        &mut self,
        streams: &mut TraceStreams,
        event: Forwarded<Arc<izanagi::event::SyscallEvent>, izanagi_telemetry::TelemetryEnvelope>,
    ) -> anyhow::Result<bool> {
        streams.round = (streams.round + 1) % 3;
        match event {
            Forwarded::Kernel(Some(event)) => {
                streams.sent_kernel += 1;
                self.send(&Message::Telemetry(event)).await?;
            }
            Forwarded::Http(Some(event)) => {
                streams.sent_http += 1;
                self.send(&Message::Telemetry(event)).await?;
            }
            Forwarded::Kernel(None) => streams.kernel = None,
            Forwarded::Http(None) => streams.http = None,
            Forwarded::Legacy(Some(event)) if !is_agent_event(&event, streams.agent_pid) => {
                self.send(&Message::Event((*event).clone())).await?;
            }
            Forwarded::Legacy(Some(_)) => {}
            Forwarded::Legacy(None) => {
                self.send(&Message::Error(
                    "trace event stream ended unexpectedly".into(),
                ))
                .await?;
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn verify_session_token(expected: &str, token_hash: Option<&str>) -> Result<(), &'static str> {
    let token_hash = token_hash.ok_or("fw_cfg token required but not provided")?;
    // The host sends SHA256(token); comparing the same hash is constant time.
    let expected_hash = sha256_hex(expected);
    if !constant_time_eq(token_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err("fw_cfg token mismatch");
    }
    Ok(())
}

struct TraceStreams {
    legacy: TraceEvents,
    kernel: Option<TelemetryEvents>,
    http: Option<TelemetryEvents>,
    budget_started: tokio::time::Instant,
    sent_kernel: usize,
    sent_http: usize,
    round: u8,
    agent_pid: u32,
}
impl TraceStreams {
    fn new(
        legacy: TraceEvents,
        kernel: Option<TelemetryEvents>,
        http: Option<TelemetryEvents>,
    ) -> Self {
        Self {
            legacy,
            kernel,
            http,
            budget_started: tokio::time::Instant::now(),
            sent_kernel: 0,
            sent_http: 0,
            round: 0,
            agent_pid: std::process::id(),
        }
    }

    fn refresh_budget(&mut self) {
        if self.budget_started.elapsed() >= std::time::Duration::from_secs(1) {
            self.budget_started = tokio::time::Instant::now();
            self.sent_kernel = 0;
            self.sent_http = 0;
        }
    }

    async fn next(
        &mut self,
    ) -> Forwarded<Arc<izanagi::event::SyscallEvent>, izanagi_telemetry::TelemetryEnvelope> {
        next_forwarded(
            &mut self.legacy,
            &mut self.kernel,
            &mut self.http,
            self.round,
            self.sent_kernel < 96,
            self.sent_http < 32,
        )
        .await
    }
}

/// 対話シェルを PTY 経由で実行し、ホストと stdin/stdout をストリーミングする。
async fn handle_shell<R, W>(
    reader: &mut MessageReader<R>,
    writer: &mut W,
    secret: Option<&[u8]>,
    send_seq: &mut u64,
    recv_seq: &mut u64,
    rows: u16,
    cols: u16,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    match prepare_shell(rows, cols)? {
        ShellLaunch::Ready(master, child) => {
            relay_shell(reader, writer, secret, send_seq, recv_seq, master, child).await
        }
        ShellLaunch::Rejected(message) => {
            send_message(writer, &Message::Error(message), secret, send_seq).await?;
            Ok(())
        }
    }
}

enum ShellLaunch {
    Ready(std::fs::File, ShellChild),
    Rejected(String),
}

fn prepare_shell(rows: u16, cols: u16) -> anyhow::Result<ShellLaunch> {
    use std::os::unix::io::FromRawFd;
    // All user lookup, environment validation and allocation happen before fork.
    let Some((uid, gid, home_dir)) = lookup_shell_user()? else {
        return Ok(ShellLaunch::Rejected(format!(
            "user '{}' not found",
            EXEC_USER
        )));
    };
    let env_vars = shell_environment(&home_dir)?;
    let (pid, master_fd) = fork_shell(uid, gid, &env_vars, rows, cols);
    if pid < 0 {
        return Ok(ShellLaunch::Rejected(format!(
            "forkpty failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Own the child before any fallible parent-side setup.
    let child = ShellChild::new(pid);
    let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    Ok(ShellLaunch::Ready(master, child))
}

fn lookup_shell_user() -> anyhow::Result<Option<(libc::uid_t, libc::gid_t, String)>> {
    // getpwnam_r is thread-safe; no passwd pointer crosses an await or a fork.
    let c_user =
        std::ffi::CString::new(EXEC_USER).map_err(|_| anyhow::anyhow!("invalid EXEC_USER"))?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf_size: usize = 1024;
    let mut found = None;
    loop {
        let mut buf = vec![0u8; buf_size];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let ret = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if ret == 0 && !result.is_null() {
            let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
                .to_str()
                .unwrap_or("/home/izanagi")
                .to_owned();
            found = Some((pwd.pw_uid, pwd.pw_gid, home));
            break;
        } else if ret == libc::ERANGE && buf_size < 1_048_576 {
            buf_size *= 2;
            continue;
        } else {
            break;
        }
    }
    Ok(found)
}

fn shell_environment(home_dir: &str) -> anyhow::Result<Vec<std::ffi::CString>> {
    // Reject interior NUL; do not silently drop unsafe environment values.
    let mut shell_env = vec![
        format!("HOME={}", home_dir),
        format!("USER={}", EXEC_USER),
        "TERM=xterm-256color".to_string(),
        "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
    ];
    if let Some(proxy) = crate::sidecar::proxy_environment() {
        for key in ["http_proxy", "HTTP_PROXY"] {
            shell_env.push(format!("{key}={proxy}"));
        }
        for key in ["no_proxy", "NO_PROXY"] {
            shell_env.push(format!("{key}="));
        }
    }
    shell_env
        .iter()
        .map(|s| {
            std::ffi::CString::new(s.as_str()).map_err(|_| {
                anyhow::anyhow!("environment variable contains interior NUL byte: {}", s)
            })
        })
        .collect::<anyhow::Result<Vec<std::ffi::CString>>>()
}

fn fork_shell(
    uid: libc::uid_t,
    gid: libc::gid_t,
    env_vars: &[std::ffi::CString],
    rows: u16,
    cols: u16,
) -> (libc::pid_t, libc::c_int) {
    // The child uses only these preallocated CString values and pointer arrays.
    let mut envp: Vec<*const libc::c_char> = env_vars.iter().map(|value| value.as_ptr()).collect();
    envp.push(std::ptr::null());

    let shell = std::ffi::CString::new("/bin/bash").expect("static string");
    let argv0 = std::ffi::CString::new("-bash").expect("static string");
    let argv: [*const libc::c_char; 2] = [argv0.as_ptr(), std::ptr::null()];

    // chdir 先を fork 前に確保
    let workdir = std::ffi::CString::new("/workspace").expect("static string");

    // PTY を確保
    let mut winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let mut master_fd: libc::c_int = -1;
    let pid = unsafe {
        libc::forkpty(
            &mut master_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut winsize,
        )
    };

    if pid == 0 {
        exec_shell_child(uid, gid, &workdir, &shell, &argv, &envp);
    }

    (pid, master_fd)
}

fn exec_shell_child(
    uid: libc::uid_t,
    gid: libc::gid_t,
    workdir: &std::ffi::CStr,
    shell: &std::ffi::CStr,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
) -> ! {
    // Post-fork: async-signal-safe libc calls only, without allocation or logging.
    unsafe {
        if libc::setgid(gid) != 0 {
            libc::_exit(126);
        }
        if libc::setuid(uid) != 0 {
            libc::_exit(126);
        }

        if libc::chdir(workdir.as_ptr()) != 0 {
            libc::_exit(126);
        }

        // /proc/self/environ のパーミッションを制限し、
        // シェルプロセスが自身の環境変数を /proc 経由で読めないようにする。
        #[cfg(target_os = "linux")]
        if libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) != 0 {
            libc::_exit(126);
        }

        // execve で環境変数を envp 経由で渡す。親プロセスの環境を継承しない。
        libc::execve(shell.as_ptr(), argv.as_ptr(), envp.as_ptr());
        libc::_exit(127);
    }
}

/// agent 自身が発生させた syscall イベントかどうかを判定する。
/// eBPF の tgid (= プロセスグループID) で判定。tokio ワーカースレッドも
/// 同じ tgid を持つため、プロセス名に依存せず正確にフィルタできる。
/// tgid が 0 の場合 (DTrace 等) はプロセス名でフォールバックする。
fn is_agent_event(event: &izanagi::event::SyscallEvent, agent_pid: u32) -> bool {
    if event.tgid != 0 {
        event.tgid == agent_pid
    } else {
        &*event.process_name == "izanagi-agent"
    }
}

/// シークレットの有無に応じて認証付き/なしでメッセージを送信する。
pub(crate) async fn send_message<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
    secret: Option<&[u8]>,
    send_seq: &mut u64,
) -> anyhow::Result<()> {
    match secret {
        Some(s) => protocol::write_message_authenticated(writer, msg, s, send_seq).await,
        None => protocol::write_message(writer, msg).await,
    }
}

/// シークレットの有無に応じて認証付き/なしでメッセージを受信する。
pub(crate) async fn recv_message<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut MessageReader<R>,
    secret: Option<&[u8]>,
    recv_seq: &mut u64,
) -> anyhow::Result<Option<Message>> {
    reader.recv(secret, recv_seq).await
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn hello_failures_reject_before_ready() {
        for (host_auth, token, expected, error) in [
            (
                true,
                None,
                None,
                "authentication mode mismatch: host=true, agent=false",
            ),
            (
                false,
                None,
                Some("session-token"),
                "fw_cfg token required but not provided",
            ),
            (
                false,
                Some("wrong-hash"),
                Some("session-token"),
                "fw_cfg token mismatch",
            ),
        ] {
            let (mut host, agent) = tokio::io::duplex(4096);
            let expected = std::sync::Arc::new(expected.map(str::to_owned));
            let task =
                tokio::spawn(async move { super::handle_connection(agent, None, &expected).await });
            super::protocol::write_message(
                &mut host,
                &super::Message::Hello {
                    authenticated: host_auth,
                    token: token.map(str::to_owned),
                },
            )
            .await
            .unwrap();
            assert_eq!(
                super::protocol::read_message(&mut host).await.unwrap(),
                Some(super::Message::Error(error.into()))
            );
            assert_eq!(task.await.unwrap().unwrap_err().to_string(), error);
            assert!(
                super::protocol::read_message(&mut host)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn unauthenticated_operations_are_rejected_without_closing_session() {
        let (host, agent) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            super::handle_connection(agent, None, &std::sync::Arc::new(None)).await
        });
        let (reader, writer) = tokio::io::split(host);
        let mut client = izanagi::protocol_client::ProtocolClient::new(reader, writer, None);
        client.handshake_and_wait_ready(None).await.unwrap();
        for (message, operation) in [
            (
                super::Message::Exec {
                    cmd: vec![],
                    env: Default::default(),
                },
                "Exec",
            ),
            (super::Message::Shell { rows: 24, cols: 80 }, "Shell"),
            (
                super::Message::StartBehavior {
                    filter: izanagi::tracer::TraceFilter {
                        categories: vec![],
                        pids: None,
                    },
                    config: super::protocol::BehaviorStartConfig {
                        session_id: "session".into(),
                        proxy_listen: "127.0.0.1:18080".into(),
                        allowed_hosts: vec![],
                        fixture_endpoint: None,
                    },
                },
                "behavior",
            ),
        ] {
            client.send_message(&message).await.unwrap();
            assert_eq!(
                client.recv_message().await.unwrap(),
                Some(super::Message::Error(format!(
                    "{operation} requires authenticated session"
                )))
            );
        }
        client.send_message(&super::Message::Stop).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authenticated_token_handshake_preserves_message_sequences() {
        let (host, agent) = tokio::io::duplex(4096);
        let key = vec![7u8; 32];
        let agent_key = key.clone();
        let task = tokio::spawn(async move {
            super::handle_connection(
                agent,
                Some(&agent_key),
                &std::sync::Arc::new(Some("session-token".into())),
            )
            .await
        });
        let (reader, writer) = tokio::io::split(host);
        let mut client = izanagi::protocol_client::ProtocolClient::new(reader, writer, Some(key));
        client
            .handshake_and_wait_ready(Some(super::sha256_hex("session-token")))
            .await
            .unwrap();
        for _ in 0..2 {
            client
                .send_message(&super::Message::Exec {
                    cmd: vec![],
                    env: Default::default(),
                })
                .await
                .unwrap();
            assert!(matches!(
                client.recv_message().await.unwrap(),
                Some(super::Message::ExecResult { exit_code: -1, .. })
            ));
        }
        client.send_message(&super::Message::Stop).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    #[tokio::test]
    async fn tracer_startup_failure_keeps_control_session_usable() {
        let (host, agent) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            super::handle_connection(agent, None, &std::sync::Arc::new(None)).await
        });
        let (reader, writer) = tokio::io::split(host);
        let mut client = izanagi::protocol_client::ProtocolClient::new(reader, writer, None);
        client.handshake_and_wait_ready(None).await.unwrap();
        client
            .send_message(&super::Message::Start(izanagi::tracer::TraceFilter {
                categories: vec![],
                pids: None,
            }))
            .await
            .unwrap();
        assert!(
            matches!(client.recv_message().await.unwrap(), Some(super::Message::Error(error)) if error.starts_with("eBPF tracer start failed: "))
        );
        client
            .send_message(&super::Message::Exec {
                cmd: vec![],
                env: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(
            client.recv_message().await.unwrap(),
            Some(super::Message::Error(
                "Exec requires authenticated session".into()
            ))
        );
        client.send_message(&super::Message::Stop).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ready_sources_rotate_and_have_independent_budgets() {
        use super::{Forwarded, next_forwarded};
        let (legacy_tx, mut legacy) = tokio::sync::mpsc::channel(16);
        let (kernel_tx, kernel_rx) = tokio::sync::mpsc::channel(16);
        let (http_tx, http_rx) = tokio::sync::mpsc::channel(16);
        let mut kernel = Some(kernel_rx);
        let mut http = Some(http_rx);
        for _ in 0..8 {
            legacy_tx.send(1u8).await.unwrap();
            kernel_tx.send(2u8).await.unwrap();
            http_tx.send(3u8).await.unwrap();
        }
        for round in 0..6 {
            let event =
                next_forwarded(&mut legacy, &mut kernel, &mut http, round, true, true).await;
            assert!(matches!(
                (round % 3, event),
                (0, Forwarded::Legacy(Some(1)))
                    | (1, Forwarded::Kernel(Some(_)))
                    | (2, Forwarded::Http(Some(_)))
            ));
        }
        assert!(matches!(
            next_forwarded(&mut legacy, &mut kernel, &mut http, 1, false, true).await,
            Forwarded::Http(Some(_))
        ));
        assert!(matches!(
            next_forwarded(&mut legacy, &mut kernel, &mut http, 2, true, false).await,
            Forwarded::Legacy(Some(1))
        ));
        kernel = None;
        http = None;
        assert!(matches!(
            next_forwarded(&mut legacy, &mut kernel, &mut http, 1, true, true).await,
            Forwarded::Legacy(Some(1))
        ));
    }

    #[tokio::test]
    async fn v3_host_and_real_agent_handshake_over_tcp() {
        use izanagi::protocol::{Message, read_message};
        use izanagi::protocol_client::ProtocolClient;
        use tokio::net::{TcpListener, TcpStream};

        for authenticated in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let secret = authenticated.then(|| rand::random::<[u8; 32]>().to_vec());
            let agent_secret = secret.clone();
            let agent = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                super::handle_connection(
                    stream,
                    agent_secret.as_deref(),
                    &std::sync::Arc::new(None),
                )
                .await
            });
            let stream = TcpStream::connect(address).await.unwrap();
            let (reader, writer) = stream.into_split();
            let mut client = ProtocolClient::new(reader, writer, secret);
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                client.handshake_and_wait_ready(None).await.unwrap();
                client
                    .send_message(&Message::Exec {
                        cmd: vec![],
                        env: Default::default(),
                    })
                    .await
                    .unwrap();
                let reply = client.recv_message().await.unwrap().unwrap();
                if authenticated {
                    assert!(
                        matches!(reply, Message::ExecResult { exit_code, .. } if exit_code != 0)
                    );
                } else {
                    assert!(matches!(reply, Message::Error(_)));
                }
            })
            .await
            .unwrap();
            drop(client);
            tokio::time::timeout(std::time::Duration::from_secs(5), agent)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        // Legacy data is rejected by the new shared reader without deserializing.
        let mut legacy = &[5, 5, 0, 0, 0, 5, 0, 0, 0, 0][..];
        assert!(read_message(&mut legacy).await.is_err());
    }

    use super::*;
    use izanagi::event::{Syscall, SyscallEvent, SyscallResult};
    use std::time::SystemTime;

    fn make_event(pid: u32, tgid: u32, name: &str) -> SyscallEvent {
        SyscallEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            pid,
            process_name: name.into(),
            syscall: Syscall::SendTo,
            args: smallvec::smallvec![],
            result: SyscallResult::Ok(0),
            tgid,
        }
    }

    #[test]
    fn is_agent_event_tgid_match() {
        let event = make_event(100, 42, "tokio-rt-worker");
        assert!(is_agent_event(&event, 42));
    }

    #[test]
    fn is_agent_event_tgid_mismatch() {
        let event = make_event(100, 42, "tokio-rt-worker");
        assert!(!is_agent_event(&event, 99));
    }

    #[test]
    fn is_agent_event_tgid_zero_name_match() {
        let event = make_event(100, 0, "izanagi-agent");
        assert!(is_agent_event(&event, 42));
    }

    #[test]
    fn is_agent_event_tgid_zero_name_mismatch() {
        let event = make_event(100, 0, "npm");
        assert!(!is_agent_event(&event, 42));
    }

    #[test]
    fn is_agent_event_user_tokio_not_filtered() {
        // ユーザーアプリの tokio-rt-worker は tgid が agent と異なるためフィルタされない
        let event = make_event(200, 150, "tokio-rt-worker");
        assert!(!is_agent_event(&event, 42));
    }

    // --- Task 352: token hash verification test ---

    #[test]
    fn token_hash_verification() {
        let token = "test-token-123";
        let expected_hash = sha256_hex(token);
        assert!(constant_time_eq(
            expected_hash.as_bytes(),
            sha256_hex(token).as_bytes()
        ));
        assert!(!constant_time_eq(
            expected_hash.as_bytes(),
            sha256_hex("wrong-token").as_bytes()
        ));
    }

    #[test]
    fn token_hash_empty_token() {
        let hash1 = sha256_hex("");
        let hash2 = sha256_hex("");
        assert!(constant_time_eq(hash1.as_bytes(), hash2.as_bytes()));
        assert!(!constant_time_eq(
            hash1.as_bytes(),
            sha256_hex("non-empty").as_bytes()
        ));
    }
}
