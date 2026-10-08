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
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = MessageReader::new(reader);
    let authenticated = secret.is_some();
    let mut send_seq = 0u64;
    let mut recv_seq = 0u64;

    // Hello ハンドシェイク: ホストから Hello を受信し、認証モードを合意する (#177)
    // シークレット設定時は Hello メッセージも HMAC で保護する
    let hello_msg = recv_message(&mut reader, secret, &mut recv_seq).await?;
    match hello_msg {
        Some(Message::Hello {
            authenticated: host_auth,
            token,
        }) => {
            if host_auth != authenticated {
                let err_msg = format!(
                    "authentication mode mismatch: host={}, agent={}",
                    host_auth, authenticated
                );
                let _ =
                    protocol::write_message(&mut writer, &Message::Error(err_msg.clone())).await;
                anyhow::bail!("{}", err_msg);
            }

            // セッショントークンの検証 (#115)
            // VM 生存期間中は同じトークンで何度でも接続可能
            if let Some(ref expected) = **expected_token {
                match token {
                    Some(ref token_hash) => {
                        // ホスト側は SHA256(token) のハッシュを送信する。
                        // agent 側でも同じハッシュを計算して定数時間比較する。
                        let expected_hash = sha256_hex(expected);
                        if !constant_time_eq(token_hash.as_bytes(), expected_hash.as_bytes()) {
                            let err_msg = "fw_cfg token mismatch".to_string();
                            let _ = protocol::write_message(
                                &mut writer,
                                &Message::Error(err_msg.clone()),
                            )
                            .await;
                            anyhow::bail!("{}", err_msg);
                        }
                        eprintln!("fw_cfg token verified successfully");
                    }
                    None => {
                        let err_msg = "fw_cfg token required but not provided".to_string();
                        let _ =
                            protocol::write_message(&mut writer, &Message::Error(err_msg.clone()))
                                .await;
                        anyhow::bail!("{}", err_msg);
                    }
                }
            }
        }
        Some(other) => {
            let _ = other;
            anyhow::bail!("expected Hello message");
        }
        None => {
            anyhow::bail!("host disconnected before Hello");
        }
    }
    // Hello レスポンスも HMAC 保護する
    let hello_response = Message::Hello {
        authenticated,
        token: None,
    };
    match &secret {
        Some(s) => {
            protocol::write_message_authenticated(&mut writer, &hello_response, s, &mut send_seq)
                .await?
        }
        None => protocol::write_message(&mut writer, &hello_response).await?,
    }
    eprintln!(
        "hello handshake completed (authenticated={})",
        authenticated
    );

    // Ready を送信
    send_message(&mut writer, &Message::Ready, secret, &mut send_seq).await?;
    eprintln!("sent Ready");

    // メッセージループ: Start (トレース) または Exec (コマンド実行) を処理
    loop {
        match recv_message(&mut reader, secret, &mut recv_seq).await? {
            Some(Message::Exec { cmd, mut env }) => {
                if !authenticated {
                    send_message(
                        &mut writer,
                        &Message::Error("Exec requires authenticated session".to_string()),
                        secret,
                        &mut send_seq,
                    )
                    .await?;
                    continue;
                }
                eprintln!("received Exec");
                if let Some(proxy) = crate::sidecar::proxy_environment() {
                    for key in ["http_proxy", "HTTP_PROXY"] {
                        env.insert(key.into(), proxy.clone());
                    }
                    for key in ["no_proxy", "NO_PROXY"] {
                        env.insert(key.into(), String::new());
                    }
                }
                let result = execute_command(&cmd, &env).await;
                match result {
                    Ok((exit_code, stdout, stderr)) => {
                        send_message(
                            &mut writer,
                            &Message::ExecResult {
                                exit_code,
                                stdout,
                                stderr,
                            },
                            secret,
                            &mut send_seq,
                        )
                        .await?;
                        eprintln!("exec completed with exit code {}", exit_code);
                    }
                    Err(e) => {
                        // 内部詳細はログのみに出力し、クライアントにはサニタイズ済みメッセージを返す
                        eprintln!("exec error: {}", sanitize_anyhow_error(&e));
                        let sanitized_msg = sanitize_anyhow_error(&e);
                        send_message(
                            &mut writer,
                            &Message::ExecResult {
                                exit_code: -1,
                                stdout: Vec::new(),
                                stderr: sanitized_msg.into_bytes(),
                            },
                            secret,
                            &mut send_seq,
                        )
                        .await?;
                    }
                }
            }
            Some(message @ (Message::Start(_) | Message::StartBehavior { .. })) => {
                let (filter, behavior) = match message {
                    Message::Start(filter) => (filter, None),
                    Message::StartBehavior { filter, config } => (filter, Some(config)),
                    _ => unreachable!(),
                };
                if behavior.is_some() && !authenticated {
                    send_message(
                        &mut writer,
                        &Message::Error("behavior requires authenticated session".into()),
                        secret,
                        &mut send_seq,
                    )
                    .await?;
                    continue;
                }
                eprintln!("received Start");

                // eBPF Tracer を起動してイベントを転送する。
                let tracer = izanagi::ebpf_tracer::EbpfTracer::new();
                let start = if let Some(config) = &behavior {
                    tracer
                        .start_observation(&filter, config.session_id.clone())
                        .await
                        .map(|(rx, telemetry)| (rx, Some(telemetry)))
                } else {
                    tracer.start(&filter).await.map(|rx| (rx, None))
                };
                let (mut rx, mut telemetry) = match start {
                    Ok(channels) => channels,
                    Err(e) => {
                        eprintln!("eBPF tracer start failed: {}", e);
                        let err_msg = format!("eBPF tracer start failed: {}", e);
                        send_message(&mut writer, &Message::Error(err_msg), secret, &mut send_seq)
                            .await?;
                        continue;
                    }
                };

                let (mut sidecar, mut http_events) = if let Some(config) = &behavior {
                    match crate::sidecar::Sidecar::start(config).await {
                        Ok((sidecar, events)) => (Some(sidecar), Some(events)),
                        Err(_) => {
                            tracer.stop().await?;
                            send_message(
                                &mut writer,
                                &Message::Error("behavior sidecar startup failed".into()),
                                secret,
                                &mut send_seq,
                            )
                            .await?;
                            continue;
                        }
                    }
                } else {
                    (None, None)
                };
                let mut health_tick = tokio::time::interval(std::time::Duration::from_secs(1));
                let mut telemetry_budget = tokio::time::Instant::now();
                let mut sent_kernel = 0usize;
                let mut sent_http = 0usize;
                let mut forwarding_round = 0u8;
                let transfer_result: anyhow::Result<()> = async {
                send_message(&mut writer, &Message::TraceStarted, secret, &mut send_seq).await?;

                // イベント転送ループ
                // agent 自身の syscall をプロセス名でフィルタして転送量を削減する。
                // eBPF の pid フィールドは TID (スレッドID) であり std::process::id() (TGID)
                // と一致しないため、comm (プロセス名) で判定する。
                // agent の tokio-rt-worker スレッドの sendto 等がチャネルを飽和させるのを防止。
                // agent 自身の syscall を tgid でフィルタして転送量を削減する。
                // eBPF の tgid = プロセスグループID = agent の PID。
                // tokio ワーカースレッドも同じ tgid を持つため正確にフィルタできる。
                let my_pid = std::process::id();
                loop {
                    if telemetry_budget.elapsed()>=std::time::Duration::from_secs(1) { telemetry_budget=tokio::time::Instant::now();sent_kernel=0;sent_http=0; }
                    tokio::select! {
                        biased;
                        result = recv_message(&mut reader, secret, &mut recv_seq) => {
                            match result? { Some(Message::Stop)|None=>break,Some(_)=>{} }
                        }
                        _ = health_tick.tick() => {
                            if sidecar.as_mut().is_some_and(crate::sidecar::Sidecar::failed) {
                                // No direct-route fallback; applications retain a dead proxy.
                                send_message(&mut writer,&Message::Error("behavior proxy stopped unexpectedly".into()),secret,&mut send_seq).await?;
                                break;
                            }
                        }
                        event = next_forwarded(&mut rx, &mut telemetry, &mut http_events, forwarding_round, sent_kernel < 96, sent_http < 32) => {
                            forwarding_round = (forwarding_round + 1) % 3;
                            match event {
                                Forwarded::Kernel(Some(event)) => {
                                    sent_kernel += 1;
                                    send_message(&mut writer, &Message::Telemetry(event), secret, &mut send_seq).await?;
                                }
                                Forwarded::Http(Some(event)) => {
                                    sent_http += 1;
                                    send_message(&mut writer, &Message::Telemetry(event), secret, &mut send_seq).await?;
                                }
                                Forwarded::Kernel(None) => telemetry = None,
                                Forwarded::Http(None) => http_events = None,
                                Forwarded::Legacy(Some(event)) if !is_agent_event(&event, my_pid) => {
                                    send_message(&mut writer, &Message::Event((*event).clone()), secret, &mut send_seq).await?;
                                }
                                Forwarded::Legacy(Some(_)) => {}
                                Forwarded::Legacy(None) => {
                                    send_message(&mut writer, &Message::Error("trace event stream ended unexpectedly".into()), secret, &mut send_seq).await?;
                                    break;
                                }
                            }
                        }
                    }
                }
                    Ok(())
                }.await;
                tracer.stop().await?;
                drop(sidecar);
                transfer_result?;
            }
            Some(Message::Shell { rows, cols }) => {
                if !authenticated {
                    send_message(
                        &mut writer,
                        &Message::Error("Shell requires authenticated session".to_string()),
                        secret,
                        &mut send_seq,
                    )
                    .await?;
                    continue;
                }
                eprintln!("received Shell ({}x{})", cols, rows);
                handle_shell(
                    &mut reader,
                    &mut writer,
                    secret,
                    &mut send_seq,
                    &mut recv_seq,
                    rows,
                    cols,
                )
                .await?;
            }
            Some(Message::Stop) => {
                eprintln!("received Stop");
                break;
            }
            Some(other) => {
                let _ = other;
                eprintln!("unexpected message type");
            }
            None => {
                break;
            }
        }
    }

    eprintln!("connection closed");
    Ok(())
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
    use std::os::unix::io::FromRawFd;

    // --- fork 前にすべての計算・ヒープ確保を完了する (async-signal-safe) ---

    // passwd エントリを fork 前に取得 (getpwnam_r でスレッドセーフに)
    // passwd / *mut passwd は Send でないため await をまたがないようスコープを分離する
    let pw_result: Option<(libc::uid_t, libc::gid_t, String)> = {
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
        found
    };
    let (uid, gid, home_dir) = match pw_result {
        Some(v) => v,
        None => {
            send_message(
                writer,
                &Message::Error(format!("user '{}' not found", EXEC_USER)),
                secret,
                send_seq,
            )
            .await?;
            return Ok(());
        }
    };

    // 環境変数を fork 前に CString で構築する。
    // execve の envp 配列として渡すため、CString の Vec + NULL 終端ポインタ配列を用意する。
    // NUL バイトを含む値は安全でないためエラーにする (silent drop しない)。
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
    let env_vars: Vec<std::ffi::CString> = shell_env
        .iter()
        .map(|s| {
            std::ffi::CString::new(s.as_str()).map_err(|_| {
                anyhow::anyhow!("environment variable contains interior NUL byte: {}", s)
            })
        })
        .collect::<anyhow::Result<Vec<std::ffi::CString>>>()?;

    // execve の envp / argv をスタック上に構築する (ヒープ確保なし)。
    // env_vars は固定 4 要素 + NULL 終端 = 5 要素。
    let (pid, master_fd) = {
        let mut envp: Vec<*const libc::c_char> =
            env_vars.iter().map(|value| value.as_ptr()).collect();
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
            // 子プロセス: async-signal-safe な操作のみ実行する。
            // すべてのヒープ確保・ライブラリ呼び出しは fork 前に完了済み。
            // 環境変数は execve の envp 引数で渡すため clearenv/putenv は不要。
            // envp / argv は fork 前にスタック上で構築済み。子プロセス内はヒープ確保なし。
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

        (pid, master_fd)
    };

    if pid < 0 {
        let err = std::io::Error::last_os_error();
        send_message(
            writer,
            &Message::Error(format!("forkpty failed: {}", err)),
            secret,
            send_seq,
        )
        .await?;
        return Ok(());
    }

    // Own the child before any fallible parent-side setup.
    let child = ShellChild::new(pid);
    let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    relay_shell(reader, writer, secret, send_seq, recv_seq, master, child).await
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
