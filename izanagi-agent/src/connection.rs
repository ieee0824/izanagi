use std::sync::Arc;

use izanagi::protocol::{self, Message};
use izanagi::tracer::Tracer;

use crate::crypto::{constant_time_eq, sha256_hex};
use crate::exec::{EXEC_USER, execute_command};
use crate::security::sanitize_anyhow_error;

/// 1 つのホスト接続を処理する。
pub(crate) async fn handle_connection<S>(
    stream: S,
    secret: Option<&[u8]>,
    expected_token: &Arc<Option<String>>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let authenticated = secret.is_some();
    let mut send_seq = 0u64;
    let mut recv_seq = 0u64;

    // Hello ハンドシェイク: ホストから Hello を受信し、認証モードを合意する (#177)
    // シークレット設定時は Hello メッセージも HMAC で保護する
    let hello_msg = match &secret {
        Some(s) => protocol::read_message_authenticated(&mut reader, s, &mut recv_seq).await?,
        None => protocol::read_message(&mut reader).await?,
    };
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
            anyhow::bail!("expected Hello message, got {:?}", other);
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
            Some(Message::Exec { cmd, env }) => {
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
                eprintln!("received Exec: {:?}", cmd);
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
                        eprintln!("exec error: {}", e);
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
            Some(Message::Start(filter)) => {
                eprintln!("received Start with filter: {:?}", filter);

                // eBPF Tracer を起動してイベントを転送する。
                let tracer = izanagi::ebpf_tracer::EbpfTracer::new();
                let mut rx = match tracer.start(&filter).await {
                    Ok(rx) => rx,
                    Err(e) => {
                        eprintln!("eBPF tracer start failed: {}", e);
                        let err_msg = format!("eBPF tracer start failed: {}", e);
                        send_message(&mut writer, &Message::Error(err_msg), secret, &mut send_seq)
                            .await?;
                        continue;
                    }
                };

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
                    tokio::select! {
                        event = rx.recv() => {
                            match event {
                                Some(event) if !is_agent_event(&event, my_pid) => {
                                    let msg = Message::Event((*event).clone());
                                    send_message(&mut writer, &msg, secret, &mut send_seq).await?;
                                }
                                Some(_) => {
                                    // agent 自身の syscall はスキップ
                                }
                                None => {
                                    break;
                                }
                            }
                        }
                        result = recv_message(&mut reader, secret, &mut recv_seq) => {
                            match result? {
                                Some(Message::Stop) => {
                                    eprintln!("received Stop");
                                    break;
                                }
                                Some(_) => {}
                                None => {
                                    break;
                                }
                            }
                        }
                    }
                }
                tracer.stop().await?;
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
                eprintln!("unexpected message: {:?}", other);
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
    reader: &mut R,
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
    let env_vars: Vec<std::ffi::CString> = [
        format!("HOME={}", home_dir),
        format!("USER={}", EXEC_USER),
        "TERM=xterm-256color".to_string(),
        "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
    ]
    .iter()
    .map(|s| {
        std::ffi::CString::new(s.as_str())
            .map_err(|_| anyhow::anyhow!("environment variable contains interior NUL byte: {}", s))
    })
    .collect::<anyhow::Result<Vec<std::ffi::CString>>>()?;

    // execve の envp / argv をスタック上に構築する (ヒープ確保なし)。
    // env_vars は固定 4 要素 + NULL 終端 = 5 要素。
    assert_eq!(env_vars.len(), 4, "env_vars must have exactly 4 elements");
    let envp: [*const libc::c_char; 5] = [
        env_vars[0].as_ptr(),
        env_vars[1].as_ptr(),
        env_vars[2].as_ptr(),
        env_vars[3].as_ptr(),
        std::ptr::null(),
    ];

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

    // 親プロセス: master_fd を tokio の AsyncFd でラップ
    let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    // ノンブロッキングに設定
    unsafe {
        let flags = libc::fcntl(master_fd, libc::F_GETFL);
        libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let master_async = tokio::io::unix::AsyncFd::new(master)?;

    loop {
        tokio::select! {
            // PTY → ホスト (stdout)
            readable = master_async.readable() => {
                match readable {
                    Ok(mut guard) => {
                        match guard.try_io(|inner| {
                            use std::io::Read;
                            let mut buf = vec![0u8; 4096];
                            let n = inner.get_ref().read(&mut buf)?;
                            buf.truncate(n);
                            Ok(buf)
                        }) {
                            Ok(Ok(data)) if !data.is_empty() => {
                                send_message(
                                    writer,
                                    &Message::ShellData { stream: 1, data },
                                    secret,
                                    send_seq,
                                ).await?;
                            }
                            Ok(Ok(_)) => {
                                // EOF — シェル終了
                                break;
                            }
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Ok(Err(_)) => {
                                break;
                            }
                            Err(_would_block) => {
                                continue;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            // ホスト → PTY (stdin) / リサイズ / クローズ
            result = recv_message(reader, secret, recv_seq) => {
                match result? {
                    Some(Message::ShellData { stream: 0, data }) => {
                        // stdin をPTY に書き込み
                        match master_async.writable().await {
                            Ok(mut guard) => {
                                let _ = guard.try_io(|inner| {
                                    use std::io::Write;
                                    inner.get_ref().write_all(&data)
                                });
                            }
                            Err(_) => break,
                        }
                    }
                    Some(Message::ShellResize { rows, cols }) => {
                        let ws = libc::winsize {
                            ws_row: rows,
                            ws_col: cols,
                            ws_xpixel: 0,
                            ws_ypixel: 0,
                        };
                        unsafe {
                            libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
                        }
                    }
                    Some(Message::Stop) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    // 子プロセスの終了を待つ
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };

    send_message(writer, &Message::ShellClose { exit_code }, secret, send_seq).await?;
    eprintln!("shell closed with exit code {}", exit_code);

    Ok(())
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
async fn send_message<W: tokio::io::AsyncWrite + Unpin>(
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
async fn recv_message<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    secret: Option<&[u8]>,
    recv_seq: &mut u64,
) -> anyhow::Result<Option<Message>> {
    match secret {
        Some(s) => protocol::read_message_authenticated(reader, s, recv_seq).await,
        None => protocol::read_message(reader).await,
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn v2_host_and_real_agent_handshake_over_tcp() {
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
                    assert!(matches!(reply, Message::ExecResult { exit_code: 1, .. }));
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
