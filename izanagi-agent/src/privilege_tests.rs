//! Run only in a disposable Linux root process (CI runs the explicit ignored test).
use izanagi::protocol::Message;
use izanagi::protocol_client::ProtocolClient;
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

type Client = ProtocolClient<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;

#[test]
#[ignore = "reporter executed by the demoted Exec/Shell child"]
fn report_dropped_identity() {
    let (uid, gid, _) = crate::credentials::lookup_user(crate::exec::EXEC_USER)
        .unwrap()
        .unwrap();
    assert_ne!(uid, 0);
    assert_eq!(unsafe { libc::getuid() }, uid);
    assert_eq!(unsafe { libc::geteuid() }, uid);
    assert_eq!(unsafe { libc::getgid() }, gid);
    assert_eq!(unsafe { libc::getegid() }, gid);
    assert_eq!(unsafe { libc::getgroups(0, std::ptr::null_mut()) }, 0);
    println!("IZANAGI_GROUPS_CLEARED");
}

async fn authenticated_client() -> (Client, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let key = b"credential-test-fixture".to_vec();
    let (host, agent) = tokio::io::duplex(65536);
    let guest_key = key.clone();
    let task = tokio::spawn(async move {
        crate::connection::handle_connection(agent, Some(&guest_key), &std::sync::Arc::new(None))
            .await
    });
    let (reader, writer) = tokio::io::split(host);
    let mut client = ProtocolClient::new(reader, writer, Some(key));
    client.handshake_and_wait_ready(None).await.unwrap();
    (client, task)
}

async fn check_exec(command: Vec<String>) {
    let (mut client, task) = authenticated_client().await;
    client
        .send_message(&Message::Exec {
            cmd: command,
            env: Default::default(),
        })
        .await
        .unwrap();
    match client.recv_message().await.unwrap().unwrap() {
        Message::ExecResult {
            exit_code,
            stdout,
            stderr,
        } => {
            assert_eq!(exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
            assert!(String::from_utf8_lossy(&stdout).contains("IZANAGI_GROUPS_CLEARED"));
        }
        message => panic!("unexpected exec response: {message:?}"),
    }
    client.send_message(&Message::Stop).await.unwrap();
    task.await.unwrap().unwrap();
}

async fn check_shell(command: &[String]) {
    let (mut client, task) = authenticated_client().await;
    client
        .send_message(&Message::Shell { rows: 24, cols: 80 })
        .await
        .unwrap();
    // The marker is printed only by the reporter, not echoed in the PTY input.
    let command = command
        .iter()
        .map(|s| crate::security::shell_escape(s))
        .collect::<Vec<_>>()
        .join(" ");
    client
        .send_message(&Message::ShellData {
            stream: 0,
            data: format!("{command}; exit $?\n").into_bytes(),
        })
        .await
        .unwrap();
    let mut output = Vec::new();
    loop {
        match client.recv_message().await.unwrap().unwrap() {
            Message::ShellData { data, .. } => output.extend(data),
            Message::ShellClose { exit_code } => {
                assert_eq!(exit_code, 0);
                break;
            }
            other => panic!("unexpected shell response: {other:?}"),
        }
    }
    assert!(String::from_utf8_lossy(&output).contains("IZANAGI_GROUPS_CLEARED"));
    client.send_message(&Message::Stop).await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
#[ignore = "requires disposable Linux root with an izanagi user and /workspace"]
async fn privileged_exec_and_shell_discard_parent_groups() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "this regression must run as Linux root"
    );
    let groups = [0, 12345];
    assert_eq!(unsafe { libc::setgroups(groups.len(), groups.as_ptr()) }, 0);
    assert_eq!(unsafe { libc::getgroups(0, std::ptr::null_mut()) }, 2);
    let executable = std::env::current_exe()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    // Environment is private to this dedicated test process.
    unsafe {
        std::env::set_var("IZANAGI_ALLOWED_COMMANDS", &executable);
    }
    let command = vec![
        executable,
        "--exact".into(),
        "privilege_tests::report_dropped_identity".into(),
        "--ignored".into(),
        "--nocapture".into(),
    ];
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        check_exec(command.clone()).await;
        check_shell(&command).await;
    })
    .await
    .expect("credential regression hung");
    assert_eq!(
        unsafe { libc::getgroups(0, std::ptr::null_mut()) },
        2,
        "only child credentials may change"
    );
}

#[test]
#[ignore = "requires disposable Linux root"]
fn privileged_identity_transition_errors_prevent_exec() {
    use std::os::unix::process::CommandExt;
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let (uid, gid, _) = crate::credentials::lookup_user(crate::exec::EXEC_USER)
        .unwrap()
        .unwrap();
    for stage in 0..3 {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "printf EXEC_MUST_NOT_RUN"]);
        unsafe {
            command.pre_exec(move || {
                if stage == 0 && libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                crate::credentials::drop_identity(
                    if stage == 2 { u32::MAX } else { uid },
                    if stage == 1 { u32::MAX } else { gid },
                )
            });
        }
        assert!(
            command.output().is_err(),
            "exec must not run after transition failure at stage {stage}"
        );
    }
}
