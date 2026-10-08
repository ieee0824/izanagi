use std::collections::HashMap;
#[cfg(unix)]
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;

use izanagi::config::Config;
use izanagi::engine::Engine;
use izanagi::log_storage::LogStorage;
use izanagi::pcap_writer::PcapWriter;
use izanagi::proxy_manager::ProxyManager;
use izanagi::session::{self, Session};

use super::{
    acquire_instance_lock, izanagi_dir, remove_lock_file, remove_pid_file, start_engine,
    write_pid_file,
};

pub async fn cmd_up(
    config: &Config,
    config_path: &Path,
    pcap_path: Option<&Path>,
) -> anyhow::Result<u8> {
    let _lock = acquire_instance_lock()?;

    // --pcap オプションが指定されている場合、pcap ファイルを初期化
    let pcap_writer = if let Some(path) = pcap_path {
        let writer = PcapWriter::create(path)
            .map_err(|e| anyhow::anyhow!("pcap ファイルの作成に失敗: {}: {}", path.display(), e))?;
        eprintln!("[pcap] キャプチャ開始: {}", path.display());
        Some(Arc::new(writer))
    } else {
        None
    };

    // DNS プロキシ / HTTP キャプチャプロキシを自動起動 (#270, #271)
    let mut proxy_manager = ProxyManager::start(config, config_path).await?;

    let (mut engine, log_storage) = start_engine(config, pcap_writer).await?;

    // CA 証明書をサンドボックス内に配布 (#272)
    if let Some(ref http_capture) = config.http_capture {
        if http_capture.enabled {
            if let Some(ref ca_path) = http_capture.ca_cert_out {
                install_ca_cert(engine.sandbox(), ca_path).await;
            }
        }
    }

    let iza_dir = izanagi_dir();
    let runtime_state_result = persist_runtime_state(
        &iza_dir,
        engine.sandbox().session_backend(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        write_pid_file,
    );
    if let Err(startup_error) = runtime_state_result {
        if let Err(e) =
            cleanup_running_resources(&mut proxy_manager, &mut engine, &log_storage, &iza_dir).await
        {
            eprintln!("警告: 起動失敗後のクリーンアップにも失敗しました: {}", e);
        }
        return Err(startup_error);
    }

    println!(
        "サンドボックスを起動しました (PID: {})。Ctrl+C または izanagi down で停止します。",
        std::process::id()
    );

    // Ctrl+C を待ちつつ、定期的に LogStorage をフラッシュする。
    // logs -f (別プロセス) がリアルタイムでログを読めるようにするため。
    let mut flush_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let shutdown_signal = wait_for_shutdown_signal();
    tokio::pin!(shutdown_signal);
    let mut flush_error_warned = false;
    let wait_result = loop {
        tokio::select! {
            _ = flush_interval.tick() => {
                let storage = log_storage.clone();
                match tokio::task::spawn_blocking(move || storage.flush()).await {
                    Ok(Ok(_)) => { flush_error_warned = false; }
                    Ok(Err(e)) => {
                        if !flush_error_warned {
                            eprintln!("警告: ログのフラッシュに失敗 (以降の連続失敗は抑制): {}", e);
                            flush_error_warned = true;
                        }
                    }
                    Err(e) => {
                        if !flush_error_warned {
                            eprintln!("警告: フラッシュタスクの実行に失敗 (以降の連続失敗は抑制): {}", e);
                            flush_error_warned = true;
                        }
                    }
                }
            }
            result = &mut shutdown_signal => {
                break result;
            }
        }
    };

    println!("\nシャットダウン中...");
    let cleanup_result =
        cleanup_running_resources(&mut proxy_manager, &mut engine, &log_storage, &iza_dir).await;
    wait_result?;
    cleanup_result?;
    println!("サンドボックスを停止しました。");

    Ok(0)
}

fn persist_runtime_state<F>(
    iza_dir: &Path,
    backend: Option<izanagi::session::SessionBackend>,
    pid: u32,
    started_at: u64,
    write_pid: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    write_pid()?;
    if let Some(backend) = backend {
        let sess = Session {
            backend,
            pid,
            started_at,
        };
        session::save_session(iza_dir, &sess)?;
    }
    Ok(())
}

/// 起動済みリソースを停止し、状態ファイルを必ず削除する。
///
/// 停止やflushの失敗は警告として記録する。起動途中の本来のエラーを上書きせず、
/// 可能なクリーンアップを最後まで継続するためである。
async fn cleanup_running_resources(
    proxy_manager: &mut ProxyManager,
    engine: &mut Engine,
    log_storage: &LogStorage,
    iza_dir: &Path,
) -> anyhow::Result<()> {
    proxy_manager.stop().await;
    let stop_result = engine.stop().await;
    let flush_result = log_storage.flush();
    session::remove_session(iza_dir);
    remove_pid_file();
    remove_lock_file();
    stop_result?;
    flush_result?;
    Ok(())
}

/// Ctrl+C (SIGINT) または SIGTERM の最初の受信まで待機する。
///
/// `izanagi down` は SIGTERM を送信するため、SIGINT と同じ正常終了経路へ流して
/// sandbox・proxy・状態ファイルを確実にクリーンアップする。
#[cfg(unix)]
async fn wait_for_shutdown_signal() -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    wait_for_first_shutdown_signal(tokio::signal::ctrl_c(), async move {
        let _ = terminate.recv().await;
    })
    .await
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(unix)]
async fn wait_for_first_shutdown_signal<C, T>(ctrl_c: C, terminate: T) -> io::Result<()>
where
    C: Future<Output = io::Result<()>>,
    T: Future<Output = ()>,
{
    tokio::pin!(ctrl_c);
    tokio::pin!(terminate);
    tokio::select! {
        result = &mut ctrl_c => result,
        _ = &mut terminate => Ok(()),
    }
}

/// CA 証明書をサンドボックス内にインストールする。
///
/// heredoc (シングルクォートデリミタ) で PEM をサンドボックス内に書き込み、
/// `update-ca-certificates` で信頼ストアを更新する。
/// 失敗しても致命的ではないため、警告のみ出力して続行する。
async fn install_ca_cert(sandbox: &dyn izanagi::sandbox::Sandbox, ca_path: &Path) {
    // izanagi-http-capture が CA 証明書を書き出す前に読み取りを試みると
    // 一時的に ENOENT となる可能性があるため、短時間リトライする。
    let ca_pem = {
        let timeout = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();
        loop {
            match std::fs::read_to_string(ca_path) {
                Ok(s) => break s,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound && start.elapsed() < timeout {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    eprintln!(
                        "[proxy] CA 証明書の読み取りに失敗 ({}): {} — HTTPS キャプチャが正常に動作しない可能性があります",
                        ca_path.display(),
                        e
                    );
                    return;
                }
            }
        }
    };

    // heredoc デリミタ衝突チェック（PEM 内容に 'IZANAGI_CA_EOF' が行として含まれていないことを確認）
    let delimiter = "IZANAGI_CA_EOF";
    if ca_pem.lines().any(|line| line.trim() == delimiter) {
        eprintln!("[proxy] CA 証明書にデリミタ衝突あり — 手動でインストールしてください");
        return;
    }

    let env = HashMap::new();

    // heredoc で安全に書き込み（デリミタ衝突チェック済み、シングルクォートで変数展開を防止）
    let write_cmd = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "mkdir -p /usr/local/share/ca-certificates && cat > /usr/local/share/ca-certificates/izanagi-ca.crt << '{delimiter}'\n{}\n{delimiter}",
            ca_pem.trim()
        ),
    ];
    match sandbox.exec(&write_cmd, &env).await {
        Ok(output) if output.exit_code == 0 => {}
        Ok(output) => {
            eprintln!(
                "[proxy] CA 証明書の配置に失敗 (exit {}): {} — HTTPS キャプチャが正常に動作しない可能性があります",
                output.exit_code,
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "[proxy] CA 証明書の配置に失敗: {e} — HTTPS キャプチャが正常に動作しない可能性があります"
            );
            return;
        }
    }

    // 証明書ストアを更新 (Alpine/Debian: update-ca-certificates)
    let update_cmd = vec![
        "sh".to_string(),
        "-c".to_string(),
        "update-ca-certificates 2>/dev/null".to_string(),
    ];
    match sandbox.exec(&update_cmd, &env).await {
        Ok(output) if output.exit_code == 0 => {
            eprintln!("[proxy] CA 証明書をサンドボックス内にインストールしました");
        }
        Ok(output) => {
            eprintln!(
                "[proxy] CA 証明書の信頼ストア更新に失敗 (exit {}): {} — 手動で update-ca-certificates を実行してください",
                output.exit_code,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(e) => {
            eprintln!(
                "[proxy] CA 証明書の信頼ストア更新に失敗: {e} — 手動で update-ca-certificates を実行してください"
            );
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{persist_runtime_state, wait_for_first_shutdown_signal};
    use izanagi::session::{self, SessionBackend};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("izanagi-up-test-{}-{}", std::process::id(), id))
    }

    #[tokio::test]
    async fn shutdown_waiter_accepts_sigint_path() {
        let ctrl_c = std::future::ready(Ok(()));
        let terminate = std::future::pending();
        wait_for_first_shutdown_signal(ctrl_c, terminate)
            .await
            .expect("SIGINT path should complete successfully");
    }

    #[tokio::test]
    async fn shutdown_waiter_accepts_sigterm_path() {
        let ctrl_c = std::future::pending();
        let terminate = std::future::ready(());
        wait_for_first_shutdown_signal(ctrl_c, terminate)
            .await
            .expect("SIGTERM path should complete successfully");
    }

    #[tokio::test]
    async fn shutdown_waiter_propagates_sigint_handler_error() {
        let ctrl_c = std::future::ready(Err(std::io::Error::other("signal error")));
        let terminate = std::future::pending();
        assert!(
            wait_for_first_shutdown_signal(ctrl_c, terminate)
                .await
                .is_err()
        );
    }

    #[test]
    fn runtime_state_stops_when_pid_write_fails() {
        let dir = test_dir();
        let result = persist_runtime_state(&dir, None, 1, 1, || anyhow::bail!("pid write failed"));
        assert!(result.is_err());
        assert!(!session::session_file_path(&dir).exists());
    }

    #[test]
    fn runtime_state_reports_session_write_failure() {
        let parent = test_dir();
        std::fs::create_dir_all(&parent).expect("create temporary directory");
        let invalid_dir = parent.join("not-a-directory");
        std::fs::write(&invalid_dir, "file blocks directory creation")
            .expect("create blocking file");
        let backend = SessionBackend::Qemu {
            host_port: 9001,
            token_hash: None,
        };

        let result = persist_runtime_state(&invalid_dir, Some(backend), 1, 1, || Ok(()));
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(parent);
    }
}
