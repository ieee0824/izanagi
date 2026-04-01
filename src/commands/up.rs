use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use izanagi::config::Config;
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

    // PID ファイルを書き込む
    write_pid_file()?;

    // セッション情報を保存（exec/shell から接続するため）
    let iza_dir = izanagi_dir();
    if let Some(backend) = engine.sandbox().session_backend() {
        let sess = Session {
            backend,
            pid: std::process::id(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        session::save_session(&iza_dir, &sess)?;
    }

    println!(
        "サンドボックスを起動しました (PID: {})。Ctrl+C または izanagi down で停止します。",
        std::process::id()
    );

    // Ctrl+C を待ちつつ、定期的に LogStorage をフラッシュする。
    // logs -f (別プロセス) がリアルタイムでログを読めるようにするため。
    let mut flush_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut flush_error_warned = false;
    loop {
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
            _ = &mut ctrl_c => {
                break;
            }
        }
    }

    println!("\nシャットダウン中...");
    // クリーンアップは stop/flush の成否に関わらず必ず実行する
    proxy_manager.stop().await;
    let stop_result = engine.stop().await;
    let flush_result = log_storage.flush();
    session::remove_session(&iza_dir);
    remove_pid_file();
    remove_lock_file();
    stop_result?;
    flush_result?;
    println!("サンドボックスを停止しました。");

    Ok(0)
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
