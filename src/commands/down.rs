use izanagi::session;

use super::{
    ProcessStatus, check_process_alive, izanagi_dir, pid_file_path, read_pid_file,
    remove_lock_file, remove_pid_file, try_instance_lock,
};

/// ロックファイルで up プロセスの有無を確認する。
/// up プロセスが存在しない場合は stale ファイルを削除して Ok(exit_code) を返す。
/// up プロセスが存在する場合は Err を返す（呼び出し元で停止フローに進む）。
fn check_no_running_instance() -> Result<u8, anyhow::Error> {
    match try_instance_lock() {
        Ok(Some(_guard)) => {
            // ロック取得成功 = up プロセスなし。stale ファイルがあればクリーンアップ
            let has_pid = std::fs::read_to_string(pid_file_path()).is_ok();
            let has_session = session::load_session(&izanagi_dir())
                .ok()
                .flatten()
                .is_some();
            let has_stale = has_pid || has_session;
            session::remove_session(&izanagi_dir());
            remove_pid_file();
            remove_lock_file();
            if has_stale {
                eprintln!("izanagi は起動していません（stale ファイルを削除しました）");
            } else {
                eprintln!("izanagi は起動していません");
            }
            Ok(1)
        }
        Ok(None) => {
            eprintln!("izanagi は起動していません");
            Ok(1)
        }
        Err(e) => {
            // WouldBlock = up プロセスが起動中 → 停止フローへ
            let msg = e.to_string();
            if !msg.contains("別のプロセスがロックを保持しています") {
                eprintln!(
                    "警告: ロック状態の確認に失敗しました: {}。停止を試行します。",
                    e
                );
            }
            Err(anyhow::anyhow!("running"))
        }
    }
}

/// PID ファイルを読み取り、PID の整合性を検証する。
/// 検証に成功した場合は PID を返す。
fn validate_target_pid() -> anyhow::Result<u32> {
    let (pid, saved_timestamp) = read_pid_file()?;

    // PID 再利用対策: PID ファイルの mtime を確認
    if saved_timestamp > 0
        && let Ok(meta) = std::fs::metadata(pid_file_path())
        && let Ok(mtime) = meta.modified()
    {
        let mtime_secs = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if mtime_secs < saved_timestamp.saturating_sub(1) {
            session::remove_session(&izanagi_dir());
            remove_pid_file();
            remove_lock_file();
            anyhow::bail!(
                "PID ファイルのタイムスタンプが不整合です。PID {} は再利用されている可能性があります。stale ファイルを削除しました。",
                pid
            );
        }
    }

    // セッション情報との整合性チェック
    if let Ok(Some(sess)) = session::load_session(&izanagi_dir()) {
        if sess.pid != pid {
            session::remove_session(&izanagi_dir());
            remove_pid_file();
            remove_lock_file();
            anyhow::bail!(
                "PID ファイル ({}) とセッション情報 ({}) の PID が一致しません。stale ファイルを削除しました。",
                pid,
                sess.pid
            );
        }
    }

    // プロセスが存在するか確認
    match check_process_alive(pid) {
        ProcessStatus::NotRunning => {
            session::remove_session(&izanagi_dir());
            remove_pid_file();
            remove_lock_file();
            anyhow::bail!(
                "PID {} のプロセスは既に停止しています。stale ファイルを削除しました。",
                pid
            );
        }
        ProcessStatus::PermissionDenied => {
            anyhow::bail!("PID {} のプロセス確認に権限がありません", pid);
        }
        ProcessStatus::Running => {}
    }

    Ok(pid)
}

pub async fn cmd_down() -> anyhow::Result<u8> {
    // up プロセスが存在しなければ早期リターン
    if let Ok(exit_code) = check_no_running_instance() {
        return Ok(exit_code);
    }

    let pid = validate_target_pid()?;

    // SIGTERM を送信
    let result = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if result != 0 {
        anyhow::bail!("PID {} へのシグナル送信に失敗しました", pid);
    }

    println!("PID {} に停止シグナルを送信しました。", pid);

    // プロセスの終了を待つ (最大10秒)
    for _ in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if let ProcessStatus::NotRunning = check_process_alive(pid) {
            session::remove_session(&izanagi_dir());
            remove_pid_file();
            remove_lock_file();
            println!("サンドボックスを停止しました。");
            return Ok(0);
        }
    }
    anyhow::bail!("PID {} が10秒以内に停止しませんでした", pid);
}
