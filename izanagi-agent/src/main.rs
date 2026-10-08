//! izanagi-agent: QEMU ゲスト内で動作するトレースエージェント。
//!
//! virtio-vsock 経由でホストの VmAgentTracer と通信し、
//! ゲスト内の eBPF Tracer が収集した syscall イベントを転送する。
//!
//! ## 動作フロー
//!
//! 1. vsock でホストからの接続を待ち受け
//! 2. Ready メッセージを送信
//! 3. Start メッセージを受信 → eBPF Tracer を起動
//! 4. イベントを Event メッセージとしてホストに転送
//! 5. Stop メッセージ受信 → Tracer 停止 → 接続クローズ
//!
//! ## 認証
//!
//! 環境変数 `IZANAGI_SHARED_SECRET` が設定されている場合、
//! HMAC-SHA256 ベースのメッセージ認証を有効にする。
//! ホスト側と同じシークレットを使用する必要がある。
//!
//! ## 注意
//!
//! このバイナリはスケルトン実装であり、実際の動作は Linux + QEMU 環境で確認する。

mod config;
mod connection;
mod crypto;
mod exec;
mod security;
mod shell;
mod sidecar;

use izanagi::protocol;
use std::sync::Arc;

/// vsock リスナーのデフォルトポート。
const DEFAULT_PORT: u32 = 9001;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("izanagi-agent starting on vsock port {}...", DEFAULT_PORT);

    // fw_cfg からシークレットを読み取る (#161)
    // fw_cfg の値が取得できた場合、環境変数より優先する
    let secret = match config::read_fw_cfg_secret() {
        Some(s) => Some(s),
        None => protocol::load_shared_secret_from_env()?,
    };
    if secret.is_some() {
        eprintln!("HMAC authentication enabled");
    } else {
        eprintln!("WARNING: HMAC authentication disabled (IZANAGI_SHARED_SECRET not set)");
    }

    // fw_cfg からセッショントークンを読み取る (#115)
    // Linux ゲストでは /sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.token/raw に配置される
    // セッショントークン: VM 生存期間中は同じトークンで何度でも接続可能
    // fw_cfg トークンが読めない場合は fail-closed (#196)
    // IZANAGI_ALLOW_NO_TOKEN=1 で明示的にオプトアウト可能（開発・テスト用）
    let expected_token: Arc<Option<String>> = Arc::new(config::read_fw_cfg_token());
    let require_token = std::env::var("IZANAGI_ALLOW_NO_TOKEN").unwrap_or_default() != "1";
    if expected_token.is_some() {
        eprintln!("fw_cfg token authentication enabled");
    } else if require_token {
        anyhow::bail!(
            "fw_cfg token not found. Set IZANAGI_ALLOW_NO_TOKEN=1 to allow (not recommended)."
        );
    } else {
        eprintln!(
            "WARNING: fw_cfg token not found, running without token authentication (IZANAGI_ALLOW_NO_TOKEN=1)"
        );
    }

    // 環境変数設定のサマリをログ出力
    config::log_env_summary();

    // vsock リスナーの作成。
    // 実運用では tokio-vsock の VsockListener を使用する。
    // ここでは TCP でフォールバックするスケルトン実装。
    // QEMU の hostfwd はゲストの 0.0.0.0 にフォワードするため、
    // QEMU 環境では 0.0.0.0 バインドが必要。
    // IZANAGI_BIND_ADDR で上書き可能。デフォルトは 0.0.0.0（VM/コンテナ内なので安全）。
    let bind_addr = std::env::var("IZANAGI_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", bind_addr, DEFAULT_PORT)).await?;
    eprintln!("izanagi-agent listening on {}:{}", bind_addr, DEFAULT_PORT);

    loop {
        let (stream, addr) = listener.accept().await?;
        eprintln!("accepted connection from {:?}", addr);

        let secret = secret.clone();
        let expected_token = Arc::clone(&expected_token);
        tokio::spawn(async move {
            if let Err(e) =
                connection::handle_connection(stream, secret.as_deref(), &expected_token).await
            {
                eprintln!("connection error: {}", e);
            }
        });
    }
}
