use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::pcap_writer::PcapWriter;

/// Sandbox の状態。起動シーケンスの各段階を明示する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// 停止中。exec/shell は呼べない。
    Stopped,
    /// 起動処理中（VM ブート待ち等）。exec/shell はまだ呼べない。
    Starting,
    /// 稼働中。exec/shell が利用可能。
    Running,
    /// 停止処理中。新しい exec/shell は受け付けない。
    Stopping,
}

/// Sandbox バックエンドの設定。backend ごとに必要な値が異なるため enum で分岐。
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SandboxConfig {
    Qemu {
        cpus: u32,
        memory_mb: u32,
        image: String,
        share: ShareConfig,
        /// DNS プロキシの IP アドレス（QEMU の -netdev dns= に渡す）。
        dns_proxy: Option<String>,
    },
    /// Linux Landlock ベースの軽量隔離。
    Landlock { share: ShareConfig },
    /// Apple Container (macOS) ベースの隔離。
    AppleContainer {
        image: String,
        share: ShareConfig,
        /// DNS プロキシの IP アドレス（container run --dns に渡す）。
        dns_proxy: Option<String>,
        /// ネットワークモード（None でデフォルト = bridge）。
        network: Option<crate::config::ContainerNetworkMode>,
    },
}

/// ホスト - ゲスト間のファイル共有設定。
#[derive(Debug, Clone)]
pub struct ShareConfig {
    /// ホスト側の共有パス。
    pub host_paths: Vec<PathBuf>,
    /// ゲスト側のマウントポイント。
    pub mount_point: PathBuf,
}

/// コマンド実行の結果。
#[derive(Debug)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// 隔離環境のライフサイクルを管理する。
///
/// # 状態遷移
///
/// ```text
/// Stopped → Starting → Running → Stopping → Stopped
/// ```
///
/// `exec` / `shell` は `Running` 状態でのみ呼び出せる。
/// それ以外の状態で呼んだ場合は `Err` を返す。
#[async_trait::async_trait]
pub trait Sandbox: Send {
    /// 隔離環境を起動する。`Running` になるまで待つ。
    async fn up(&mut self, config: &SandboxConfig) -> anyhow::Result<()>;

    /// 隔離環境内でコマンドを実行する。完了まで待つ。
    ///
    /// # Errors
    /// 状態が `Running` でない場合は `Err` を返す。
    async fn exec(
        &self,
        cmd: &[String],
        env: &HashMap<String, String>,
    ) -> anyhow::Result<ExecOutput>;

    /// 隔離環境内でインタラクティブシェルを起動する。
    /// シェル終了まで制御を渡す。
    ///
    /// # Errors
    /// 状態が `Running` でない場合は `Err` を返す。
    async fn shell(&self) -> anyhow::Result<()>;

    /// 隔離環境を停止する。`Stopped` になるまで待つ。
    async fn down(&mut self) -> anyhow::Result<()>;

    /// 現在の状態を返す。
    fn status(&self) -> SandboxStatus;

    /// VM 起動時に生成されたセッショントークンを返す。
    /// QEMU バックエンドのみ実装する。その他は `None` を返す。
    fn session_token(&self) -> Option<&str> {
        None
    }

    /// VM/コンテナの agent がリッスンしているホスト側ポートを返す。
    /// VmAgentTracer がこのポートに接続するために使用する。
    /// QEMU / AppleContainer バックエンドのみ実装する。
    fn agent_host_port(&self) -> Option<u16> {
        None
    }

    /// セッション情報のバックエンド固有データを返す。
    /// `up` コマンドで `session.json` に保存するために使用する。
    /// 起動中でない場合は `None` を返す。
    fn session_backend(&self) -> Option<crate::session::SessionBackend> {
        None
    }

    /// pcap ライターを設定する。設定すると host <-> agent 間の通信を記録する。
    /// デフォルトでは何もしない（QEMU バックエンドのみ対応）。
    fn set_pcap_writer(&mut self, _writer: Arc<PcapWriter>) {
        // デフォルトは no-op
    }
}
