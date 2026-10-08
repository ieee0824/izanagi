use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc;

use crate::event::{SyscallCategory, SyscallEvent};

/// トレース対象のフィルタ。指定しなかったものは記録されない（デフォルト拒否）。
///
/// `Serialize`/`Deserialize` を実装しており、`Message::Start` に直接埋め込んで
/// プロトコル経由で送受信される。
///
/// **ワイヤー互換性に関する注意**: この構造体は postcard でシリアライズされ、
/// host ↔ agent 間のプロトコルメッセージに含まれる。フィールドの追加・削除・
/// 順序変更はワイヤー互換性に影響するため、host と agent を同時にデプロイするか、
/// プロトコルバージョニングを導入すること。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct TraceFilter {
    /// 監視する syscall カテゴリ。空の場合は何も記録しない。
    pub categories: Vec<SyscallCategory>,
    /// 監視対象の PID。`None` で全プロセスを監視。
    pub pids: Option<Vec<u32>>,
}

/// イベントチャネルのバッファサイズ。
/// バックプレッシャーとして機能する — バッファが埋まると Tracer 側が待機する。
pub const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// syscall イベントを収集し、チャネルで配信する。
///
/// `start` が返す `Receiver` は bounded channel であり、
/// 消費が追いつかない場合は Tracer 側でイベント生成がブロックされる。
/// これにより、メモリ使用量が際限なく増えることを防ぐ。
///
/// 内部状態の変更は各実装が内部ミューテックスで管理する。
/// `&self` とすることで、trait object を `Arc` 経由で共有可能にする。
#[async_trait::async_trait]
pub trait Tracer: Send + Sync {
    /// Whether losing the event channel is a monitoring failure.
    fn requires_live_monitoring(&self) -> bool {
        true
    }

    /// Last transport/backend failure, recorded before closing the event channel.
    fn failure_reason(&self) -> Option<String> {
        None
    }

    /// トレースを開始し、イベントを受信するチャネルを返す。
    async fn start(
        &self,
        filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>>;

    /// トレースを停止する。チャネルは close される。
    async fn stop(&self) -> anyhow::Result<()>;

    /// Hello ハンドシェイクで使用するセッショントークン（SHA256 ハッシュ済み）を設定する。
    /// VmAgentTracer のみ実装する。その他は何もしない。
    fn set_session_token(&self, _token_hash: String) {}

    /// agent の接続先ポートを設定する。
    /// VmAgentTracer のみ実装する。その他は何もしない。
    fn set_agent_port(&self, _port: u16) {}

    /// HMAC 認証用の共有シークレットを設定する。
    /// VmAgentTracer のみ実装する。その他は何もしない。
    fn set_secret(&self, _secret: Vec<u8>) {}

    /// Optional behavior telemetry has an independent bounded channel.
    fn set_behavior(
        &self,
        _config: crate::protocol::BehaviorStartConfig,
        _sender: mpsc::Sender<izanagi_telemetry::TelemetryEnvelope>,
    ) {
    }
}

/// 何もしないトレーサー。`TracerBackend::None` 選択時に使用する。
///
/// `start()` は空のチャネルを返し、イベントを一切生成しない。
pub struct NullTracer {
    tx: Mutex<Option<mpsc::Sender<Arc<SyscallEvent>>>>,
}

impl Default for NullTracer {
    fn default() -> Self {
        Self {
            tx: Mutex::new(None),
        }
    }
}

impl NullTracer {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl Tracer for NullTracer {
    fn requires_live_monitoring(&self) -> bool {
        false
    }
    async fn start(
        &self,
        _filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>> {
        let (tx, rx) = mpsc::channel(1);
        *self.tx.lock().expect("NullTracer lock poisoned") = Some(tx);
        Ok(rx)
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.tx.lock().expect("NullTracer lock poisoned").take(); // チャネルを閉じる
        Ok(())
    }
}

/// テスト用の `Tracer` trait 実装。
///
/// 事前定義した `Vec<SyscallEvent>` を `start()` 時にチャネルに流す。
/// `Engine` のインテグレーションテストや単体テストで、実際のトレーサーの代わりに使用する。
#[cfg(test)]
pub struct MockTracer {
    events: Mutex<Vec<SyscallEvent>>,
    tx: Mutex<Option<mpsc::Sender<Arc<SyscallEvent>>>>,
}

#[cfg(test)]
impl MockTracer {
    /// 指定したイベント列を流す MockTracer を作成する。
    pub fn new(events: Vec<SyscallEvent>) -> Self {
        Self {
            events: Mutex::new(events),
            tx: Mutex::new(None),
        }
    }

    /// 空のイベント列を流す MockTracer を作成する。
    pub fn empty() -> Self {
        Self::new(vec![])
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl Tracer for MockTracer {
    async fn start(
        &self,
        _filter: &TraceFilter,
    ) -> anyhow::Result<mpsc::Receiver<Arc<SyscallEvent>>> {
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        // ロックを短時間だけ保持して events を取り出す（await を跨がない）
        let events: Vec<SyscallEvent> = self
            .events
            .lock()
            .expect("MockTracer lock poisoned")
            .drain(..)
            .collect();
        for event in events {
            tx.send(Arc::new(event))
                .await
                .map_err(|e| anyhow::anyhow!("MockTracer: イベント送信に失敗: {}", e))?;
        }

        *self.tx.lock().expect("MockTracer lock poisoned") = Some(tx);
        Ok(rx)
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.tx.lock().expect("MockTracer lock poisoned").take(); // チャネルを閉じる
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Syscall, SyscallResult};
    use std::time::SystemTime;

    fn make_test_event(pid: u32, syscall: Syscall) -> SyscallEvent {
        SyscallEvent {
            timestamp: SystemTime::now(),
            pid,
            tgid: 0,
            process_name: "mock-test".into(),
            syscall,
            args: smallvec::smallvec![],
            result: SyscallResult::Ok(0),
        }
    }

    #[tokio::test]
    async fn mock_tracer_delivers_preset_events() {
        let events = vec![
            make_test_event(1, Syscall::Open),
            make_test_event(2, Syscall::Connect),
            make_test_event(3, Syscall::Execve),
        ];

        let tracer = MockTracer::new(events);
        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        let mut rx = tracer.start(&filter).await.unwrap();

        let e1 = rx.recv().await.unwrap();
        assert_eq!(e1.pid, 1);
        assert_eq!(e1.syscall, Syscall::Open);

        let e2 = rx.recv().await.unwrap();
        assert_eq!(e2.pid, 2);
        assert_eq!(e2.syscall, Syscall::Connect);

        let e3 = rx.recv().await.unwrap();
        assert_eq!(e3.pid, 3);
        assert_eq!(e3.syscall, Syscall::Execve);

        tracer.stop().await.unwrap();

        // stop 後はチャネルが閉じられ、recv は None を返す
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn mock_tracer_empty_closes_on_stop() {
        let tracer = MockTracer::empty();
        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        let mut rx = tracer.start(&filter).await.unwrap();
        tracer.stop().await.unwrap();

        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn null_tracer_returns_empty_channel() {
        let tracer = NullTracer::new();
        let filter = TraceFilter {
            categories: vec![],
            pids: None,
        };

        let mut rx = tracer.start(&filter).await.unwrap();
        tracer.stop().await.unwrap();

        // stop 後はチャネルが閉じられ、recv は None を返す
        assert!(rx.recv().await.is_none());
    }
}
