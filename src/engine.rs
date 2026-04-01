use std::sync::Arc;

use anyhow::bail;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::apple_container_sandbox::AppleContainerSandbox;
use crate::config::{Config, SandboxBackend, TracerBackend};
use crate::detector::{Alert, Detector};
use crate::dtrace_tracer::DTraceTracer;
use crate::ebpf_tracer::EbpfTracer;
use crate::event::SyscallEvent;
use crate::landlock_sandbox::LandlockSandbox;
use crate::qemu_sandbox::QemuSandbox;
use crate::sandbox::{Sandbox, SandboxConfig, SandboxStatus};
use crate::tracer::{NullTracer, TraceFilter, Tracer};
use crate::vm_agent_tracer::{VmAgentConfig, VmAgentTracer};

use crate::util::sha256_hex;

/// Config の `sandbox.backend` からプラットフォームに応じた Sandbox 実装を選択する。
pub fn select_sandbox(config: &Config) -> anyhow::Result<Box<dyn Sandbox>> {
    select_sandbox_for_platform(config, cfg!(target_os = "linux"), cfg!(target_os = "macos"))
}

/// プラットフォーム判定を引数として受け取る Sandbox 選択。テスト用。
fn select_sandbox_for_platform(
    config: &Config,
    is_linux: bool,
    is_macos: bool,
) -> anyhow::Result<Box<dyn Sandbox>> {
    match config.sandbox.backend {
        SandboxBackend::Qemu => Ok(Box::new(QemuSandbox::new())),
        SandboxBackend::Native => {
            if is_macos {
                Ok(Box::new(AppleContainerSandbox::new()))
            } else if is_linux {
                Ok(Box::new(LandlockSandbox::new()))
            } else {
                bail!("native サンドボックスは Linux または macOS でのみ利用可能です")
            }
        }
        SandboxBackend::AppleContainer => {
            if !is_macos {
                bail!("apple-container サンドボックスは macOS でのみ利用可能です")
            }
            Ok(Box::new(AppleContainerSandbox::new()))
        }
    }
}

/// Config の `sandbox.tracer` からプラットフォームに応じた Tracer 実装を選択する。
pub fn select_tracer(config: &Config) -> anyhow::Result<Box<dyn Tracer>> {
    select_tracer_for_platform(config, cfg!(target_os = "linux"), cfg!(target_os = "macos"))
}

/// プラットフォーム判定を引数として受け取る Tracer 選択。テスト用。
fn select_tracer_for_platform(
    config: &Config,
    is_linux: bool,
    is_macos: bool,
) -> anyhow::Result<Box<dyn Tracer>> {
    match config.sandbox.tracer {
        TracerBackend::None => Ok(Box::new(NullTracer::new())),
        TracerBackend::Auto => {
            // QEMU / AppleContainer はホスト側トレーサーが使えないため NullTracer
            match config.sandbox.backend {
                SandboxBackend::Qemu => return Ok(Box::new(NullTracer::new())),
                SandboxBackend::AppleContainer => return Ok(Box::new(NullTracer::new())),
                _ => {}
            }
            if is_linux {
                Ok(Box::new(EbpfTracer::new()))
            } else if is_macos {
                Ok(Box::new(DTraceTracer::new()))
            } else {
                bail!("auto トレーサーは Linux または macOS でのみ利用可能です")
            }
        }
        TracerBackend::Ebpf => {
            if !is_linux {
                bail!("eBPF トレーサーは Linux でのみ利用可能です")
            }
            Ok(Box::new(EbpfTracer::new()))
        }
        TracerBackend::Dtrace => {
            if !is_macos {
                bail!("DTrace トレーサーは macOS でのみ利用可能です")
            }
            Ok(Box::new(DTraceTracer::new()))
        }
        TracerBackend::VmAgent => {
            if config.sandbox.backend != SandboxBackend::Qemu {
                bail!("vm-agent トレーサーは QEMU バックエンドでのみ利用可能です")
            }
            Ok(Box::new(VmAgentTracer::new(VmAgentConfig::default())))
        }
    }
}

/// Config から Engine を構築する。バックエンド選択・Detector 構築を一括で行う。
pub fn build_engine(config: &Config) -> anyhow::Result<Engine> {
    let sandbox = select_sandbox(config)?;
    let tracer = select_tracer(config)?;
    let rules = config.to_rules();
    let detector = Detector::new(rules);
    Ok(Engine::new(sandbox, tracer, detector))
}

/// Sandbox・Tracer・Detector を合成し、全体のライフサイクルを管理する。
pub struct Engine {
    sandbox: Box<dyn Sandbox>,
    tracer: Box<dyn Tracer>,
    detector: Arc<Detector>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
    /// 全 syscall イベント受信時のコールバック。設定されている場合、
    /// 監視ループ内で各イベントに対して呼ばれる。
    on_event: Option<EventHandler>,
}

/// アラート発生時のコールバック。
pub type AlertHandler = Box<dyn Fn(&Alert) + Send>;

/// イベント受信時のコールバック。全 syscall イベントに対して呼ばれる。
/// `None` の場合はイベント記録をスキップする（アラートのみ処理）。
pub type EventHandler = Box<dyn Fn(&SyscallEvent) + Send>;

impl Engine {
    pub fn new(sandbox: Box<dyn Sandbox>, tracer: Box<dyn Tracer>, detector: Detector) -> Self {
        Self {
            sandbox,
            tracer,
            detector: Arc::new(detector),
            shutdown_tx: None,
            handle: None,
            on_event: None,
        }
    }

    /// 全 syscall イベント受信時のコールバックを設定する。
    /// `start()` 前に呼ぶこと。
    pub fn set_event_handler(&mut self, handler: EventHandler) {
        self.on_event = Some(handler);
    }

    /// pcap ライターを設定する。`start()` 前に呼ぶこと。
    /// サンドボックスバックエンドが対応していない場合は無視される。
    pub fn set_pcap_writer(&mut self, writer: Arc<crate::pcap_writer::PcapWriter>) {
        self.sandbox.set_pcap_writer(writer);
    }

    /// サンドボックスとトレーサーを起動し、イベント監視ループをバックグラウンドで開始する。
    ///
    /// `on_alert` はアラート検知時に呼ばれる。ログ出力・通知など用途は呼び出し側に委ねる。
    /// 返り値の `JoinHandle` で監視ループの完了を待てる。
    pub async fn start(
        &mut self,
        sandbox_config: &SandboxConfig,
        trace_filter: &TraceFilter,
        on_alert: AlertHandler,
    ) -> anyhow::Result<()> {
        // 順序が重要: sandbox → tracer の順で起動する。
        // tracer は sandbox 内のプロセスを監視するため、先に sandbox が Running である必要がある。
        self.sandbox.up(sandbox_config).await?;

        // QEMU バックエンド使用時、sandbox のセッショントークン・ポート・シークレットを tracer に渡す。
        // Sandbox の up() 後にトークンとポートが確定するため、ここで設定する。
        if let Some(token) = self.sandbox.session_token() {
            let token_hash = sha256_hex(token);
            self.tracer.set_session_token(token_hash);
        }
        if let Some(port) = self.sandbox.agent_host_port() {
            self.tracer.set_agent_port(port);
        }
        // VmAgentTracer は agent と同じ HMAC シークレットで認証する必要がある。
        // シークレットの読み込みに失敗した場合はエラーを伝播し、認証なしで tracer を起動しない。
        if let Some(secret) = crate::protocol::load_shared_secret_from_env()? {
            self.tracer.set_secret(secret);
        }

        let mut rx = match self.tracer.start(trace_filter).await {
            Ok(rx) => rx,
            Err(e) => {
                // tracer の起動に失敗した場合、sandbox を停止してリソースリークを防ぐ
                if let Err(down_err) = self.sandbox.down().await {
                    eprintln!("警告: sandbox の停止にも失敗しました: {}", down_err);
                }
                return Err(e.context("tracer の起動に失敗（sandbox は停止試行済み）"));
            }
        };

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        // Detector の参照を clone して監視ループに渡す。
        // Arc を使うことで stop() → start() 後もルールが保持される。
        let detector = Arc::clone(&self.detector);

        // on_event / on_alert を Arc でラップし spawn_blocking に渡せるようにする。
        // Box<dyn Fn + Send> → Arc<dyn Fn + Send + Sync> への変換は
        // Mutex でラップして Sync を付与する。spawn_blocking の各呼び出しは
        // 排他的に実行されるため安全。
        let on_event: Option<Arc<dyn Fn(&SyscallEvent) + Send + Sync>> =
            self.on_event.take().map(|h| {
                let wrapper = std::sync::Mutex::new(h);
                Arc::new(move |event: &SyscallEvent| {
                    if let Ok(handler) = wrapper.lock() {
                        handler(event);
                    }
                }) as Arc<dyn Fn(&SyscallEvent) + Send + Sync>
            });

        // on_alert も同様に Arc ラップし、spawn_blocking でオフロードする。
        // LogStorage::store_alert 等の同期 I/O が tokio ワーカーをブロックするのを防止。
        let on_alert: Arc<dyn Fn(&Alert) + Send + Sync> = {
            let wrapper = std::sync::Mutex::new(on_alert);
            Arc::new(move |alert: &Alert| {
                if let Ok(handler) = wrapper.lock() {
                    handler(alert);
                }
            })
        };

        let handle = tokio::spawn(async move {
            // イベント処理総数のカウンタ。
            // 一定件数ごとにチャネル長をチェックし、飽和状態を検知する。
            //
            // NOTE: check_interval と閾値 (capacity * 3/4) がローカル変数のため、
            // 飽和検知ロジックの単体テストは現時点で困難。リファクタリング Phase で
            // これらを設定値として外部注入可能にし、テストを追加すること。
            // (tasks.db Phase 8 / task 320)
            let mut total_events: u64 = 0;
            let check_interval: u64 = 1000;
            let capacity = crate::tracer::EVENT_CHANNEL_CAPACITY as u64;

            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(event) => {
                                total_events += 1;

                                // 定期的にチャネル長をチェックし、飽和を検知
                                if total_events % check_interval == 0 {
                                    let pending = rx.len() as u64;
                                    if pending > capacity * 3 / 4 {
                                        eprintln!(
                                            "警告: イベントチャネルが飽和状態です (バッファ: {}/{})。\
                                             イベントの大量生成による検知回避の可能性があります。",
                                            pending, capacity
                                        );
                                    }
                                }

                                // レダクション機構は SyscallArg::redacted_display() で適用済み。
                                if let Some(ref handler) = on_event {
                                    let handler = Arc::clone(handler);
                                    let event = Arc::clone(&event);
                                    tokio::task::spawn_blocking(move || {
                                        handler(&event);
                                    });
                                }
                                if let Some(alert) = detector.analyze(&event) {
                                    let handler = Arc::clone(&on_alert);
                                    let alert = alert.clone();
                                    tokio::task::spawn_blocking(move || {
                                        handler(&alert);
                                    });
                                }
                            }
                            None => break, // チャネルが閉じられた
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        self.handle = Some(handle);
        Ok(())
    }

    /// トレーサーとサンドボックスを停止する。
    ///
    /// shutdown signal を送ってから、tracer → sandbox の順で停止する。
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        // shutdown signal を送って監視ループを終了させる
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // 監視ループの完了を待つ
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }

        // tracer と sandbox は起動中の場合のみ停止。
        // 両方のエラーを収集し、最初のエラーを返す（片方の失敗がもう片方を妨げない）。
        let tracer_err = self.tracer.stop().await.err();
        let sandbox_err = if self.sandbox.status() == SandboxStatus::Running {
            self.sandbox.down().await.err()
        } else {
            None
        };

        if let Some(e) = tracer_err {
            eprintln!("警告: tracer の停止に失敗: {}", e);
        }
        if let Some(e) = sandbox_err {
            return Err(e);
        }
        Ok(())
    }

    /// 内部の Sandbox への参照を返す。
    /// `exec` / `shell` の呼び出しに使う。
    pub fn sandbox(&self) -> &dyn Sandbox {
        self.sandbox.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Syscall, SyscallArg, SyscallEvent, SyscallResult};
    use crate::log_storage::LogStorage;
    use crate::sandbox::{ExecOutput, SandboxStatus};
    use crate::tracer::{EVENT_CHANNEL_CAPACITY, MockTracer};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::SystemTime;
    use tokio::sync::mpsc;

    // --- MockSandbox ---

    struct MockSandbox {
        status: SandboxStatus,
    }

    impl MockSandbox {
        fn new() -> Self {
            Self {
                status: SandboxStatus::Stopped,
            }
        }
    }

    #[async_trait::async_trait]
    impl Sandbox for MockSandbox {
        async fn up(&mut self, _config: &SandboxConfig) -> anyhow::Result<()> {
            self.status = SandboxStatus::Running;
            Ok(())
        }

        async fn exec(
            &self,
            _cmd: &[String],
            _env: &HashMap<String, String>,
        ) -> anyhow::Result<ExecOutput> {
            Ok(ExecOutput {
                exit_code: 0,
                stdout: vec![],
                stderr: vec![],
            })
        }

        async fn shell(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn down(&mut self) -> anyhow::Result<()> {
            self.status = SandboxStatus::Stopped;
            Ok(())
        }

        fn status(&self) -> SandboxStatus {
            self.status
        }
    }

    // --- TrackableSandbox (down が呼ばれたか追跡) ---

    struct TrackableSandbox {
        status: SandboxStatus,
        down_called: std::sync::Arc<AtomicBool>,
    }

    impl TrackableSandbox {
        fn new(down_called: std::sync::Arc<AtomicBool>) -> Self {
            Self {
                status: SandboxStatus::Stopped,
                down_called,
            }
        }
    }

    #[async_trait::async_trait]
    impl Sandbox for TrackableSandbox {
        async fn up(&mut self, _config: &SandboxConfig) -> anyhow::Result<()> {
            self.status = SandboxStatus::Running;
            Ok(())
        }

        async fn exec(
            &self,
            _cmd: &[String],
            _env: &HashMap<String, String>,
        ) -> anyhow::Result<ExecOutput> {
            Ok(ExecOutput {
                exit_code: 0,
                stdout: vec![],
                stderr: vec![],
            })
        }

        async fn shell(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn down(&mut self) -> anyhow::Result<()> {
            self.status = SandboxStatus::Stopped;
            self.down_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn status(&self) -> SandboxStatus {
            self.status
        }
    }

    // --- FailingTracer (start で必ず失敗) ---

    struct FailingTracer;

    #[async_trait::async_trait]
    impl crate::tracer::Tracer for FailingTracer {
        async fn start(
            &self,
            _filter: &TraceFilter,
        ) -> anyhow::Result<mpsc::Receiver<std::sync::Arc<SyscallEvent>>> {
            anyhow::bail!("tracer start failed")
        }

        async fn stop(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn dummy_sandbox_config() -> SandboxConfig {
        SandboxConfig::Landlock {
            share: crate::sandbox::ShareConfig {
                host_paths: vec![],
                mount_point: std::path::PathBuf::from("/workspace"),
            },
        }
    }

    fn dummy_trace_filter() -> TraceFilter {
        TraceFilter {
            categories: vec![],
            pids: None,
        }
    }

    #[tokio::test]
    async fn engine_start_downs_sandbox_on_tracer_failure() {
        let down_called = std::sync::Arc::new(AtomicBool::new(false));
        let sandbox = TrackableSandbox::new(down_called.clone());
        let tracer = FailingTracer;
        let detector = Detector::new(vec![]);

        let mut engine = Engine::new(Box::new(sandbox), Box::new(tracer), detector);

        let config = dummy_sandbox_config();
        let filter = dummy_trace_filter();

        let result = engine.start(&config, &filter, Box::new(|_| {})).await;
        assert!(result.is_err(), "tracer の起動失敗でエラーが返ること");
        assert!(
            down_called.load(Ordering::SeqCst),
            "tracer 失敗時に sandbox.down() が呼ばれること"
        );
    }

    #[tokio::test]
    async fn engine_start_and_stop_lifecycle() {
        let sandbox = MockSandbox::new();
        let tracer = MockTracer::empty();
        let detector = Detector::new(vec![]);

        let mut engine = Engine::new(Box::new(sandbox), Box::new(tracer), detector);

        let config = dummy_sandbox_config();
        let filter = dummy_trace_filter();

        engine
            .start(&config, &filter, Box::new(|_| {}))
            .await
            .expect("start should succeed");

        assert_eq!(engine.sandbox().status(), SandboxStatus::Running);

        engine.stop().await.expect("stop should succeed");
    }

    #[tokio::test]
    async fn engine_alert_callback_is_invoked() {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        // MockTracer を改造: 直接 tx を渡す
        struct PresetTracer {
            rx: std::sync::Mutex<Option<mpsc::Receiver<std::sync::Arc<SyscallEvent>>>>,
        }

        #[async_trait::async_trait]
        impl crate::tracer::Tracer for PresetTracer {
            async fn start(
                &self,
                _filter: &TraceFilter,
            ) -> anyhow::Result<mpsc::Receiver<std::sync::Arc<SyscallEvent>>> {
                Ok(self.rx.lock().unwrap().take().unwrap())
            }

            async fn stop(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // 常にマッチするルール
        use crate::detector::{AlertLevel, Rule, RuleMatch};
        struct AlwaysWarnRule;
        impl Rule for AlwaysWarnRule {
            fn name(&self) -> &str {
                "always-warn"
            }
            fn check(&self, _event: &SyscallEvent) -> Option<RuleMatch> {
                Some(RuleMatch {
                    level: AlertLevel::Warn,
                    message: "test alert".to_string(),
                })
            }
        }

        let detector = Detector::new(vec![Box::new(AlwaysWarnRule)]);

        let alert_fired = std::sync::Arc::new(AtomicBool::new(false));
        let alert_fired_clone = alert_fired.clone();

        let mut engine = Engine::new(
            Box::new(MockSandbox::new()),
            Box::new(PresetTracer {
                rx: std::sync::Mutex::new(Some(event_rx)),
            }),
            detector,
        );

        let config = dummy_sandbox_config();
        let filter = dummy_trace_filter();

        engine
            .start(
                &config,
                &filter,
                Box::new(move |alert| {
                    assert_eq!(alert.level, AlertLevel::Warn);
                    alert_fired_clone.store(true, Ordering::SeqCst);
                }),
            )
            .await
            .expect("start should succeed");

        // イベントを送信
        let event = std::sync::Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 1,
            tgid: 0,
            process_name: "test".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![],
            result: SyscallResult::Ok(0),
        });
        event_tx.send(event).await.unwrap();

        // チャネルを閉じてループを終了させる
        drop(event_tx);

        // 監視ループがイベントを処理してチャネル閉鎖で終了するのを待つ
        if let Some(handle) = engine.handle.take() {
            handle.await.unwrap();
        }
        // spawn_blocking でオフロードした on_alert タスクの完了を待つ
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            alert_fired.load(Ordering::SeqCst),
            "alert callback should have been invoked"
        );

        engine.stop().await.expect("stop should succeed");
    }

    #[tokio::test]
    async fn engine_stop_is_idempotent() {
        let down_called = std::sync::Arc::new(AtomicU64::new(0));
        let down_counter = down_called.clone();

        struct CountingSandbox {
            status: SandboxStatus,
            down_count: std::sync::Arc<AtomicU64>,
        }

        #[async_trait::async_trait]
        impl Sandbox for CountingSandbox {
            async fn up(&mut self, _config: &SandboxConfig) -> anyhow::Result<()> {
                self.status = SandboxStatus::Running;
                Ok(())
            }
            async fn exec(
                &self,
                _cmd: &[String],
                _env: &HashMap<String, String>,
            ) -> anyhow::Result<ExecOutput> {
                Ok(ExecOutput {
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                })
            }
            async fn shell(&self) -> anyhow::Result<()> {
                Ok(())
            }
            async fn down(&mut self) -> anyhow::Result<()> {
                self.status = SandboxStatus::Stopped;
                self.down_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn status(&self) -> SandboxStatus {
                self.status
            }
        }

        let sandbox = CountingSandbox {
            status: SandboxStatus::Stopped,
            down_count: down_counter,
        };
        let tracer = MockTracer::empty();
        let detector = Detector::new(vec![]);

        let mut engine = Engine::new(Box::new(sandbox), Box::new(tracer), detector);

        let config = dummy_sandbox_config();
        let filter = dummy_trace_filter();

        engine
            .start(&config, &filter, Box::new(|_| {}))
            .await
            .expect("start should succeed");

        engine.stop().await.expect("first stop should succeed");
        engine
            .stop()
            .await
            .expect("second stop should also succeed");

        // down() は1回だけ呼ばれること
        assert_eq!(
            down_called.load(Ordering::SeqCst),
            1,
            "down() should be called exactly once"
        );
    }

    // --- バックエンド選択テスト ---

    #[test]
    fn select_sandbox_native_macos() {
        let config = Config::default();
        let sandbox = select_sandbox_for_platform(&config, false, true);
        assert!(sandbox.is_ok());
    }

    #[test]
    fn select_sandbox_native_linux() {
        let config = Config::default();
        let sandbox = select_sandbox_for_platform(&config, true, false);
        assert!(sandbox.is_ok());
    }

    #[test]
    fn select_sandbox_native_unsupported() {
        let config = Config::default();
        let result = select_sandbox_for_platform(&config, false, false);
        assert!(result.is_err());
    }

    #[test]
    fn select_sandbox_qemu() {
        let mut config = Config::default();
        config.sandbox.backend = SandboxBackend::Qemu;
        let sandbox = select_sandbox_for_platform(&config, false, true);
        assert!(sandbox.is_ok());
    }

    #[test]
    fn select_tracer_none() {
        let mut config = Config::default();
        config.sandbox.tracer = TracerBackend::None; // 明示的に None を設定
        let tracer = select_tracer_for_platform(&config, false, false);
        assert!(tracer.is_ok());
    }

    #[test]
    fn select_tracer_auto_macos() {
        let mut config = Config::default();
        config.sandbox.tracer = TracerBackend::Auto;
        let tracer = select_tracer_for_platform(&config, false, true);
        assert!(tracer.is_ok());
    }

    #[test]
    fn select_tracer_auto_linux() {
        let mut config = Config::default();
        config.sandbox.tracer = TracerBackend::Auto;
        let tracer = select_tracer_for_platform(&config, true, false);
        assert!(tracer.is_ok());
    }

    #[test]
    fn select_tracer_auto_unsupported() {
        let mut config = Config::default();
        config.sandbox.tracer = TracerBackend::Auto;
        let result = select_tracer_for_platform(&config, false, false);
        assert!(result.is_err());
    }

    #[test]
    fn select_tracer_ebpf_on_macos_fails() {
        let mut config = Config::default();
        config.sandbox.tracer = TracerBackend::Ebpf;
        let result = select_tracer_for_platform(&config, false, true);
        assert!(result.is_err());
    }

    #[test]
    fn select_tracer_dtrace_on_linux_fails() {
        let mut config = Config::default();
        config.sandbox.tracer = TracerBackend::Dtrace;
        let result = select_tracer_for_platform(&config, true, false);
        assert!(result.is_err());
    }

    #[test]
    fn select_tracer_vm_agent_without_qemu_fails() {
        let mut config = Config::default();
        config.sandbox.tracer = TracerBackend::VmAgent;
        // backend が Native のまま vm-agent を指定
        let result = select_tracer_for_platform(&config, true, false);
        assert!(result.is_err());
    }

    #[test]
    fn select_tracer_vm_agent_with_qemu() {
        let mut config = Config::default();
        config.sandbox.backend = SandboxBackend::Qemu;
        config.sandbox.tracer = TracerBackend::VmAgent;
        let result = select_tracer_for_platform(&config, true, false);
        assert!(result.is_ok());
    }

    /// macOS でも VmAgent トレーサーが選択可能であることを確認。
    /// #287 で cfg(target_os = "linux") 制限を除去したため。
    #[test]
    fn select_tracer_vm_agent_with_qemu_on_macos() {
        let mut config = Config::default();
        config.sandbox.backend = SandboxBackend::Qemu;
        config.sandbox.tracer = TracerBackend::VmAgent;
        let result = select_tracer_for_platform(&config, false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn select_tracer_auto_apple_container_uses_null() {
        let mut config = Config::default();
        config.sandbox.backend = SandboxBackend::AppleContainer;
        config.sandbox.tracer = TracerBackend::Auto;
        let result = select_tracer_for_platform(&config, false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn select_tracer_auto_qemu_uses_null() {
        let mut config = Config::default();
        config.sandbox.backend = SandboxBackend::Qemu;
        config.sandbox.tracer = TracerBackend::Auto;
        let result = select_tracer_for_platform(&config, false, true);
        assert!(result.is_ok());
    }

    // --- E2E テスト (#48) ---

    static E2E_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn e2e_temp_dir() -> PathBuf {
        let id = E2E_TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "izanagi_e2e_{}_{}_{}",
            std::process::id(),
            id,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// E2E: Engine の start → exec → stop の一連のフロー
    #[tokio::test]
    async fn e2e_start_exec_stop() {
        let sandbox = MockSandbox::new();
        let tracer = MockTracer::empty();
        let detector = Detector::new(vec![]);

        let mut engine = Engine::new(Box::new(sandbox), Box::new(tracer), detector);

        let config = dummy_sandbox_config();
        let filter = dummy_trace_filter();

        // start
        engine
            .start(&config, &filter, Box::new(|_| {}))
            .await
            .expect("start should succeed");
        assert_eq!(engine.sandbox().status(), SandboxStatus::Running);

        // exec
        let env = HashMap::new();
        let output = engine
            .sandbox()
            .exec(&["echo".to_string(), "hello".to_string()], &env)
            .await
            .expect("exec should succeed");
        assert_eq!(output.exit_code, 0);

        // shell (MockSandbox は即座に成功)
        engine
            .sandbox()
            .shell()
            .await
            .expect("shell should succeed");

        // stop
        engine.stop().await.expect("stop should succeed");
        assert_eq!(engine.sandbox().status(), SandboxStatus::Stopped);
    }

    /// E2E: アラート検知のインテグレーションテスト
    #[tokio::test]
    async fn e2e_alert_detection() {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        struct PresetTracer {
            rx: std::sync::Mutex<Option<mpsc::Receiver<std::sync::Arc<SyscallEvent>>>>,
        }

        #[async_trait::async_trait]
        impl crate::tracer::Tracer for PresetTracer {
            async fn start(
                &self,
                _filter: &TraceFilter,
            ) -> anyhow::Result<mpsc::Receiver<std::sync::Arc<SyscallEvent>>> {
                Ok(self.rx.lock().unwrap().take().unwrap())
            }

            async fn stop(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // SuspiciousPathRule をセットアップ
        use crate::rules::SuspiciousPathRule;
        let rule = SuspiciousPathRule::new(&["/etc/passwd".to_string()]);
        let detector = Detector::new(vec![Box::new(rule)]);

        let alert_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let alert_count_clone = alert_count.clone();

        let log_dir = e2e_temp_dir();
        let log_storage = std::sync::Arc::new(LogStorage::new(&log_dir).unwrap());
        let log_storage_alert = log_storage.clone();

        let mut engine = Engine::new(
            Box::new(MockSandbox::new()),
            Box::new(PresetTracer {
                rx: std::sync::Mutex::new(Some(event_rx)),
            }),
            detector,
        );

        let config = dummy_sandbox_config();
        let filter = dummy_trace_filter();

        engine
            .start(
                &config,
                &filter,
                Box::new(move |alert| {
                    alert_count_clone.fetch_add(1, Ordering::SeqCst);
                    let _ = log_storage_alert.store_alert(alert);
                }),
            )
            .await
            .expect("start should succeed");

        // /etc/passwd へのアクセスイベントを送信
        let suspicious_event = std::sync::Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 42,
            tgid: 0,
            process_name: "npm".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![SyscallArg::Path(PathBuf::from("/etc/passwd"))],
            result: SyscallResult::Ok(0),
        });
        event_tx.send(suspicious_event).await.unwrap();

        // 安全なイベントを送信 (アラートなし)
        let safe_event = std::sync::Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 42,
            tgid: 0,
            process_name: "npm".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![SyscallArg::Path(PathBuf::from("/tmp/safe"))],
            result: SyscallResult::Ok(0),
        });
        event_tx.send(safe_event).await.unwrap();

        // チャネルを閉じてループを終了
        drop(event_tx);

        // 監視ループの完了を待つ
        if let Some(handle) = engine.handle.take() {
            handle.await.unwrap();
        }
        // spawn_blocking でオフロードした on_alert タスクの完了を待つ
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // アラートが1件のみ発生していることを確認
        assert_eq!(alert_count.load(Ordering::SeqCst), 1);

        // ログストレージにアラートが書き込まれていることを確認
        log_storage.flush().unwrap();
        let alerts = log_storage.read_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("/etc/passwd"));

        engine.stop().await.expect("stop should succeed");

        let _ = std::fs::remove_dir_all(&log_dir);
    }

    /// E2E: ログ書き込み・読み取りの結合テスト
    #[tokio::test]
    async fn e2e_log_storage_integration() {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        struct PresetTracer {
            rx: std::sync::Mutex<Option<mpsc::Receiver<std::sync::Arc<SyscallEvent>>>>,
        }

        #[async_trait::async_trait]
        impl crate::tracer::Tracer for PresetTracer {
            async fn start(
                &self,
                _filter: &TraceFilter,
            ) -> anyhow::Result<mpsc::Receiver<std::sync::Arc<SyscallEvent>>> {
                Ok(self.rx.lock().unwrap().take().unwrap())
            }

            async fn stop(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // UnexpectedExecRule を使って curl の実行を検知
        use crate::rules::UnexpectedExecRule;
        let rule = UnexpectedExecRule::new();
        let detector = Detector::new(vec![Box::new(rule)]);

        let log_dir = e2e_temp_dir();
        let log_storage = std::sync::Arc::new(LogStorage::new(&log_dir).unwrap());
        let log_storage_event = log_storage.clone();
        let log_storage_alert = log_storage.clone();

        let mut engine = Engine::new(
            Box::new(MockSandbox::new()),
            Box::new(PresetTracer {
                rx: std::sync::Mutex::new(Some(event_rx)),
            }),
            detector,
        );

        let config = dummy_sandbox_config();
        let filter = dummy_trace_filter();

        engine.set_event_handler(Box::new(move |event: &SyscallEvent| {
            let _ = log_storage_event.store_event(event);
        }));
        engine
            .start(
                &config,
                &filter,
                Box::new(move |alert| {
                    let _ = log_storage_alert.store_alert(alert);
                }),
            )
            .await
            .expect("start should succeed");

        // イベント1: curl の execve (アラート発生)
        let event1 = std::sync::Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 100,
            tgid: 0,
            process_name: "sh".into(),
            syscall: Syscall::Execve,
            args: smallvec::smallvec![SyscallArg::Path(PathBuf::from("/usr/bin/curl"))],
            result: SyscallResult::Ok(0),
        });
        event_tx.send(event1).await.unwrap();

        // イベント2: ls の execve (アラートなし)
        let event2 = std::sync::Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 101,
            tgid: 0,
            process_name: "sh".into(),
            syscall: Syscall::Execve,
            args: smallvec::smallvec![SyscallArg::Path(PathBuf::from("/usr/bin/ls"))],
            result: SyscallResult::Ok(0),
        });
        event_tx.send(event2).await.unwrap();

        // チャネルを閉じて待機
        drop(event_tx);
        if let Some(handle) = engine.handle.take() {
            handle.await.unwrap();
        }
        // spawn_blocking でオフロードした on_event/on_alert タスクの完了を待つ。
        // 監視ループ終了後もブロッキングスレッドプールでタスクが実行中の場合がある。
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // イベントログに2件書き込まれていることを確認
        log_storage.flush().unwrap();
        let events = log_storage.read_events().unwrap();
        assert_eq!(events.len(), 2);

        // アラートログに1件 (curl) 書き込まれていることを確認
        let alerts = log_storage.read_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("curl"));

        // suspicious フィルタ (Warn 以上) でアラートが取得できることを確認
        use crate::detector::AlertLevel;
        let suspicious = log_storage.read_alerts_filtered(AlertLevel::Warn).unwrap();
        assert_eq!(suspicious.len(), 1);

        engine.stop().await.expect("stop should succeed");

        let _ = std::fs::remove_dir_all(&log_dir);
    }
}
