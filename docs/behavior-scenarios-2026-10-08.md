# #30・#31 マージ後の挙動確認

対象リビジョン: `f88b03b21878e2648e23020dec224b639815cc9b`。実行環境: macOS / aarch64。
監視の開始・継続・停止と、シェルの入出力・終了・キャンセルを対象に、仕様シナリオと境界シナリオを構築した。
本確認はアプリケーション全機能の保証ではない。検出した不具合を [issue #35](https://github.com/ieee0824/izanagi/issues/35) に登録し、ホストと agent の受信処理を修正した。

## 結果

**不具合 1 件を確認し、修正。** 通信フレームを途中まで受信したときに入力や SIGWINCH が受信処理をキャンセルすると、読み取り済みのバイトを失っていた。
接続が持つ `MessageReader` が読み取り済みバイトを保存し、キャンセル後も続きから読む。
プロトコル層と、新規 QEMU / 既存セッションの両シェル入口の再現テストが成功するようになった。

- 変更前の既存ホストテスト: 466 件成功。
- 修正前の追加確認: 474 件成功、再現テスト 3 件失敗。同じ根本原因であり、別々の不具合 3 件ではない。
- 修正後のホストテスト: macOS 480 件成功、失敗・ignore なし。繰り返しキャンセル、次フレーム、認証失敗時のシーケンス維持、ヘッダのサイズ上限の回帰テストも追加。
- PR #36 の CI: Linux ホスト 458 件、macOS ホスト 480 件、Linux agent 38 件成功。
- agent の macOS で実行可能なテスト: 33 件成功。Linux 専用 PTY / eBPF の実動作は含まない。
- Format / Clippy (`--all-targets -- -D warnings`) / `git diff --check`: 成功。
- 実 QEMU スモーク: 既存 Debian イメージが Hello 前に接続を閉じ、失敗。Exec / Event まで到達していない。

## 仕様どおりの動作を確認するシナリオ

| ID | 操作・条件 | 期待結果 | 実行結果・証拠 |
| --- | --- | --- | --- |
| N01 | 正しい認証モードで Hello → Ready → Start → TraceStarted | ACK 後にのみ起動成功 | 成功。既存 TCP ライフサイクル、追加 ACK テスト |
| N02 | ACK を遅延させる | ACK 前には start が成功しない | 成功。`start_waits_for_ack_and_can_retry_after_connection_failure` |
| N03 | 正常な監視イベントを送る | ホストへ内容が届き、検知処理に渡る | 成功。既存 tracer / Engine テスト |
| N04 | 新規 QEMU シェルでキー入力、出力、画面サイズ変更 | 入力転送、出力表示、43 行 × 119 列の resize 通知 | 成功。追加 PTY `roundtrip` |
| N05 | 既存セッションのシェルで同じ操作 | 同じ入出力・resize 動作 | 成功。追加 PTY `roundtrip` |
| N06 | シェルが 0 / 42 で終了 | 終了コードを伝達。QemuSandbox は 42 をエラーとして扱う | 両入口で成功。追加 PTY `nonzero` と既存 `close` |
| N07 | ユーザーが何も入力せず、シェルが終了 | stdin を開いたまま、子プロセスと Tokio runtime が終了 | 両入口で成功。既存 PTY テスト |
| N08 | 正常停止、再度停止 | 監視と sandbox の停止、停止の冪等性 | 成功。既存 Engine / tracer ライフサイクル |

## 境界・異常・競合を狙うシナリオ

| ID | 操作・条件 | 期待結果 | 実行結果・証拠 |
| --- | --- | --- | --- |
| E01 | Hello のエラー / 切断、Start の初期化エラー。認証あり・なし × exec・shell | 起動失敗、sandbox 停止、実行回数 0 | 成功。既存 `startup_failures_stop_sandbox_before_exec_or_shell` の 12 条件 |
| E02 | Ready / ShellClose / Error / EOF を ACK の代わりに返す | TraceStarted 以外は起動成功としない | 成功。追加 ACK テストの計 10 条件 |
| E03 | Hello / Ready / TraceStarted の各段階で相手が沈黙。認証あり・なし | 15 秒で失敗し、接続を閉じる | 成功。追加 `silent_agent_is_bounded_at_hello_ready_and_trace_ack` の 6 条件 |
| E04 | 実行中の監視で Error / 切断 × exec・shell | 実行を中断、原因伝達、次の実行拒否、stop で sandbox 停止 | 成功。既存 runtime failure テストの 4 条件 |
| E05 | 起動待ち future を abort | 接続を閉じ、起動予約を戻す | 成功。既存 cancellation テスト |
| E06 | 起動途中に tracer.stop | start が cancelled となり、再試行可能 | 成功。追加 `stop_during_start_closes_peer_and_allows_retry` |
| E07 | イベントチャネルを満杯にしてから停止 | イベント送信待ちでも停止は 2 秒以内に完了 | 成功。追加 `saturated_event_channel_does_not_prevent_shutdown` |
| E08 | 稼働中の tracer を drop | 受信タスク、TCP 接続、イベントチャネルが終了 | 成功。既存 drop テスト |
| E09 | シェルが Error / 切断 / キャンセル | 入力なしで終了、端末モードと stdin フラグを復元 | 両入口で成功。既存 PTY テスト |
| E10 | シェル応答として Ready を送る | 予期しない応答として失敗、端末を復元 | 両入口で成功。追加 PTY `unexpected` |
| E11 | 正しい出力フレームを 1 バイトずつ送る。認証あり・なし | 元の出力を復元 | 成功。追加 fragmented output テスト |
| E12 | 各フレーム分割位置で途中切断。認証あり・なし | 不完全なフレームを拒否 | 成功。追加 truncated frames テストの 92 条件 |
| E13 | 各分割位置で receive をキャンセルし、残りのフレームを送る | 読み取り済みバイトを保持して元の出力を復元 | 修正前 92 / 92 条件で失敗、**修正後全条件成功** |
| E14 | 新規 QEMU シェルで出力フレーム先頭 1 バイト → SIGWINCH → 残り | resize を通知し、出力と正常終了を受信 | 実 PTY 子プロセスで失敗を再現、**修正後成功** |
| E15 | 既存セッションのシェルで同じ競合 | 同じく出力と正常終了を受信 | 実 PTY 子プロセスで失敗を再現、**修正後成功** |

PTY テストは実際の端末と子プロセスを使う。接続相手は決定的な異常・競合を作る TCP テスト peer であり、VM 内 agent の代替である。
SIGWINCH の再現では、peer がフレーム先頭を送ってから resize を発火し、実際の ShellResize 応答を待って残りを送る。
タイミングだけに依存せず、受信キャンセルが発生したことを確認する。

## 不具合: 途中受信キャンセルで正常なシェル通信が壊れる

優先度: **P1 相当**。TCP の通常の分割と画面リサイズの競合で、正常なシェルが強制終了する。
新規 sandbox と既存セッションの両方に影響する。非認証のプロトコルテストでも、認証付き PTY でも再現した。

修正前の原因:

1. `src/terminal_shell.rs` の `tokio::select!` は入力または SIGWINCH を処理すると、保留中の `client.recv_message()` を drop する。
2. `src/protocol_client.rs` は受信状態を保持せず、`protocol::read_message*` を毎回新しく呼ぶ。
3. `src/protocol.rs` のヘッダ・ボディ・認証トレーラはローカル変数と `read_exact` で読み取る。途中まで読み取ってから future を drop すると、そのバイトは TCP から消費済みだが復元されない。
4. 次の receive はフレーム途中のバイトを新しいヘッダと解釈する。先頭 1 バイトでの再現では `incompatible protocol version; upgrade host and agent together` を返す。

修正ではフレームのバッファと読み取り位置を `MessageReader` に保持した。サイズ上限はボディの確保前に検証する。
認証シーケンスはフレーム全体の HMAC・型・ボディの検証成功後だけ更新する。
不完全・不正なフレームを受信した reader は再利用を拒否し、接続を閉じるよう呼び出し元に要求する。
agent 側も Hello から shell / イベント転送まで同じ reader を使用し、途中受信状態を保持する。
Linux 専用の `shell_output_does_not_discard_partial_host_frame` は、ホストの分割 Stop フレーム受信中に実シェル出力を発生させ、正しく停止・子プロセス回収できることを確認する。

## 再現・再実行

以下の 3 コマンドは修正前には終了コード 101、修正後には成功する。
再現テストは ignore / should_panic にしていない。

```sh
cargo test --test behavior_scenarios fragmented_shell_receive_survives_input_or_resize_cancellation -- --nocapture
cargo test --lib new_sandbox_shell_survives_fragmented_output_and_resize -- --nocapture
cargo test --bin izanagi existing_session_shell_survives_fragmented_output_and_resize -- --nocapture
```

全シナリオを実行するコマンド:

```sh
cargo test --all-targets
cargo test --manifest-path izanagi-agent/Cargo.toml
cargo clippy --all-targets -- -D warnings
```

## 実 VM の確認（2026-10-08 追加）

macOS arm64 / QEMU HVF、Debian 13 arm64 (Linux 6.12.74)、2 CPU / 2 GB で実行した。
既存 Debian イメージを読み取り専用の backing とした専用 qcow2 overlay に、同じソースからビルドした Linux agent (`--features ebpf`) と eBPF オブジェクトを配置した。
専用の一時 workspace と専用認証キーを使い、通常起動は snapshot=on、token + HMAC 認証を有効にした。
元のイメージと開発プロジェクトの共有ファイルは変更していない。

| シナリオ | 結果 |
| --- | --- |
| 認証 Hello / Ready / TraceStarted、Exec と eBPF Event | 成功 |
| コマンド PID と OpenAt パスの一致、パスのログ記録・suspicious_paths アラート | 修正後に成功 |
| stdout / stderr 分離、終了コード 7 | 成功 |
| guest 非 root (uid 1000)、/workspace の書き込みとホスト側反映 | 成功 |
| 新規 shell、既存セッション shell、入力・出力・resize・連続出力 | 成功 |
| 入力を閉じずに shell の exit 7 / exit 0、termios と O_NONBLOCK 復元 | 成功 |
| 双方向 1 バイト分割 TCP プロキシ + SIGWINCH の反復 | 成功、約 10,000 回の 1 バイト書き込み |
| up / down、セッション・PID・ロックの削除 | 成功 |
| VM の SIGTERM 強制停止、待機中 exec・入力待ち shell・up の失敗 | 成功、約 0.35 秒でエラーと後片付け、端末設定復元 |

初回接続の handshake timeout は再試行され、起動後の認証と監視開始は成功した。
新規 shell の flock ファイルは残るがロックは解放され、次の up が取得できた。up/down と監視異常終了はファイルも削除した。
F_GETFL の値は PTY 書き込み後に 2 → 65538 となるが、CLI を使わない単純な os.write でも同じ差分が出た。[Apple XNU の FWASWRITTEN (0x10000)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h) に対応し、O_NONBLOCK の変更ではない。

### 実 VM で発見したパス取得の欠落 (#37)

修正前は openat のイベントが届いてもパスが空で、/workspace/qa-file を作成・読取した 30,730 件のログにも対象パスがなかった。
eBPF の emit_event が path_len を 0 にして submit しており、パス検知の入力がなかった。
openat の第 2 引数、stat / access / execve の第 1 引数を bpf_probe_read_user_str_bytes で取得するよう修正した。
バッファは 256 バイト、末尾 NUL は有効長に含めず、不正ポインタの読取失敗でもイベントを送信する。
相対パスの絶対化、256 バイト以上のパスの完全取得、sys_enter からの実 syscall 戻り値取得はこの修正の対象外。

qemu_protocol_smoke は背景イベントを受信するだけの判定から、実行コマンド自身の PID・OpenAt・パスが一致するイベントを要求する判定に強化した。
修正した eBPF オブジェクトを実 guest にロードし、`authenticated v2 Exec and matching PID/path Event received` を確認した。

実 VM は Debian イメージの IZANAGI_ALLOW_ALL_COMMANDS=1 を使っているため、agent の許可外コマンド拒否は今回の実 VM 検証範囲に含めない。

検証バイナリの SHA-256:

- host: `7e7b736b9e8f104e3719388b5e6de1f77a70d2837fc78a6dff83bb7b113f55e8`
- Linux agent: `ee75f78c5a676870cb8dcce1717522c321da45a6518da7447ff6f6743f891276`
- 修正後 eBPF: `42dff22781140140e93ee3439bf2897f87b91ae026bc43d7882a4a6a76e6b11c`

ローカル検証: macOS 全 target 480 テスト成功、Clippy warnings=error 成功、eBPF nightly ビルド成功、実 guest で verifier / attach 成功。
