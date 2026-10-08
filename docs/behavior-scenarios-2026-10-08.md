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

## 実 VM の確認範囲と残作業

既存 `/Users/ast/.izanagi/images/debian-aarch64.qcow2` に対して、独立したテスト認証キー、ホスト共有なし、512 MB / 1 CPU、snapshot=on で `qemu_protocol_smoke` を実行した。
ゲストは起動したが Hello 前に接続を閉じ、ホストは失敗して VM を停止した。
ログには workspace.mount の失敗もあり、空の共有設定がイメージに合っていない。旧 agent / イメージとの不一致の可能性を示すエラーだが、原因の確定はしていない。
したがって **最新 agent と eBPF を組み込んだ VM での Exec / Event / Shell の成功は未確認**。

リリース前には同じリビジョンで agent・eBPF・ゲストイメージを再ビルドし、専用の一時ディレクトリを /workspace に共有して、次を確認する:

1. 認証 Hello / Ready / TraceStarted が完了する。
2. `echo` の stdout と終了コード、非ゼロ終了、許可外コマンドの拒否を確認する。
3. ファイルアクセスを発生させ、対象 PID の Event とログを確認する。
4. shell の入力・出力・resize・入力なし終了と、端末復元を確認する。
5. 専用 VM の監視接続を切断し、exec / shell / up が失敗して VM・セッション状態を片付けることを確認する。
6. 上記の分割フレーム + resize の再現テストが修正後に成功する。

Linux での追加シナリオは今回の PR の CI で確認する。実 VM での最新イメージの成功確認は未実施。
