# 行動分析 PoC の検証記録

合成 fixture の mock 結果は処理経路と評価の算術の検証です。実 Jev と VM は下の別節で区別して記録します。少数の模擬入力から運用時の精度は主張しません。

## 固定条件

- fixtures: `tests/fixtures/behavior/{normal,access-post,event-loss}.jsonl`
- manifest: `tests/fixtures/behavior/manifest.json` (seed 39、synthetic-v1)
- fixture の SHA256 を manifest に保存し、読み込んだ同じ bytes を検証して再生
- model 条件: jev-1.13.0、question version 1、confidence 閾値 0.6
- 分布合計許容差 0.001、confidence 丸め許容差 0.01
- eligibility: correlated は confirmed writer と必要な観測、network-only は意図的 mask と source gap を区別
- feature/host policy version は 1、昇格方針は `audit_only_no_automatic_promotion_v1`
- MCP commit は未検証なら null。参考実装の commit を実行版と偽らない
- VM image digest は合成データを示す 64 桁のゼロ。実 image の測定値ではない

正常 POST、資格情報へのアクセス試行と関連 POST、同じ系列で観測が欠損するケースの 3 windows を、A/B/C/D へ同じラベルで渡します。ラベルはシナリオ仕様から固定し、分類結果から生成しません。family の development/held-out 混在を拒否します。

## 合成・mock baseline

再現コマンド:

```sh
cargo test --locked --test behavior_classifier --test behavior_evaluation --test behavior_cli
cargo run --locked -- behavior evaluate --manifest tests/fixtures/behavior/manifest.json
```

| 方式 | windows | 追加系列警告 | 棄権 | 失敗 | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A: 既存ルール | 3 | 0 | 0 | 0 | 未定義 | 0 |
| B: 通信のみ + mock | 3 | 0 | 3 | 0 | 未定義 | 0 |
| C: 相関特徴 + mock | 3 | 1 | 1 | 0 | 1 | 0.5 |
| D: 決定論的時系列ルール | 3 | 1 | 1 | 0 | 1 | 0.5 |

各方式の正常作業あたりの追加誤警告は 0。C/D の観測欠損ケースは棄権し、疑わしい系列 2 件の分母から除外しないため Recall は 0.5 です。B の mask は欠損ではなく、mock が入力不足として unknown を返した結果です。既存ルールの警告と追加系列警告は別に集計しています。

CLI の mock report は `simulated=true`、回答モデルは `mock-v1` と記録します。値が良いことを Jev の有効性の根拠にはしません。timeout を返す分類器の比較でも全 windows を残し、Failed と Normal を混同しないことをテストしています。

## 確認した境界

- stdio MCP initialize・tools/list・jev.choice 呼び出し、structuredContent と成功時 text fallback
- API/MCP error の扱い、固定 model、不正 question/type/候補/分布/usage/選択/confidence の拒否
- 高 confidence unknown、低 confidence、必要な観測欠損の棄権
- UTF-8 JSON byte 上限、巨大 stdout/stderr、timeout、subprocess の終了と秘密値を含むメッセージの非記録
- immutable event-time replay、最新 revision、file digest、独立 labels、family 分割、fixture path confinement
- オフライン CLI が VM 設定・sandbox 用 secret を読まないこと
- リモート送信の `--allow-export`、MCP への環境 allowlist、raw path/host canary の除去
- 出力権限 0600、既存 input/output の非上書き、show の session 照合と expired evidence

## 実モデル・実 VM の結果

2026-10-09、接続済み Jev MCP を通じ `jev-1.13.0` を実呼び出ししました。question version 1、閾値 0.6、confidence 許容差 0.01 を呼び出し前に固定し、結果を見た後の調整はしていません。要求は 8 KiB 未満の閉じた projection のみ。path、host、本文、header、query、argv、資格情報を送信していません。

応答を `tests/fixtures/behavior/jev-responses.json` に保存しました。次のコマンドは API を再度呼ばず、保存した実応答を同じ host 検証へ通します。

```sh
cargo run --locked -- behavior evaluate --manifest tests/fixtures/behavior/manifest.json --classifier recorded --recorded-responses tests/fixtures/behavior/jev-responses.json
```

| 方式 | windows | 系列警告 | 棄権 | 失敗 | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| A | 3 | 0 | 0 | 0 | 0 |
| B: 通信特徴 + 実応答 | 3 | 0 | 2 | 1 | 0 |
| C: 相関特徴 + 実応答 | 3 | 0 | 2 | 0 | 0 |
| D | 3 | 1 | 1 | 0 | 0.5 |

C の正常系列は normal / confidence 0.95。疑わしい系列は access_post_suspected が選ばれましたが confidence 0.3 で棄権しました。欠損系列は API を呼ばず棄権します。B の正常系列は API が返した confidence 0.28 と、返された分布の最大値 0.53 から計算する 0.295 の差が許容差を超え、InvalidResponse でした。値の補正や再試行はしていません。全方式で元の分母を保持します。この小規模試験では Jev が D を改善した証拠はなく、運用判定への昇格は見送ります。

実 API 4 呼び出しの usage 合計は input 2499 / output 177 tokens。recorded report の elapsed は保存応答の検証時間であり、API 推論時間ではありません。

実 VM は Debian 13 / aarch64 / Linux 6.12.74、QEMU HVF、2 CPU、2 GiB、専用 qcow2 overlay、guest UID 1000、認証付き wire v3。新しい eBPF object の ABI と必要 probe を検証し、guest sidecar の ready 後に実行しています。

- 初回の実測で TCP SYN_SENT の送信元 port が 0 になることを確認し、ESTABLISHED の tuple も元の connector とともに観測する修正を追加。
- 同一の Python プロセスから credential-role file の open 成功 1 回・ENOENT 1 回と、同一接続上の POST 2 回を観測・相関。
- 各 POST で upstream へ実際に 192 bytes を書き、113 bytes を受信、status 200。本文 22 bytes と全 request 195 bytes を区別。
- body/header/query/path に入れた `DO_NOT_LOG` canary は行動監査 JSONL に存在しない。
- kernel は connector を観測できても、socket の namespace と実 writer の完全な証明はできない。両 window は MissingWriter / SocketAmbiguous を明示し、D/C は Unknown / Abstained。確認済み writer を合成していない。
- 正常終了で VM と host 監視が終了し、session/PID/lock を解放。JSONL の保存失敗・storage gap は 0。

検証 overlay SHA256: `7fc3cf31b7d65fc6117b55e17fb0ebb343e3a668280498242868c502b4c10408`。sanitized 実イベント JSONL SHA256: `2393dae22f4af5c21dd49001ec5989d381f4b046f0eb05fe41e3df0b0a6022f1`。ローカル artifacts は `/private/tmp/izanagi-jev-vm-39/{observed-events-second.jsonl,results-second.json,up-second.log}`。

この実 VM 試験は HTTP/1.1 明示 proxy の観測と欠損処理を検証します。kernel writer / namespace の証明、TLS/QUIC/direct route、広い実 workload の precision/recall は運用昇格の前に必要です。


## 追加の境界契約と実 Jev 応答

`boundary-manifest.json` は `boundary-contract-v2` の合成契約セットです。全件 development として、元の 3-window held-out 評価と混ぜません。独立ラベルは generator 内のケース仕様から定義し、分類器の回答から変更しません。

正常 install/build の file role、正当な credential upload、ENOENT/EACCES、open 成功/read なし、POST 失敗、無関係 PID、PID/namespace 再利用、確認済み子、keep-alive、同宛先への独立した並行接続、指示風 path、clock jump、ring loss、TLS/QUIC/bypass の coverage 不足を計 21 windows で比較します。TLS/QUIC/direct stream 自体を観測したと偽らず、他の captured POST がある workload の観測不足として試験します。実 install/build の精度測定ではありません。

```sh
python3 tests/fixtures/behavior/generate_boundaries.py
cargo run --locked -- behavior evaluate --manifest tests/fixtures/behavior/boundary-manifest.json
```

| 方式 | windows | 系列警告 | 棄権 | Precision | Recall | F1 | coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 21 | 0 | 0 | 未定義 | 0 | 0 | 1 |
| B + mock | 21 | 0 | 21 | 未定義 | 0 | 0 | 0 |
| C + mock | 21 | 8 | 5 | 0.875 | 1 | 0.933 | 0.762 |
| D | 21 | 7 | 5 | 1 | 1 | 1 | 0.762 |

C の単純 mock は known 宛先への正当な credential upload も警告し、追加誤警告は正常 workload あたり 0.25。D は novel を区別し、この fixture では誤警告 0。合成契約が良い値でも、実 workload の性能や Jev の性能とは呼びません。

正当な upload の closed projection だけを追加で実 `jev-1.13.0` に渡した結果、normal / confidence 0.71 / selected probability 0.81。同じ固定閾値で host 検証を通過し、Normal と保存しました。`jev-boundary-responses.json` と `jev-boundary-measurement.json` で再現できます。他の新しい projection は記録応答がなければ Skipped のままです。

この追加呼び出しの MCP round-trip は 427 ms、input/output は 632/43 tokens。測定 1 件の p50/p95 はともに 427 ms ですが、サンプルが 1 件なので分布性能を主張しません。MCP/ネットワークを含む host 側の往復であり、純粋なモデル推論時間ではありません。元の 4 呼び出しの閾値・質問・記録応答は変更していません。実 API の合計は 5 呼び出し、3131/220 tokens です。

高 confidence の誤答も独立ラベルに対する false negative として計数するテストを追加しました。MCP の停止、429/529、誤った RPC ID、二重応答、不正 JSON、巨大 stderr、timeout は正常判定に変換しません。provider panic は worker の失敗として保存し、ingestion と終了処理を継続します。

## 負荷と lifecycle の最終実 VM 試験

Core source/collector: `3ab9d3fd358e979ae222cfb942399b6c543128af`。環境は上記 Debian/QEMU と同じ。再現可能な harness は [tests/manual/README.md](../tests/manual/README.md)、版・バイナリ/fixture/image hash・測定値は [vm-validation-summary.json](../tests/fixtures/behavior/vm-validation-summary.json)。実イベント JSONL digest は `3bfbb9da7f38556b6ede34f377955b3c7748c5d44990ef7d151ad39f91570478`。

- 通常 POST 2 件: credential access 0。資格情報参照後 POST 2 件: 同一 process の open 成功 1/ENOENT 1。両系列で connector の証拠を保存。
- 各 POST は upstream 192 bytes / response 113 bytes / status 200。4 windows と classification は **up が稼働中に保存**され、MissingWriter / SocketAmbiguous のため全件 Abstained。
- body/header/query/path の canary は audit JSONL になし。保存失敗/storage gap は 0。
- 通常 down は exit 0、session/PID/lock 削除。shell の proxy 環境、47×121 resize、exit 7、termios/O_NONBLOCK 復元は成功。
- 再起動後に専用 QEMU を SIGTERM で停止。待機中 exec・入力待ち shell・up はすべて exit 1、約 1.206 秒で終了。端末と state も復元・削除。

| 測定 | 結果 | 範囲 |
| --- | ---: | --- |
| host Izanagi peak RSS | 20.219 MiB | 0.5 秒間隔、150 samples |
| QEMU peak RSS | 773.422 MiB | 149 samples |
| host / QEMU peak `%cpu` | 32.3 / 199.8 | `ps` lifetime 値、瞬時 CPU ではない |
| guest agent / proxy 終了前 RSS | 20.500 / 4.016 MiB | `ps` の 2 回測定 |
| HTTP round-trip p50 / p95 | 2.767 / 44.460 ms | 4 requests、nearest-rank |
| source drop | 976 | ObservationGap として記録 |

従来機能との overhead 比較、広い実作業での推論 p50/p95、実 workload の precision/recall は未測定です。測定した数値の対象を限定し、これらの値で運用昇格を認めません。

### 負荷で見つかった #48

eBPF と HTTP が共有する優先枠により HTTP が滞留し、さらに遅着する kernel イベントがライブ時計の基点を巻き戻して window 確定を先送りしていました。kernel 96/HTTP 32 件毎秒の独立枠、syscall を含む公平な中継、Stop/health の優先、host の timer 優先と巻き戻さない時計を追加。source saturation と遅着 backlog の回帰テスト、および上記実 VM の停止前 4 windows 保存で修正を確認しました。

## 受け入れ条件と証拠

| 条件 | 確認方法 |
| --- | --- |
| 共通 ID・品質・privacy・rotation | telemetry の behavior 16/storage 6 tests、CLI の show/clear/expired |
| wire v3/HMAC/token/cancel-safe、raw ABI mismatch | protocol/agent lifecycle/PTY tests、旧 object の拒否 test、実 guest ready |
| PID/boot/session/namespace/port/共有 socket/子 lineage | telemetry の独立契約 tests と 21-window boundary manifest |
| entry-only result Unknown、open/POST の成否と実測量 | collector unit tests、実 VM の成功/ENOENT/2 requests×2 series |
| framing/private-IP/secret/keep-alive | HTTP forward の contract tests、legacy tests、実 VM canary |
| API 無効・送信不可なら呼出ゼロ | default config と CLI、Counted classifier、閉じた projection/環境 allowlist |
| 応答 model/distribution/unknown/error/上限 | classifier tests、保存した実 API 応答、悪い RPC ID と二重応答 |
| deterministic replay/paired denominators/独立 labels | evaluation tests、固定 file digests、high-confidence 誤答の計数 |
| queue/stale/panic/終了後応答が監視を阻害しない | runtime/worker/Engine lifecycle tests、最終実 VM monitor loss |
| guest sidecar 配置と lifecycle | Makefile/Packer 配置、Packer validate、同版の実 guest 起動/stop |

実 VM artifacts は `/private/tmp/izanagi-jev-vm-39-final-3/`。認証キーは artifact/manifest/projection に保存しません。Jev は必須ではなく、機能は既定で無効・有効化時も mock が既定。実 Jev は追加の export opt-in がある場合だけ起動します。

## 2026-10-09: issues #54–#56 の回帰検証

修正前に絶対パス制約、MCP 子孫終了、Connector から実送信範囲を証明する回帰テストが失敗することを確認し、修正後に成功した。MCP は絶対パスのみ許可し、Unix の専用プロセスグループを成功・不正応答・タイムアウト・キャンセル時に終了する。自ら別セッションへ逃れる悪意ある実行ファイルの隔離を保証する機能ではない。

TCP の成功送信範囲と HTTP proxy の受信リクエスト範囲を照合する。BTF による構造体と関数シグネチャの検証が失敗すると監視起動を拒否する。raw kernel ABI は 2 のため agent と eBPF object を一緒に更新する。

macOS ARM64 の root 536 tests、agent 42、HTTP 64、telemetry 27、common (`--features user`) 8 が成功した。root clippy `-D warnings`、各変更 component の rustfmt、Linux GNU guest と no_std eBPF のクロスビルドも成功した。Linux 専用 feature の lint/test は PR CI で確認する。

Debian aarch64 / Linux `6.12.74+deb13+1-arm64` の専用 QEMU overlay で `tests/manual/behavior_vm.py` を実行した。通常 POST と資格情報アクセス試行後の keep-alive POST の計 4 件は confirmed_writer・quality 問題なしとなり、mock 分類が成功した。fork 共有と SCM_RIGHTS による親子の分割送信 2 件は socket_shared として棄権した。HTTP canary の本文・header・path は audit に残らなかった。shell の終了コード 7・端末復元、監視消失時の up/exec/shell の失敗と約 0.61 秒での状態解放も成功した。

同じ VM の metadata audit を実 Jev `jev-1.13.0` で replay し、正常 2 件は分類成功、アクセス後 POST 2 件は低 confidence により棄権した。混在送信 2 件は incomplete_observation で API 前に棄権した。API キーはローカル MCP 設定から子プロセス環境へ渡し、記録していない。この少数のシナリオは実装経路の確認であり、分類精度の測定ではない。
