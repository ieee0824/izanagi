# 行動分析 PoC の検証記録

合成 fixture の mock 結果は処理経路と評価の算術の検証です。実 Jev と VM は下の別節で区別して記録します。少数の模擬入力から運用時の精度は主張しません。

## 固定条件

- fixtures: `tests/fixtures/behavior/{normal,access-post,event-loss}.jsonl`
- manifest: `tests/fixtures/behavior/manifest.json` (seed 39、synthetic-v1)
- fixture の SHA256 を manifest に保存し、読み込んだ同じ bytes を検証して再生
- model 条件: jev-1.13.0、question version 1、confidence 閾値 0.6
- 分布合計許容差 0.001、confidence 丸め許容差 0.01
- eligibility: correlated は confirmed writer と必要な観測、network-only は意図的 mask と source gap を区別
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

この実 VM 試験は HTTP/1.1 明示 proxy の観測と欠損処理を検証します。kernel writer / namespace の証明、TLS/QUIC/direct route、広い実 workload の precision/recall、CPU/RSS の測定は運用昇格の前に必要です。
