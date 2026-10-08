# 行動分析の実 VM スモーク

`behavior_vm.py` は実際の QEMU/Linux agent・eBPF・guest HTTP sidecar を使い、負荷付きの HTTP 転送、credential-role open 成功/ENOENT、相関と観測不足、canary の非保存、shell の proxy 環境/resize/exit/端末復元を確認する。API は呼ばず、分類器は mock に固定する。通常の unit test には含めない。

## 準備

1. 同じ source revision から host、`make build-agent-gnu build-ebpf build-http-gnu` をビルドする。
2. 元の Debian aarch64 イメージを backing とする専用 overlay を用意し、root 所有の agent (`/usr/local/bin/izanagi-agent`)、HTTP sidecar (`/usr/local/bin/izanagi-http-capture`)、object (`/opt/izanagi/izanagi-ebpf.o`) を配置する。Packer でも配置できる。agent/sidecar は 0755、object は 0644 とする。
3. 空の artifact directory と、その中に専用の guest UID 1000 から書ける `workspace` を用意する。通常の開発 workspace を fixture の共有先にしない。
4. 次の設定を `fixture.toml` として用意する。パスは準備した絶対パスに置き換える。認証キーは専用ファイルを 0600 で準備し、`IZANAGI_SECRET_FILE` で指定する。API key を設定しない。

```toml
[sandbox]
backend = "qemu"
tracer = "vm-agent"
require_auth = true
[sandbox.qemu]
cpus = 2
memory = "2G"
image = "/absolute/path/to/test-overlay.qcow2"
[share]
paths = ["/absolute/path/to/artifacts/workspace"]
mount_point = "/workspace"
[monitor]
syscalls = ["file", "network", "process"]
[detect]
suspicious_paths = ["/workspace/dummy-credentials"]
allowed_hosts = ["127.0.0.1"]
[behavior]
enabled = true
proxy_listen = "127.0.0.1:18080"
fixture_endpoint = "127.0.0.1:19090"
baseline_hosts = []
[behavior.classifier]
provider = "mock"
```

`fixture_endpoint` は、この隔離 guest 内の receiver だけに許す exact endpoint である。一般の allowlist の private-IP 保護を無効化する設定ではない。guest は `python3`、`ps`、`/bin/sh` を使える必要がある。

## 実行

```sh
IZANAGI_SECRET_FILE=/absolute/path/to/test-key \
  python3 tests/manual/behavior_vm.py \
  --directory /absolute/path/to/artifacts \
  --binary target/release/izanagi \
  --config /absolute/path/to/fixture.toml
```

Python 3.11 以上、macOS の PTY と QEMU HVF を使用する。停止した fixture instance から開始し、通常系列と資格情報参照系列それぞれで約 31 秒の startup lookback 除外後に POST を送る。通常 down に加え、再起動後に専用 QEMU 子プロセスを停止して monitor loss と exec/shell/up の失敗・state 削除も確認する。`finally` で shell と VM を停止する。再実行は新しい artifact directory を使用する。

`observed-events-second.jsonl`、`results-second.json`、`resources.json`、`shell-results.json`、`up-second.log` を保存する。host は 0.5 秒間隔の RSS と `ps` の lifetime `%cpu`、guest は実行前後の RSS/CPU、HTTP は各系列 2 requests の round-trip 時間を記録する。これらを profiler の瞬時 CPU、推論時間、一般性能と呼ばない。overlay/collector/host/fixture の SHA256 と source commit は実行前に別途記録する。

現在の Linux collector は connector を観測するが、writer と namespace の完全な証明はない。試験は open/POST の関連を確認しつつ、ライブ C の結果が `Abstained` であることも確認する。通常 install/build や広い攻撃集合の精度は、この 4 requests から推定しない。
