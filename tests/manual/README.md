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
restrict_network = false # 専用 fixture のホスト HTTP プロキシに接続する
[share]
paths = ["/absolute/path/to/artifacts/workspace"]
mount_point = "/workspace"
read_only = false # 専用 fixture 内の receiver log と計測結果を書き込む
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

`observed-events-second.jsonl`、`results-second.json`、`writer-negative-results.json`、`resources.json`、`shell-results.json`、`up-second.log` を保存する。host は 0.5 秒間隔の RSS と `ps` の lifetime `%cpu`、guest は実行前後の RSS/CPU、HTTP は各系列 2 requests の round-trip 時間を記録する。これらを profiler の瞬時 CPU、推論時間、一般性能と呼ばない。overlay/collector/host/fixture の SHA256 と source commit は実行前に別途記録する。

Linux collector は成功した `tcp_sendmsg_locked` の送信範囲と実 socket namespace を取得する。kernel BTF の layout・関数 signature 検証と writer probe の装着が開始条件。raw ABI v2 の agent/object を使う。試験は正例 4 requests が `ConfirmedWriter` で mock 分類されることを確認する。続いて fork/dup と SCM_RIGHTS により同じ HTTP リクエストの header/body を別プロセスで送り、転送は完了しても複数 writer として棄権することを確認する。欠落や unsupported な転送を成功した writer proof に昇格させない。通常 install/build や広い攻撃集合の精度は、この小さな試験から推定しない。


### Read-only workspace shares (#63)

Only a newly created fixture directory is shared. Original projects and credentials
are not shared, and QEMU uses a disposable legacy-image overlay.

```sh
python3 tests/manual/workspace_share.py qemu --image ~/.izanagi/images/alpine-aarch64.qcow2
python3 tests/manual/workspace_share.py apple-container
```

The QEMU check requires image_security.py prerequisites. The Apple Container check
requires a running container service and cached `alpine:3.23`. Both checks read a
Git config, reject overwrite/append/truncate/remove/rename/create/hardlink and build
script writes in read-only mode, verify unchanged host fixtures, then prove a write
reaches the host with the explicitly writable mode. Fixtures deliberately allow
writes by Unix permissions so the positive control can distinguish access-mode
protection. A guest-side command marker rejects transport/CLI failures as evidence
of write denial. Linux CI runs tests/workspace_share.rs against real Landlock with
`IZANAGI_REQUIRE_LANDLOCK_TEST=1`; lack of ABI v3 fails instead of silently skipping.


### QEMU network boundary (#64)

On macOS/aarch64, with the legacy image and tools required by `image_security.py`:

```sh
python3 tests/manual/qemu_network.py ~/.izanagi/images/alpine-aarch64.qcow2
```

Uses a disposable overlay without host shares or credentials, checks the forwarded
listener on 127.0.0.1 and rejection through the host LAN address, then probes a host
loopback TCP listener via 10.0.2.2 and external 1.1.1.1:443. Both fail with
`restrict=on` and succeed with `restrict=off` as a positive control. The external
positive control requires working Internet access; it fails rather than skips if
that access is unavailable. No application payload is sent to the external endpoint.

## Guest DNS integration (#65)

Use the same revision for the host, agent and guest probe. The DNS component suite
starts the actual proxy and checks that UDP/TCP relay requests appear as `BLOCKED`.
The following manual regression additionally exercises the production backend
startup and the guest's normal system resolver:

```sh
cargo build --locked --manifest-path izanagi-dns-proxy/Cargo.toml
cargo build --locked --example dns_sandbox_smoke
cargo zigbuild --locked --manifest-path izanagi-agent/Cargo.toml --target aarch64-unknown-linux-gnu --release
cargo zigbuild --locked --example dns_guest_probe --target aarch64-unknown-linux-gnu --release
python3 tests/manual/guest_dns.py container
python3 tests/manual/guest_dns.py qemu --image ~/.izanagi/images/debian-aarch64.qcow2
```

The macOS/aarch64 QEMU check uses `image_security.py`'s legacy provisioning login
only on a disposable overlay. It installs the new agent/probe and a fixture-only
command allowlist, then stops the provisioning VM before production startup.
It never shares host files or alters the backing image. The container check builds
and deletes a dedicated Debian fixture image. Both require a `BLOCKED` entry for
`denied.izanagi-test.org` in the actual host proxy log. They create a private
fixture HMAC key, use UDP and TCP on a nonstandard host port, and stop all services.

The new read-only `DnsStatus` message is appended to v3's existing message variants;
existing frames retain their encoding. DNS-enabled startup rejects an older guest
that cannot confirm the configured relay, without needing to add `cat` to a command
allowlist. Test the root status regression and DNS startup failure regression for
unconfigured/mismatched agents, unreachable upstreams and released listeners.

## Agent supplementary-group regression (#67)

CI's Linux agent component job runs `privilege_tests::privileged_` explicitly as
root in a disposable runner, with a fixture `izanagi` account and `/workspace`.
CI installs the test executable in a dedicated traversable temporary directory;
the runner's private source/build directory permissions remain unchanged.
The tests are ignored in ordinary non-root component suites. Never run them in a
production agent process: they deliberately seed groups `0` and `12345` in their
own test process.

The authenticated Exec and PTY Shell paths execute a reporter under the target
UID/GID. It checks `getgroups()` directly, requiring no inherited supplementary
groups and the target primary GID. A separate subprocess regression makes each
of the three identity transitions fail and requires spawn to refuse exec.
The parent retains its original seeded groups after both real paths finish.

For a local Linux root fixture, build the agent test executable with
`cargo test --locked --manifest-path izanagi-agent/Cargo.toml --no-run`, then run
that executable with `privilege_tests::privileged_ --ignored --nocapture
--test-threads=1`. The lookup uses `getpwnam_r` before fork; the child only performs
credential syscalls, session/chdir setup, dumpability setup and exec.

## Container session credentials (#68)

Build the host and Linux agent from the same revision, then build the disposable
`tests/fixtures/container-agent/Dockerfile` image with only the agent binary in
its build context. It contains an unprivileged user and both default/custom
working directories; it shares no host project or credentials.

```sh
cargo zigbuild --locked --manifest-path izanagi-agent/Cargo.toml --target aarch64-unknown-linux-gnu --release
fixture=$(mktemp -d "$PWD/.izanagi-session.XXXXXX")
cp izanagi-agent/target/aarch64-unknown-linux-gnu/release/izanagi-agent "$fixture/izanagi-agent"
cp tests/fixtures/container-agent/Dockerfile "$fixture/Dockerfile"
container build --platform linux/arm64 -t izanagi-session-test "$fixture"
printf '%s' 'fixture-host-key-not-for-container' > "$fixture/host-key"
chmod 0600 "$fixture/host-key"
IZANAGI_SECRET_FILE="$fixture/host-key" IZANAGI_TEST_CONTAINER_IMAGE=izanagi-session-test \
  cargo test --locked --lib real_container_session_credentials_and_agent_execution -- --ignored --nocapture
container image delete izanagi-session-test
rm -rf -- "$fixture"
```

The test uses production sandbox startup twice. It checks raw runtime `exec -u
izanagi ... env` contains no inline key, the guest user cannot read the mounted
key, the mount rejects root writes, shutdown deletes host files, and keys differ
across sessions and from the fixture host key. Wrong/absent keys fail to
authenticate. Authenticated Exec and Shell verify sanitized environments,
unprivileged identities, no supplementary groups, and the custom working
directory. A persisted-session connection reads its private key file. Linux CI
runs the same regression using Docker; Apple Container must be verified on macOS.
