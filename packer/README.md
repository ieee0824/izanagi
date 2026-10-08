# Packer イメージビルド

## Debian aarch64（macOS / QEMU HVF）

```bash
rustup toolchain install nightly-2026-02-12 --profile minimal --component rust-src
cargo install bpf-linker --locked
make build-agent-gnu
make build-ebpf
make build-http-gnu
make qemu-image-quick
```

eBPF の既定ツールチェーンは LLVM 22 のリンカーと互換性がある
`nightly-2026-02-12`。別の環境では `EBPF_TOOLCHAIN` を指定できる。
Debian ISO のバージョンと SHA256 は `debian.pkr.hcl` で固定している。
既存イメージを置き換える前に、停止した VM のイメージを退避すること。
プロトコル v3 と eBPF raw ABI ではホスト・agent・eBPF object を同時更新する必要がある。
Debian イメージは root 所有の HTTP sidecar も配置するが、行動分析は既定で無効。
直接 `packer build` する場合は `agent_binary`、`ebpf_binary`、`http_binary` を指定する。

実通信スモークテスト:

```bash
IZANAGI_SECRET_FILE=/path/to/secret cargo run --example qemu_protocol_smoke -- /path/to/qemu-test.toml
```

設定の共有パスは空のテストディレクトリを指定する。VMはsnapshotモードで
起動し、認証付きExec・Event受信後に停止する。

## Alpine

Alpine Linux + izanagi-agent の QEMU qcow2 イメージを自動ビルドする。

## 前提条件

- Packer 1.15+
- QEMU (`brew install qemu`)
- izanagi-agent の musl バイナリ (CI の build-agent ワークフローからダウンロード)

## ビルド

```bash
# プラグインをインストール（初回のみ）
cd packer
packer init alpine.pkr.hcl

# イメージをビルド
packer build -var "agent_binary=/tmp/izanagi-agent" alpine.pkr.hcl
```

ビルド完了後、`output/alpine-aarch64.qcow2` が生成される。

## イメージの配置

```bash
cp output/alpine-aarch64.qcow2 ~/.izanagi/images/
```

## イメージの内容

- Alpine Linux 3.23 (aarch64)
- izanagi-agent (`/usr/local/bin/izanagi-agent`)
- OpenRC で agent が自動起動
- SSH (root/izanagi) — Packer プロビジョニング用
- 9p カーネルモジュール有効 — virtio-9p ファイル共有用
