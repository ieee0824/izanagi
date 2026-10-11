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
- SSH (root/izanagi) — ビルド中のプロビジョニング専用。最終イメージでは root パスワードをロックし、SSH の自動起動を無効化する
- 9p カーネルモジュール有効 — virtio-9p ファイル共有用

既存イメージには公開済みのビルド用 root パスワードが残っているため、停止・退避後に
`make qemu-image`（Debian）または `make qemu-image-alpine`（Alpine）で再作成する。
最終シャットダウンの既存 SSH セッション内で `lock-down.sh` を実行する。
root のパスワードをロックし、ビルド用 `PermitRootLogin yes` を除去する。
Debian は SSH サービスと socket を mask し、Alpine は全 runlevel から sshd を外す。
`verify-image.sh` が shadow のロック、実効 SSH 設定、自動起動の無効化を検証し、失敗した場合は
シャットダウンへ進まないため Packer は正常なイメージとして完了できない。

### イメージの検証

ゲスト内で root として `sh verify-image.sh --after-boot` を実行すると、上記に加え sshd が
実際に動作していないことを検査する。shadow のハッシュや認証情報は表示しない。

公開済みのビルド用ログインが残る旧イメージを使う macOS/aarch64 の再起動テスト:

```bash
python3 tests/manual/image_security.py ~/.izanagi/images/alpine-aarch64.qcow2 ~/.izanagi/images/debian-aarch64.qcow2
```

このテストは元イメージに書き込まない一時 qcow2 オーバーレイを使い、最終化前の検証失敗、
最終化、再起動後の検証成功、SSH が応答しないことを確認する。ホストの共有領域やトークンは
渡さず、ネットワークは制限する。Debian で root SSH が禁止されている場合は公開ビルド用
パスワードによるコンソールログインで、一時オーバーレイだけにプロビジョニング接続を作る。
検証後はテスト VM とオーバーレイを削除する。新しいセキュアなイメージで旧ログインを再度有効にしない。

CI の `Image security` は使い捨て Debian/Alpine コンテナで実際の passwd・OpenSSH・
サービス設定を検証し、ロック解除、SSH の再有効化、root ログイン許可、sshd の手動起動を
それぞれ拒否する回帰テストを実行する。コンテナテスト自体は VM の再起動検証ではない。
