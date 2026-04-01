# Packer イメージビルド

Alpine Linux + izanagi-agent の QEMU qcow2 イメージを自動ビルドする。

## 前提条件

- Packer 1.15+
- QEMU (`brew install qemu`)
- izanagi-agent の musl バイナリ (CI の build-agent ワークフローからダウンロード)

## ビルド

```bash
# プラグインをインストール（初回のみ）
cd packer
packer init .

# イメージをビルド
packer build -var "agent_binary=/tmp/izanagi-agent" .
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
