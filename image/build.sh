#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# コンテナランタイムを検出
if command -v container &>/dev/null; then
    RUNTIME="container"
elif command -v docker &>/dev/null; then
    RUNTIME="docker"
else
    echo "Error: container or docker command not found"
    echo "Install Apple Container or Docker"
    exit 1
fi

AGENT_BINARY="${1:-}"

# 引数なしの場合はコンテナ内でビルド
if [ -z "$AGENT_BINARY" ]; then
    echo "=== agent をコンテナ内でビルド ==="
    $RUNTIME build -f "$SCRIPT_DIR/Dockerfile.build" -t izanagi-agent-builder "$PROJECT_ROOT"

    # ビルドしたバイナリを取り出す
    CID=$($RUNTIME run --rm -d izanagi-agent-builder sleep 10 2>/dev/null || true)
    if [ -n "$CID" ]; then
        $RUNTIME cp "$CID:/izanagi-agent" "$SCRIPT_DIR/izanagi-agent"
        $RUNTIME stop "$CID" 2>/dev/null || true
    else
        # scratch イメージからはコンテナ起動できないので、builder ステージから取る
        $RUNTIME build -f "$SCRIPT_DIR/Dockerfile.build" --target builder -t izanagi-agent-builder "$PROJECT_ROOT"
        CID=$($RUNTIME run --rm -d izanagi-agent-builder sleep 30)
        $RUNTIME cp "$CID:/src/izanagi-agent/target/release/izanagi-agent" "$SCRIPT_DIR/izanagi-agent"
        $RUNTIME stop "$CID" 2>/dev/null || true
    fi
    chmod +x "$SCRIPT_DIR/izanagi-agent"
    echo "agent ビルド完了"
else
    if [ ! -f "$AGENT_BINARY" ]; then
        echo "Error: $AGENT_BINARY not found"
        exit 1
    fi
    cp "$AGENT_BINARY" "$SCRIPT_DIR/izanagi-agent"
    chmod +x "$SCRIPT_DIR/izanagi-agent"
fi

# 終了時に agent バイナリを削除
cleanup() {
    rm -f "$SCRIPT_DIR/izanagi-agent"
}
trap cleanup EXIT

echo "=== VM イメージをビルド ==="
$RUNTIME build -t izanagi-vm "$SCRIPT_DIR"

echo ""
echo "Done! Image: izanagi-vm"
echo "Run with: $RUNTIME run --rm -it -p 9001:9001 izanagi-vm"
echo "Completed at: $(date '+%Y-%m-%d %H:%M:%S')"
