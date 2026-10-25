#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RUNTIME="${IZANAGI_CONTAINER_RUNTIME:-}"
AGENT_BINARY=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime)
            [ "$#" -ge 2 ] || { echo "Error: --runtime requires a value"; exit 2; }
            RUNTIME="$2"
            shift 2
            ;;
        --runtime=*) RUNTIME="${1#*=}"; shift ;;
        -h|--help)
            echo "Usage: $0 [--runtime container|docker|podman] [agent-binary]"
            exit 0
            ;;
        -*) echo "Error: unknown option: $1"; exit 2 ;;
        *)
            [ -z "$AGENT_BINARY" ] || { echo "Error: only one agent binary may be specified"; exit 2; }
            AGENT_BINARY="$1"
            shift
            ;;
    esac
done

if [ -z "$RUNTIME" ]; then
    for candidate in container docker podman; do
        if command -v "$candidate" &>/dev/null; then
            RUNTIME="$candidate"
            break
        fi
    done
fi
case "$RUNTIME" in
    container|docker|podman) ;;
    *) echo "Error: runtime must be container, docker, or podman"; exit 2 ;;
esac
command -v "$RUNTIME" &>/dev/null || { echo "Error: $RUNTIME command not found"; exit 1; }

# 引数なしの場合はコンテナ内でビルド
if [ -z "$AGENT_BINARY" ]; then
    echo "=== agent をコンテナ内でビルド ==="
    $RUNTIME build -f "$SCRIPT_DIR/Dockerfile.build" -t izanagi-agent-builder "$PROJECT_ROOT"

    # ビルドしたバイナリを取り出す
    # scratch image has no default command; create only materializes its filesystem.
    CID=$($RUNTIME create izanagi-agent-builder /izanagi-agent)
    $RUNTIME cp "$CID:/izanagi-agent" "$SCRIPT_DIR/izanagi-agent"
    $RUNTIME rm "$CID" >/dev/null
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
