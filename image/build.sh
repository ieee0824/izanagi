#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$PROJECT_ROOT/Cargo.toml" | head -n 1)"
[ -n "$VERSION" ] || { echo "Error: package version not found in Cargo.toml"; exit 1; }

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

CID=""
BUILD_DIR=""
cleanup() {
    if [ -n "$CID" ]; then "$RUNTIME" rm "$CID" >/dev/null || true; fi
    if [ -n "$BUILD_DIR" ]; then rm -rf -- "$BUILD_DIR"; fi
    rm -f "$SCRIPT_DIR/izanagi-agent"
}
trap cleanup EXIT

# 引数なしの場合はコンテナ内でビルド
if [ -z "$AGENT_BINARY" ]; then
    echo "=== agent をコンテナ内でビルド ==="
    if [ "$RUNTIME" = container ]; then
        BUILD_DIR="$(mktemp -d)"
        "$RUNTIME" build -f "$SCRIPT_DIR/Dockerfile.build" --output "type=local,dest=$BUILD_DIR" "$PROJECT_ROOT"
        AGENT_OUTPUT="$(find "$BUILD_DIR" -type f -name izanagi-agent -print)"
        [ -n "$AGENT_OUTPUT" ] && [ -f "$AGENT_OUTPUT" ] || { echo "Error: expected one agent binary in build output"; exit 1; }
        cp "$AGENT_OUTPUT" "$SCRIPT_DIR/izanagi-agent"
    else
        "$RUNTIME" build -f "$SCRIPT_DIR/Dockerfile.build" -t izanagi-agent-builder "$PROJECT_ROOT"
        CID=$("$RUNTIME" create izanagi-agent-builder /izanagi-agent)
        "$RUNTIME" cp "$CID:/izanagi-agent" "$SCRIPT_DIR/izanagi-agent"
        "$RUNTIME" rm "$CID" >/dev/null
        CID=""
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

echo "=== VM イメージをビルド ==="
# Always retain an immutable project-version tag. Rebuild the cached final
# stage once more for the convenience `latest` tag so every supported runtime
# follows the same code path without relying on runtime-specific tag commands.
$RUNTIME build -t "izanagi-vm:$VERSION" "$SCRIPT_DIR"
$RUNTIME build -t izanagi-vm:latest "$SCRIPT_DIR"

echo ""
echo "Done! Images: izanagi-vm:$VERSION, izanagi-vm:latest"
echo "Run with: $RUNTIME run --rm -it -p 9001:9001 izanagi-vm:$VERSION"
echo "Completed at: $(date '+%Y-%m-%d %H:%M:%S')"
