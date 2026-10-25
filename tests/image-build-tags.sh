#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT

export IZANAGI_IMAGE_BUILD_LOG="$FIXTURE/build.log"
touch "$IZANAGI_IMAGE_BUILD_LOG" "$FIXTURE/agent"
cat > "$FIXTURE/docker" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$IZANAGI_IMAGE_BUILD_LOG"
SH
chmod +x "$FIXTURE/docker"

PATH="$FIXTURE:$PATH" "$ROOT/image/build.sh" --runtime docker "$FIXTURE/agent"

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
grep -Fx "build -t izanagi-vm:$VERSION $ROOT/image" "$IZANAGI_IMAGE_BUILD_LOG"
grep -Fx "build -t izanagi-vm:latest $ROOT/image" "$IZANAGI_IMAGE_BUILD_LOG"
