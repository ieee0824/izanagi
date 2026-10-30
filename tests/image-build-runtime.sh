#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
export BUILD_TEST_LOG="$FIXTURE/log"
cat > "$FIXTURE/container" <<'SH'
#!/bin/bash
printf '%s\n' "$*" >> "$BUILD_TEST_LOG"
while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then
        dest="${2#type=local,dest=}"
        mkdir -p "$dest/linux_arm64"
        touch "$dest/linux_arm64/izanagi-agent"
        exit 0
    fi
    shift
done
SH
cat > "$FIXTURE/docker" <<'SH'
#!/bin/bash
printf '%s\n' "$*" >> "$BUILD_TEST_LOG"
case "$1" in
    create) echo fixture-id ;;
    cp) exit 1 ;;
esac
SH
chmod +x "$FIXTURE/container" "$FIXTURE/docker"
PATH="$FIXTURE:$PATH" "$ROOT/image/build.sh" --runtime container
! test -e "$ROOT/image/izanagi-agent"
if PATH="$FIXTURE:$PATH" "$ROOT/image/build.sh" --runtime docker; then
    echo 'expected copy failure' >&2
    exit 1
fi
grep -Fx 'rm fixture-id' "$BUILD_TEST_LOG"
! test -e "$ROOT/image/izanagi-agent"
