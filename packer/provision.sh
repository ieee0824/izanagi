#!/bin/bash
set -euo pipefail

# 既存の qcow2 イメージに SSH 経由で izanagi-agent をプロビジョニングする。
# 前提: ~/.izanagi/images/alpine-aarch64.qcow2 が手動セットアップ済み

AGENT_BINARY="${1:-}"
if [ -z "$AGENT_BINARY" ]; then
    echo "Usage: $0 <path-to-izanagi-agent-binary>"
    echo ""
    echo "前提条件:"
    echo "  1. ~/.izanagi/images/alpine-aarch64.qcow2 が存在すること"
    echo "  2. agent バイナリが aarch64-unknown-linux-musl でビルドされていること"
    exit 1
fi

if [ ! -f "$AGENT_BINARY" ]; then
    echo "Error: $AGENT_BINARY not found"
    exit 1
fi

IMAGE="$HOME/.izanagi/images/alpine-aarch64.qcow2"
if [ ! -f "$IMAGE" ]; then
    echo "Error: $IMAGE not found"
    echo "手動で Alpine をインストールしてください (README 参照)"
    exit 1
fi

SSH_PORT=2222
AGENT_PORT=9001
SSH_OPTS="-o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "=== QEMU VM を起動 ==="
qemu-system-aarch64 -accel hvf -cpu host -m 2G -smp 2 \
  -M virt -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  -drive "file=$IMAGE,format=qcow2,if=virtio" \
  -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${AGENT_PORT}-:${AGENT_PORT}" \
  -device virtio-net-pci,netdev=net0 \
  -nographic &
QEMU_PID=$!

cleanup() {
    echo "=== QEMU を停止 ==="
    kill $QEMU_PID 2>/dev/null || true
    wait $QEMU_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "=== SSH 接続待ち ==="
for i in $(seq 1 60); do
    if sshpass -p izanagi ssh -p $SSH_PORT $SSH_OPTS root@localhost true 2>/dev/null; then
        echo "SSH 接続成功"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "Error: SSH 接続タイムアウト (60秒)"
        exit 1
    fi
    sleep 1
done

echo "=== agent を転送 ==="
sshpass -p izanagi scp -P $SSH_PORT $SSH_OPTS "$AGENT_BINARY" root@localhost:/usr/local/bin/izanagi-agent

echo "=== agent をセットアップ ==="
sshpass -p izanagi ssh -p $SSH_PORT $SSH_OPTS root@localhost << 'SETUP'
chmod +x /usr/local/bin/izanagi-agent

# OpenRC init スクリプト
cat > /etc/init.d/izanagi-agent << 'INITEOF'
#!/sbin/openrc-run
name="izanagi-agent"
command="/usr/local/bin/izanagi-agent"
command_background=true
pidfile="/run/izanagi-agent.pid"
output_log="/var/log/izanagi-agent.log"
error_log="/var/log/izanagi-agent.log"
INITEOF
chmod +x /etc/init.d/izanagi-agent
rc-update add izanagi-agent default

# 9p カーネルモジュール
echo "9p" >> /etc/modules
echo "9pnet" >> /etc/modules
echo "9pnet_virtio" >> /etc/modules

echo "=== セットアップ完了 ==="
SETUP

echo "=== VM をシャットダウン ==="
sshpass -p izanagi ssh -p $SSH_PORT $SSH_OPTS root@localhost poweroff || true

# QEMU の終了を待つ
wait $QEMU_PID 2>/dev/null || true
trap - EXIT

echo ""
echo "完了！イメージ: $IMAGE"
echo "izanagi-agent がプリインストールされました。"
