#!/bin/sh
# Run only as root inside a disposable Debian/Alpine test container.
set -eu

checks=${1:?path to packer scripts required}
sshd_pid=
trap 'if [ -n "$sshd_pid" ]; then kill "$sshd_pid" 2>/dev/null || true; fi' EXIT

expect_rejected() {
    if sh "$checks/verify-image.sh" "$@" >/dev/null 2>&1; then
        echo "expected image verification to reject unsafe state" >&2
        exit 1
    fi
}

configure_legacy_image() {
    printf 'root:izanagi\n' | chpasswd
    mkdir -p /run/sshd
    sed -i '1iPermitRootLogin yes' /etc/ssh/sshd_config
    ssh-keygen -A >/dev/null 2>&1
    if command -v systemctl >/dev/null 2>&1; then
        systemctl unmask ssh.service ssh.socket
        systemctl enable ssh.service
    else
        rc-update add sshd default
    fi
}

check_service_rejection() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl unmask ssh.service
    else
        rc-update add sshd default
    fi
    expect_rejected
    sh "$checks/lock-down.sh" >/dev/null
}

configure_legacy_image
expect_rejected
sh "$checks/lock-down.sh"
sh "$checks/verify-image.sh" --after-boot

# Independently regress each security boundary after the valid state passes.
passwd -u root >/dev/null
expect_rejected
sh "$checks/lock-down.sh" >/dev/null
check_service_rejection
if command -v systemctl >/dev/null 2>&1; then
    systemctl unmask ssh.socket
    expect_rejected
    sh "$checks/lock-down.sh" >/dev/null
fi
sed -i '1iPermitRootLogin yes' /etc/ssh/sshd_config
expect_rejected
sh "$checks/lock-down.sh" >/dev/null

# A disabled service can still be started manually: post-boot checks catch that.
/usr/sbin/sshd -D &
sshd_pid=$!
sleep 1
kill -0 "$sshd_pid"
expect_rejected --after-boot
kill "$sshd_pid"
wait "$sshd_pid" || true
sshd_pid=
sh "$checks/verify-image.sh" --after-boot
printf '%s\n' 'Image security regression checks passed'
