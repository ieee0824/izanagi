#!/bin/sh
# Run last, inside the guest. Keep the current provisioning SSH session alive.
set -eu

passwd -l root

if [ -f /etc/ssh/sshd_config ]; then
    # Remove the build-time policy; the first value wins before included files.
    sed -i '/^[[:space:]]*PermitRootLogin[[:space:]]/d' /etc/ssh/sshd_config
    sed -i '1iPermitRootLogin no' /etc/ssh/sshd_config
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable ssh.service
    systemctl mask ssh.service ssh.socket
elif [ -d /etc/runlevels ]; then
    for link in /etc/runlevels/*/sshd; do
        if [ -L "$link" ]; then
            rm "$link"
        fi
    done
else
    echo "unsupported guest service manager" >&2
    exit 1
fi

sh "$(dirname "$0")/verify-image.sh"
