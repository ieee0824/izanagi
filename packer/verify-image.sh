#!/bin/sh
# Run as root in the guest; never print shadow entries or password hashes.
set -eu

case "${1:-}" in
    "") after_boot=false ;;
    --after-boot) after_boot=true ;;
    *) echo "usage: verify-image.sh [--after-boot]" >&2; exit 1 ;;
esac
[ "$#" -le 1 ]

awk -F: '$1 == "root" { found = 1; locked = ($2 ~ /^[!*]/) }
    END { exit !(found && locked) }' /etc/shadow

if command -v sshd >/dev/null 2>&1; then
    sshd -T | awk '$1 == "permitrootlogin" { found = 1; denied = ($2 == "no") }
        END { exit !(found && denied) }'
fi

if command -v systemctl >/dev/null 2>&1; then
    [ "$(systemctl is-enabled ssh.service 2>/dev/null || true)" = "masked" ]
    [ "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = "masked" ]
elif [ -d /etc/runlevels ]; then
    for entry in /etc/runlevels/*/sshd; do
        if [ -e "$entry" ] || [ -L "$entry" ]; then
            echo "sshd remains enabled in an OpenRC runlevel" >&2
            exit 1
        fi
    done
else
    echo "unsupported guest service manager" >&2
    exit 1
fi

if "$after_boot"; then
    command -v pgrep >/dev/null
    if pgrep -x sshd >/dev/null; then
        echo "sshd is running after boot" >&2
        exit 1
    fi
fi
printf '%s\n' 'IZANAGI_IMAGE_SECURITY_OK'
