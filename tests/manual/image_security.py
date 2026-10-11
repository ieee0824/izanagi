#!/usr/bin/env python3
"""Verify image finalization and reboot on a disposable QEMU overlay.

Uses the public legacy build login only. Never shares host directories or tokens.
Requires macOS/aarch64 QEMU HVF, qemu-img, sshpass, and a legacy build image.
"""
import argparse
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
SSH_OPTIONS = ["-F", "/dev/null", "-o", "IdentityAgent=none",
               "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=2", "-o", "LogLevel=ERROR"]


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=30, **kwargs)


def ssh(port, command, data=None):
    return run(["sshpass", "-p", "izanagi", "ssh", "-p", str(port), *SSH_OPTIONS,
                "root@127.0.0.1", command], input=data)


def copy(port, source, destination):
    result = run(["sshpass", "-p", "izanagi", "scp", "-O", "-P", str(port),
                  *SSH_OPTIONS, str(source), f"root@127.0.0.1:{destination}"])
    if result.returncode:
        raise RuntimeError("copy to disposable guest failed")


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start(overlay, port, serial, restrict=True, extra_args=None):
    command = ["qemu-system-aarch64", "-accel", "hvf", "-cpu", "host", "-m", "1024",
               "-smp", "2", "-M", "virt", "-bios",
               "/opt/homebrew/share/qemu/edk2-aarch64-code.fd", "-drive",
               f"file={overlay},format=qcow2,if=virtio", "-netdev",
               f"user,id=net0,restrict={'on' if restrict else 'off'},hostfwd=tcp:127.0.0.1:{port}-:22",
               "-device", "virtio-net-pci,netdev=net0", "-display", "none",
               "-serial", "stdio", "-monitor", "none"]
    command.extend(extra_args or [])
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    process.serial_path = serial
    process.serial_thread = threading.Thread(target=record_serial, args=(process, serial), daemon=True)
    process.serial_thread.start()
    return process


def record_serial(process, serial):
    with serial.open("wb") as log:
        while data := process.stdout.read1(4096):
            log.write(data)
            log.flush()


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    process.serial_thread.join(timeout=10)


def wait_console(process, expected, start=0):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.serial_path.exists():
            data = process.serial_path.read_bytes()[start:]
            if expected in data:
                return
        if process.poll() is not None:
            break
        time.sleep(0.2)
    raise RuntimeError("legacy guest console login failed")


def enable_build_ssh(process):
    # Debian legacy images prohibit root SSH but retain the public root password.
    # Enable provisioning access only on this disposable, restricted-network overlay.
    wait_console(process, b"login:")
    process.stdin.write(b"root\n")
    process.stdin.flush()
    wait_console(process, b"Password:")
    position = process.serial_path.stat().st_size
    process.stdin.write(b"izanagi\n")
    process.stdin.flush()
    wait_console(process, b"#", position)
    command = ("iface=$(ip -o link show | awk -F': ' '$2 != \"lo\" {print $2; exit}'); "
               "ip link set \"$iface\" up; ip addr replace 10.0.2.15/24 dev \"$iface\"; "
               "sed -i '1iPermitRootLogin yes' /etc/ssh/sshd_config; "
               "if command -v systemctl >/dev/null; then "
               "systemctl unmask ssh.service ssh.socket; systemctl restart ssh.service; "
               "else rc-service sshd start; fi\n")
    process.stdin.write(command.encode())
    process.stdin.flush()


def wait_ssh(process, port):
    started = time.monotonic()
    deadline = started + 120
    console_attempted = False
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("QEMU exited before guest SSH became available")
        if ssh(port, "true").returncode == 0:
            return
        if not console_attempted and time.monotonic() - started > 20:
            console_attempted = True
            enable_build_ssh(process)
        time.sleep(1)
    raise RuntimeError("legacy build login unavailable in the disposable guest")


# Declarative guest service definitions are kept together for the two init systems.
INSTALL_PROBE = r'''set -eu
mkdir -p /usr/local/libexec
cp /tmp/verify-image.sh /usr/local/libexec/izanagi-verify-image.sh
cat > /usr/local/libexec/izanagi-image-security-test <<'EOF'
#!/bin/sh
if sh /usr/local/libexec/izanagi-verify-image.sh --after-boot >/dev/console 2>&1; then
    echo IZANAGI_POST_BOOT_OK >/dev/console
else
    echo IZANAGI_POST_BOOT_FAILED >/dev/console
fi
EOF
chmod 0755 /usr/local/libexec/izanagi-image-security-test
if command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/izanagi-image-security-test.service <<'EOF'
[Unit]
After=network.target ssh.service ssh.socket
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/izanagi-image-security-test
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable izanagi-image-security-test.service
else
    mkdir -p /etc/local.d
    ln -s /usr/local/libexec/izanagi-image-security-test /etc/local.d/izanagi-image-security-test.start
    rc-update add local default
fi
'''


def finalize(port):
    copy(port, ROOT / "packer/lock-down.sh", "/tmp/izanagi-lock-down.sh")
    copy(port, ROOT / "packer/verify-image.sh", "/tmp/verify-image.sh")
    before = ssh(port, "sh /tmp/verify-image.sh")
    if before.returncode == 0:
        raise RuntimeError("expected the legacy image to fail verification before finalization")
    installed = ssh(port, "sh -s", INSTALL_PROBE.encode())
    if installed.returncode:
        raise RuntimeError("post-boot probe installation failed")
    command = "set -eu\nsh /tmp/izanagi-lock-down.sh\nsync\nnohup sh -c 'sleep 2; poweroff' >/dev/null 2>&1 &\n"
    result = ssh(port, "sh -s", command.encode())
    if result.returncode or b"IZANAGI_IMAGE_SECURITY_OK" not in result.stdout:
        raise RuntimeError(f"guest finalization failed: exit={result.returncode}, "
                           f"marker={b'IZANAGI_IMAGE_SECURITY_OK' in result.stdout}, "
                           f"diagnostics={result.stderr.decode(errors='replace').strip()}")


def verify_reboot(process, serial, port):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("QEMU exited during post-boot verification")
        output = serial.read_bytes() if serial.exists() else b""
        if b"IZANAGI_POST_BOOT_FAILED" in output:
            raise RuntimeError("guest security checks failed after reboot")
        if b"IZANAGI_POST_BOOT_OK" in output:
            with socket.socket() as sock:
                sock.settimeout(3)
                try:
                    sock.connect(("127.0.0.1", port))
                    banner = sock.recv(256)
                except (OSError, TimeoutError):
                    banner = b""
            if b"SSH-" in banner:
                raise RuntimeError("SSH still responds after reboot")
            return
        time.sleep(1)
    raise RuntimeError("post-boot security verification timed out")


def check_image(image):
    with tempfile.TemporaryDirectory(prefix="izanagi-image-security-") as temporary:
        directory = Path(temporary)
        overlay = directory / "overlay.qcow2"
        created = run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                       str(image.resolve()), str(overlay)])
        if created.returncode:
            raise RuntimeError("disposable overlay creation failed")
        port = available_port()
        process = start(overlay, port, directory / "before.log")
        try:
            wait_ssh(process, port)
            finalize(port)
            process.wait(timeout=60)
        finally:
            stop(process)
        serial = directory / "after.log"
        process = start(overlay, port, serial)
        try:
            verify_reboot(process, serial, port)
        finally:
            stop(process)
    print(f"PASS: {image.name}: legacy rejection, finalization, reboot, no sshd")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", type=Path, nargs="+")
    arguments = parser.parse_args()
    for image in arguments.images:
        check_image(image)


if __name__ == "__main__":
    main()
