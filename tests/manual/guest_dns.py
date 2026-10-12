#!/usr/bin/env python3
"""Prove production DNS wiring on real guests using disposable fixtures only.

Build host examples/dns_sandbox_smoke, Linux agent and examples/dns_guest_probe
first. QEMU provisioning requires image_security's legacy fixture prerequisites.
"""
import argparse
from pathlib import Path
import socket
import subprocess
import tempfile
import uuid

import image_security as guest

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / 'izanagi-agent/target/aarch64-unknown-linux-gnu/release/izanagi-agent'
PROBE = ROOT / 'target/aarch64-unknown-linux-gnu/release/examples/dns_guest_probe'


def checked(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stderr.decode(errors="replace")}')
    return result


def check_guest(backend, image, host, directory):
    config = directory / 'izanagi.toml'
    extra = (f'[sandbox.qemu]\ncpus=2\nmemory="1G"\nimage="{image}"\nrestrict_network=false\n'
             if backend == 'qemu' else f'[sandbox.apple_container]\nimage="{image}"\n')
    port = guest.available_port()
    config.write_text(f'[sandbox]\nbackend="{backend}"\ntracer="none"\n' + extra +
                      '[share]\npaths=[]\nmount_point="/workspace"\n[monitor]\nsyscalls=[]\n'
                      '[detect]\nsuspicious_paths=[]\nallowed_hosts=["allowed.example"]\n'
                      f'[dns_proxy]\nenabled=true\nlisten="{host}:{port}"\n')
    config.chmod(0o600)
    secret = directory / 'secret'
    secret.write_text(uuid.uuid4().hex)
    secret.chmod(0o600)
    import os
    environment = dict(os.environ, IZANAGI_SECRET_FILE=str(secret))
    import shutil
    executable = directory / 'dns_sandbox_smoke'
    shutil.copy(ROOT / 'target/debug/examples/dns_sandbox_smoke', executable)
    shutil.copy(ROOT / 'izanagi-dns-proxy/target/debug/izanagi-dns-proxy', directory / 'izanagi-dns-proxy')
    result = checked([str(executable), str(config)], env=environment)
    log = result.stderr.decode(errors='replace')
    if '[BLOCKED] denied.izanagi-test.org from' not in log:
        raise RuntimeError('guest query did not appear as BLOCKED in the actual proxy log')
    (directory / 'proxy.log').write_text(log)
    print(f'PASS: {backend}: system resolver + TCP, actual proxy BLOCKED log')
    print(result.stdout.decode().strip())


def check_container(directory):
    name = 'izanagi-dns-test-' + uuid.uuid4().hex
    context = directory / 'image'
    context.mkdir()
    import shutil
    shutil.copy(AGENT, context / 'izanagi-agent')
    shutil.copy(PROBE, context / 'izanagi-dns-probe')
    (context / 'Dockerfile').write_text('FROM debian:trixie-slim\n'
        'RUN useradd -m izanagi && mkdir -p /workspace && chown izanagi:izanagi /workspace\n'
        'COPY izanagi-agent izanagi-dns-probe /usr/local/bin/\n'
        'RUN chmod 0755 /usr/local/bin/izanagi-*\nENTRYPOINT ["/usr/local/bin/izanagi-agent"]\n')
    checked(['container', 'build', '-t', name, str(context)])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(('192.0.2.1', 9))
            host = sock.getsockname()[0]
        check_guest('apple-container', name, host, directory)
    finally:
        checked(['container', 'image', 'delete', name])


def check_qemu(image, directory):
    overlay = directory / 'overlay.qcow2'
    checked(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image.resolve()), str(overlay)])
    port = guest.available_port()
    process = guest.start(overlay, port, directory / 'serial.log')
    try:
        guest.wait_ssh(process, port)
        guest.copy(port, AGENT, '/tmp/izanagi-new-agent')
        guest.copy(port, PROBE, '/tmp/izanagi-dns-probe')
        result = guest.ssh(port, 'chmod 0755 /tmp/izanagi-new-agent /tmp/izanagi-dns-probe; '
            'mv /tmp/izanagi-new-agent /usr/local/bin/izanagi-agent; '
            'mv /tmp/izanagi-dns-probe /usr/local/bin/izanagi-dns-probe; '
            'mkdir -p /etc/systemd/system/izanagi-agent.service.d; '
            'printf "[Service]\\nEnvironment=IZANAGI_ALLOWED_COMMANDS=/usr/local/bin/izanagi-dns-probe\\n" '
            '> /etc/systemd/system/izanagi-agent.service.d/dns-test.conf; sync' )
        if result.returncode:
            raise RuntimeError('guest fixture installation failed')
    finally:
        guest.stop(process)
    check_guest('qemu', overlay, '127.0.0.1', directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backend', choices=['qemu', 'container'])
    parser.add_argument('--image', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='izanagi-dns-guest-') as temporary:
        directory = Path(temporary)
        if args.backend == 'qemu':
            if args.image is None:
                parser.error('--image required for QEMU')
            check_qemu(args.image, directory)
        else:
            check_container(directory)


if __name__ == '__main__':
    main()
