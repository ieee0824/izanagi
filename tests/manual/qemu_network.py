#!/usr/bin/env python3
"""Check loopback-only forwarding and slirp isolation on a disposable legacy image.

Uses image_security's restricted provisioning helper; no host files or tokens shared.
Requires its macOS/aarch64 QEMU and legacy build login prerequisites.
"""
import argparse
from pathlib import Path
import socket
import tempfile

import image_security as guest


def host_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("1.1.1.1", 443))
        return sock.getsockname()[0]


def check_forward(port):
    result = guest.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"])
    if result.returncode or f"127.0.0.1:{port}".encode() not in result.stdout:
        raise RuntimeError("agent-style forward is not listening on loopback")
    if f"*:{port}".encode() in result.stdout:
        raise RuntimeError("forward is exposed on all interfaces")
    with socket.socket() as sock:
        sock.settimeout(2)
        if sock.connect_ex((host_address(), port)) == 0:
            raise RuntimeError("forward is reachable through the host LAN address")


def check_access(port, target_port, restricted):
    # TCP handshake probes: no credentials or application requests are sent.
    # Restricted mode must fail both; unrestricted mode is the positive control.
    for address, destination in [("10.0.2.2", target_port), ("1.1.1.1", 443)]:
        result = guest.ssh(port, f"printf IZANAGI_NETWORK_PROBE; nc -z -w 3 {address} {destination}")
        if b"IZANAGI_NETWORK_PROBE" not in result.stdout or result.returncode not in [0, 1]:
            raise RuntimeError("guest TCP probe did not execute; cannot establish network isolation")
        if (result.returncode == 0) == restricted:
            raise RuntimeError(f"unexpected reachability of {address}, restrict={restricted}")


def check_image(image):
    with tempfile.TemporaryDirectory(prefix="izanagi-network-") as temporary:
        directory = Path(temporary)
        overlay = directory / "overlay.qcow2"
        result = guest.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                            str(image.resolve()), str(overlay)])
        if result.returncode:
            raise RuntimeError("overlay creation failed")
        with socket.socket() as service:
            service.bind(("127.0.0.1", 0))
            service.listen(8)
            destination = service.getsockname()[1]
            for restricted in [True, False]:
                port = guest.available_port()
                process = guest.start(overlay, port, directory / f"serial-{restricted}.log",
                                      restrict=restricted)
                try:
                    guest.wait_ssh(process, port)
                    if guest.ssh(port, "command -v nc").returncode:
                        raise RuntimeError("guest needs netcat for TCP probes")
                    check_forward(port)
                    check_access(port, destination, restricted)
                    print(f"PASS: restrict={restricted}: loopback forward, host and external probes")
                finally:
                    guest.stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    check_image(parser.parse_args().image)


if __name__ == "__main__":
    main()
