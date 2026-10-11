#!/usr/bin/env python3
"""Verify read-only and explicitly writable workspace shares on real VM backends.

Only shares a newly created fixture directory. QEMU uses a disposable legacy
image overlay and restricted network; credentials and original projects are not shared.
"""
import argparse
from pathlib import Path
import tempfile

import image_security as guest


ATTEMPTS = ["printf changed > .git/config", "printf changed >> .git/config",
            "truncate -s 0 .git/config", "rm .git/config", "mv .git/config moved",
            "touch .git/hooks/new", "ln .git/config linked", "printf changed > build.rs"]


def fixture(directory):
    (directory / ".git/hooks").mkdir(parents=True, exist_ok=True)
    (directory / ".git/config").write_text("fixture-original")
    (directory / "build.rs").write_text("fixture-build")
    for path in [directory, directory / ".git", directory / ".git/hooks"]:
        path.chmod(0o777)
    for path in [directory / ".git/config", directory / "build.rs"]:
        path.chmod(0o666)


def unchanged(directory):
    if (directory / ".git/config").read_text() != "fixture-original":
        raise RuntimeError("host Git config changed through read-only share")
    if (directory / "build.rs").read_text() != "fixture-build":
        raise RuntimeError("host build script changed through read-only share")


def verify(directory, execute, read_only):
    if execute("cat .git/config").returncode:
        raise RuntimeError("shared fixture is not readable")
    if read_only:
        for attempt in ATTEMPTS:
            if execute(attempt).returncode == 0:
                raise RuntimeError(f"read-only mutation unexpectedly succeeded: {attempt}")
            unchanged(directory)
    else:
        result = execute("printf changed > .git/config")
        if result.returncode:
            raise RuntimeError(f"writable positive control failed: {result.stderr.decode(errors='replace')}")
        if (directory / ".git/config").read_text() != "changed":
            raise RuntimeError("writable change did not reach host fixture")


def check_container(directory):
    for read_only in [True, False]:
        fixture(directory)
        volume = f"{directory}:/workspace" + (":ro" if read_only else "")
        def execute(command):
            return guest.run(["container", "run", "--rm", "--volume", volume,
                              "--workdir", "/workspace", "alpine:3.23", "sh", "-c", command])
        verify(directory, execute, read_only)
        print(f"PASS: Apple Container read_only={read_only}")


def check_qemu(directory, image):
    overlay = directory.parent / "overlay.qcow2"
    created = guest.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                         str(image.resolve()), str(overlay)])
    if created.returncode:
        raise RuntimeError("overlay creation failed")
    for read_only in [True, False]:
        fixture(directory)
        port = guest.available_port()
        mode = "on" if read_only else "off"
        extra = ["-fsdev", f"local,id=fs0,path={directory},security_model=mapped-xattr,readonly={mode}",
                 "-device", "virtio-9p-pci,fsdev=fs0,mount_tag=workspace"]
        process = guest.start(overlay, port, directory.parent / f"serial-{mode}.log", extra_args=extra)
        try:
            guest.wait_ssh(process, port)
            mounted = guest.ssh(port, "mkdir -p /workspace; modprobe 9pnet_virtio; mount -t 9p -o trans=virtio,version=9p2000.L workspace /workspace")
            if mounted.returncode:
                raise RuntimeError(f"9p share mount failed: {mounted.stderr.decode(errors='replace')}")
            verify(directory, lambda command: guest.ssh(port, "cd /workspace && " + command), read_only)
            print(f"PASS: QEMU 9p read_only={read_only}")
        finally:
            guest.stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend", choices=["qemu", "apple-container"])
    parser.add_argument("--image", type=Path)
    args = parser.parse_args()
    if args.backend == "qemu" and args.image is None:
        parser.error("qemu requires --image (legacy build image)")
    with tempfile.TemporaryDirectory(prefix="izanagi-share-") as temporary:
        directory = Path(temporary) / "workspace"
        directory.mkdir()
        if args.backend == "qemu":
            check_qemu(directory, args.image)
        else:
            check_container(directory)


if __name__ == "__main__":
    main()
