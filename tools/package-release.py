#!/usr/bin/env python3
"""Package already-built native binaries without modifying the build tree."""

import argparse
import hashlib
import pathlib
import re
import tarfile


TARGETS = {
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
}


def release_files(root, target, ebpf_object):
    files = {"README.md": root / "README.md"}
    for binary, package in (
        ("izanagi", root),
        ("izanagi-dns-proxy", root / "izanagi-dns-proxy"),
        ("izanagi-http-capture", root / "izanagi-http-capture"),
    ):
        files[f"bin/{binary}"] = package / "target" / target / "release" / binary
    if "linux" in target:
        if ebpf_object is None:
            raise ValueError("Linux packages require --ebpf-object")
        files["guest/izanagi-agent"] = (
            root / "izanagi-agent" / "target" / target / "release" / "izanagi-agent"
        )
        files["share/izanagi/izanagi-ebpf.o"] = ebpf_object
    for source in files.values():
        if not source.is_file():
            raise ValueError(f"Missing release input: {source}")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("dist"))
    parser.add_argument("--ebpf-object", type=pathlib.Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", args.version):
        parser.error("version must be MAJOR.MINOR.PATCH with an optional prerelease suffix")
    files = release_files(args.root, args.target, args.ebpf_object)
    name = f"izanagi-v{args.version}-{args.target}"
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for destination, source in sorted(files.items()):
            info = tar.gettarinfo(str(source), arcname=f"{name}/{destination}")
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if destination.startswith(("bin/", "guest/")) else 0o644
            with source.open("rb") as stream:
                tar.addfile(info, stream)
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    archive.with_suffix(".gz.sha256").write_text(f"{digest.hexdigest()}  {archive.name}\n")
    print(archive)


if __name__ == "__main__":
    main()
