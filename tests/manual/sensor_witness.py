#!/usr/bin/env python3
"""Root-only SOCKET_LAYOUT experiment in a disposable Linux VM.

Use an SSH reverse-forwarded host HTTP receiver as --port. No real credentials.
The collector is compiled from sensor_witness_collector.rs; see README.md.
"""
import argparse
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import time


def maps():
    return json.loads(subprocess.check_output(["bpftool", "-j", "map", "show"]))


def update(identity, value):
    return subprocess.run(
        ["bpftool", "map", "update", "id", str(identity), "key", "hex",
         "00", "00", "00", "00", "value", "hex", *value],
        text=True, capture_output=True)


def lookup(identity):
    return json.loads(subprocess.check_output([
        "bpftool", "-j", "map", "lookup", "id", str(identity),
        "key", "hex", "00", "00", "00", "00"]))


def request(client, port, phase):
    # A new child and connection per phase, allowing PID/tuple attribution.
    return json.loads(subprocess.check_output([str(client), str(port), phase]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run only as root in disposable VM"
    directory = args.directory.resolve()
    directory.mkdir(mode=0o700)  # Refuse artifact reuse.
    before = {m["id"] for m in maps()}
    stop = directory / "stop"
    result = {"phases": [], "complete": False}
    identity = None
    original = None
    with (directory / "collector.stderr").open("w") as errors:
        collector = subprocess.Popen([str(args.collector.resolve()), str(args.object.resolve()),
                                      str(directory / "events.jsonl"), str(stop)],
                                     stdout=subprocess.PIPE, stderr=errors, text=True)
        try:
            assert select.select([collector.stdout], [], [], 20)[0], "startup timeout"
            assert collector.stdout.readline().strip() == "READY", "collector startup failed"
            new_maps = [m for m in maps() if m["id"] not in before]
            (directory / "maps.json").write_text(json.dumps(new_maps, indent=2))
            candidates = [m for m in new_maps if m["name"] == "SOCKET_LAYOUT"]
            assert len(candidates) == 1, "layout map must be newly created and unique"
            identity = candidates[0]["id"]
            dump = lookup(identity)
            (directory / "layout-original.json").write_text(json.dumps(dump, indent=2))
            original = dump["value"]
            assert len(original) == 16
            assert struct.unpack("<4I", bytes(int(v, 16) for v in original))[3] == 1
            for phase in ["before", "after-denied-update"]:
                if phase == "after-denied-update":
                    denied = update(identity, original[:12] + ["00"] * 4)
                    result["update"] = {
                        "returncode": denied.returncode,
                        "stderr": denied.stderr.strip(),
                    }
                    assert denied.returncode != 0, "frozen map update unexpectedly succeeded"
                    assert lookup(identity)["value"] == original, "frozen map changed"
                start = time.monotonic_ns()
                record = request(args.client.resolve(), args.port, phase)
                time.sleep(1)
                result["phases"].append(dict(phase=phase, start_ns=start,
                                             end_ns=time.monotonic_ns(), **record))
                assert collector.poll() is None, "collector exited"
            result["complete"] = True
        finally:
            stop.touch()
            try:
                collector.wait(timeout=10)
            except subprocess.TimeoutExpired:
                collector.kill()
                collector.wait()
            result["collector_exit"] = collector.returncode
            events = [json.loads(line) for line in
                      (directory / "events.jsonl").read_text().splitlines()]
            write_ports = {
                event["payload"]["SocketWrite"]["tuple"]["client"].rsplit(":", 1)[-1]
                for event in events if "SocketWrite" in event["payload"]
            }
            result["witnessed_write_ports"] = sorted(write_ports)
            assert all(str(phase["local_port"]) in write_ports
                       for phase in result["phases"]), "socket write evidence missing"
            (directory / "results.json").write_text(json.dumps(result, indent=2))
        assert collector.returncode == 0


if __name__ == "__main__":
    main()
