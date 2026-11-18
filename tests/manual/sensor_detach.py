#!/usr/bin/env python3
"""Detach only links created by a disposable collector and compare file telemetry."""
import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import time


def bpftool(kind):
    return json.loads(subprocess.check_output(["bpftool", "-j", kind, "show"]))


def operation():
    result = subprocess.run(
        ["/bin/sh", "-c", "printf '%s\\n' $$; exec /bin/cat /etc/hostname"],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = result.stdout.splitlines()
    return {"pid": int(lines[0]), "output": lines[1:]}


def start_collector(binary, object_path, events, stop, errors):
    process = subprocess.Popen(
        [str(binary), str(object_path), str(events), str(stop)],
        stdout=subprocess.PIPE,
        stderr=errors,
        text=True,
    )
    assert select.select([process.stdout], [], [], 20)[0], "collector startup timeout"
    assert process.stdout.readline().strip() == "READY", "collector startup failed"
    return process


def stop_collector(process, stop):
    stop.touch()
    process.wait(timeout=10)
    assert process.returncode == 0, "collector exit"


def count_pid_events(path, pid):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    return sum((record.get("process") or {}).get("tgid") == pid for record in records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run only as root in disposable VM"
    directory = args.directory.resolve()
    directory.mkdir(mode=0o700)
    before_links = {link["id"] for link in bpftool("link")}
    results = {"complete": False}
    with (directory / "collector-first.stderr").open("w") as errors:
        stop = directory / "stop-first"
        events = directory / "events-first.jsonl"
        collector = start_collector(args.collector.resolve(), args.object.resolve(), events, stop, errors)
        try:
            new_links = [link for link in bpftool("link") if link["id"] not in before_links]
            assert new_links, "collector created no discoverable links"
            (directory / "links.json").write_text(json.dumps(new_links, indent=2))
            results["before"] = operation()
            attempts = []
            for link in new_links:
                detached = subprocess.run(
                    ["bpftool", "link", "detach", "id", str(link["id"])],
                    capture_output=True,
                    text=True,
                )
                attempts.append(
                    {
                        "id": link["id"],
                        "type": link["type"],
                        "returncode": detached.returncode,
                        "stderr": detached.stderr.strip(),
                    }
                )
            results["detach_attempts"] = attempts
            if all(attempt["returncode"] == 0 for attempt in attempts):
                results["during"] = operation()
                time.sleep(1)
                results["collector_alive_after_detach"] = collector.poll() is None
        finally:
            stop_collector(collector, stop)
    with (directory / "collector-reloaded.stderr").open("w") as errors:
        stop = directory / "stop-reloaded"
        events_reloaded = directory / "events-reloaded.jsonl"
        collector = start_collector(
            args.collector.resolve(), args.object.resolve(), events_reloaded, stop, errors
        )
        results["reloaded"] = operation()
        time.sleep(1)
        stop_collector(collector, stop)
    results["before_events"] = count_pid_events(events, results["before"]["pid"])
    if "during" in results:
        results["during_events"] = count_pid_events(events, results["during"]["pid"])
    results["reloaded_events"] = count_pid_events(events_reloaded, results["reloaded"]["pid"])
    results["complete"] = True
    (directory / "results.json").write_text(json.dumps(results, indent=2))
    assert results["before_events"] > 0
    assert results["reloaded_events"] > 0
    if "during" in results:
        assert results["collector_alive_after_detach"]
        assert results["during_events"] == 0


if __name__ == "__main__":
    main()
