#!/usr/bin/env python3
"""Delete a live process-generation entry and measure attribution loss."""
import argparse
import json
import http.server
import os
from pathlib import Path
import select
import subprocess
import threading
import time


def maps():
    return json.loads(subprocess.check_output(["bpftool", "-j", "map", "show"]))


class Handler(http.server.BaseHTTPRequestHandler):
    requests = 0
    bodies = []
    def do_POST(self):
        type(self).requests += 1
        length = int(self.headers.get("Content-Length", "0"))
        type(self).bodies.append(self.rfile.read(length).decode())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *_):
        pass


def client_run(binary, port, credential, map_id=None):
    process = subprocess.Popen(
        [str(binary), str(port), str(credential)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True
    )
    assert select.select([process.stdout], [], [], 10)[0], "client startup timeout"
    pid = int(process.stdout.readline())
    deletion = None
    if map_id is not None:
        key = [f"{byte:02x}" for byte in pid.to_bytes(4, "little")]
        deleted = subprocess.run(
            ["bpftool", "map", "delete", "id", str(map_id), "key", "hex", *key],
            capture_output=True,
            text=True,
        )
        deletion = {"returncode": deleted.returncode, "stderr": deleted.stderr.strip(), "key": key}
        assert deleted.returncode == 0, deletion
    stdout, stderr = process.communicate("go\n", timeout=10)
    return {"pid": pid, "returncode": process.returncode, "stdout": stdout,
            "stderr": stderr, "deletion": deletion}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run only as root in disposable VM"
    directory = args.directory.resolve()
    directory.mkdir(mode=0o700)
    credential = directory / "dummy-credential"
    credential.write_text("izanagi-dummy-136")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    before = {item["id"] for item in maps()}
    events = directory / "events.jsonl"
    stop = directory / "stop"
    with (directory / "collector.stderr").open("w") as errors:
        collector = subprocess.Popen(
            [str(args.collector.resolve()), str(args.object.resolve()), str(events), str(stop)],
            stdout=subprocess.PIPE, stderr=errors, text=True,
        )
        assert select.select([collector.stdout], [], [], 20)[0], "collector startup timeout"
        assert collector.stdout.readline().strip() == "READY"
        generation = [item for item in maps()
                      if item["id"] not in before and item["name"] == "PROCESS_GENERAT"]
        assert len(generation) == 1
        baseline = client_run(args.client.resolve(), server.server_port, credential)
        tampered = client_run(
            args.client.resolve(), server.server_port, credential, generation[0]["id"]
        )
        time.sleep(1)
        stop.touch()
        collector.wait(timeout=10)
    server.shutdown()
    server_thread.join(timeout=10)
    records = [json.loads(line) for line in events.read_text().splitlines()]
    def summary(pid):
        selected = [record for record in records if record.get("tid") == pid]
        network = [record for record in selected if isinstance(record.get("payload"), dict)
                   and any(kind in record["payload"] for kind in ("SocketConnect", "SocketWrite"))]
        return {
            "events": len(selected),
            "attributed": sum(record.get("process") is not None for record in selected),
            "missing_identity": sum("missing_process_identity" in record["quality"]["issues"]
                                    for record in selected),
            "network_events": len(network),
            "network_unattributed": sum(record.get("process") is None for record in network),
        }
    results = {"complete": True, "baseline": baseline, "tampered": tampered,
               "baseline_summary": summary(baseline["pid"]),
               "tampered_summary": summary(tampered["pid"]),
               "collector_exit": collector.returncode, "host_requests": Handler.requests,
               "host_bodies": Handler.bodies}
    (directory / "results.json").write_text(json.dumps(results, indent=2))
    assert baseline["returncode"] == tampered["returncode"] == collector.returncode == 0
    assert results["baseline_summary"]["attributed"] > 0
    assert results["tampered_summary"]["missing_identity"] > 0
    assert results["tampered_summary"]["network_unattributed"] > 0
    assert Handler.requests == 2
    assert Handler.bodies == ["izanagi-dummy-136", "izanagi-dummy-136"]


if __name__ == "__main__":
    main()
