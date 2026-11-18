#!/usr/bin/env python3
"""Measure non-root ring-buffer pressure against a disposable collector."""
import argparse
import http.server
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import subprocess
import tempfile
import threading
import time


def drop_privileges():
    account = pwd.getpwnam("nobody")
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


class Handler(http.server.BaseHTTPRequestHandler):
    bodies = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        type(self).bodies.append(self.rfile.read(length).decode())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--witness-client", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--iterations", type=int, default=100_000)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run only as root in disposable VM"
    directory = args.directory.resolve()
    directory.mkdir(mode=0o700)
    events = directory / "events.jsonl"
    stop = directory / "stop"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    with (directory / "collector.stderr").open("w") as errors:
        collector = subprocess.Popen(
            [str(args.collector.resolve()), str(args.object.resolve()), str(events), str(stop)],
            stdout=subprocess.PIPE,
            stderr=errors,
            text=True,
        )
        assert select.select([collector.stdout], [], [], 20)[0], "startup timeout"
        assert collector.stdout.readline().strip() == "READY"
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="izanagi-overflow-") as public:
            os.chmod(public, 0o755)
            client = Path(public) / "client"
            shutil.copy2(args.client.resolve(), client)
            os.chmod(client, 0o755)
            witness_client = Path(public) / "witness-client"
            shutil.copy2(args.witness_client.resolve(), witness_client)
            os.chmod(witness_client, 0o755)
            workers = [
                subprocess.Popen(
                    [str(client), str(args.iterations)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    preexec_fn=drop_privileges,
                )
                for _ in range(args.workers)
            ]
            worker_results = []
            for worker in workers:
                stdout, stderr = worker.communicate(timeout=90)
                worker_results.append(
                    {"pid": worker.pid, "returncode": worker.returncode,
                     "stdout": stdout, "stderr": stderr}
                )
            witness = subprocess.run(
                [str(witness_client), str(server.server_port), "after-overflow"],
                capture_output=True,
                text=True,
                preexec_fn=drop_privileges,
                timeout=10,
            )
        elapsed = time.monotonic() - started
        time.sleep(2)
        stop.touch()
        collector.wait(timeout=10)
    server.shutdown()
    server_thread.join(timeout=10)
    records = [json.loads(line) for line in events.read_text().splitlines()]
    gaps = [record["payload"]["ObservationGap"] for record in records
            if isinstance(record.get("payload"), dict) and "ObservationGap" in record["payload"]]
    results = {
        "workers": worker_results,
        "worker_uid": pwd.getpwnam("nobody").pw_uid,
        "iterations_per_worker": args.iterations,
        "elapsed_seconds": elapsed,
        "collector_exit": collector.returncode,
        "observation_gaps": gaps,
        "dropped_total": sum(gap["dropped"] for gap in gaps),
        "witness": {"returncode": witness.returncode, "stdout": witness.stdout,
                    "stderr": witness.stderr},
        "host_bodies": Handler.bodies,
    }
    (directory / "results.json").write_text(json.dumps(results, indent=2))
    assert all(worker["returncode"] == 0 for worker in worker_results)
    assert collector.returncode == 0
    assert witness.returncode == 0
    assert Handler.bodies == ["izanagi-dummy-136"]


if __name__ == "__main__":
    main()
