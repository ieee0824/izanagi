"""Finite-lived local process cleanup fixture; no network or real credentials."""
import json
import subprocess
import sys
import time
from pathlib import Path

mode, directory = sys.argv[1:]
directory = Path(directory)
child = None
for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": [{"name": "jev.choice", "inputSchema": {"type": "object"}}]}
    else:
        # Close inherited stdio so cleanup cannot rely on a pipe reaching EOF.
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import sys,time;from pathlib import Path;"
             "p=Path(sys.argv[1]);(p/'ready').write_text('ready');"
             "time.sleep(1);(p/'survived').write_text('survived')",
             str(directory)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        while not (directory / "ready").exists():
            time.sleep(.005)
        if mode in ["timeout", "cancel"]:
            time.sleep(5)
        if mode == "invalid":
            print("invalid JSON", flush=True)
            continue
        result = {"structuredContent": {
            "model": "jev-1.13.0", "answers": {"result": {
                "type": "choice", "choice": "normal",
                "probabilities": {"normal": 1.0, "access_post_suspected": 0.0, "unknown": 0.0},
                "confidence": 1.0}}, "usage": {"input_tokens": 0, "output_tokens": 0}}}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
