"""Local stdio protocol fixture; does not import networking or read credentials."""
import json
import os
import sys
import time

mode = sys.argv[1]
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "notifications/initialized":
        continue
    method = request["method"]
    if method == "initialize":
        result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "fixture", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "missing" if mode == "missing_tool" else "jev.choice", "inputSchema": {"type": "object"}}]}
    else:
        arguments = request["params"]["arguments"]
        assert arguments["model"] == "jev-1.13.0"
        assert arguments["profile"] == "reliable"
        assert "IZANAGI_SECRET_FILE" not in os.environ
        assert "IZANAGI_SESSION_TOKEN" not in os.environ
        assert "AWS_SECRET_ACCESS_KEY" not in os.environ
        if mode == "timeout":
            time.sleep(30)
        if mode == "stderr":
            sys.stderr.write("DO_NOT_LOG_CANARY" * 10000)
            sys.stderr.flush()
            time.sleep(30)
        if mode == "oversize":
            print("x" * 70000, flush=True)
            continue
        if mode == "malformed":
            print("not JSON: DO_NOT_LOG_CANARY", flush=True)
            continue
        choice = "unknown" if mode == "unknown" else "normal"
        evaluation = {"model": "jev-moving-alias" if mode == "model_mismatch" else "jev-1.13.0", "answers": {"result": {
            "type": "choice", "choice": choice,
            "probabilities": {name: float(name == choice) for name in ["normal", "access_post_suspected", "unknown"]},
            "confidence": 1.0}}, "usage": {"input_tokens": 17, "output_tokens": 9}}
        if mode == "call_error":
            result = {"isError": True, "structuredContent": {"error": {"kind": "rate_limit", "message": "DO_NOT_LOG_CANARY", "retryable": True, "status": 429}}, "content": [{"type": "text", "text": json.dumps(evaluation)}]}
        elif mode == "text":
            result = {"content": [{"type": "text", "text": json.dumps(evaluation)}]}
        else:
            result = {"structuredContent": evaluation, "content": [{"type": "text", "text": json.dumps(evaluation)}], "isError": False}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
