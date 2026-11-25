"""
Local Llama service: serves the ExecuTorch Llama program over HTTP on the loopback interface.

On the Raspberry Pi the node runs Llama in-process (advisor/engines.py). On a development host
where the node runs on Windows and ExecuTorch lives in WSL, start this inside WSL instead:

    source ~/chargeguard-et/bin/activate
    python advisor/llama_service.py                # listens on 127.0.0.1:8765

and the node finds it automatically (or set CHARGEGUARD_LLAMA_URL). Standard library only.

    GET  /health    -> {"ok": true, "model": ..., "loaded": bool}
    POST /generate  {"prompt": str, "max_tokens": int} -> {"text": str, "stats": {...}}
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from advisor.engines import LlamaExecuTorchAdvisor  # noqa: E402

ENGINE = LlamaExecuTorchAdvisor()
LOCK = threading.Lock()              # one generation at a time: the CPU is the bottleneck anyway
MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": ENGINE.available(), "model": Path(ENGINE.model).name,
                             "loaded": ENGINE._py_runner is not None})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/generate":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0))
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "bad body size"})
        try:
            req = json.loads(self.rfile.read(n))
            prompt = str(req["prompt"])
            max_tokens = max(1, min(int(req.get("max_tokens", ENGINE.max_tokens)), 512))
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"error": "expected {prompt, max_tokens}"})
        with LOCK:
            ENGINE.max_tokens = max_tokens
            t0 = time.perf_counter()
            try:
                text = ENGINE._generate_python(prompt)
            except Exception as e:  # report, keep serving
                return self._send(500, {"error": f"{type(e).__name__}: {e}"})
            stats = dict(ENGINE.last_stats, wall_ms=round((time.perf_counter() - t0) * 1000, 1))
        self._send(200, {"text": text, "stats": stats})

    def log_message(self, fmt, *args):
        sys.stderr.write("llama-service: " + fmt % args + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--warm", action="store_true", help="load the model before accepting requests")
    a = ap.parse_args()
    if not ENGINE.available():
        sys.exit(f"model not found: {ENGINE.model} / {ENGINE.tokenizer} (run advisor/export_llama.sh)")
    if a.warm:
        ENGINE.max_tokens = 1
        ENGINE._generate_python(ENGINE.chat_prompt("Reply OK.", {"ping": 1}))
        ENGINE.max_tokens = 220
    print(f"llama-service on http://{a.host}:{a.port} ({Path(ENGINE.model).name})", flush=True)
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
