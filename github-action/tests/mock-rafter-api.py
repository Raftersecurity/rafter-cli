#!/usr/bin/env python3
"""Minimal stand-in for the Rafter backend, used to reproduce sable-l10k.

Serves the two endpoints the GitHub Action talks to and injects exactly one
transient 500 into the poll sequence:

  POST /api/static/scan            -> 200 {"scan_id": ...}
  GET  /api/static/scan?scan_id=.. -> poll 1: 200 {"status": "processing"}
                                      poll 2: 500 {"error": "Failed to fetch
                                                report from storage: Object not found"}
                                      poll 3: 200 {"status": "completed", ...}

A backend that is eventually consistent about report objects looks exactly like
this from the client's side. The question the repro answers is whether the
action survives it.

Env:
  PORT        listen port (default 8787)
  FAIL_ON     1-based poll index that returns the 500 (default 2)
  FAIL_FOREVER  if "1", every poll from FAIL_ON onward 500s (persistent case)
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("PORT", "8787"))
FAIL_ON = int(os.environ.get("FAIL_ON", "2"))
FAIL_FOREVER = os.environ.get("FAIL_FOREVER") == "1"

SCAN_ID = "repro-sable-l10k-0001"

state = {"polls": 0}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/api/static/scan":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(200, {"scan_id": SCAN_ID})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/static/scan":
            return self._send(404, {"error": "not found"})

        qs = parse_qs(parsed.query)
        fmt = (qs.get("format") or ["json"])[0]

        state["polls"] += 1
        n = state["polls"]

        if n == FAIL_ON or (FAIL_FOREVER and n >= FAIL_ON):
            # The verbatim customer-facing body.
            return self._send(
                500, {"error": "Failed to fetch report from storage: Object not found"}
            )

        if n < FAIL_ON:
            return self._send(200, {"scan_id": SCAN_ID, "status": "processing"})

        completed = {"scan_id": SCAN_ID, "status": "completed", "vulnerabilities": []}
        if fmt == "md":
            completed["markdown"] = "# Rafter\n\nNo findings.\n"
        elif fmt == "sarif":
            completed = {"version": "2.1.0", "runs": []}
        return self._send(200, completed)

    def log_message(self, fmt, *args):
        # Keep the runner log readable: one line per request, to stderr.
        super().log_message(fmt, *args)


if __name__ == "__main__":
    print(f"mock rafter api on :{PORT} (500 on poll #{FAIL_ON}, forever={FAIL_FOREVER})", flush=True)
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
