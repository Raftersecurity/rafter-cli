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
  PORT          listen port (default 8787)
  FAIL_ON       1-based GET index that starts failing (default 2)
  FAIL_STATUS   status code to fail with (default 500; 404 exercises the
                read-after-write-lag branch, 429 the rate-limit branch)
  FAIL_RETRY_AFTER  when set, injected failures carry this literal Retry-After
                header value. sable-96ex: a 429 is retried ONLY when one is
                present, so setting/omitting this is what separates the two
                halves of that contract.
  FAIL_FOREVER  if "1", every GET from FAIL_ON onward fails (persistent case)
  FAIL_COUNT    how many consecutive GETs fail starting at FAIL_ON (default 1;
                ignored when FAIL_FOREVER is set)
  COMPLETE_AFTER  GET index from which status is "completed" (default FAIL_ON,
                i.e. as soon as the injected failures are done). Set it higher
                than the failure window to make the RESULTS fetch fail rather
                than the poll.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("PORT", "8787"))
FAIL_ON = int(os.environ.get("FAIL_ON", "2"))
FAIL_STATUS = int(os.environ.get("FAIL_STATUS", "500"))
FAIL_FOREVER = os.environ.get("FAIL_FOREVER") == "1"
FAIL_COUNT = int(os.environ.get("FAIL_COUNT", "1"))
#: Sent verbatim, so a test can inject a malformed value ("soon", "-1") and
#: check the client refuses to act on it.
FAIL_RETRY_AFTER = os.environ.get("FAIL_RETRY_AFTER")
COMPLETE_AFTER = int(os.environ.get("COMPLETE_AFTER", str(FAIL_ON)))

SCAN_ID = "repro-sable-l10k-0001"

state = {"polls": 0}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, retry_after=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if retry_after is not None:
            self.send_header("Retry-After", retry_after)
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

        failing = (FAIL_FOREVER and n >= FAIL_ON) or (
            FAIL_ON <= n < FAIL_ON + FAIL_COUNT
        )
        if failing:
            # The verbatim customer-facing body.
            if FAIL_STATUS == 429:
                return self._send(
                    FAIL_STATUS,
                    {"error": "Too many requests"},
                    retry_after=FAIL_RETRY_AFTER,
                )
            return self._send(
                FAIL_STATUS,
                {"error": "Failed to fetch report from storage: Object not found"},
            )

        if n < COMPLETE_AFTER:
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
    print(
        f"mock rafter api on :{PORT} ({FAIL_STATUS} on poll #{FAIL_ON}, "
        f"forever={FAIL_FOREVER}, retry-after={FAIL_RETRY_AFTER})",
        flush=True,
    )
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
