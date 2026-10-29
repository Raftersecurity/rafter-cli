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
                read-after-write-lag branch)
  FAIL_FOREVER  if "1", every GET from FAIL_ON onward fails (persistent case)
  FAIL_COUNT    how many consecutive GETs fail starting at FAIL_ON (default 1;
                ignored when FAIL_FOREVER is set)
  COMPLETE_AFTER  GET index from which status is "completed" (default FAIL_ON,
                i.e. as soon as the injected failures are done). Set it higher
                than the failure window to make the RESULTS fetch fail rather
                than the poll.
  RESULTS_SHAPE  what the completed JSON body looks like (sable-fgk7). Default
                "ok": {"status":"completed","vulnerabilities":[]}. Others:
                  with-findings  three findings: one critical, one high, one low
                  missing-key    {"scan_id":..,"status":"completed"} — parses,
                                 has no vulnerabilities array at all
                  not-json       a 200 whose body is an HTML error page
                  error-object   a 200 whose body is {"error": ...}
                Each of the last three used to make the action report
                "No security findings detected" and pass every threshold.
  SHAPE_FROM     GET index from which the JSON body takes RESULTS_SHAPE
                (default COMPLETE_AFTER + 1, so the poll loop sees one healthy
                "completed" and the RESULTS fetch gets the shaped body).
                md/sarif fetches are never shaped.
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
COMPLETE_AFTER = int(os.environ.get("COMPLETE_AFTER", str(FAIL_ON)))
RESULTS_SHAPE = os.environ.get("RESULTS_SHAPE", "ok")
SHAPE_FROM = int(os.environ.get("SHAPE_FROM", str(COMPLETE_AFTER + 1)))

SCAN_ID = "repro-sable-l10k-0001"

# Severities chosen so every count output is pinned to a distinct value:
# findings=3, critical=1, high=1, medium=0, low=1.
WITH_FINDINGS = [
    {"rule_id": "sql-injection", "severity": "critical", "file_path": "db.php", "line_start": 12},
    {"rule_id": "xss-echo", "severity": "high", "file_path": "view.php", "line_start": 40},
    {"rule_id": "weak-hash", "severity": "low", "file_path": "auth.php", "line_start": 7},
]

state = {"polls": 0}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        self._send_raw(code, json.dumps(payload).encode(), "application/json")

    def _send_raw(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_shaped_results(self):
        """The completed JSON body under RESULTS_SHAPE (never for md/sarif)."""
        if RESULTS_SHAPE == "with-findings":
            return self._send(200, {"scan_id": SCAN_ID, "status": "completed",
                                    "vulnerabilities": WITH_FINDINGS})
        if RESULTS_SHAPE == "missing-key":
            return self._send(200, {"scan_id": SCAN_ID, "status": "completed"})
        if RESULTS_SHAPE == "not-json":
            return self._send_raw(200, b"<html><body><h1>502 Bad Gateway</h1></body></html>",
                                  "text/html")
        if RESULTS_SHAPE == "error-object":
            return self._send(200, {"error": "Failed to fetch report from storage: Object not found"})
        raise SystemExit(f"unknown RESULTS_SHAPE {RESULTS_SHAPE!r}")

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
            return self._send(
                FAIL_STATUS,
                {"error": "Failed to fetch report from storage: Object not found"},
            )

        if n < COMPLETE_AFTER:
            return self._send(200, {"scan_id": SCAN_ID, "status": "processing"})

        if fmt == "json" and RESULTS_SHAPE != "ok" and n >= SHAPE_FROM:
            return self._send_shaped_results()

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
