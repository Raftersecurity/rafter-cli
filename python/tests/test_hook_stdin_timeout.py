"""Regression: the hook stdin read must be bounded so a never-closing stdin
(a harness that wires up a pipe but never writes/closes it) can't wedge the
hook. Python uses a daemon reader thread joined with a timeout, so the process
can exit even if stdin never EOFs. Parity with the Node hook's
RAFTER_HOOK_STDIN_TIMEOUT_MS override.
"""
from __future__ import annotations

import sys
import time

from rafter_cli.commands import hook as hookmod


def test_stdin_timeout_env_override(monkeypatch):
    monkeypatch.setenv("RAFTER_HOOK_STDIN_TIMEOUT_MS", "250")
    assert hookmod._stdin_timeout_s() == 0.25

    # Unset → default.
    monkeypatch.delenv("RAFTER_HOOK_STDIN_TIMEOUT_MS", raising=False)
    assert hookmod._stdin_timeout_s() == hookmod._STDIN_TIMEOUT_S

    # Garbage / non-positive → default (fail safe, never 0/negative).
    monkeypatch.setenv("RAFTER_HOOK_STDIN_TIMEOUT_MS", "not-a-number")
    assert hookmod._stdin_timeout_s() == hookmod._STDIN_TIMEOUT_S
    monkeypatch.setenv("RAFTER_HOOK_STDIN_TIMEOUT_MS", "0")
    assert hookmod._stdin_timeout_s() == hookmod._STDIN_TIMEOUT_S
    monkeypatch.setenv("RAFTER_HOOK_STDIN_TIMEOUT_MS", "-100")
    assert hookmod._stdin_timeout_s() == hookmod._STDIN_TIMEOUT_S

    # Non-finite must NOT pass — float("inf") would make join(timeout=inf) hang
    # forever, reintroducing the exact bug. Parity with Node's Number.isFinite.
    for bad in ("inf", "Infinity", "-inf", "nan"):
        monkeypatch.setenv("RAFTER_HOOK_STDIN_TIMEOUT_MS", bad)
        assert hookmod._stdin_timeout_s() == hookmod._STDIN_TIMEOUT_S, bad


def test_read_stdin_returns_promptly_when_stdin_never_eofs(monkeypatch):
    class BlockingStdin:
        """A stdin whose read() blocks forever — i.e. an open pipe with no EOF."""

        def read(self) -> str:
            time.sleep(60)
            return "should-never-be-returned"

    monkeypatch.setenv("RAFTER_HOOK_STDIN_TIMEOUT_MS", "200")
    monkeypatch.setattr(sys, "stdin", BlockingStdin())

    start = time.monotonic()
    out = hookmod._read_stdin()
    elapsed = time.monotonic() - start

    assert out == ""  # bailed on the bound, did not wait for the blocked read
    assert elapsed < 2.0, f"read_stdin took {elapsed:.2f}s — not bounded"
