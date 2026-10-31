"""Shared ``--wait`` polling logic for `rafter sites create` and
`rafter sites scan`. Mirrors node/src/commands/sites/wait.ts behaviorally.
"""
from __future__ import annotations

import sys
import time
from typing import Callable

from ..utils.api import (
    API_TIMEOUT_SHORT,
    EXIT_GENERAL_ERROR,
    EXIT_SUCCESS,
    api_get,
    resolve_key,
    write_payload,
)
from .sites import describe_sites_error, sites_api_url

# Default `--timeout` for `sites create --wait` / `sites scan --wait`, in seconds.
DEFAULT_WAIT_TIMEOUT_SECONDS = 900

# Exit code when the user interrupts --wait with Ctrl-C: 128 + SIGINT, the
# shell convention, so scripts can tell "stopped waiting" from a failed run.
# The scan itself keeps running on the server. Mirrors EXIT_WAIT_INTERRUPTED
# in node/src/commands/sites/wait.ts.
EXIT_WAIT_INTERRUPTED = 130

# How often to poll the status route while waiting, in seconds.
DEFAULT_POLL_INTERVAL_SECONDS = 10


def parse_wait_timeout(raw: "str | None") -> "tuple[float, str | None]":
    """Parse and validate ``--timeout <seconds>``. Returns (seconds, error_message)."""
    if raw is None:
        return DEFAULT_WAIT_TIMEOUT_SECONDS, None
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        parsed = float("nan")
    if not (parsed == parsed) or parsed <= 0:  # NaN check without importing math
        return DEFAULT_WAIT_TIMEOUT_SECONDS, "Error: --timeout must be a positive number of seconds"
    return parsed, None


def wait_for_site_run(
    site_id: str,
    started_run_id: str,
    api_key: "str | None",
    fmt: str,
    quiet: bool,
    timeout_seconds: float = DEFAULT_WAIT_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> int:
    """Poll ``GET static/sites/:site_id`` every ``poll_interval_seconds`` until
    ``latest_run.status`` is ``"succeeded"`` or ``"failed"``, or until
    ``timeout_seconds`` elapses. Prints the final status payload the same way
    ``rafter sites get`` does (``write_payload``) and returns the exit code:
    ``0`` on succeeded, ``1`` on failed, timeout, or a run-id mismatch.

    ``sleep`` and ``now`` are injected so tests can run this hermetically and
    fast — production call sites use the real ``time.sleep``/``time.monotonic``;
    a test passes a no-op sleep and a fake, test-controlled clock.

    ``started_run_id`` guards against reporting the wrong run's outcome: if
    another scan starts on the same site while we wait (its id will differ
    from ``started_run_id``), we stop and name both ids rather than printing
    that run's status as if it were ours.
    """
    key = resolve_key(api_key)
    deadline = now() + timeout_seconds
    try:
        return _poll(site_id, started_run_id, key, fmt, quiet, timeout_seconds, deadline,
                     poll_interval_seconds, sleep, now)
    except KeyboardInterrupt:
        print(
            f"Stopped waiting for run {started_run_id}; the scan keeps running. "
            f"Check it with 'rafter sites get {site_id}'.",
            file=sys.stderr,
        )
        return EXIT_WAIT_INTERRUPTED


def _poll(site_id, started_run_id, key, fmt, quiet, timeout_seconds, deadline,
          poll_interval_seconds, sleep, now) -> int:
    while True:
        resp = api_get(
            sites_api_url(f"/{site_id}"),
            headers={"x-api-key": key},
            timeout=API_TIMEOUT_SHORT,
        )
        if resp.status_code != 200:
            message, exit_code = describe_sites_error(resp)
            print(f"Error: {message}", file=sys.stderr)
            return exit_code

        data = resp.json()
        latest_run = data.get("latest_run")

        if latest_run and latest_run.get("id") != started_run_id:
            print(
                f"Error: another run ({latest_run.get('id')}) started on site {site_id} "
                f"while waiting for run {started_run_id} to finish — not reporting its "
                f"status. Run 'rafter sites get {site_id}' to see the current state.",
                file=sys.stderr,
            )
            return EXIT_GENERAL_ERROR

        if latest_run and latest_run.get("status") in ("succeeded", "failed"):
            write_payload(data, fmt, quiet)
            return EXIT_SUCCESS if latest_run["status"] == "succeeded" else EXIT_GENERAL_ERROR

        if now() >= deadline:
            print(
                f"Error: timed out after {timeout_seconds:g}s waiting for run {started_run_id} "
                f"on site {site_id} to finish. Resume with 'rafter sites get {site_id}'.",
                file=sys.stderr,
            )
            return EXIT_GENERAL_ERROR

        sleep(poll_interval_seconds)
