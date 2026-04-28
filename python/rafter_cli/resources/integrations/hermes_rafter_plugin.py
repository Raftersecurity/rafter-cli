"""Rafter prompt-shield plugin for Hermes-agent.

Drop this file in `~/.hermes/plugins/` (or copy via `rafter agent init --with-hermes`).
On gateway message dispatch, the plugin shells out to `rafter hook gateway-dispatch`
which scans the inbound text for secrets, persists them to the project's .env,
and returns a rewrite directive. Hermes then dispatches the redacted text to
its agent — the literal credentials never reach the LLM.

Hook semantics (from NousResearch/hermes-agent gateway/run.py:3402-3441):
  - returning {"action": "allow"}            → pass through unchanged
  - returning {"action": "rewrite", "text"}  → replace event.text
  - returning {"action": "skip", "reason"}   → drop the message

Failure modes:
  - rafter not on PATH        → silently allow (this plugin is no-op)
  - rafter call times out     → silently allow (don't break gateway flow)
  - rafter returns junk JSON  → silently allow

Configure via env:
  RAFTER_PROMPT_SHIELD=0           disable entirely
  RAFTER_BIN=/path/to/rafter       override binary lookup
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any


_RAFTER_TIMEOUT_S = 5.0


def _find_rafter() -> str | None:
    override = os.environ.get("RAFTER_BIN")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    return shutil.which("rafter")


def _scan_via_rafter(event_dict: dict[str, Any], cwd: str) -> dict[str, Any] | None:
    """Invoke `rafter hook gateway-dispatch` and return the parsed JSON result.
    Returns None on any failure (caller should treat as 'allow')."""
    rafter = _find_rafter()
    if not rafter:
        return None
    try:
        proc = subprocess.run(
            [rafter, "hook", "gateway-dispatch"],
            input=json.dumps({"event": event_dict, "cwd": cwd}),
            capture_output=True,
            text=True,
            timeout=_RAFTER_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        return None


def _event_to_dict(event) -> dict[str, Any]:
    """Convert a Hermes event dataclass into a plain dict for JSON transport."""
    if hasattr(event, "__dataclass_fields__"):
        import dataclasses
        return dataclasses.asdict(event)
    if isinstance(event, dict):
        return event
    # Best-effort attribute scrape.
    return {k: getattr(event, k) for k in ("text", "channel", "sender_id", "body") if hasattr(event, k)}


def register(ctx) -> None:
    """Hermes plugin entry point. Registers a `pre_gateway_dispatch` hook."""
    if os.environ.get("RAFTER_PROMPT_SHIELD") == "0":
        return  # plugin disabled

    def _pre_gateway_dispatch(event):
        # Skip if the event has no text to scan.
        text = getattr(event, "text", None) if not isinstance(event, dict) else event.get("text")
        if not isinstance(text, str) or not text:
            return None  # treated as allow

        result = _scan_via_rafter(_event_to_dict(event), os.getcwd())
        if result is None:
            return None  # rafter unavailable or failed → allow

        action = result.get("action")
        if action in ("rewrite", "skip"):
            return result
        # action == "allow" or anything else → pass through
        return None

    # Hermes plugins use either ctx.register_hook("pre_gateway_dispatch", fn)
    # or ctx.hook(name)(fn) decorator style. Try the explicit form first.
    if hasattr(ctx, "register_hook"):
        ctx.register_hook("pre_gateway_dispatch", _pre_gateway_dispatch)
    elif hasattr(ctx, "hook"):
        ctx.hook("pre_gateway_dispatch")(_pre_gateway_dispatch)
    # Else: API mismatch — silently no-op rather than crash Hermes startup.
