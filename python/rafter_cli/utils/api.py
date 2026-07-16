"""Backend API utilities extracted from __main__.py."""
from __future__ import annotations

import json
import os
import sys

import typer
from dotenv import load_dotenv

API_BASE = "https://rafter.so/api/"

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_SCAN_NOT_FOUND = 2
EXIT_QUOTA_EXHAUSTED = 3
EXIT_INSUFFICIENT_SCOPE = 4
# sable-9ddf — a paid Plus scan was refused because approval is required and no
# explicit confirmation (--yes / RAFTER_CONFIRM=1 / interactive yes) was given.
EXIT_CONFIRMATION_REQUIRED = 5


def handle_403(resp: "requests.Response") -> int:
    """Detect a 403 error and print a helpful message.

    Returns the appropriate exit code, or -1 if not a 403.
    """
    if resp.status_code != 403:
        return -1
    try:
        body = resp.json()
    except Exception:
        body = None
    if isinstance(body, dict) and "scan_mode" in body:
        mode = body["scan_mode"]
        limit = body.get("limit", "?")
        used = body.get("used", limit)
        print(
            f"Error: {mode.capitalize()} scan limit reached ({used}/{limit} used this billing period).\n"
            f"Upgrade your plan or wait for your quota to reset.",
            file=sys.stderr,
        )
        return EXIT_QUOTA_EXHAUSTED
    if "scope" in resp.text:
        print(
            'Error: This API key only has read access.\n'
            'To trigger scans, create a key with "Read & Scan" scope at https://rfrr.co/account',
            file=sys.stderr,
        )
    else:
        print(f"Error: Forbidden (403) — {resp.text or 'access denied'}", file=sys.stderr)
    return EXIT_INSUFFICIENT_SCOPE


def handle_scope_error(resp: "requests.Response") -> bool:
    """Deprecated: use handle_403 instead."""
    return handle_403(resp) >= 0

# Network timeouts (connect, read) in seconds
API_TIMEOUT = (10, 300)
API_TIMEOUT_SHORT = (10, 30)


def resolve_key(cli_opt: str | None) -> str:
    """Resolve API key: --api-key flag > RAFTER_API_KEY env > global config."""
    if cli_opt:
        return cli_opt
    load_dotenv()
    env_key = os.getenv("RAFTER_API_KEY")
    if env_key:
        return env_key
    # Lowest precedence: a key persisted in the GLOBAL ~/.rafter/config.json via
    # `rafter agent config set backend.apiKey`. Read through load() (global only)
    # — load_with_policy() never merges backend.*, so a project-local .rafter.yml
    # can NOT inject a key that would redirect scans to another account.
    try:
        from ..core.config_manager import ConfigManager

        # Python config serializes the dataclass field as snake_case
        # (backend.api_key); Node uses backend.apiKey. Same value, per-language key.
        stored = ConfigManager().get("backend.api_key")
        if isinstance(stored, str) and stored.strip():
            return stored.strip()
    except Exception:
        pass  # config unreadable — fall through to the error below
    print(
        "No API key provided. Use --api-key, set RAFTER_API_KEY, or run "
        "'rafter agent config set backend.apiKey <key>'",
        file=sys.stderr,
    )
    raise typer.Exit(code=EXIT_GENERAL_ERROR)


def write_payload(data: dict, fmt: str = "json", quiet: bool = False) -> int:
    """Write payload to stdout following UNIX principles."""
    if fmt == "md":
        payload = data.get("markdown", "")
    else:
        payload = json.dumps(data, indent=2 if not quiet else None)
    sys.stdout.write(payload)
    return EXIT_SUCCESS
