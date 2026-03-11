"""Backend API utilities extracted from __main__.py."""
from __future__ import annotations

import json
import os
import sys

import typer
from dotenv import load_dotenv

API_BASE = "https://rafter.so/api"

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_SCAN_NOT_FOUND = 2
EXIT_QUOTA_EXHAUSTED = 3
EXIT_INSUFFICIENT_SCOPE = 4


def handle_scope_error(resp: "requests.Response") -> bool:
    """Detect a 403 scope-enforcement error and print a helpful message.

    Returns True if it was a scope error (caller should exit), False otherwise.
    Imports requests lazily to avoid circular imports.
    """
    if resp.status_code != 403:
        return False
    body = resp.text
    if "scope" in body:
        print(
            'Error: This API key only has read access.\n'
            'To trigger scans, create a key with "Read & Scan" scope at https://rfrr.co/account',
            file=sys.stderr,
        )
    else:
        print(f"Error: Forbidden (403) — {body or 'access denied'}", file=sys.stderr)
    return True

# Network timeouts (connect, read) in seconds
API_TIMEOUT = (10, 300)
API_TIMEOUT_SHORT = (10, 30)


def resolve_key(cli_opt: str | None) -> str:
    """Resolve API key from CLI option, env var, or error."""
    if cli_opt:
        return cli_opt
    load_dotenv()
    env_key = os.getenv("RAFTER_API_KEY")
    if env_key:
        return env_key
    print("No API key provided. Use --api-key or set RAFTER_API_KEY", file=sys.stderr)
    raise typer.Exit(code=EXIT_GENERAL_ERROR)


def write_payload(data: dict, fmt: str = "json", quiet: bool = False) -> int:
    """Write payload to stdout following UNIX principles."""
    if fmt == "md":
        payload = data.get("markdown", "")
    else:
        payload = json.dumps(data, indent=2 if not quiet else None)
    sys.stdout.write(payload)
    return EXIT_SUCCESS
