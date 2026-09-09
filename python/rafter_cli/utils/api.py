"""Backend API utilities extracted from __main__.py."""
from __future__ import annotations

import json
import os
import sys

import requests
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


def _safe_for_terminal(value: "str | None") -> str:
    """Strip non-printable bytes and cap length before echoing untrusted text.

    A redirect target is attacker-controlled if the endpoint is. Header values
    cannot contain CR/LF, but ESC is a legal byte, so an unsanitized Location
    can emit ANSI sequences that rewrite the user's terminal.
    """
    if not isinstance(value, str):
        return ""
    printable = "".join(c for c in value if c.isprintable())
    return printable[:200] + "\u2026" if len(printable) > 200 else printable


def api_url(path: str) -> str:
    """Join API_BASE with a path without producing a double slash.

    Mirrors Node's ``apiUrl()``. This is not cosmetic: API_BASE ends in "/" and
    call sites used to concatenate "/static/...", producing
    ``https://rafter.so/api//static/scan``, which production answers with a 308
    to the single-slash form. That worked only because the client followed the
    redirect — so sable-2s6p's fix would have broken every core command.
    """
    return f"{API_BASE.rstrip('/')}/{path.lstrip('/')}"


def api_request(method: str, url: str, **kwargs) -> "requests.Response":
    """sable-2s6p — the HTTP entry point for every authenticated Rafter API call.

    ``allow_redirects=False`` is the point of it. ``requests`` replays headers on
    a redirect and, unlike ``Authorization``, a custom ``x-api-key`` header is
    NOT stripped when the host changes (``SessionRedirectMixin.rebuild_auth``
    only handles ``Authorization``). Since the API base is user-settable
    (``--rafter-url``, self-hosted installs), a 302 from a misconfigured or
    hostile endpoint would walk the caller's API key to another host.

    Nothing in this CLI needs to follow a redirect, so none of them do. A
    redirect now arrives at the caller as a plain 3xx response, which every
    caller already treats as a non-200 error.

    Use this for anything that sends ``x-api-key``. Plain ``requests`` is fine
    for user-supplied webhooks and other unauthenticated calls.
    """
    kwargs["allow_redirects"] = False
    resp = requests.request(method, url, **kwargs)
    if 300 <= resp.status_code < 400:
        # Otherwise this surfaces as a bare non-200 with an empty body, which
        # tells the user nothing about why.
        target = _safe_for_terminal(resp.headers.get("location")) or "another host"
        print(
            f"The Rafter API redirected to {target}, and Rafter does not follow "
            "redirects on authenticated requests — your API key would be sent to "
            "the redirect target. If you are pointing Rafter at a self-hosted "
            "instance, use its final URL.",
            file=sys.stderr,
        )
    return resp


def api_get(url: str, **kwargs) -> "requests.Response":
    return api_request("GET", url, **kwargs)


def api_post(url: str, **kwargs) -> "requests.Response":
    return api_request("POST", url, **kwargs)


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
