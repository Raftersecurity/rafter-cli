"""Sites commands: create, scan, list, get — live-application security monitoring.

Rafter Sites scans a registered domain for exposed backends, DNS misconfig,
SEO, and accessibility issues. Every route lives under
``https://rafter.so/api/static/sites`` and requires an ``x-api-key`` header.

Mirrors ``node/src/commands/sites/*.ts`` behaviorally (same commands, flags,
error messages, and exit codes) — see that directory plus
``node/src/commands/sites/errors.ts`` for the reference implementation this
was built against.
"""
from __future__ import annotations

import sys
from urllib.parse import quote, urlparse

import requests
import typer

from ..utils.api import (
    API_BASE,
    API_TIMEOUT,
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    resolve_key,
    write_payload,
)

SITES_API_BASE = f"{API_BASE}static/sites"

VALID_SECTIONS = {"flight", "security", "dns"}


def _looks_like_url(value: str) -> bool:
    """True when ``value`` parses as an absolute URL (has a scheme); false → treat as a project id."""
    try:
        parsed = urlparse(value)
        return bool(parsed.scheme and parsed.netloc)
    except ValueError:
        return False


def _error_body_message(resp: "requests.Response") -> str:
    """Extract a human-readable message from a Sites API error response body."""
    try:
        body = resp.json()
    except Exception:
        return resp.text or ""
    if isinstance(body, dict):
        if isinstance(body.get("error"), str) and body["error"]:
            return body["error"]
        if isinstance(body.get("message"), str) and body["message"]:
            return body["message"]
    return resp.text or ""


def describe_sites_error(resp: "requests.Response") -> tuple[str, int]:
    """Map a Sites API error response to a (message, exit_code) pair.

    Unlike the remote-scan API (``handle_403`` in ``utils/api.py``, which infers
    "quota" from a ``scan_mode`` field), the Sites API returns 403 for BOTH wrong
    API-key scope and plan/site limits — the only signal is the free-text
    ``error`` string, so 403 is never assumed to mean quota here. 404 means "not
    found or not owned by this account" — the Sites API deliberately does not
    distinguish the two.
    """
    status = resp.status_code
    msg = _error_body_message(resp)

    if status == 400:
        return f"Bad request — {msg}", EXIT_GENERAL_ERROR
    if status == 401:
        return f"Unauthorized — {msg or 'invalid or missing API key'}", EXIT_GENERAL_ERROR
    if status == 403:
        return f"Forbidden — {msg or 'access denied'}", EXIT_INSUFFICIENT_SCOPE
    if status == 404:
        return f"Not found — {msg or 'site not found, or not owned by this account'}", EXIT_SCAN_NOT_FOUND
    if status == 429:
        return f"Rate limited — {msg or 'too many requests, try again later'}", EXIT_QUOTA_EXHAUSTED
    return msg or "Request failed", EXIT_GENERAL_ERROR


def reject_unsupported_format(fmt: str) -> bool:
    """The Sites API never returns a ``markdown`` field, so ``--format md`` has
    nothing to render. Rather than silently falling back to JSON (which looks
    like success but produces the wrong format), reject up front with a clear
    error. Returns True (and prints the error) when ``fmt`` is unsupported.
    """
    if fmt != "md":
        return False
    print("Error: Sites does not support --format md yet, use --format json", file=sys.stderr)
    return True


def resolve_mcp_api_key() -> "str | None":
    """Resolve the Rafter API key for a context with no CLI flag (an MCP tool
    call). Same precedence as ``resolve_key()`` (env > stored config) minus the
    ``--api-key`` flag, but returns None instead of calling ``sys.exit`` —
    killing the whole MCP server over one tool's missing key would take every
    other tool down with it.
    """
    import os

    env_key = os.environ.get("RAFTER_API_KEY")
    if env_key:
        return env_key
    try:
        from ..core.config_manager import ConfigManager

        stored = ConfigManager().get("backend.api_key")
        if isinstance(stored, str) and stored.strip():
            return stored.strip()
    except Exception:
        pass  # config unreadable — fall through
    return None


sites_app = typer.Typer(
    name="sites",
    help="Manage Rafter Sites — live-application security monitoring",
    no_args_is_help=True,
)


@sites_app.command("create")
def sites_create(
    url: str = typer.Argument(..., help="URL of the site to monitor"),
    api_key: "str | None" = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Register a site for live monitoring and kick off its first scan."""
    if reject_unsupported_format(fmt):
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    key = resolve_key(api_key)
    resp = requests.post(
        SITES_API_BASE,
        headers={"x-api-key": key},
        json={"url": url},
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)
    write_payload(resp.json(), fmt, quiet)


@sites_app.command("scan")
def sites_scan(
    project_id_or_url: str = typer.Argument(..., help="site's project id, or its URL"),
    api_key: "str | None" = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    sections: "str | None" = typer.Option(None, "--sections", help="comma-separated subset of flight,security,dns (default: all)"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Trigger a re-scan of an existing site."""
    if reject_unsupported_format(fmt):
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    body: dict = {"url": project_id_or_url} if _looks_like_url(project_id_or_url) else {"projectId": project_id_or_url}

    if sections:
        section_list = [s.strip() for s in sections.split(",") if s.strip()]
        invalid = [s for s in section_list if s not in VALID_SECTIONS]
        if invalid:
            print(
                f"Error: invalid --sections value(s): {', '.join(invalid)} (expected: flight, security, dns)",
                file=sys.stderr,
            )
            raise typer.Exit(code=EXIT_GENERAL_ERROR)
        body["sections"] = section_list

    key = resolve_key(api_key)
    resp = requests.post(
        f"{SITES_API_BASE}/scan",
        headers={"x-api-key": key},
        json=body,
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)
    write_payload(resp.json(), fmt, quiet)


@sites_app.command("list")
def sites_list(
    api_key: "str | None" = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    limit: "int | None" = typer.Option(None, "--limit", help="results per page, 1-100 (default: 25)"),
    offset: "int | None" = typer.Option(None, "--offset", help="pagination offset (default: 0)"),
    include_archived: bool = typer.Option(False, "--include-archived", help="include archived sites"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """List registered sites."""
    if reject_unsupported_format(fmt):
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    params: dict = {}
    if limit is not None:
        params["limit"] = str(limit)
    if offset is not None:
        params["offset"] = str(offset)
    if include_archived:
        params["include_archived"] = "true"

    key = resolve_key(api_key)
    resp = requests.get(
        SITES_API_BASE,
        headers={"x-api-key": key},
        params=params,
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)
    write_payload(resp.json(), fmt, quiet)


@sites_app.command("get")
def sites_get(
    id: str = typer.Argument(..., help="site's project id"),
    api_key: "str | None" = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Get a site's status, latest run, and findings summary."""
    if reject_unsupported_format(fmt):
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    key = resolve_key(api_key)
    site_id = quote(id, safe="")
    resp = requests.get(
        f"{SITES_API_BASE}/{site_id}",
        headers={"x-api-key": key},
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)
    write_payload(resp.json(), fmt, quiet)
