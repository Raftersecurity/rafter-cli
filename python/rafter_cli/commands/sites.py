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

import re
import sys
from urllib.parse import quote, urlparse

import requests
import typer

from ..utils.api import (
    api_get,
    api_post,
    api_url,
    API_TIMEOUT,
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    resolve_key,
    write_payload,
)

def sites_api_url(suffix: str = "") -> str:
    """Sites endpoint, built per call so RAFTER_API_URL is honored."""
    return api_url(f"static/sites{suffix}")

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


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def strip_control_chars_for_display(value: str) -> str:
    """Strip ASCII/Latin-1 control characters before printing to a terminal,
    keeping ``\\n`` and ``\\t``.

    A Sites report's titles, descriptions and recommendations come from
    scanning a third-party site and could carry terminal escape sequences
    (e.g. an OSC/CSI sequence that rewrites the prompt or hides later
    output) — same hazard as ``_safe_for_terminal`` in ``utils/api.py``, but
    preserving layout instead of flattening to one line. JSON output never
    goes through this: JSON's own escaping already neutralizes control
    characters, and stripping there would corrupt byte-faithful output.
    """
    return _CONTROL_CHARS_RE.sub("", value)


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
    wait: bool = typer.Option(False, "--wait", help="poll until the triggered run finishes (succeeded or failed)"),
    timeout: "str | None" = typer.Option(None, "--timeout", help="max seconds to wait with --wait (default: 900)"),
):
    """Register a site for live monitoring and kick off its first scan."""
    if reject_unsupported_format(fmt):
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    from .sites_wait import parse_wait_timeout, wait_for_site_run

    timeout_seconds = None
    if wait:
        timeout_seconds, timeout_error = parse_wait_timeout(timeout)
        if timeout_error:
            print(timeout_error, file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)

    key = resolve_key(api_key)
    resp = api_post(
        sites_api_url(),
        headers={"x-api-key": key},
        json={"url": url},
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)

    data = resp.json()
    if not wait:
        write_payload(data, fmt, quiet)
        return

    run = data.get("run") or {}
    run_id = run.get("id")
    if not run_id:
        # No run was started — the site already existed, or the first scan
        # failed to kick off (`scan_error`). Either way there is nothing to
        # poll; report the create result as-is.
        print("Error: no run was started; nothing to wait for.", file=sys.stderr)
        write_payload(data, fmt, quiet)
        return

    site_id = (data.get("site") or {}).get("id")
    exit_code = wait_for_site_run(site_id, run_id, api_key, fmt, quiet, timeout_seconds=timeout_seconds)
    raise typer.Exit(code=exit_code)


@sites_app.command("scan")
def sites_scan(
    project_id_or_url: str = typer.Argument(..., help="site's project id, or its URL"),
    api_key: "str | None" = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    sections: "str | None" = typer.Option(None, "--sections", help="comma-separated subset of flight,security,dns (default: all)"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
    wait: bool = typer.Option(False, "--wait", help="poll until the triggered run finishes (succeeded or failed)"),
    timeout: "str | None" = typer.Option(None, "--timeout", help="max seconds to wait with --wait (default: 900)"),
):
    """Trigger a re-scan of an existing site."""
    if reject_unsupported_format(fmt):
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    from .sites_wait import parse_wait_timeout, wait_for_site_run

    timeout_seconds = None
    if wait:
        timeout_seconds, timeout_error = parse_wait_timeout(timeout)
        if timeout_error:
            print(timeout_error, file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)

    is_url = _looks_like_url(project_id_or_url)
    body: dict = {"url": project_id_or_url} if is_url else {"projectId": project_id_or_url}

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
    resp = api_post(
        sites_api_url("/scan"),
        headers={"x-api-key": key},
        json=body,
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)

    data = resp.json()
    if not wait:
        write_payload(data, fmt, quiet)
        return

    run = data.get("run") or {}
    run_id = run.get("id")
    if not run_id:
        print("Error: no run was started; nothing to wait for.", file=sys.stderr)
        write_payload(data, fmt, quiet)
        return

    # The scan response carries only `run`, not the site itself. Prefer a
    # site id the response names explicitly; fall back to the argument only
    # when it was already a project id (not a URL we'd have no site id for).
    site_id = run.get("siteId") or run.get("projectId") or (project_id_or_url if not is_url else None)
    if not site_id:
        print(
            "Error: cannot determine the site id to wait on (the scan response named none, "
            "and a URL was given instead of a project id). Use 'rafter sites list' to find it, "
            f"then 'rafter sites get <id>' to check run {run_id}.",
            file=sys.stderr,
        )
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    exit_code = wait_for_site_run(site_id, run_id, api_key, fmt, quiet, timeout_seconds=timeout_seconds)
    raise typer.Exit(code=exit_code)


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
    resp = api_get(
        sites_api_url(),
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
    resp = api_get(
        sites_api_url(f"/{site_id}"),
        headers={"x-api-key": key},
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)
    write_payload(resp.json(), fmt, quiet)


@sites_app.command("report")
def sites_report(
    id: str = typer.Argument(..., help="site's project id"),
    api_key: "str | None" = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Get a site's full security report (JSON or Markdown).

    Unlike create/scan/list/get, --format md is valid here — the report
    route actually renders one — so this does NOT call reject_unsupported_format.
    """
    resolved_fmt = "md" if fmt == "md" else "json"
    key = resolve_key(api_key)
    site_id = quote(id, safe="")
    resp = api_get(
        sites_api_url(f"/{site_id}/report"),
        headers={"x-api-key": key},
        params={"format": resolved_fmt},
        timeout=API_TIMEOUT,
    )
    if resp.status_code != 200:
        message, exit_code = describe_sites_error(resp)
        print(f"Error: {message}", file=sys.stderr)
        raise typer.Exit(code=exit_code)
    if resolved_fmt == "md":
        # The report's content comes from scanning a third-party site and is
        # not trusted terminal input — strip control chars before printing.
        sys.stdout.write(strip_control_chars_for_display(resp.text))
        return
    write_payload(resp.json(), fmt, quiet)
