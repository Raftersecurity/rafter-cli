"""Top-level scan command group: rafter scan [local|remote]."""
from __future__ import annotations

import sys
import time

import requests
import typer

from .agent import _run_local_scan
from ..utils.api import (
    API_BASE,
    API_TIMEOUT,
    API_TIMEOUT_SHORT,
    EXIT_GENERAL_ERROR,
    EXIT_QUOTA_EXHAUSTED,
    resolve_key,
    write_payload,
)
from ..utils.git import detect_repo

scan_app = typer.Typer(
    name="scan",
    help="Security scanning (local and remote)",
    invoke_without_command=True,
)


def _run_remote_scan(
    repo: str | None,
    branch: str | None,
    api_key: str | None,
    fmt: str,
    skip_interactive: bool,
    quiet: bool,
) -> None:
    """Shared remote scan logic used by default action and `scan remote`."""
    key = resolve_key(api_key)
    try:
        repo_slug, branch_name = detect_repo(repo, branch)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    if not (repo and branch) and not quiet:
        print(f"Repo auto-detected: {repo_slug} @ {branch_name} (note: scanning remote)", file=sys.stderr)

    headers = {"x-api-key": key, "Content-Type": "application/json"}

    resp = requests.post(
        f"{API_BASE}/static/scan",
        headers=headers,
        json={"repository_name": repo_slug, "branch_name": branch_name},
        timeout=API_TIMEOUT,
    )

    if resp.status_code == 429:
        print("Quota exhausted", file=sys.stderr)
        raise typer.Exit(code=EXIT_QUOTA_EXHAUSTED)
    elif resp.status_code != 200:
        print(f"Error: {resp.text}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    scan_id = resp.json()["scan_id"]
    if not quiet:
        print(f"Scan ID: {scan_id}", file=sys.stderr)

    if skip_interactive:
        return

    # Poll until done
    while True:
        poll = requests.get(
            f"{API_BASE}/static/scan",
            headers={"x-api-key": key},
            params={"scan_id": scan_id, "format": fmt},
            timeout=API_TIMEOUT_SHORT,
        )
        if poll.status_code != 200:
            print(f"Error: {poll.text}", file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)

        data = poll.json()
        status = data.get("status")

        if status == "completed":
            if not quiet:
                print("Scan completed!", file=sys.stderr)
            write_payload(data, fmt, quiet)
            return
        elif status == "failed":
            print("Scan failed.", file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)
        elif status in ("queued", "pending", "processing"):
            if not quiet:
                print("Waiting for scan to complete...", file=sys.stderr)
            time.sleep(10)
        else:
            if not quiet:
                print(f"Scan status: {status}", file=sys.stderr)
            write_payload(data, fmt, quiet)
            return


@scan_app.callback(invoke_without_command=True)
def scan_default(
    ctx: typer.Context,
    repo: str = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: str = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("md", "--format", "-f", help="json | md"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Trigger a remote security scan (default when no subcommand given)."""
    if ctx.invoked_subcommand is not None:
        return
    _run_remote_scan(repo, branch, api_key, fmt, skip_interactive, quiet)


@scan_app.command("local")
def scan_local(
    path: str = typer.Argument(".", help="File or directory to scan"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only output if secrets found"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    format: str = typer.Option("text", "--format", help="Output format: text, json, sarif"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files"),
    diff: str = typer.Option(None, "--diff", help="Scan files changed since a git ref"),
    engine: str = typer.Option("auto", "--engine", help="gitleaks or patterns"),
    baseline: bool = typer.Option(False, "--baseline", help="Filter findings present in the saved baseline"),
    watch: bool = typer.Option(False, "--watch", help="Watch for file changes and re-scan on change"),
):
    """Scan local files for secrets."""
    _run_local_scan(path, quiet, json_output, format, staged, diff, engine, baseline, watch)


@scan_app.command("remote")
def scan_remote(
    repo: str = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: str = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt: str = typer.Option("md", "--format", "-f", help="json | md"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Trigger a remote backend security scan."""
    _run_remote_scan(repo, branch, api_key, fmt, skip_interactive, quiet)
