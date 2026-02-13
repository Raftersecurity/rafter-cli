"""Backend commands: run, get, usage — extracted from original __main__.py."""
from __future__ import annotations

import json
import sys
import time

import requests
import typer

from ..utils.api import (
    API_BASE,
    API_TIMEOUT,
    API_TIMEOUT_SHORT,
    EXIT_GENERAL_ERROR,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
    resolve_key,
    write_payload,
)
from ..utils.git import detect_repo


def _handle_scan_status_interactive(
    scan_id: str, headers: dict, fmt: str, quiet: bool
) -> int:
    poll = requests.get(
        f"{API_BASE}/static/scan",
        headers=headers,
        params={"scan_id": scan_id, "format": fmt},
        timeout=API_TIMEOUT_SHORT,
    )

    if poll.status_code == 404:
        print(f"Scan '{scan_id}' not found", file=sys.stderr)
        raise typer.Exit(code=EXIT_SCAN_NOT_FOUND)
    elif poll.status_code != 200:
        print(f"Error: {poll.text}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    data = poll.json()
    status = data.get("status")

    if status in ("queued", "pending", "processing"):
        if not quiet:
            print(
                "Waiting for scan to complete... (this could take several minutes)",
                file=sys.stderr,
            )
        while status in ("queued", "pending", "processing"):
            time.sleep(10)
            poll = requests.get(
                f"{API_BASE}/static/scan",
                headers=headers,
                params={"scan_id": scan_id, "format": fmt},
                timeout=API_TIMEOUT_SHORT,
            )
            data = poll.json()
            status = data.get("status")
            if status == "completed":
                if not quiet:
                    print("Scan completed!", file=sys.stderr)
                return write_payload(data, fmt, quiet)
            elif status == "failed":
                print("Scan failed.", file=sys.stderr)
                raise typer.Exit(code=EXIT_GENERAL_ERROR)
        if not quiet:
            print(f"Scan status: {status}", file=sys.stderr)
    elif status == "completed":
        if not quiet:
            print("Scan completed!", file=sys.stderr)
        return write_payload(data, fmt, quiet)
    elif status == "failed":
        print("Scan failed.", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    else:
        if not quiet:
            print(f"Scan status: {status}", file=sys.stderr)

    return write_payload(data, fmt, quiet)


def register_backend_commands(app: typer.Typer) -> None:
    """Register run/get/usage on the root typer app."""

    @app.command()
    def run(
        repo: str = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
        branch: str = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
        api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
        fmt: str = typer.Option("md", "--format", "-f", help="json | md"),
        skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
        quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
    ):
        """Trigger a security scan."""
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

        _handle_scan_status_interactive(scan_id, headers, fmt, quiet)

    @app.command()
    def get(
        scan_id: str = typer.Argument(...),
        api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
        fmt: str = typer.Option("md", "--format", "-f", help="json | md"),
        interactive: bool = typer.Option(False, "--interactive", help="poll until done"),
        quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
    ):
        """Retrieve scan results."""
        key = resolve_key(api_key)
        headers = {"x-api-key": key}

        if not interactive:
            resp = requests.get(
                f"{API_BASE}/static/scan",
                headers=headers,
                params={"scan_id": scan_id, "format": fmt},
                timeout=API_TIMEOUT,
            )
            if resp.status_code == 404:
                print(f"Scan '{scan_id}' not found", file=sys.stderr)
                raise typer.Exit(code=EXIT_SCAN_NOT_FOUND)
            elif resp.status_code != 200:
                print(f"Error: {resp.text}", file=sys.stderr)
                raise typer.Exit(code=EXIT_GENERAL_ERROR)
            data = resp.json()
            return write_payload(data, fmt, quiet)

        _handle_scan_status_interactive(scan_id, headers, fmt, quiet)

    @app.command()
    def usage(
        api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    ):
        """Check quota and usage."""
        key = resolve_key(api_key)
        headers = {"x-api-key": key}
        resp = requests.get(
            f"{API_BASE}/static/usage", headers=headers, timeout=API_TIMEOUT_SHORT
        )
        if resp.status_code != 200:
            print(f"Error: {resp.text}", file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)
        print(json.dumps(resp.json(), indent=2))
