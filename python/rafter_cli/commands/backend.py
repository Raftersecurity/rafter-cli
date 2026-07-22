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
    EXIT_CONFIRMATION_REQUIRED,
    EXIT_GENERAL_ERROR,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
    handle_403,
    resolve_key,
    write_payload,
)
from ..utils.git import detect_repo


def _plus_approval_gate_enabled() -> bool:
    """sable-9ddf — is the Plus-scan approval gate enabled?

    OR semantics across the machine-owner's global config and the project's
    ``.rafter.yml``: if EITHER opts in, approval is required. A project policy
    can turn the gate ON but can NEVER turn it OFF — a hostile repo must not be
    able to silently re-open the credit-burn hole a user closed globally.

    Fails open (returns False) if config/policy can't be read, consistent with
    the OFF-by-default product behavior and the codebase's config-load fallback.
    """
    from ..core.config_manager import ConfigManager
    from ..core.policy_loader import load_policy

    global_flag = False
    try:
        global_flag = ConfigManager().load().agent.scan.plus_requires_approval is True
    except Exception:
        pass  # fail open
    policy_flag = False
    try:
        policy = load_policy()
        policy_flag = bool(policy and policy.get("scan", {}).get("plus_requires_approval") is True)
    except Exception:
        pass  # fail open
    return global_flag or policy_flag


def _confirm_plus_scan(mode: str, yes: bool) -> None:
    """Gate a paid Plus scan behind explicit confirmation when the switch is on.

    Returns normally if the scan may proceed; raises ``typer.Exit`` otherwise.
    No-op for non-plus modes and when the gate is disabled (the default).
    """
    import os as _os

    if (mode or "fast") != "plus":
        return
    if not _plus_approval_gate_enabled():
        return

    env_confirm = _os.environ.get("RAFTER_CONFIRM")
    if yes or env_confirm in ("1", "true"):
        return

    if sys.stdin.isatty():
        answer = input(
            "  Plus is a PAID scan tier and will consume your credits. Proceed? [y/N] "
        ).strip().lower()
        if answer in ("y", "yes"):
            return
        print("Plus scan cancelled.", file=sys.stderr)
        raise typer.Exit(code=EXIT_CONFIRMATION_REQUIRED)

    print(
        "Refusing to run a paid Plus scan: approval is required "
        "(scan.plus_requires_approval is enabled).\n"
        "Re-run with --yes (or set RAFTER_CONFIRM=1) to confirm the credit spend, "
        "or use the free --mode fast scan.",
        file=sys.stderr,
    )
    raise typer.Exit(code=EXIT_CONFIRMATION_REQUIRED)


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


def _do_remote_scan(
    repo: "str | None",
    branch: "str | None",
    api_key: "str | None",
    fmt: str,
    skip_interactive: bool,
    quiet: bool,
    mode: str = "fast",
    github_token: "str | None" = None,
    provider: "str | None" = None,
    repo_url: "str | None" = None,
    yes: bool = False,
) -> None:
    """Shared implementation for remote backend scan — used by both `rafter run` and `rafter scan`."""
    import os as _os

    # sable-9ddf — gate paid Plus scans before doing any work (key resolution,
    # repo detection, or the billable API call).
    _confirm_plus_scan(mode, yes)

    key = resolve_key(api_key)
    gh_token = github_token or _os.environ.get("RAFTER_GITHUB_TOKEN")
    try:
        repo_slug, branch_name, detected_provider, detected_repo_url = detect_repo(repo, branch)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    if not (repo and branch) and not quiet:
        print(f"Repo auto-detected: {repo_slug} @ {branch_name} (note: scanning remote)", file=sys.stderr)

    # Explicit flags override inferred values.
    resolved_provider = provider or detected_provider
    resolved_repo_url = repo_url or detected_repo_url

    headers = {"x-api-key": key, "Content-Type": "application/json"}

    body: dict = {"repository_name": repo_slug, "branch_name": branch_name, "scan_mode": mode}
    if gh_token:
        body["github_token"] = gh_token

    # Additive, backward-compatible: only send provider + repo_url for non-github
    # remotes. For github (or an unknown host that defaulted to github), omit both
    # so the request body is byte-identical to the legacy github-only behavior.
    if resolved_provider and resolved_provider != "github" and resolved_repo_url:
        body["provider"] = resolved_provider
        body["repo_url"] = resolved_repo_url

    resp = requests.post(
        f"{API_BASE}/static/scan",
        headers=headers,
        json=body,
        timeout=API_TIMEOUT,
    )

    forbidden_code = handle_403(resp)
    if forbidden_code >= 0:
        raise typer.Exit(code=forbidden_code)
    elif resp.status_code == 429:
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


def register_backend_commands(app: typer.Typer) -> None:
    """Register run/get/usage on the root typer app."""

    @app.command()
    def run(
        repo: str = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
        branch: str = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
        api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
        fmt: str = typer.Option("md", "--format", "-f", help="json | md"),
        mode: str = typer.Option("fast", "--mode", "-m", help="scan mode: fast | plus"),
        github_token: str = typer.Option(None, "--github-token", envvar="RAFTER_GITHUB_TOKEN", help="GitHub PAT for private repos"),
        provider: str = typer.Option(None, "--provider", help="git provider: gitlab | gitea | bitbucket (default: auto-detected; github requires nothing)"),
        repo_url: str = typer.Option(None, "--repo-url", help="full https clone URL for non-github remotes (default: auto-detected)"),
        skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
        yes: bool = typer.Option(False, "--yes", "-y", help="confirm a paid Plus scan without prompting (when scan.plus_requires_approval is on)"),
        quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
    ):
        """Trigger a security scan."""
        _do_remote_scan(repo, branch, api_key, fmt, skip_interactive, quiet, mode, github_token=github_token, provider=provider, repo_url=repo_url, yes=yes)

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
