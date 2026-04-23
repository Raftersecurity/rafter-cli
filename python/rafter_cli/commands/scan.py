"""Top-level rafter scan command group.

Default (no subcommand): remote scan (same as `rafter run`)
rafter scan remote:       explicit alias for remote scan
rafter scan local [path]: hidden back-compat alias for `rafter secrets`
                          (was `rafter agent scan` before 0.7.4).
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional

import typer

from ..utils.formatter import fmt
from rich import print as rprint

scan_app = typer.Typer(
    name="scan",
    help="Trigger a remote security scan (requires RAFTER_API_KEY).",
    invoke_without_command=True,
    no_args_is_help=False,
)

local_app = typer.Typer(
    name="local",
    help="(deprecated alias for 'rafter secrets')",
    context_settings={"allow_interspersed_args": True},
    hidden=True,
)
scan_app.add_typer(local_app)

remote_app = typer.Typer(
    name="remote",
    help="Trigger a remote backend security scan (explicit alias for 'rafter run')",
)
scan_app.add_typer(remote_app)


# ── default: remote scan ─────────────────────────────────────

@scan_app.callback()
def scan_default(
    ctx: typer.Context,
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt_: str = typer.Option("md", "--format", "-f", help="json | md"),
    mode: str = typer.Option("fast", "--mode", "-m", help="scan mode: fast | plus"),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="RAFTER_GITHUB_TOKEN", help="GitHub PAT for private repos"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Scan for security issues. Defaults to remote scan."""
    if ctx.invoked_subcommand is None:
        # No subcommand — run remote scan
        _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode, github_token)


# ── rafter scan remote ────────────────────────────────────────────────

@remote_app.callback(invoke_without_command=True)
def scan_remote(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt_: str = typer.Option("md", "--format", "-f", help="json | md"),
    mode: str = typer.Option("fast", "--mode", "-m", help="scan mode: fast | plus"),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="RAFTER_GITHUB_TOKEN", help="GitHub PAT for private repos"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Trigger a remote backend security scan (explicit alias for 'rafter run')."""
    _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode, github_token)


def _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode="fast", github_token=None):
    """Shared handler: invoke remote scan (same logic as `rafter run`)."""
    from ..commands.backend import _do_remote_scan
    _do_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode, github_token=github_token)


# ── rafter scan local ─────────────────────────────────────────────────

@local_app.callback(invoke_without_command=True)
def scan_local(
    path: str = typer.Argument(".", help="File or directory to scan"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only output if secrets found"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    format: str = typer.Option("text", "--format", help="Output format: text, json, sarif"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files"),
    diff: Optional[str] = typer.Option(None, "--diff", help="Scan files changed since a git ref"),
    engine: str = typer.Option("auto", "--engine", help="gitleaks or patterns"),
    baseline: bool = typer.Option(False, "--baseline", help="Filter findings present in the saved baseline"),
    watch: bool = typer.Option(False, "--watch", help="Watch for file changes and re-scan on change"),
    history: bool = typer.Option(False, "--history", help="Scan git history for secrets (requires gitleaks engine)"),
):
    """(deprecated alias for 'rafter secrets')."""
    from .agent import (
        _select_engine,
        _scan_file,
        _scan_directory,
        _output_scan_results,
        _output_sarif,
        _watch_and_scan,
        _apply_baseline,
        _load_baseline_entries,
    )
    from ..core.config_manager import ConfigManager

    manager = ConfigManager()
    cfg = manager.load_with_policy()
    scan_cfg = cfg.agent.scan

    custom_patterns = (
        [{"name": p.name, "regex": p.regex, "severity": p.severity} for p in scan_cfg.custom_patterns]
        if scan_cfg.custom_patterns else None
    )

    baseline_entries = _load_baseline_entries() if baseline else []

    # Resolve scan path for git-aware modes (--diff, --staged)
    resolved_scan_path = os.path.abspath(path)
    git_cwd = resolved_scan_path if os.path.isdir(resolved_scan_path) else None

    # --diff
    if diff:
        try:
            diff_output = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACM", diff],
                capture_output=True, text=True, check=True,
                cwd=git_cwd,
            ).stdout.strip()
        except subprocess.CalledProcessError:
            print("Error: Not in a git repository or invalid ref", file=sys.stderr)
            raise typer.Exit(code=2)

        if not diff_output:
            if not quiet:
                rprint(fmt.success(f"No files changed since {diff}"))
            raise typer.Exit(code=0)

        changed = [f.strip() for f in diff_output.split("\n") if f.strip()]
        if not quiet:
            print(f"Scanning {len(changed)} file(s) changed since {diff}...", file=sys.stderr)

        repo_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
            cwd=git_cwd,
        ).stdout.strip()

        eng = _select_engine(engine, quiet)
        all_results = []
        for f in changed:
            resolved = os.path.join(repo_root, f)
            if os.path.isfile(resolved):
                all_results.extend(_scan_file(resolved, eng, custom_patterns))
        filtered = _apply_baseline(all_results, baseline_entries)
        _output_scan_results(filtered, json_output, quiet, f"files changed since {diff}", format=format)
        return

    # --staged
    if staged:
        try:
            staged_output = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                capture_output=True, text=True, check=True,
                cwd=git_cwd,
            ).stdout.strip()
        except subprocess.CalledProcessError:
            print("Error: Not in a git repository", file=sys.stderr)
            raise typer.Exit(code=2)

        if not staged_output:
            if not quiet:
                rprint(fmt.success("No files staged for commit"))
            raise typer.Exit(code=0)

        staged_files = [f.strip() for f in staged_output.split("\n") if f.strip()]
        if not quiet:
            print(f"Scanning {len(staged_files)} staged file(s)...", file=sys.stderr)

        repo_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
            cwd=git_cwd,
        ).stdout.strip()

        eng = _select_engine(engine, quiet)
        all_results = []
        for f in staged_files:
            resolved = os.path.join(repo_root, f)
            if os.path.isfile(resolved):
                all_results.extend(_scan_file(resolved, eng, custom_patterns))
        filtered = _apply_baseline(all_results, baseline_entries)
        _output_scan_results(filtered, json_output, quiet, "staged files", format=format)
        return

    # Default: scan path
    resolved_path = os.path.abspath(path)
    if not os.path.exists(resolved_path):
        print(f"Error: Path not found: {resolved_path}", file=sys.stderr)
        raise typer.Exit(code=2)

    # --watch
    if watch:
        _watch_and_scan(resolved_path, engine, quiet, json_output, format, custom_patterns, scan_cfg)
        return

    eng = _select_engine(engine, quiet)

    if os.path.isdir(resolved_path):
        if not quiet:
            print(f"Scanning directory: {resolved_path} ({eng})", file=sys.stderr)
        results = _scan_directory(resolved_path, eng, scan_cfg, history=history)
    else:
        if not quiet:
            print(f"Scanning file: {resolved_path} ({eng})", file=sys.stderr)
        results = _scan_file(resolved_path, eng, custom_patterns)

    filtered = _apply_baseline(results, baseline_entries)
    _output_scan_results(filtered, json_output, quiet, format=format)


# ── rafter secrets — top-level alias for local secret scanning ────────

secrets_app = typer.Typer(
    name="secrets",
    help=(
        "Scan files/directories for hardcoded secrets (regex + gitleaks). "
        "Secrets only — not a code analysis. For full SAST/SCA, use 'rafter run'."
    ),
    invoke_without_command=True,
    no_args_is_help=False,
    context_settings={"allow_interspersed_args": True},
)


@secrets_app.callback(invoke_without_command=True)
def secrets(
    path: str = typer.Argument(".", help="File or directory to scan"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only output if secrets found"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    format: str = typer.Option("text", "--format", help="Output format: text, json, sarif"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files"),
    diff: Optional[str] = typer.Option(None, "--diff", help="Scan files changed since a git ref"),
    engine: str = typer.Option("auto", "--engine", help="gitleaks or patterns"),
    baseline: bool = typer.Option(False, "--baseline", help="Filter findings present in the saved baseline"),
    watch: bool = typer.Option(False, "--watch", help="Watch for file changes and re-scan on change"),
    history: bool = typer.Option(False, "--history", help="Scan git history for secrets (requires gitleaks engine)"),
):
    """Scan files/directories for hardcoded secrets."""
    return scan_local(
        path=path,
        quiet=quiet,
        json_output=json_output,
        format=format,
        staged=staged,
        diff=diff,
        engine=engine,
        baseline=baseline,
        watch=watch,
        history=history,
    )
