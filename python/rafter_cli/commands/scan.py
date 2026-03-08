"""Top-level rafter scan command group.

Default (no subcommand): remote backend scan (same as `rafter run`)
rafter scan remote:       explicit alias for remote backend scan
rafter scan local [path]: local secret scanner (formerly `rafter agent scan`)
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
    help=(
        "Scan for security issues. Default: remote backend scan. "
        "Use 'scan local' for local secret scanning."
    ),
    invoke_without_command=True,
    no_args_is_help=False,
)

local_app = typer.Typer(name="local", help="Scan files or directories for secrets (local)")
scan_app.add_typer(local_app)

remote_app = typer.Typer(
    name="remote",
    help="Trigger a remote backend security scan (explicit alias for 'rafter run')",
)
scan_app.add_typer(remote_app)


# ── default: remote backend scan ─────────────────────────────────────

@scan_app.callback()
def scan_default(
    ctx: typer.Context,
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt_: str = typer.Option("md", "--format", "-f", help="json | md"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Scan for security issues. Defaults to remote backend scan."""
    if ctx.invoked_subcommand is None:
        # No subcommand — run remote backend scan
        _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet)


# ── rafter scan remote ────────────────────────────────────────────────

@remote_app.callback(invoke_without_command=True)
def scan_remote(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt_: str = typer.Option("md", "--format", "-f", help="json | md"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Trigger a remote backend security scan (explicit alias for 'rafter run')."""
    _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet)


def _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet):
    """Shared handler: invoke remote backend scan (same logic as `rafter run`)."""
    from ..commands.backend import _do_remote_scan
    _do_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet)


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
):
    """Scan files or directories for secrets (local). Formerly 'rafter agent scan'."""
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

    # --diff
    if diff:
        try:
            diff_output = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACM", diff],
                capture_output=True, text=True, check=True,
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

        eng = _select_engine(engine, quiet)
        all_results = []
        for f in changed:
            resolved = os.path.abspath(f)
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

        eng = _select_engine(engine, quiet)
        all_results = []
        for f in staged_files:
            resolved = os.path.abspath(f)
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
        results = _scan_directory(resolved_path, eng, scan_cfg)
    else:
        if not quiet:
            print(f"Scanning file: {resolved_path} ({eng})", file=sys.stderr)
        results = _scan_file(resolved_path, eng, custom_patterns)

    filtered = _apply_baseline(results, baseline_entries)
    _output_scan_results(filtered, json_output, quiet, format=format)
