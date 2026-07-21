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
    provider: Optional[str] = typer.Option(None, "--provider", help="git provider: gitlab | gitea | bitbucket (default: auto-detected; github requires nothing)"),
    repo_url: Optional[str] = typer.Option(None, "--repo-url", help="full https clone URL for non-github remotes (default: auto-detected)"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    yes: bool = typer.Option(False, "--yes", "-y", help="confirm a paid Plus scan without prompting (when scan.plus_requires_approval is on)"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Scan for security issues. Defaults to remote scan."""
    if ctx.invoked_subcommand is None:
        # No subcommand — run remote scan
        _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode, github_token, provider, repo_url, yes)


# ── rafter scan remote ────────────────────────────────────────────────

@remote_app.callback(invoke_without_command=True)
def scan_remote(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    fmt_: str = typer.Option("md", "--format", "-f", help="json | md"),
    mode: str = typer.Option("fast", "--mode", "-m", help="scan mode: fast | plus"),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="RAFTER_GITHUB_TOKEN", help="GitHub PAT for private repos"),
    provider: Optional[str] = typer.Option(None, "--provider", help="git provider: gitlab | gitea | bitbucket (default: auto-detected; github requires nothing)"),
    repo_url: Optional[str] = typer.Option(None, "--repo-url", help="full https clone URL for non-github remotes (default: auto-detected)"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    yes: bool = typer.Option(False, "--yes", "-y", help="confirm a paid Plus scan without prompting (when scan.plus_requires_approval is on)"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    """Trigger a remote backend security scan (explicit alias for 'rafter run')."""
    _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode, github_token, provider, repo_url, yes)


def _run_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode="fast", github_token=None, provider=None, repo_url=None, yes=False):
    """Shared handler: invoke remote scan (same logic as `rafter run`)."""
    from ..commands.backend import _do_remote_scan
    _do_remote_scan(repo, branch, api_key, fmt_, skip_interactive, quiet, mode, github_token=github_token, provider=provider, repo_url=repo_url, yes=yes)


# ── rafter scan local ─────────────────────────────────────────────────

@local_app.callback(invoke_without_command=True)
def scan_local(
    path: str = typer.Argument(".", help="File or directory to scan"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only output if secrets found"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    format: str = typer.Option("text", "--format", help="Output format: text, json, sarif"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files"),
    diff: Optional[str] = typer.Option(None, "--diff", help="Scan files changed since a git ref"),
    engine: str = typer.Option("auto", "--engine", help="betterleaks or patterns"),
    baseline: bool = typer.Option(False, "--baseline", help="Filter findings present in the saved baseline"),
    watch: bool = typer.Option(False, "--watch", help="Watch for file changes and re-scan on change"),
    history: bool = typer.Option(False, "--history", help="Scan git history for secrets (requires betterleaks engine)"),
    gitignore: bool = typer.Option(True, "--gitignore/--no-gitignore", help="Respect .gitignore when walking the scan target (default: on)"),
    auto_update: bool = typer.Option(True, "--auto-update/--no-auto-update", help="Auto-update a stale managed betterleaks binary; --no-auto-update falls back to the patterns engine instead (default: on)"),
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
        _apply_exclude_paths,
        _load_baseline_entries,
        _run_git_added_line_scan,
    )
    from ..core.config_manager import ConfigManager
    from ..core.custom_patterns import load_suppressions, policy_ignore_to_suppressions

    manager = ConfigManager()
    cfg = manager.load_with_policy()
    scan_cfg = cfg.agent.scan

    custom_patterns = (
        [{"name": p.name, "regex": p.regex, "severity": p.severity} for p in scan_cfg.custom_patterns]
        if scan_cfg.custom_patterns else None
    )

    # sable-o4k — stale-binary auto-update is on unless the CLI flag or the
    # scan.auto_update_betterleaks config key opts out. Either disables it.
    auto_update_enabled = auto_update and scan_cfg.auto_update_betterleaks

    # Combine policy-derived ignore rules with .rafterignore. Policy first so
    # an explicit reason wins over a bare .rafterignore line.
    suppressions = policy_ignore_to_suppressions(scan_cfg.ignore) + load_suppressions()

    baseline_entries = _load_baseline_entries() if baseline else []

    # Resolve scan path for git-aware modes (--diff, --staged)
    resolved_scan_path = os.path.abspath(path)
    git_cwd = resolved_scan_path if os.path.isdir(resolved_scan_path) else None

    # --diff
    if diff:
        _run_git_added_line_scan(
            ["diff", "-U0", "--no-color", "--diff-filter=ACM", diff],
            git_cwd,
            custom_patterns,
            scan_cfg,
            baseline_entries,
            suppressions,
            f"files changed since {diff}",
            f"No files changed since {diff}",
            json_output=json_output,
            quiet=quiet,
            format=format,
        )
        return

    # --staged
    if staged:
        _run_git_added_line_scan(
            ["diff", "-U0", "--no-color", "--cached", "--diff-filter=ACM"],
            git_cwd,
            custom_patterns,
            scan_cfg,
            baseline_entries,
            suppressions,
            "staged files",
            "No files staged for commit",
            json_output=json_output,
            quiet=quiet,
            format=format,
            not_repo_message="Error: Not in a git repository",
        )
        return

    # Default: scan path
    resolved_path = os.path.abspath(path)
    if not os.path.exists(resolved_path):
        print(f"Error: Path not found: {resolved_path}", file=sys.stderr)
        raise typer.Exit(code=2)

    # --watch
    if watch:
        _watch_and_scan(resolved_path, engine, quiet, json_output, format, custom_patterns, scan_cfg, suppressions, auto_update_enabled)
        return

    eng = _select_engine(engine, quiet, auto_update_enabled)

    if os.path.isdir(resolved_path):
        if not quiet:
            print(f"Scanning directory: {resolved_path} ({eng})", file=sys.stderr)
        results = _scan_directory(resolved_path, eng, scan_cfg, history=history, respect_gitignore=gitignore)
    else:
        if not quiet:
            print(f"Scanning file: {resolved_path} ({eng})", file=sys.stderr)
        results = _scan_file(resolved_path, eng, custom_patterns)

    filtered = _apply_baseline(results, baseline_entries)
    _output_scan_results(filtered, json_output, quiet, format=format, suppressions=suppressions)


# ── rafter secrets — top-level alias for local secret scanning ────────

secrets_app = typer.Typer(
    name="secrets",
    help=(
        "Secrets only — scan files/directories for hardcoded secrets "
        "(regex + betterleaks). Not a code analysis. For full SAST/SCA, use 'rafter run'."
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
    engine: str = typer.Option("auto", "--engine", help="betterleaks or patterns"),
    baseline: bool = typer.Option(False, "--baseline", help="Filter findings present in the saved baseline"),
    watch: bool = typer.Option(False, "--watch", help="Watch for file changes and re-scan on change"),
    history: bool = typer.Option(False, "--history", help="Scan git history for secrets (requires betterleaks engine)"),
    gitignore: bool = typer.Option(True, "--gitignore/--no-gitignore", help="Respect .gitignore when walking the scan target (default: on)"),
    auto_update: bool = typer.Option(True, "--auto-update/--no-auto-update", help="Auto-update a stale managed betterleaks binary; --no-auto-update falls back to the patterns engine instead (default: on)"),
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
        gitignore=gitignore,
        auto_update=auto_update,
    )
