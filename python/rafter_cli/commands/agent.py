"""Agent security commands: init, scan, audit, exec, config, install-hook."""
from __future__ import annotations

import importlib.resources
import json
import os
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from rich import print as rprint

from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..core.config_manager import ConfigManager
from ..scanners.gitleaks import GitleaksScanner
from ..scanners.regex_scanner import RegexScanner, ScanResult
from ..utils.formatter import fmt, is_agent_mode

agent_app = typer.Typer(name="agent", help="Agent security features", no_args_is_help=True)

# ── config sub-app ───────────────────────────────────────────────────
config_app = typer.Typer(name="config", help="Manage agent configuration", no_args_is_help=True)


@config_app.command("show")
def config_show():
    """Show current configuration."""
    from dataclasses import asdict

    manager = ConfigManager()
    print(json.dumps(asdict(manager.load()), indent=2))


@config_app.command("get")
def config_get(key: str = typer.Argument(..., help="Config key (e.g. agent.risk_level)")):
    """Get a configuration value."""
    manager = ConfigManager()
    value = manager.get(key)
    if value is None:
        print(f"Key not found: {key}", file=sys.stderr)
        raise typer.Exit(code=1)
    if isinstance(value, dict):
        print(json.dumps(value, indent=2))
    else:
        print(value)


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key (e.g. agent.risk_level)"),
    value: str = typer.Argument(..., help="Value to set"),
):
    """Set a configuration value."""
    manager = ConfigManager()
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        parsed = value
    manager.set(key, parsed)
    rprint(fmt.success(f"Set {key} = {json.dumps(parsed)}"))


agent_app.add_typer(config_app)

# ── init helpers ─────────────────────────────────────────────────────


def _install_claude_code_hooks() -> None:
    """Install Rafter PreToolUse hooks into ~/.claude/settings.json."""
    home = Path.home()
    claude_dir = home / ".claude"
    settings_path = claude_dir / "settings.json"

    claude_dir.mkdir(parents=True, exist_ok=True)

    # Read existing settings or start fresh
    settings: dict[str, Any] = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, ValueError):
            rprint(fmt.warning("Existing settings.json was unreadable, creating new one"))

    # Merge hooks — don't overwrite existing non-Rafter hooks
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "PreToolUse" not in settings["hooks"]:
        settings["hooks"]["PreToolUse"] = []

    rafter_command = "rafter hook pretool"

    # Remove any existing Rafter hooks to avoid duplicates
    settings["hooks"]["PreToolUse"] = [
        entry for entry in settings["hooks"]["PreToolUse"]
        if not any(
            h.get("command") == rafter_command
            for h in (entry.get("hooks") or [])
        )
    ]

    # Add Rafter hooks
    rafter_hook = {"type": "command", "command": rafter_command}
    settings["hooks"]["PreToolUse"].extend([
        {"matcher": "Bash", "hooks": [rafter_hook]},
        {"matcher": "Write|Edit", "hooks": [rafter_hook]},
    ])

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    rprint(fmt.success(f"Installed PreToolUse hooks to {settings_path}"))


# ── init ─────────────────────────────────────────────────────────────


@agent_app.command()
def init(
    risk_level: str = typer.Option("moderate", "--risk-level", help="minimal, moderate, or aggressive"),
    skip_gitleaks: bool = typer.Option(False, "--skip-gitleaks", help="Skip gitleaks check"),
    skip_claude_code: bool = typer.Option(False, "--skip-claude-code", help="Skip Claude Code hook installation"),
    claude_code: bool = typer.Option(False, "--claude-code", help="Force Claude Code detection"),
):
    """Initialize agent security system."""
    rprint(fmt.header("Rafter Agent Security Setup"))
    rprint(fmt.divider())
    rprint()

    manager = ConfigManager()

    # Detect environments
    home = Path.home()
    has_claude_code = claude_code or (home / ".claude").exists()

    if has_claude_code:
        rprint(fmt.success("Detected environment: Claude Code"))
    else:
        rprint(fmt.info("Claude Code not detected"))

    # Initialize
    manager.initialize()
    rprint(fmt.success("Created config at ~/.rafter/config.json"))

    # Validate + set risk level
    valid = ("minimal", "moderate", "aggressive")
    if risk_level not in valid:
        rprint(fmt.error(f"Invalid risk level: {risk_level}"))
        print(f"Valid options: {', '.join(valid)}", file=sys.stderr)
        raise typer.Exit(code=1)

    manager.set("agent.risk_level", risk_level)
    rprint(fmt.success(f"Set risk level: {risk_level}"))

    # Gitleaks check
    if not skip_gitleaks:
        scanner = GitleaksScanner()
        result = scanner.check()
        if result.available:
            rprint(fmt.success(f"Gitleaks available on PATH ({result.stdout})"))
        else:
            rprint(fmt.warning("Gitleaks not available — pattern-based scanning will be used instead."))
            if result.error:
                rprint(fmt.info(f"  Reason: {result.error}"))
            if result.stderr:
                rprint(fmt.info(f"  stderr: {result.stderr}"))
            diag = GitleaksScanner.collect_diagnostics(scanner._path)
            if diag:
                rprint(fmt.info("Diagnostics:"))
                rprint(diag)
            rprint(fmt.info(
                "To fix: install gitleaks (https://github.com/gitleaks/gitleaks/releases) "
                "and ensure it is on PATH, then re-run 'rafter agent init'."
            ))

    # Install Claude Code hooks
    if has_claude_code and not skip_claude_code:
        try:
            _install_claude_code_hooks()
            manager.set("agent.environments.claude_code.enabled", True)
        except Exception as e:
            rprint(fmt.error(f"Failed to install Claude Code hooks: {e}"))

    rprint()
    rprint(fmt.success("Agent security initialized!"))
    rprint()
    rprint("Next steps:")
    if has_claude_code and not skip_claude_code:
        rprint("  - Restart Claude Code to load hooks")
    rprint("  - Run: rafter agent scan . (test secret scanning)")
    rprint("  - Configure: rafter agent config show")
    rprint()


# ── scan ─────────────────────────────────────────────────────────────


def _select_engine(preference: str, quiet: bool) -> str:
    """Return 'gitleaks' or 'patterns'."""
    if preference == "patterns":
        return "patterns"

    scanner = GitleaksScanner()
    available = scanner.is_available()

    if preference == "gitleaks":
        if not available:
            if not quiet:
                print(fmt.warning("Gitleaks requested but not available, using patterns"), file=sys.stderr)
            return "patterns"
        return "gitleaks"

    # auto
    return "gitleaks" if available else "patterns"


def _scan_file(file_path: str, engine: str, custom_patterns=None) -> list[ScanResult]:
    if engine == "gitleaks":
        try:
            gl = GitleaksScanner()
            result = gl.scan_file(file_path)
            return [ScanResult(file=result.file, matches=result.matches)] if result.matches else []
        except Exception:
            scanner = RegexScanner(custom_patterns)
            r = scanner.scan_file(file_path)
            return [r] if r.matches else []
    else:
        scanner = RegexScanner(custom_patterns)
        r = scanner.scan_file(file_path)
        return [r] if r.matches else []


def _scan_directory(dir_path: str, engine: str, scan_cfg=None) -> list[ScanResult]:
    custom = None
    exclude = None
    if scan_cfg:
        custom = [{"name": p.name, "regex": p.regex, "severity": p.severity} for p in scan_cfg.custom_patterns] if scan_cfg.custom_patterns else None
        exclude = scan_cfg.exclude_paths or None

    if engine == "gitleaks":
        try:
            gl = GitleaksScanner()
            results = gl.scan_directory(dir_path)
            return [ScanResult(file=r.file, matches=r.matches) for r in results]
        except Exception:
            scanner = RegexScanner(custom)
            return scanner.scan_directory(dir_path, exclude_paths=exclude)
    else:
        scanner = RegexScanner(custom)
        return scanner.scan_directory(dir_path, exclude_paths=exclude)


def _output_scan_results(
    results: list[ScanResult],
    json_output: bool,
    quiet: bool,
    context: str | None = None,
) -> None:
    if json_output:
        out = [
            {"file": r.file, "matches": [
                {"pattern": {"name": m.pattern.name, "severity": m.pattern.severity, "description": m.pattern.description or ""},
                 "line": m.line, "column": m.column, "redacted": m.redacted}
                for m in r.matches
            ]}
            for r in results
        ]
        print(json.dumps(out, indent=2))
        raise typer.Exit(code=1 if results else 0)

    if not results:
        if not quiet:
            msg = f"No secrets detected in {context}" if context else "No secrets detected"
            rprint(f"\n{fmt.success(msg)}\n")
        raise typer.Exit(code=0)

    rprint(f"\n{fmt.warning(f'Found secrets in {len(results)} file(s):')}\n")

    total = 0
    for r in results:
        rprint(f"\n{fmt.info(r.file)}")
        for m in r.matches:
            total += 1
            loc = f"Line {m.line}" if m.line else "Unknown location"
            rprint(f"  {fmt.severity(m.pattern.severity)} {m.pattern.name}")
            rprint(f"     Location: {loc}")
            rprint(f"     Pattern: {m.pattern.description or m.pattern.regex}")
            rprint(f"     Redacted: {m.redacted}")
            rprint()

    rprint(f"\n{fmt.warning(f'Total: {total} secret(s) detected in {len(results)} file(s)')}\n")

    if context == "staged files":
        rprint(f"{fmt.error('Commit blocked. Remove secrets before committing.')}\n")
    else:
        rprint("Run 'rafter agent audit' to see the security log.\n")

    raise typer.Exit(code=1)


@agent_app.command()
def scan(
    path: str = typer.Argument(".", help="File or directory to scan"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only output if secrets found"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files"),
    diff: str = typer.Option(None, "--diff", help="Scan files changed since a git ref"),
    engine: str = typer.Option("auto", "--engine", help="gitleaks or patterns"),
):
    """Scan files or directories for secrets."""
    manager = ConfigManager()
    cfg = manager.load_with_policy()
    scan_cfg = cfg.agent.scan

    custom_patterns = (
        [{"name": p.name, "regex": p.regex, "severity": p.severity} for p in scan_cfg.custom_patterns]
        if scan_cfg.custom_patterns else None
    )

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
        all_results: list[ScanResult] = []
        for f in changed:
            resolved = os.path.abspath(f)
            if os.path.isfile(resolved):
                all_results.extend(_scan_file(resolved, eng, custom_patterns))
        _output_scan_results(all_results, json_output, quiet, f"files changed since {diff}")
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
        _output_scan_results(all_results, json_output, quiet, "staged files")
        return

    # Default: scan path
    resolved_path = os.path.abspath(path)
    if not os.path.exists(resolved_path):
        print(f"Error: Path not found: {resolved_path}", file=sys.stderr)
        raise typer.Exit(code=2)

    eng = _select_engine(engine, quiet)

    if os.path.isdir(resolved_path):
        if not quiet:
            print(f"Scanning directory: {resolved_path} ({eng})", file=sys.stderr)
        results = _scan_directory(resolved_path, eng, scan_cfg)
    else:
        if not quiet:
            print(f"Scanning file: {resolved_path} ({eng})", file=sys.stderr)
        results = _scan_file(resolved_path, eng, custom_patterns)

    _output_scan_results(results, json_output, quiet)


# ── audit ────────────────────────────────────────────────────────────

_EVENT_INDICATORS_AGENT = {
    "command_intercepted": "[INTERCEPT]",
    "secret_detected": "[SECRET]",
    "content_sanitized": "[SANITIZE]",
    "policy_override": "[OVERRIDE]",
    "scan_executed": "[SCAN]",
    "config_changed": "[CONFIG]",
}

_EVENT_INDICATORS_HUMAN = {
    "command_intercepted": "\U0001f6e1\ufe0f",
    "secret_detected": "\U0001f511",
    "content_sanitized": "\U0001f9f9",
    "policy_override": "\u26a0\ufe0f",
    "scan_executed": "\U0001f50d",
    "config_changed": "\u2699\ufe0f",
}


@agent_app.command()
def audit(
    last: int = typer.Option(10, "--last", help="Show last N entries"),
    event: str = typer.Option(None, "--event", help="Filter by event type"),
    agent_type: str = typer.Option(None, "--agent", help="Filter by agent type"),
    since: str = typer.Option(None, "--since", help="Show entries since date (YYYY-MM-DD)"),
):
    """View audit log entries."""
    logger = AuditLogger()

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            print(f"Invalid date: {since}", file=sys.stderr)
            raise typer.Exit(code=1)

    entries = logger.read(
        event_type=event,
        agent_type=agent_type,
        since=since_dt,
        limit=last,
    )

    if not entries:
        print("No audit log entries found")
        return

    print(f"\nShowing {len(entries)} audit log entries:\n")

    indicators = _EVENT_INDICATORS_AGENT if is_agent_mode() else _EVENT_INDICATORS_HUMAN

    for e in entries:
        ts = e.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        et = e.get("event_type", "unknown")
        ind = indicators.get(et, "[EVENT]" if is_agent_mode() else "\U0001f4dd")
        print(f"{ind} [{ts}] {et}")
        if e.get("agent_type"):
            print(f"   Agent: {e['agent_type']}")
        action = e.get("action") or {}
        if action.get("command"):
            print(f"   Command: {action['command']}")
        if action.get("risk_level"):
            print(f"   Risk: {action['risk_level']}")
        sc = e.get("security_check") or {}
        print(f"   Check: {'PASSED' if sc.get('passed') else 'FAILED'}")
        if sc.get("reason"):
            print(f"   Reason: {sc['reason']}")
        res = e.get("resolution") or {}
        print(f"   Action: {res.get('action_taken', 'unknown')}")
        if res.get("override_reason"):
            print(f"   Override: {res['override_reason']}")
        print()


# ── exec ─────────────────────────────────────────────────────────────


@agent_app.command("exec")
def exec_cmd(
    command: str = typer.Argument(..., help="Command to execute"),
    skip_scan: bool = typer.Option(False, "--skip-scan", help="Skip pre-execution file scanning"),
    force: bool = typer.Option(False, "--force", help="Skip approval prompts"),
):
    """Execute command with security validation."""
    interceptor = CommandInterceptor()
    evaluation = interceptor.evaluate(command)

    # Blocked
    if not evaluation.allowed and not evaluation.requires_approval:
        rprint(f"\n{fmt.error('Command BLOCKED')}\n")
        print(f"Risk Level: {evaluation.risk_level.upper()}", file=sys.stderr)
        print(f"Reason: {evaluation.reason}", file=sys.stderr)
        print(f"Command: {command}\n", file=sys.stderr)
        interceptor.log_evaluation(evaluation, "blocked")
        raise typer.Exit(code=1)

    # Pre-exec scan for git commands
    if not skip_scan and command.strip().startswith(("git commit", "git push")):
        try:
            staged = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True, text=True,
            ).stdout.strip().split("\n")
            staged = [f for f in staged if f]
            if staged:
                scanner = RegexScanner()
                results = scanner.scan_files(staged)
                total = sum(len(r.matches) for r in results)
                if results:
                    rprint(f"\n{fmt.warning('Secrets detected in staged files!')}\n")
                    print(f"Found {total} secret(s) in {len(results)} file(s)", file=sys.stderr)
                    rprint(f"\nRun 'rafter agent scan' for details.\n")
                    interceptor.log_evaluation(evaluation, "blocked")
                    raise typer.Exit(code=1)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    # Requires approval
    if evaluation.requires_approval and not force:
        rprint(f"\n{fmt.warning('Command requires approval')}\n")
        print(f"Risk Level: {evaluation.risk_level.upper()}")
        print(f"Command: {command}")
        if evaluation.reason:
            print(f"Reason: {evaluation.reason}")
        print()

        answer = input("Approve this command? (yes/no): ").strip().lower()
        if answer not in ("yes", "y"):
            rprint(f"\n{fmt.error('Command cancelled')}\n")
            interceptor.log_evaluation(evaluation, "blocked")
            raise typer.Exit(code=1)

        rprint(f"\n{fmt.success('Command approved by user')}\n")
        interceptor.log_evaluation(evaluation, "overridden")
    elif force and evaluation.requires_approval:
        rprint(f"\n{fmt.warning('Forcing execution (--force flag)')}\n")
        interceptor.log_evaluation(evaluation, "overridden")
    else:
        interceptor.log_evaluation(evaluation, "allowed")

    # Execute
    try:
        import shlex
        subprocess.run(shlex.split(command), check=True)
        rprint(f"\n{fmt.success('Command executed successfully')}\n")
    except subprocess.CalledProcessError as e:
        rprint(f"\n{fmt.error(f'Command failed with exit code {e.returncode}')}\n")
        raise typer.Exit(code=e.returncode or 1)


# ── install-hook ──────────────────────────────────────────────────────


def _get_hook_template() -> str:
    """Read the bundled pre-commit hook shell template."""
    ref = importlib.resources.files("rafter_cli.resources").joinpath("pre-commit-hook.sh")
    return ref.read_text(encoding="utf-8")


@agent_app.command("install-hook")
def install_hook(
    global_: bool = typer.Option(False, "--global", help="Install globally for all repos (via git config)"),
):
    """Install pre-commit hook to scan for secrets."""
    if global_:
        _install_global_hook()
    else:
        _install_local_hook()


def _install_local_hook() -> None:
    """Install pre-commit hook for the current repository."""
    try:
        git_dir = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        rprint(fmt.error("Not in a git repository"))
        print("   Run this command from inside a git repository", file=sys.stderr)
        raise typer.Exit(code=1)

    hooks_dir = Path(git_dir).resolve() / "hooks"
    hook_path = hooks_dir / "pre-commit"

    hooks_dir.mkdir(parents=True, exist_ok=True)

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        if "Rafter Security Pre-Commit Hook" in existing:
            rprint(fmt.success("Rafter pre-commit hook already installed"))
            return
        backup_path = hook_path.with_name(f"pre-commit.backup-{int(__import__('time').time() * 1000)}")
        hook_path.rename(backup_path)
        rprint(fmt.info(f"Backed up existing hook to: {backup_path.name}"))

    hook_content = _get_hook_template()
    hook_path.write_text(hook_content, encoding="utf-8")
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    rprint(fmt.success("Installed Rafter pre-commit hook"))
    rprint(f"  Location: {hook_path}")
    rprint()
    rprint("The hook will:")
    rprint("  - Scan staged files for secrets before each commit")
    rprint("  - Block commits if secrets are detected")
    rprint("  - Can be bypassed with: git commit --no-verify (not recommended)")
    rprint()


def _install_global_hook() -> None:
    """Install pre-commit hook globally for all repositories."""
    home = Path.home()
    global_hooks_dir = home / ".rafter" / "git-hooks"
    hook_path = global_hooks_dir / "pre-commit"

    global_hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_content = _get_hook_template()
    hook_path.write_text(hook_content, encoding="utf-8")
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    try:
        subprocess.run(
            ["git", "config", "--global", "core.hooksPath", str(global_hooks_dir)],
            check=True, capture_output=True,
        )
    except subprocess.CalledProcessError:
        rprint(fmt.error("Failed to configure global git hooks"))
        print(f"   Manually run: git config --global core.hooksPath {global_hooks_dir}", file=sys.stderr)
        raise typer.Exit(code=1)

    rprint(fmt.success("Installed Rafter pre-commit hook globally"))
    rprint(f"  Location: {hook_path}")
    rprint(f"  Git config: core.hooksPath = {global_hooks_dir}")
    rprint()
    rprint("The hook will apply to ALL git repositories on this machine.")
    rprint()
    rprint("To disable globally:")
    rprint("  git config --global --unset core.hooksPath")
    rprint()
    rprint("To install per-repository instead:")
    rprint("  cd <repo> && rafter agent install-hook")
    rprint()
