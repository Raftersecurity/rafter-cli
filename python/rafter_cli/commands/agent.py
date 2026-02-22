"""Agent security commands: init, scan, audit, exec, config, install-hook, verify, audit-skill."""
from __future__ import annotations

import importlib.resources
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from rich import print as rprint

from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..core.config_manager import ConfigManager
from ..core.pattern_engine import PatternEngine
from ..scanners.gitleaks import GitleaksScanner
from ..scanners.regex_scanner import RegexScanner, ScanResult
from ..scanners.secret_patterns import DEFAULT_SECRET_PATTERNS
from ..utils.formatter import fmt, is_agent_mode
from ..utils.skill_manager import SkillManager
from ..utils.binary_manager import BinaryManager

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

    pre_command = "rafter hook pretool"
    post_command = "rafter hook posttool"

    if "PostToolUse" not in settings["hooks"]:
        settings["hooks"]["PostToolUse"] = []

    # Remove any existing Rafter hooks to avoid duplicates
    settings["hooks"]["PreToolUse"] = [
        entry for entry in settings["hooks"]["PreToolUse"]
        if not any(
            h.get("command") == pre_command
            for h in (entry.get("hooks") or [])
        )
    ]
    settings["hooks"]["PostToolUse"] = [
        entry for entry in settings["hooks"]["PostToolUse"]
        if not any(
            h.get("command") == post_command
            for h in (entry.get("hooks") or [])
        )
    ]

    # Add Rafter hooks
    pre_hook = {"type": "command", "command": pre_command}
    post_hook = {"type": "command", "command": post_command}
    settings["hooks"]["PreToolUse"].extend([
        {"matcher": "Bash", "hooks": [pre_hook]},
        {"matcher": "Write|Edit", "hooks": [pre_hook]},
    ])
    settings["hooks"]["PostToolUse"].extend([
        {"matcher": ".*", "hooks": [post_hook]},
    ])

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    rprint(fmt.success(f"Installed PreToolUse hooks to {settings_path}"))
    rprint(fmt.success(f"Installed PostToolUse hooks to {settings_path}"))


# ── init ─────────────────────────────────────────────────────────────


def _install_openclaw_skill() -> tuple[bool, str, str, str]:
    """Install Rafter Security skill to OpenClaw. Returns (ok, source, dest, error)."""
    home = Path.home()
    skills_dir = home / ".openclaw" / "skills"
    dest_path = skills_dir / "rafter-security.md"

    # Find source skill file
    try:
        ref = importlib.resources.files("rafter_cli.resources").joinpath("rafter-security-skill.md")
        source_path = str(ref)
    except Exception:
        source_path = "(bundled resource)"

    if not skills_dir.exists():
        return False, source_path, str(dest_path), f"OpenClaw skills directory not found: {skills_dir}"

    try:
        content = importlib.resources.files("rafter_cli.resources").joinpath("rafter-security-skill.md").read_text(encoding="utf-8")
    except Exception as e:
        return False, source_path, str(dest_path), f"Source skill file not found: {e}"

    try:
        dest_path.write_text(content, encoding="utf-8")
        return True, source_path, str(dest_path), ""
    except Exception as e:
        return False, source_path, str(dest_path), str(e)


@agent_app.command()
def init(
    risk_level: str = typer.Option("moderate", "--risk-level", help="minimal, moderate, or aggressive"),
    skip_gitleaks: bool = typer.Option(False, "--skip-gitleaks", help="Skip gitleaks check"),
    skip_openclaw: bool = typer.Option(False, "--skip-openclaw", help="Skip OpenClaw skill installation"),
    skip_claude_code: bool = typer.Option(False, "--skip-claude-code", help="Skip Claude Code hook installation"),
    claude_code: bool = typer.Option(False, "--claude-code", help="Force Claude Code detection"),
    update: bool = typer.Option(False, "--update", help="Re-download gitleaks and reinstall integrations without resetting config"),
):
    """Initialize agent security system."""
    rprint(fmt.header("Rafter Agent Security Setup"))
    rprint(fmt.divider())
    rprint()

    manager = ConfigManager()

    # Detect environments
    home = Path.home()
    has_openclaw = (home / ".openclaw").exists()
    has_claude_code = claude_code or (home / ".claude").exists()

    if has_openclaw:
        rprint(fmt.success("Detected environment: OpenClaw"))
    else:
        rprint(fmt.info("OpenClaw not detected"))

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
        _gitleaks_on_path = None if update else shutil.which("gitleaks")
        _rafter_bin = Path.home() / ".rafter" / "bin" / "gitleaks"
        if _gitleaks_on_path:
            rprint(fmt.success(f"Gitleaks available on PATH ({_gitleaks_on_path})"))
        elif not update and _rafter_bin.exists():
            rprint(fmt.success(f"Gitleaks available at {_rafter_bin}"))
        else:
            if update:
                rprint(fmt.info("Updating gitleaks binary..."))
            else:
                rprint(fmt.info("Gitleaks not found — attempting auto-download..."))
            _bm = BinaryManager()
            if _bm.is_platform_supported():
                try:
                    _bm.download_gitleaks(on_progress=typer.echo)
                    rprint(fmt.success("Gitleaks downloaded and verified."))
                except Exception as _dl_err:
                    rprint(fmt.warning(f"Auto-download failed: {_dl_err}"))
                    rprint(fmt.info(
                        "To fix: install gitleaks manually "
                        "(https://github.com/gitleaks/gitleaks/releases) "
                        "and ensure it is on PATH, then re-run 'rafter agent init'."
                    ))
            else:
                rprint(fmt.warning(
                    "Gitleaks not available for this platform — "
                    "pattern-based scanning will be used instead."
                ))
                rprint(fmt.info(
                    "To fix: install gitleaks (https://github.com/gitleaks/gitleaks/releases) "
                    "and ensure it is on PATH, then re-run 'rafter agent init'."
                ))

    # Install OpenClaw skill if applicable
    if has_openclaw and not skip_openclaw:
        ok, source, dest, error = _install_openclaw_skill()
        if ok:
            rprint(fmt.success(f"Installed Rafter Security skill to {dest}"))
            manager.set("agent.environments.openclaw.enabled", True)
        else:
            rprint(fmt.error("Failed to install Rafter Security skill"))
            rprint(fmt.warning(f"  Source: {source}"))
            rprint(fmt.warning(f"  Destination: {dest}"))
            if error:
                rprint(fmt.warning(f"  Error: {error}"))

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
    if has_openclaw and not skip_openclaw:
        rprint("  - Restart OpenClaw to load skill")
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
    format: str = "text",
) -> None:
    if format == "sarif":
        _output_sarif(results)
        return

    if json_output or format == "json":
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


def _output_sarif(results: list[ScanResult]) -> None:
    """Emit SARIF 2.1.0 JSON for GitHub/GitLab security tab integration."""
    rules: dict[str, dict] = {}
    sarif_results = []
    for r in results:
        for m in r.matches:
            rule_id = re.sub(r"\s+", "-", m.pattern.name.lower())
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": m.pattern.name,
                    "shortDescription": {"text": m.pattern.description or m.pattern.name},
                }
            level = "error" if m.pattern.severity in ("critical", "high") else "warning"
            location: dict[str, Any] = {
                "artifactLocation": {"uri": r.file.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
            }
            if m.line:
                location["region"] = {"startLine": m.line, "startColumn": m.column or 1}
            sarif_results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{m.pattern.name} detected"},
                "locations": [{"physicalLocation": location}],
            })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rafter",
                    "informationUri": "https://rafter.so",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    print(json.dumps(sarif, indent=2))
    raise typer.Exit(code=1 if results else 0)


@agent_app.command()
def scan(
    path: str = typer.Argument(".", help="File or directory to scan"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only output if secrets found"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    format: str = typer.Option("text", "--format", help="Output format: text, json, sarif"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files"),
    diff: str = typer.Option(None, "--diff", help="Scan files changed since a git ref"),
    engine: str = typer.Option("auto", "--engine", help="gitleaks or patterns"),
    baseline: bool = typer.Option(False, "--baseline", help="Filter findings present in the saved baseline"),
):
    """Scan files or directories for secrets."""
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
        all_results: list[ScanResult] = []
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


def _get_hook_template(hook_name: str = "pre-commit") -> str:
    """Read the bundled hook shell template."""
    filename = f"{hook_name}-hook.sh"
    ref = importlib.resources.files("rafter_cli.resources").joinpath(filename)
    return ref.read_text(encoding="utf-8")


@agent_app.command("install-hook")
def install_hook(
    global_: bool = typer.Option(False, "--global", help="Install globally for all repos (via git config)"),
    push: bool = typer.Option(False, "--push", help="Install pre-push hook instead of pre-commit"),
):
    """Install git hook to scan for secrets."""
    hook_name = "pre-push" if push else "pre-commit"
    if global_:
        _install_global_hook(hook_name)
    else:
        _install_local_hook(hook_name)


def _install_local_hook(hook_name: str = "pre-commit") -> None:
    """Install hook for the current repository."""
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
    hook_path = hooks_dir / hook_name

    hooks_dir.mkdir(parents=True, exist_ok=True)

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        marker = f"Rafter Security Pre-{'Push' if hook_name == 'pre-push' else 'Commit'} Hook"
        if marker in existing:
            rprint(fmt.success(f"Rafter {hook_name} hook already installed"))
            return
        import time
        backup_path = hook_path.with_name(f"{hook_name}.backup-{int(time.time() * 1000)}")
        hook_path.rename(backup_path)
        rprint(fmt.info(f"Backed up existing hook to: {backup_path.name}"))

    hook_content = _get_hook_template(hook_name)
    hook_path.write_text(hook_content, encoding="utf-8")
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    rprint(fmt.success(f"Installed Rafter {hook_name} hook"))
    rprint(f"  Location: {hook_path}")
    rprint()
    rprint("The hook will:")
    if hook_name == "pre-push":
        rprint("  - Scan commits being pushed for secrets")
        rprint("  - Block pushes if secrets are detected")
        rprint("  - Can be bypassed with: git push --no-verify (not recommended)")
    else:
        rprint("  - Scan staged files for secrets before each commit")
        rprint("  - Block commits if secrets are detected")
        rprint("  - Can be bypassed with: git commit --no-verify (not recommended)")
    rprint()


def _install_global_hook(hook_name: str = "pre-commit") -> None:
    """Install hook globally for all repositories."""
    home = Path.home()
    global_hooks_dir = home / ".rafter" / "git-hooks"
    hook_path = global_hooks_dir / hook_name

    global_hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_content = _get_hook_template(hook_name)
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

    rprint(fmt.success(f"Installed Rafter {hook_name} hook globally"))
    rprint(f"  Location: {hook_path}")
    rprint(f"  Git config: core.hooksPath = {global_hooks_dir}")
    rprint()
    rprint("The hook will apply to ALL git repositories on this machine.")
    rprint()
    rprint("To disable globally:")
    rprint("  git config --global --unset core.hooksPath")
    rprint()
    rprint("To install per-repository instead:")
    push_flag = " --push" if hook_name == "pre-push" else ""
    rprint(f"  cd <repo> && rafter agent install-hook{push_flag}")
    rprint()


# ── verify ──────────────────────────────────────────────────────────


@dataclass
class _CheckResult:
    name: str
    passed: bool
    detail: str
    optional: bool = False  # optional checks warn but don't fail exit code


def _check_gitleaks() -> _CheckResult:
    """Check if gitleaks is available and executable. Checks PATH first, then ~/.rafter/bin."""
    name = "Gitleaks"
    # Check PATH first (e.g. Homebrew), then fall back to rafter-managed binary
    gitleaks_path = shutil.which("gitleaks")
    if not gitleaks_path:
        rafter_bin = Path.home() / ".rafter" / "bin" / "gitleaks"
        if rafter_bin.exists():
            gitleaks_path = str(rafter_bin)
    if not gitleaks_path:
        return _CheckResult(name, False, f"Not found on PATH or at {Path.home() / '.rafter' / 'bin' / 'gitleaks'}")

    # Verify the found binary actually works
    bm = BinaryManager()
    result = bm.verify_gitleaks_verbose(binary_path=Path(gitleaks_path))
    if result["ok"]:
        return _CheckResult(name, True, result["stdout"] or gitleaks_path)

    detail = f"Found at {gitleaks_path} but failed to execute"
    if result["stderr"]:
        detail += f"\n   stderr: {result['stderr']}"
    diag = bm.collect_binary_diagnostics(binary_path=Path(gitleaks_path))
    if diag:
        detail += f"\n{diag}"
    return _CheckResult(name, False, detail)


def _check_config() -> _CheckResult:
    """Check if ~/.rafter/config.json exists and is valid."""
    name = "Config"
    config_path = Path.home() / ".rafter" / "config.json"

    if not config_path.exists():
        return _CheckResult(name, False, f"Not found: {config_path}")

    try:
        json.loads(config_path.read_text())
        return _CheckResult(name, True, str(config_path))
    except (json.JSONDecodeError, OSError) as e:
        return _CheckResult(name, False, f"Invalid: {config_path} — {e}")


def _check_claude_code() -> _CheckResult:
    """Check if Claude Code integration is healthy."""
    name = "Claude Code"
    home = Path.home()
    claude_dir = home / ".claude"

    if not claude_dir.exists():
        return _CheckResult(name, False, "Not detected — run 'rafter agent init --claude-code' to enable", optional=True)

    settings_path = claude_dir / "settings.json"
    if not settings_path.exists():
        return _CheckResult(name, False, f"Settings file not found: {settings_path}", optional=True)

    try:
        settings = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return _CheckResult(name, False, f"Cannot read settings: {e}", optional=True)

    hooks = settings.get("hooks", {}).get("PreToolUse", [])
    has_rafter = any(
        any(h.get("command") == "rafter hook pretool" for h in (entry.get("hooks") or []))
        for entry in hooks
    )
    if not has_rafter:
        return _CheckResult(name, False, "Rafter hooks not installed — run 'rafter agent init --claude-code'", optional=True)
    return _CheckResult(name, True, "Hooks installed")


def _check_openclaw() -> _CheckResult:
    """Check if OpenClaw integration is healthy."""
    name = "OpenClaw"
    home = Path.home()
    skills_dir = home / ".openclaw" / "skills"

    if not skills_dir.exists():
        return _CheckResult(name, False, "Not detected — run 'rafter agent init' to enable", optional=True)

    skill_path = skills_dir / "rafter-security.md"
    if not skill_path.exists():
        return _CheckResult(name, False, "Rafter skill not installed — run 'rafter agent init'", optional=True)

    # Try to extract version from frontmatter
    version = ""
    try:
        content = skill_path.read_text(encoding="utf-8")
        import re
        match = re.search(r"^version:\s*(.+)$", content, re.MULTILINE)
        if match:
            version = match.group(1).strip()
    except OSError:
        pass

    detail = f"Rafter skill installed{f' (v{version})' if version else ''}"
    return _CheckResult(name, True, detail)


@agent_app.command()
def verify():
    """Check agent security integration status."""
    rprint(fmt.header("Rafter Agent Verify"))
    rprint(fmt.divider())
    rprint()

    results = [
        _check_config(),
        _check_gitleaks(),
        _check_claude_code(),
        _check_openclaw(),
    ]

    for r in results:
        if r.passed:
            rprint(fmt.success(f"{r.name}: {r.detail}"))
        elif r.optional:
            rprint(fmt.warning(f"{r.name}: {r.detail}"))
        else:
            rprint(fmt.error(f"{r.name}: FAIL — {r.detail}"))

    rprint()
    hard_failed = [r for r in results if not r.passed and not r.optional]
    warned = [r for r in results if not r.passed and r.optional]
    passed = [r for r in results if r.passed]

    if not hard_failed:
        warn_note = f" ({len(warned)} optional check{'s' if len(warned) != 1 else ''} not configured)" if warned else ""
        rprint(fmt.success(f"{len(passed)}/{len(results)} core checks passed{warn_note}"))
    else:
        rprint(fmt.error(f"{len(hard_failed)} check{'s' if len(hard_failed) != 1 else ''} failed"))
    rprint()

    if hard_failed:
        raise typer.Exit(code=1)


# ── audit-skill ──────────────────────────────────────────────────────

# High-risk command patterns for skill auditing
_HIGH_RISK_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"rm\s+-rf\s+/(?!\w)", "name": "rm -rf /"},
    {"pattern": r"sudo\s+rm", "name": "sudo rm"},
    {"pattern": r"curl[^|]*\|\s*(?:ba)?sh", "name": "curl | sh"},
    {"pattern": r"wget[^|]*\|\s*(?:ba)?sh", "name": "wget | sh"},
    {"pattern": r"eval\s*\(", "name": "eval()"},
    {"pattern": r"exec\s*\(", "name": "exec()"},
    {"pattern": r"chmod\s+777", "name": "chmod 777"},
    {"pattern": r":\(\)\{\s*:\|:&\s*\};:", "name": "fork bomb"},
    {"pattern": r"dd\s+if=/dev/(?:zero|random)\s+of=/dev", "name": "dd to device"},
    {"pattern": r"mkfs", "name": "mkfs (format)"},
    {"pattern": r"base64\s+-d[^|]*\|\s*(?:ba)?sh", "name": "base64 decode | sh"},
]


@dataclass
class QuickScanResults:
    secrets: int
    urls: list[str]
    high_risk_commands: list[dict[str, Any]]


def _run_quick_scan(content: str) -> QuickScanResults:
    """Run deterministic security analysis on skill content."""
    # 1. Scan for secrets
    engine = PatternEngine(DEFAULT_SECRET_PATTERNS)
    secret_matches = engine.scan(content)

    # 2. Extract URLs
    url_regex = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
    urls = list(dict.fromkeys(url_regex.findall(content)))  # deduplicate, preserve order

    # 3. Detect high-risk commands
    commands: list[dict[str, Any]] = []
    for hp in _HIGH_RISK_PATTERNS:
        compiled = re.compile(hp["pattern"], re.IGNORECASE)
        for m in compiled.finditer(content):
            line_number = content[:m.start()].count("\n") + 1
            commands.append({"command": hp["name"], "line": line_number})

    return QuickScanResults(
        secrets=len(secret_matches),
        urls=urls,
        high_risk_commands=commands,
    )


def _display_quick_scan(scan: QuickScanResults, skill_name: str) -> None:
    """Render human-readable quick scan results."""
    print("\n\U0001f4ca Quick Scan Results")
    print("\u2550" * 60)

    # Secrets
    if scan.secrets == 0:
        print("\u2713 Secrets: None detected")
    else:
        print(f"\u26a0\ufe0f  Secrets: {scan.secrets} found")
        print("   \u2192 API keys, tokens, or credentials detected")
        print("   \u2192 Run: rafter agent scan <path> for details")

    # URLs
    if not scan.urls:
        print("\u2713 External URLs: None")
    else:
        print(f"\u26a0\ufe0f  External URLs: {len(scan.urls)} found")
        for url in scan.urls[:5]:
            print(f"   \u2022 {url}")
        if len(scan.urls) > 5:
            print(f"   ... and {len(scan.urls) - 5} more")

    # High-risk commands
    if not scan.high_risk_commands:
        print("\u2713 High-risk commands: None detected")
    else:
        print(f"\u26a0\ufe0f  High-risk commands: {len(scan.high_risk_commands)} found")
        for cmd in scan.high_risk_commands[:5]:
            print(f"   \u2022 {cmd['command']} (line {cmd['line']})")
        if len(scan.high_risk_commands) > 5:
            print(f"   ... and {len(scan.high_risk_commands) - 5} more")

    print()


def _generate_manual_review_prompt(
    skill_name: str,
    skill_path: str,
    scan: QuickScanResults,
    content: str,
) -> str:
    """Construct a security assessment prompt for external AI review."""
    urls_detail = ""
    if scan.urls:
        urls_detail = "\n  " + "\n  ".join(scan.urls)

    commands_detail = ""
    if scan.high_risk_commands:
        commands_detail = "\n  " + "\n  ".join(
            f"{c['command']} (line {c['line']})" for c in scan.high_risk_commands
        )

    return f"""You are reviewing a Claude Code skill for security issues. Analyze the skill below and provide:

1. **Security Assessment**: Evaluate trustworthiness, identify risks
2. **External Dependencies**: Review URLs, APIs, network calls - are they trustworthy?
3. **Command Safety**: Analyze shell commands - any dangerous patterns?
4. **Bundled Resources**: Check for suspicious scripts, images, binaries
5. **Prompt Injection Risks**: Could malicious input exploit this skill?
6. **Data Exfiltration**: Does it send sensitive data externally?
7. **Credential Handling**: How are API keys/secrets managed?
8. **Input Validation**: Is user input properly sanitized?
9. **File System Access**: What files does it read/write?
10. **Scope Alignment**: Does behavior match stated purpose?
11. **Recommendations**: Should I install this? What precautions?

**Skill**: {skill_name}
**Path**: {skill_path}

**Quick Scan Findings**:
- Secrets detected: {scan.secrets}
- External URLs: {len(scan.urls)}{urls_detail}
- High-risk commands: {len(scan.high_risk_commands)}{commands_detail}

**Skill Content**:
```markdown
{content}
```

Provide a clear risk rating (LOW/MEDIUM/HIGH/CRITICAL) and actionable recommendations."""


@agent_app.command("audit-skill")
def audit_skill(
    skill_path: str = typer.Argument(..., help="Path to skill file to audit"),
    skip_openclaw: bool = typer.Option(False, "--skip-openclaw", help="Skip OpenClaw integration, show manual review prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Security audit of a Claude Code skill file."""
    # Validate skill file exists
    resolved = Path(skill_path).resolve()
    if not resolved.exists():
        print(f"Error: Skill file not found: {skill_path}", file=sys.stderr)
        raise typer.Exit(code=1)

    skill_content = resolved.read_text(encoding="utf-8")
    skill_name = resolved.name

    # Run deterministic analysis
    if not json_output:
        print(f"\n\U0001f50d Auditing skill: {skill_name}\n")
        print("\u2550" * 60)
        print("Running quick security scan...\n")

    quick_scan = _run_quick_scan(skill_content)

    # Display quick scan results
    if not json_output:
        _display_quick_scan(quick_scan, skill_name)

    # Check OpenClaw availability
    skill_manager = SkillManager()
    openclaw_available = skill_manager.is_openclaw_installed()
    rafter_skill_installed = skill_manager.is_rafter_skill_installed()

    if json_output:
        result = {
            "skill": skill_name,
            "path": str(resolved),
            "quickScan": {
                "secrets": quick_scan.secrets,
                "urls": quick_scan.urls,
                "highRiskCommands": quick_scan.high_risk_commands,
            },
            "openClawAvailable": openclaw_available,
            "rafterSkillInstalled": rafter_skill_installed,
        }
        print(json.dumps(result, indent=2))
        if quick_scan.secrets > 0 or len(quick_scan.high_risk_commands) > 0:
            raise typer.Exit(code=1)
        return

    # Check if we can use OpenClaw
    if openclaw_available and not skip_openclaw:
        if not rafter_skill_installed:
            print("\n\u26a0\ufe0f  Rafter Security skill not installed in OpenClaw.")
            print("   Run: rafter agent init\n")
        else:
            print("\n\U0001f916 For comprehensive security review:\n")
            print("   1. Open OpenClaw")
            print(f"   2. Run: /rafter-audit-skill {resolved}")
            print("\n   The auditor will analyze:")
            print("   \u2022 Trust & attribution")
            print("   \u2022 Network security")
            print("   \u2022 Command execution risks")
            print("   \u2022 File system access")
            print("   \u2022 Credential handling")
            print("   \u2022 Input validation & injection risks")
            print("   \u2022 Data exfiltration patterns")
            print("   \u2022 Obfuscation techniques")
            print("   \u2022 Scope & intent alignment")
            print("   \u2022 Error handling & info disclosure")
            print("   \u2022 Dependencies & supply chain")
            print("   \u2022 Environment manipulation\n")
    else:
        # OpenClaw not available or skipped — show manual review prompt
        print("\n\U0001f4cb Manual Security Review Prompt\n")
        print("\u2550" * 60)
        print("\nCopy the following to your AI assistant for review:\n")
        print("\u2500" * 60)
        print(_generate_manual_review_prompt(skill_name, str(resolved), quick_scan, skill_content))
        print("\u2500" * 60)

    print()

    if quick_scan.secrets > 0 or len(quick_scan.high_risk_commands) > 0:
        raise typer.Exit(code=1)


# ── update-gitleaks ──────────────────────────────────────────────────────


@agent_app.command("update-gitleaks")
def update_gitleaks(
    version: str = typer.Option(
        None,
        "--version",
        help="Gitleaks version to install (default: bundled version)",
    ),
):
    """Update (or reinstall) the managed gitleaks binary."""
    from ..utils.binary_manager import GITLEAKS_VERSION

    target_version = version or GITLEAKS_VERSION
    _bm = BinaryManager()

    if not _bm.is_platform_supported():
        rprint(fmt.error(
            f"Gitleaks not available for {_bm._sys_platform()}/{_bm._machine()}"
        ))
        raise typer.Exit(code=1)

    # Show current version if installed
    _rafter_bin = _bm.get_gitleaks_path()
    if _rafter_bin.exists():
        result = _bm.verify_gitleaks_verbose()
        if result["ok"]:
            rprint(fmt.info(f"Current: {result['stdout']}"))
        else:
            rprint(fmt.warning(f"Current binary at {_rafter_bin} is not working"))
    else:
        rprint(fmt.info("Gitleaks not currently installed (managed binary)"))

    rprint(fmt.info(f"Installing gitleaks v{target_version}..."))
    rprint()

    try:
        _bm.download_gitleaks(on_progress=typer.echo, version=target_version)
        rprint()
        result = _bm.verify_gitleaks_verbose()
        rprint(fmt.success(f"Gitleaks updated: {result['stdout']}"))
        rprint(fmt.info(f"  Binary: {_rafter_bin}"))
    except Exception as _err:
        rprint()
        rprint(fmt.error(f"Update failed: {_err}"))
        rprint(fmt.info(
            "To fix: install gitleaks manually "
            "(https://github.com/gitleaks/gitleaks/releases) "
            "and ensure it is on PATH."
        ))
        raise typer.Exit(code=1)


# ── agent status ─────────────────────────────────────────────────────────

@agent_app.command("status")
def status():
    """Show agent security status dashboard."""
    from ..core.config_schema import get_audit_log_path, get_rafter_dir

    rafter_dir = get_rafter_dir()
    audit_path = get_audit_log_path()

    print("Rafter Agent Status")
    print("=" * 50)

    # --- Config ---
    config_path = rafter_dir / "config.json"
    if config_path.exists():
        try:
            cfg = ConfigManager().load()
            print(f"\nConfig:       {config_path}")
            print(f"Risk level:   {cfg.agent.risk_level}")
        except Exception:
            print(f"\nConfig:       {config_path} (parse error)")
    else:
        print(f"\nConfig:       not found — run: rafter agent init")

    # --- Gitleaks ---
    gl_path = shutil.which("gitleaks") or str(rafter_dir / "bin" / "gitleaks")
    if shutil.which("gitleaks"):
        try:
            ver = subprocess.run(["gitleaks", "version"], capture_output=True, text=True, timeout=5)
            print(f"Gitleaks:     {ver.stdout.strip()} (PATH)")
        except Exception:
            print("Gitleaks:     on PATH (version check failed)")
    elif Path(gl_path).exists():
        print(f"Gitleaks:     {gl_path} (local)")
    else:
        print("Gitleaks:     not found — run: rafter agent init")

    # --- Claude Code hooks ---
    claude_dir = Path.home() / ".claude"
    settings_path = claude_dir / "settings.json"
    pretool_ok = posttool_ok = False
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            hooks = settings.get("hooks", {})
            for hook_entry in hooks.get("PreToolUse", []):
                for h in hook_entry.get("hooks", []):
                    if "rafter hook pretool" in h.get("command", ""):
                        pretool_ok = True
            for hook_entry in hooks.get("PostToolUse", []):
                for h in hook_entry.get("hooks", []):
                    if "rafter hook posttool" in h.get("command", ""):
                        posttool_ok = True
        except Exception:
            pass
    pretool_status = "installed" if pretool_ok else "not installed — run: rafter agent init"
    posttool_status = "installed" if posttool_ok else "not installed — run: rafter agent init"
    print(f"PreToolUse:   {pretool_status}")
    print(f"PostToolUse:  {posttool_status}")

    # --- OpenClaw skill ---
    skill_path = Path.home() / ".openclaw" / "skills" / "rafter-security.md"
    if skill_path.exists():
        print(f"OpenClaw:     skill installed ({skill_path})")
    elif (Path.home() / ".openclaw").exists():
        print("OpenClaw:     detected but skill missing — run: rafter agent init")
    else:
        print("OpenClaw:     not detected (optional)")

    # --- Audit log summary ---
    print(f"\nAudit log:    {audit_path}")
    if audit_path.exists():
        logger = AuditLogger()
        all_entries = logger.read()
        total = len(all_entries)
        secrets = sum(1 for e in all_entries if e.get("event_type") == "secret_detected")
        blocked = sum(1 for e in all_entries if e.get("event_type") == "command_intercepted"
                      and e.get("resolution", {}).get("action_taken") == "blocked")
        print(f"Total events: {total}  |  Secrets detected: {secrets}  |  Commands blocked: {blocked}")

        recent = logger.read(limit=5)
        if recent:
            print("\nRecent events:")
            for e in reversed(recent):
                ts = e.get("timestamp", "")[:19].replace("T", " ")
                evt = e.get("event_type", "unknown")
                action = e.get("resolution", {}).get("action_taken", "")
                print(f"  {ts}  {evt}  [{action}]")
    else:
        print("No events logged yet.")

    print()


# ── baseline ─────────────────────────────────────────────────────────

_BASELINE_PATH = Path.home() / ".rafter" / "baseline.json"

baseline_app = typer.Typer(name="baseline", help="Manage the findings baseline (allowlist for known findings)", no_args_is_help=True)
agent_app.add_typer(baseline_app)


def _load_baseline() -> dict:
    if not _BASELINE_PATH.exists():
        return {"version": 1, "created": "", "updated": "", "entries": []}
    try:
        return json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "created": "", "updated": "", "entries": []}


def _save_baseline(data: dict) -> None:
    _BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _BASELINE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_baseline_entries() -> list[dict]:
    return _load_baseline().get("entries", [])


def _apply_baseline(results: list[ScanResult], entries: list[dict]) -> list[ScanResult]:
    if not entries:
        return results
    filtered = []
    for r in results:
        kept = [
            m for m in r.matches
            if not any(
                e["file"] == r.file
                and e["pattern"] == m.pattern.name
                and (e.get("line") is None or e.get("line") == m.line)
                for e in entries
            )
        ]
        if kept:
            filtered.append(ScanResult(file=r.file, matches=kept))
    return filtered


@baseline_app.command("create")
def baseline_create(
    path: str = typer.Argument(".", help="Path to scan"),
    engine: str = typer.Option("auto", "--engine", help="gitleaks or patterns"),
):
    """Scan and save all current findings as the baseline."""
    import datetime
    resolved = os.path.abspath(path)
    if not os.path.exists(resolved):
        print(f"Error: Path not found: {resolved}", file=sys.stderr)
        raise typer.Exit(code=2)

    manager = ConfigManager()
    cfg = manager.load_with_policy()
    scan_cfg = cfg.agent.scan

    print(f"Scanning {resolved} to build baseline...", file=sys.stderr)

    eng = _select_engine(engine, quiet=False)
    if os.path.isdir(resolved):
        results = _scan_directory(resolved, eng, scan_cfg)
    else:
        custom_patterns = (
            [{"name": p.name, "regex": p.regex, "severity": p.severity} for p in scan_cfg.custom_patterns]
            if scan_cfg.custom_patterns else None
        )
        results = _scan_file(resolved, eng, custom_patterns)

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    entries = []
    for r in results:
        for m in r.matches:
            entries.append({"file": r.file, "line": m.line, "pattern": m.pattern.name, "addedAt": now})

    existing = _load_baseline()
    data = {
        "version": 1,
        "created": existing.get("created") or now,
        "updated": now,
        "entries": entries,
    }
    _save_baseline(data)

    if not entries:
        rprint(fmt.success("No findings — baseline is empty (all clean)"))
    else:
        rprint(fmt.success(f"Baseline saved: {len(entries)} finding(s) recorded"))
        rprint(f"  Location: {_BASELINE_PATH}")
        rprint()
        rprint("Future scans with --baseline will suppress these findings.")


@baseline_app.command("show")
def baseline_show(
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show current baseline entries."""
    data = _load_baseline()

    if json_out:
        print(json.dumps(data, indent=2))
        return

    entries = data.get("entries", [])
    if not entries:
        print("Baseline is empty. Run: rafter agent baseline create")
        return

    print(f"Baseline: {len(entries)} entries")
    if data.get("updated"):
        print(f"Updated: {data['updated']}")
    print()

    by_file: dict[str, list] = {}
    for e in entries:
        by_file.setdefault(e["file"], []).append(e)

    for file, file_entries in by_file.items():
        rprint(fmt.info(file))
        for e in file_entries:
            loc = f"line {e['line']}" if e.get("line") is not None else "unknown location"
            print(f"  {e['pattern']} ({loc})")
        print()


@baseline_app.command("clear")
def baseline_clear():
    """Remove all baseline entries."""
    if not _BASELINE_PATH.exists():
        print("No baseline file found — nothing to clear.")
        return
    _BASELINE_PATH.unlink()
    rprint(fmt.success("Baseline cleared"))


@baseline_app.command("add")
def baseline_add(
    file: str = typer.Option(..., "--file", help="File path"),
    pattern: str = typer.Option(..., "--pattern", help="Pattern name (e.g. 'AWS Access Key')"),
    line: int = typer.Option(None, "--line", help="Line number"),
):
    """Manually add a finding to the baseline."""
    import datetime
    data = _load_baseline()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    entry = {
        "file": os.path.abspath(file),
        "line": line,
        "pattern": pattern,
        "addedAt": now,
    }
    data.setdefault("entries", []).append(entry)
    data["updated"] = now
    if not data.get("created"):
        data["created"] = now
    _save_baseline(data)

    rprint(fmt.success(f"Added to baseline: {pattern} in {file}"))
