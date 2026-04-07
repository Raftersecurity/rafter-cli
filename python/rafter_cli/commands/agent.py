"""Agent security commands: init, scan, audit, exec, config, install-hook, verify, audit-skill."""
from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
from rich import print as rprint

from .. import __version__
from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..core.config_manager import ConfigManager
from ..core.pattern_engine import PatternEngine
from ..scanners.gitleaks import GitleaksScanner
from ..scanners.regex_scanner import RegexScanner, ScanResult
from ..scanners.secret_patterns import DEFAULT_SECRET_PATTERNS
from ..utils.formatter import fmt, is_agent_mode, print_stderr
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


def _resolve_rafter_path() -> str:
    """Find the absolute path to the rafter binary for reliable hook invocation.

    Claude Code hooks run in a minimal shell environment that may not include
    the user's PATH additions (e.g. ~/.local/bin, ~/go/bin). Using the full
    path ensures hooks work regardless of the shell environment.
    """
    import shutil

    rafter_bin = shutil.which("rafter")
    if rafter_bin:
        return str(Path(rafter_bin).resolve())

    # Common installation locations as fallback
    home = Path.home()
    candidates = [
        home / ".local" / "bin" / "rafter",
        home / "go" / "bin" / "rafter",
        Path("/usr/local/bin/rafter"),
        Path("/opt/homebrew/bin/rafter"),
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate)

    # Last resort: bare command name (may fail in restricted PATH environments)
    return "rafter"


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

    rafter_bin = _resolve_rafter_path()
    pre_command = f"{rafter_bin} hook pretool"
    post_command = f"{rafter_bin} hook posttool"

    # Also match old bare "rafter" commands for dedup cleanup
    _old_pre = "rafter hook pretool"
    _old_post = "rafter hook posttool"

    if "PostToolUse" not in settings["hooks"]:
        settings["hooks"]["PostToolUse"] = []

    # Remove any existing Rafter hooks (old or new format) to avoid duplicates
    settings["hooks"]["PreToolUse"] = [
        entry for entry in settings["hooks"]["PreToolUse"]
        if not any(
            h.get("command", "") in (pre_command, _old_pre)
            or "rafter hook pretool" in h.get("command", "")
            for h in (entry.get("hooks") or [])
        )
    ]
    settings["hooks"]["PostToolUse"] = [
        entry for entry in settings["hooks"]["PostToolUse"]
        if not any(
            h.get("command", "") in (post_command, _old_post)
            or "rafter hook posttool" in h.get("command", "")
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
    if rafter_bin != "rafter":
        rprint(fmt.info(f"Using resolved path: {rafter_bin}"))


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

    openclaw_dir = home / ".openclaw"
    if not openclaw_dir.exists():
        return False, source_path, str(dest_path), f"OpenClaw not found: {openclaw_dir}"

    # Ensure skills directory exists (may not exist on fresh OpenClaw installs)
    skills_dir.mkdir(parents=True, exist_ok=True)

    try:
        content = importlib.resources.files("rafter_cli.resources").joinpath("rafter-security-skill.md").read_text(encoding="utf-8")
    except Exception as e:
        return False, source_path, str(dest_path), f"Source skill file not found: {e}"

    try:
        dest_path.write_text(content, encoding="utf-8")
        return True, source_path, str(dest_path), ""
    except Exception as e:
        return False, source_path, str(dest_path), str(e)


def _install_codex_skills() -> tuple[bool, str]:
    """Install Rafter skills to ~/.agents/skills/ for Codex CLI. Returns (ok, error)."""
    home = Path.home()
    agents_skills_dir = home / ".agents" / "skills"

    try:
        # Install backend skill
        backend_dir = agents_skills_dir / "rafter"
        backend_dir.mkdir(parents=True, exist_ok=True)
        res = importlib.resources.files("rafter_cli.resources")
        try:
            content = res.joinpath("skills", "rafter", "SKILL.md").read_text(encoding="utf-8")
            (backend_dir / "SKILL.md").write_text(content, encoding="utf-8")
            rprint(fmt.success(f"Installed Rafter Remote skill to {backend_dir / 'SKILL.md'}"))
        except Exception:
            rprint(fmt.warning("Remote skill template not found in package resources"))

        # Install agent security skill
        agent_dir = agents_skills_dir / "rafter-agent-security"
        agent_dir.mkdir(parents=True, exist_ok=True)
        try:
            content = res.joinpath("skills", "rafter-agent-security", "SKILL.md").read_text(encoding="utf-8")
            (agent_dir / "SKILL.md").write_text(content, encoding="utf-8")
            rprint(fmt.success(f"Installed Rafter Agent Security skill to {agent_dir / 'SKILL.md'}"))
        except Exception:
            rprint(fmt.warning("Agent Security skill template not found in package resources"))

        return True, ""
    except Exception as e:
        return False, str(e)


# ── MCP server entry (shared across MCP-native clients) ──────────────

_RAFTER_MCP_ENTRY = {
    "command": "rafter",
    "args": ["mcp", "serve"],
}


def _install_gemini_mcp() -> bool:
    """Install MCP server config for Gemini CLI (~/.gemini/settings.json)."""
    home = Path.home()
    gemini_dir = home / ".gemini"
    settings_path = gemini_dir / "settings.json"

    gemini_dir.mkdir(parents=True, exist_ok=True)

    settings: dict[str, Any] = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, ValueError):
            rprint(fmt.warning("Existing Gemini settings.json was unreadable, creating new one"))

    if "mcpServers" not in settings:
        settings["mcpServers"] = {}
    settings["mcpServers"]["rafter"] = {**_RAFTER_MCP_ENTRY}

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    rprint(fmt.success(f"Installed Rafter MCP server to {settings_path}"))
    return True


def _install_cursor_mcp() -> bool:
    """Install MCP server config for Cursor (~/.cursor/mcp.json)."""
    home = Path.home()
    cursor_dir = home / ".cursor"
    mcp_path = cursor_dir / "mcp.json"

    cursor_dir.mkdir(parents=True, exist_ok=True)

    config: dict[str, Any] = {}
    if mcp_path.exists():
        try:
            config = json.loads(mcp_path.read_text())
        except (json.JSONDecodeError, ValueError):
            rprint(fmt.warning("Existing Cursor mcp.json was unreadable, creating new one"))

    if "mcpServers" not in config:
        config["mcpServers"] = {}
    config["mcpServers"]["rafter"] = {**_RAFTER_MCP_ENTRY}

    mcp_path.write_text(json.dumps(config, indent=2) + "\n")
    rprint(fmt.success(f"Installed Rafter MCP server to {mcp_path}"))
    return True


def _install_windsurf_mcp() -> bool:
    """Install MCP server config for Windsurf (~/.codeium/windsurf/mcp_config.json)."""
    home = Path.home()
    windsurf_dir = home / ".codeium" / "windsurf"
    mcp_path = windsurf_dir / "mcp_config.json"

    windsurf_dir.mkdir(parents=True, exist_ok=True)

    config: dict[str, Any] = {}
    if mcp_path.exists():
        try:
            config = json.loads(mcp_path.read_text())
        except (json.JSONDecodeError, ValueError):
            rprint(fmt.warning("Existing Windsurf mcp_config.json was unreadable, creating new one"))

    if "mcpServers" not in config:
        config["mcpServers"] = {}
    config["mcpServers"]["rafter"] = {**_RAFTER_MCP_ENTRY}

    mcp_path.write_text(json.dumps(config, indent=2) + "\n")
    rprint(fmt.success(f"Installed Rafter MCP server to {mcp_path}"))
    return True


def _install_continue_dev_mcp() -> bool:
    """Install MCP server config for Continue.dev (~/.continue/config.json)."""
    home = Path.home()
    continue_dir = home / ".continue"
    config_path = continue_dir / "config.json"

    continue_dir.mkdir(parents=True, exist_ok=True)

    config: dict[str, Any] = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, ValueError):
            rprint(fmt.warning("Existing Continue.dev config.json was unreadable, creating new one"))

    if "mcpServers" not in config:
        config["mcpServers"] = []

    # Array format (older Continue.dev) vs object format (newer)
    if isinstance(config["mcpServers"], list):
        config["mcpServers"] = [s for s in config["mcpServers"] if s.get("name") != "rafter"]
        config["mcpServers"].append({
            "name": "rafter",
            "command": _RAFTER_MCP_ENTRY["command"],
            "args": _RAFTER_MCP_ENTRY["args"],
        })
    else:
        config["mcpServers"]["rafter"] = {**_RAFTER_MCP_ENTRY}

    config_path.write_text(json.dumps(config, indent=2) + "\n")
    rprint(fmt.success(f"Installed Rafter MCP server to {config_path}"))
    return True


def _install_aider_mcp() -> bool:
    """Install MCP config for Aider (~/.aider.conf.yml)."""
    home = Path.home()
    config_path = home / ".aider.conf.yml"

    content = ""
    if config_path.exists():
        content = config_path.read_text()

    if "rafter mcp serve" in content:
        rprint(fmt.success("Rafter MCP already configured in Aider config"))
        return True

    mcp_line = "\n# Rafter security MCP server\nmcp-server-command: rafter mcp serve\n"
    config_path.write_text(content + mcp_line)
    rprint(fmt.success(f"Installed Rafter MCP server to {config_path}"))
    return True


@agent_app.command()
def init(
    risk_level: str = typer.Option("moderate", "--risk-level", help="minimal, moderate, or aggressive"),
    with_gitleaks: bool = typer.Option(False, "--with-gitleaks", help="Download and install Gitleaks binary"),
    with_openclaw: bool = typer.Option(False, "--with-openclaw", help="Install OpenClaw integration"),
    with_claude_code: bool = typer.Option(False, "--with-claude-code", help="Install Claude Code integration"),
    with_codex: bool = typer.Option(False, "--with-codex", help="Install Codex CLI integration"),
    with_gemini: bool = typer.Option(False, "--with-gemini", help="Install Gemini CLI integration"),
    with_aider: bool = typer.Option(False, "--with-aider", help="Install Aider integration"),
    with_cursor: bool = typer.Option(False, "--with-cursor", help="Install Cursor integration"),
    with_windsurf: bool = typer.Option(False, "--with-windsurf", help="Install Windsurf integration"),
    with_continue: bool = typer.Option(False, "--with-continue", help="Install Continue.dev integration"),
    all_integrations: bool = typer.Option(False, "--all", help="Install all detected integrations and download Gitleaks"),
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
    has_claude_code = (home / ".claude").exists()
    has_codex = (home / ".codex").exists()
    has_gemini = (home / ".gemini").exists()
    has_cursor = (home / ".cursor").exists()
    has_windsurf = (home / ".codeium" / "windsurf").exists()
    has_continue_dev = (home / ".continue").exists()
    has_aider = (home / ".aider.conf.yml").exists()

    # Resolve opt-in flags (--all enables all detected)
    want_openclaw = with_openclaw or all_integrations
    want_claude_code = with_claude_code or all_integrations
    want_codex = with_codex or all_integrations
    want_gemini = with_gemini or all_integrations
    want_cursor = with_cursor or all_integrations
    want_windsurf = with_windsurf or all_integrations
    want_continue = with_continue or all_integrations
    want_aider = with_aider or all_integrations
    want_gitleaks = with_gitleaks or all_integrations

    # Show detected environments
    detected = []
    if has_openclaw:
        detected.append("OpenClaw")
    if has_claude_code:
        detected.append("Claude Code")
    if has_codex:
        detected.append("Codex CLI")
    if has_gemini:
        detected.append("Gemini CLI")
    if has_cursor:
        detected.append("Cursor")
    if has_windsurf:
        detected.append("Windsurf")
    if has_continue_dev:
        detected.append("Continue.dev")
    if has_aider:
        detected.append("Aider")

    if detected:
        rprint(fmt.info(f"Detected environments: {', '.join(detected)}"))
    else:
        rprint(fmt.info("No agent environments detected"))

    # Warn about requested but undetected environments
    if want_openclaw and not has_openclaw:
        rprint(fmt.warning("OpenClaw requested but not detected (~/.openclaw not found)"))
    if want_claude_code and not has_claude_code:
        rprint(fmt.warning("Claude Code requested but not detected (~/.claude not found)"))
    if want_codex and not has_codex:
        rprint(fmt.warning("Codex CLI requested but not detected (~/.codex not found)"))
    if want_gemini and not has_gemini:
        rprint(fmt.warning("Gemini CLI requested but not detected (~/.gemini not found)"))
    if want_cursor and not has_cursor:
        rprint(fmt.warning("Cursor requested but not detected (~/.cursor not found)"))
    if want_windsurf and not has_windsurf:
        rprint(fmt.warning("Windsurf requested but not detected (~/.codeium/windsurf not found)"))
    if want_continue and not has_continue_dev:
        rprint(fmt.warning("Continue.dev requested but not detected (~/.continue not found)"))
    if want_aider and not has_aider:
        rprint(fmt.warning("Aider requested but not detected (~/.aider.conf.yml not found)"))

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

    # Gitleaks check (opt-in via --with-gitleaks or --all)
    if want_gitleaks:
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

    # Install OpenClaw skill if opted in
    openclaw_ok = False
    if has_openclaw and want_openclaw:
        ok, source, dest, error = _install_openclaw_skill()
        openclaw_ok = ok
        if ok:
            rprint(fmt.success(f"Installed Rafter Security skill to {dest}"))
            manager.set("agent.environments.openclaw.enabled", True)
        else:
            rprint(fmt.error("Failed to install Rafter Security skill"))
            rprint(fmt.warning(f"  Source: {source}"))
            rprint(fmt.warning(f"  Destination: {dest}"))
            if error:
                rprint(fmt.warning(f"  Error: {error}"))

    # Install Claude Code hooks if opted in
    claude_code_ok = False
    if has_claude_code and want_claude_code:
        try:
            _install_claude_code_hooks()
            manager.set("agent.environments.claude_code.enabled", True)
            claude_code_ok = True
        except Exception as e:
            rprint(fmt.error(f"Failed to install Claude Code hooks: {e}"))

    # Install Codex CLI skills if opted in
    codex_ok = False
    if has_codex and want_codex:
        try:
            ok, error = _install_codex_skills()
            codex_ok = ok
            if ok:
                manager.set("agent.environments.codex.enabled", True)
            else:
                rprint(fmt.error(f"Failed to install Codex CLI skills: {error}"))
        except Exception as e:
            rprint(fmt.error(f"Failed to install Codex CLI integration: {e}"))

    # Install Gemini CLI MCP if opted in
    gemini_ok = False
    if has_gemini and want_gemini:
        try:
            gemini_ok = _install_gemini_mcp()
            if gemini_ok:
                manager.set("agent.environments.gemini.enabled", True)
        except Exception as e:
            rprint(fmt.error(f"Failed to install Gemini CLI integration: {e}"))

    # Install Cursor MCP if opted in
    cursor_ok = False
    if has_cursor and want_cursor:
        try:
            cursor_ok = _install_cursor_mcp()
            if cursor_ok:
                manager.set("agent.environments.cursor.enabled", True)
        except Exception as e:
            rprint(fmt.error(f"Failed to install Cursor integration: {e}"))

    # Install Windsurf MCP if opted in
    windsurf_ok = False
    if has_windsurf and want_windsurf:
        try:
            windsurf_ok = _install_windsurf_mcp()
            if windsurf_ok:
                manager.set("agent.environments.windsurf.enabled", True)
        except Exception as e:
            rprint(fmt.error(f"Failed to install Windsurf integration: {e}"))

    # Install Continue.dev MCP if opted in
    continue_ok = False
    if has_continue_dev and want_continue:
        try:
            continue_ok = _install_continue_dev_mcp()
            if continue_ok:
                manager.set("agent.environments.continue_dev.enabled", True)
        except Exception as e:
            rprint(fmt.error(f"Failed to install Continue.dev integration: {e}"))

    # Install Aider MCP if opted in
    aider_ok = False
    if has_aider and want_aider:
        try:
            aider_ok = _install_aider_mcp()
            if aider_ok:
                manager.set("agent.environments.aider.enabled", True)
        except Exception as e:
            rprint(fmt.error(f"Failed to install Aider integration: {e}"))

    rprint()
    rprint(fmt.success("Agent security initialized!"))
    rprint()

    any_integration = openclaw_ok or claude_code_ok or codex_ok or gemini_ok or cursor_ok or windsurf_ok or continue_ok or aider_ok

    if any_integration:
        rprint("Next steps:")
        if openclaw_ok:
            rprint("  - Restart OpenClaw to load skill")
        if claude_code_ok:
            rprint("  - Restart Claude Code to load hooks")
        if codex_ok:
            rprint("  - Restart Codex CLI to load skills")
        if gemini_ok:
            rprint("  - Restart Gemini CLI to load MCP server")
        if cursor_ok:
            rprint("  - Restart Cursor to load MCP server")
        if windsurf_ok:
            rprint("  - Restart Windsurf to load MCP server")
        if continue_ok:
            rprint("  - Restart Continue.dev to load MCP server")
        if aider_ok:
            rprint("  - Restart Aider to load MCP server")
    elif detected:
        rprint("No integrations were installed. To install, re-run with opt-in flags:")
        rprint("  rafter agent init --all                  # Install all detected")
        if has_claude_code:
            rprint("  rafter agent init --with-claude-code     # Claude Code only")
        if has_openclaw:
            rprint("  rafter agent init --with-openclaw        # OpenClaw only")
        if has_codex:
            rprint("  rafter agent init --with-codex           # Codex CLI only")
        if has_gemini:
            rprint("  rafter agent init --with-gemini          # Gemini CLI only")
        if has_cursor:
            rprint("  rafter agent init --with-cursor          # Cursor only")
        if has_windsurf:
            rprint("  rafter agent init --with-windsurf        # Windsurf only")
        if has_continue_dev:
            rprint("  rafter agent init --with-continue        # Continue.dev only")
        if has_aider:
            rprint("  rafter agent init --with-aider           # Aider only")
    else:
        rprint("No agent environments detected. Install an agent tool and re-run with --with-<tool>.")

    rprint()
    rprint("  - Run: rafter scan local . (test secret scanning)")
    rprint("  - Configure: rafter agent config show")
    rprint()


# ── scan ─────────────────────────────────────────────────────────────


def _select_engine(preference: str, quiet: bool) -> str:
    """Return 'gitleaks' or 'patterns'."""
    valid_engines = ("auto", "gitleaks", "patterns")
    if preference not in valid_engines:
        print(f"Invalid engine: {preference}. Valid values: {', '.join(valid_engines)}", file=sys.stderr)
        raise typer.Exit(code=2)

    if preference == "patterns":
        return "patterns"

    scanner = GitleaksScanner()
    available = scanner.is_available()

    if preference == "gitleaks":
        if not available:
            if not quiet:
                print_stderr(fmt.warning("Gitleaks requested but not available, using patterns"))
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
    exit_on_findings: bool = True,
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
        if exit_on_findings:
            raise typer.Exit(code=1 if results else 0)
        return

    if not results:
        if not quiet:
            msg = f"No secrets detected in {context}" if context else "No secrets detected"
            rprint(f"\n{fmt.success(msg)}\n")
        if exit_on_findings:
            raise typer.Exit(code=0)
        return

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
    elif exit_on_findings:
        rprint("Run 'rafter agent audit' to see the security log.\n")

    if exit_on_findings:
        raise typer.Exit(code=1)


def _watch_and_scan(
    watch_path: str,
    engine: str,
    quiet: bool,
    json_output: bool,
    format: str,
    custom_patterns,
    scan_cfg,
) -> None:
    """Watch a path for changes and re-scan on each change. Ctrl+C exits."""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
    except ImportError:
        print("Error: watchdog package required for --watch mode. Install with: pip install watchdog", file=sys.stderr)
        raise typer.Exit(code=2)

    logger = AuditLogger()
    eng = _select_engine(engine, quiet)

    if not quiet:
        print_stderr(fmt.info(f"Watching {watch_path} for changes ({eng}). Press Ctrl+C to exit."))

    # Initial scan
    if os.path.isdir(watch_path):
        initial_results = _scan_directory(watch_path, eng, scan_cfg)
    else:
        initial_results = _scan_file(watch_path, eng, custom_patterns)

    if initial_results:
        rprint(fmt.warning("\n[Initial scan] Found secrets:"))
        _output_scan_results(initial_results, json_output, False, format=format, exit_on_findings=False)
        _log_watch_findings(logger, initial_results)
    elif not quiet:
        rprint(fmt.success("[Initial scan] No secrets detected"))

    import re as _re
    _IGNORE_PATTERN = _re.compile(r'(^|[/\\])(\.git|node_modules|\.hg|__pycache__|\.tox|\.venv)([/\\]|$)')

    class _Handler(FileSystemEventHandler):
        def _should_ignore(self, file_path: str) -> bool:
            return bool(_IGNORE_PATTERN.search(file_path))

        def _handle(self, file_path: str) -> None:
            if not os.path.isfile(file_path):
                return
            if self._should_ignore(file_path):
                return
            from datetime import datetime as _dt
            ts = _dt.now().strftime("%H:%M:%S")
            if not quiet:
                print(f"\n[{ts}] Changed: {file_path}", file=sys.stderr)
            results = _scan_file(file_path, eng, custom_patterns)
            if results:
                _output_scan_results(results, json_output, False, format=format, exit_on_findings=False)
                _log_watch_findings(logger, results)
            elif not quiet:
                rprint(fmt.success("  No secrets detected"))

        def on_modified(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

        def on_created(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

    event_handler = _Handler()
    observer = Observer()
    observer.schedule(event_handler, watch_path, recursive=True)
    observer.start()

    try:
        import time
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
        if not quiet:
            rprint(fmt.info("\nWatch mode stopped."))
    observer.join()


def _log_watch_findings(logger: AuditLogger, results: list[ScanResult]) -> None:
    for result in results:
        for match in result.matches:
            logger.log_secret_detected(
                location=result.file,
                secret_type=match.pattern.name,
                action_taken="allowed",
            )


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
    watch: bool = typer.Option(False, "--watch", help="Watch for file changes and re-scan on change"),
):
    """Scan files or directories for secrets. [deprecated: use 'rafter scan local' instead]"""
    print(
        "Warning: rafter agent scan is deprecated and will be removed in a future major version. "
        "Use rafter scan local instead.",
        file=sys.stderr,
    )
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
    share: bool = typer.Option(False, "--share", help="Generate a redacted excerpt for issue reports"),
):
    """View audit log entries."""
    if share:
        _audit_share()
        return

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
        et = e.get("eventType", e.get("event_type", "unknown"))
        ind = indicators.get(et, "[EVENT]" if is_agent_mode() else "\U0001f4dd")
        print(f"{ind} [{ts}] {et}")
        if e.get("agentType") or e.get("agent_type"):
            print(f"   Agent: {e.get('agentType') or e['agent_type']}")
        action = e.get("action") or {}
        if action.get("command"):
            print(f"   Command: {action['command']}")
        if action.get("riskLevel") or action.get("risk_level"):
            print(f"   Risk: {action.get('riskLevel') or action['risk_level']}")
        sc = e.get("securityCheck") or e.get("security_check") or {}
        print(f"   Check: {'PASSED' if sc.get('passed') else 'FAILED'}")
        if sc.get("reason"):
            print(f"   Reason: {sc['reason']}")
        res = e.get("resolution") or {}
        print(f"   Action: {res.get('actionTaken', res.get('action_taken', 'unknown'))}")
        if res.get("overrideReason") or res.get("override_reason"):
            print(f"   Override: {res.get('overrideReason') or res['override_reason']}")
        print()


# ── audit share helpers ───────────────────────────────────────────────


def _truncate_command(cmd: str, max_len: int = 60) -> str:
    if len(cmd) <= max_len:
        return cmd
    return cmd[:max_len] + "..."


def _format_share_detail(entry: dict) -> str:
    res = entry.get("resolution") or {}
    action = res.get("actionTaken", res.get("action_taken", "unknown"))
    suffix = f"[{action}]"
    event_type = entry.get("eventType", entry.get("event_type", ""))
    sc = entry.get("securityCheck") or entry.get("security_check") or {}
    action_block = entry.get("action") or {}

    if event_type == "secret_detected":
        reason = sc.get("reason", "")
        return f"{reason} {suffix}"

    if action_block.get("command"):
        return f"{_truncate_command(action_block['command'])} {suffix}"

    if sc.get("reason"):
        return f"{sc['reason']} {suffix}"

    return suffix


def _audit_share() -> None:
    version = __version__
    os_info = f"{platform.system().lower()}/{platform.machine()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    manager = ConfigManager()
    cfg = manager.load_with_policy()
    patterns = cfg.agent.command_policy.require_approval if cfg.agent and cfg.agent.command_policy else []
    risk_level = cfg.agent.risk_level if cfg.agent else "moderate"

    payload = json.dumps(sorted(patterns))
    policy_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]

    logger = AuditLogger()
    entries = logger.read(limit=5)

    lines = [
        "Rafter Audit Excerpt",
        f"Generated: {timestamp}",
        "",
        "Environment:",
        f"  CLI:    {version}",
        f"  OS:     {os_info}",
        f"  Policy: sha256:{policy_hash} ({risk_level})",
        "",
        "Recent events (last 5):",
    ]

    if not entries:
        lines.append("  (no entries)")
    else:
        for e in entries:
            ts = e.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except Exception:
                pass
            event_type = e.get("eventType", e.get("event_type", "unknown"))
            event_pad = event_type.ljust(20)
            risk_raw = (e.get("action") or {}).get("riskLevel", (e.get("action") or {}).get("risk_level", "low"))
            risk_pad = risk_raw.upper().ljust(8)
            detail = _format_share_detail(e)
            lines.append(f"  {ts}  {event_pad}  {risk_pad} {detail}")

    lines.append("")
    lines.append("Share this excerpt when reporting issues at https://github.com/Raftersecurity/rafter-cli/issues")

    print("\n".join(lines))


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
                    rprint(f"\nRun 'rafter scan local' for details.\n")
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
    if result["stdout"]:
        detail += f"\n   stdout: {result['stdout']}"
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
        return _CheckResult(name, False, "Not detected — run 'rafter agent init --with-claude-code' to enable", optional=True)

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
        return _CheckResult(name, False, "Rafter hooks not installed — run 'rafter agent init --with-claude-code'", optional=True)
    return _CheckResult(name, True, "Hooks installed")


def _check_openclaw() -> _CheckResult:
    """Check if OpenClaw integration is healthy."""
    name = "OpenClaw"
    home = Path.home()
    skills_dir = home / ".openclaw" / "skills"

    if not skills_dir.exists():
        return _CheckResult(name, False, "Not detected — run 'rafter agent init --with-openclaw' to enable", optional=True)

    skill_path = skills_dir / "rafter-security.md"
    if not skill_path.exists():
        return _CheckResult(name, False, "Rafter skill not installed — run 'rafter agent init --with-openclaw'", optional=True)

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


def _check_codex() -> _CheckResult:
    """Check if Codex CLI integration is healthy."""
    name = "Codex CLI"
    home = Path.home()

    if not (home / ".codex").exists():
        return _CheckResult(name, False, "Not detected — run 'rafter agent init --with-codex' to enable", optional=True)

    skill_path = home / ".agents" / "skills" / "rafter" / "SKILL.md"
    if not skill_path.exists():
        return _CheckResult(name, False, "Rafter skills not installed — run 'rafter agent init --with-codex'", optional=True)

    return _CheckResult(name, True, f"Skills installed ({home / '.agents' / 'skills'})")


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
        _check_codex(),
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
        print("   \u2192 Run: rafter scan local <path> for details")

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
        raise typer.Exit(code=2)

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
        has_findings = quick_scan.secrets > 0 or len(quick_scan.high_risk_commands) > 0
        print(json.dumps(result, indent=2))
        raise typer.Exit(code=1 if has_findings else 0)

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
        print("Gitleaks:     not found — run: rafter agent init --with-gitleaks")

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
    pretool_status = "installed" if pretool_ok else "not installed — run: rafter agent init --with-claude-code"
    posttool_status = "installed" if posttool_ok else "not installed — run: rafter agent init --with-claude-code"
    print(f"PreToolUse:   {pretool_status}")
    print(f"PostToolUse:  {posttool_status}")

    # --- OpenClaw skill ---
    skill_path = Path.home() / ".openclaw" / "skills" / "rafter-security.md"
    if skill_path.exists():
        print(f"OpenClaw:     skill installed ({skill_path})")
    elif (Path.home() / ".openclaw").exists():
        print("OpenClaw:     detected but skill missing — run: rafter agent init --with-openclaw")
    else:
        print("OpenClaw:     not detected (optional)")

    # --- Codex CLI skills ---
    codex_dir = Path.home() / ".codex"
    codex_skill_path = Path.home() / ".agents" / "skills" / "rafter" / "SKILL.md"
    if codex_skill_path.exists():
        print(f"Codex CLI:    skills installed ({Path.home() / '.agents' / 'skills'})")
    elif codex_dir.exists():
        print("Codex CLI:    detected but skills missing — run: rafter agent init --with-codex")
    else:
        print("Codex CLI:    not detected (optional)")

    # --- MCP-native AI engine integrations ---
    home = Path.home()
    mcp_agents = [
        {"name": "Gemini CLI", "flag": "--with-gemini", "config_dir": home / ".gemini", "config_file": home / ".gemini" / "settings.json", "needle": "rafter"},
        {"name": "Cursor", "flag": "--with-cursor", "config_dir": home / ".cursor", "config_file": home / ".cursor" / "mcp.json", "needle": "rafter"},
        {"name": "Windsurf", "flag": "--with-windsurf", "config_dir": home / ".codeium" / "windsurf", "config_file": home / ".codeium" / "windsurf" / "mcp_config.json", "needle": "rafter"},
        {"name": "Continue.dev", "flag": "--with-continue", "config_dir": home / ".continue", "config_file": home / ".continue" / "config.json", "needle": "rafter"},
    ]

    for agent in mcp_agents:
        label = f"{agent['name']}:".ljust(14)
        config_file = agent["config_file"]
        config_dir = agent["config_dir"]
        if config_file.exists():
            try:
                content = config_file.read_text()
                if agent["needle"] in content:
                    print(f"{label}MCP installed ({config_file})")
                else:
                    print(f"{label}detected but MCP missing — run: rafter agent init {agent['flag']}")
            except OSError:
                print(f"{label}config unreadable ({config_file})")
        elif config_dir.exists():
            print(f"{label}detected but MCP missing — run: rafter agent init {agent['flag']}")
        else:
            print(f"{label}not detected (optional)")

    # --- Aider ---
    aider_config = home / ".aider.conf.yml"
    if aider_config.exists():
        try:
            content = aider_config.read_text()
            if "rafter mcp serve" in content:
                print(f"Aider:        MCP installed ({aider_config})")
            else:
                print("Aider:        detected but MCP missing — run: rafter agent init --with-aider")
        except OSError:
            print(f"Aider:        config unreadable ({aider_config})")
    else:
        print("Aider:        not detected (optional)")

    # --- Audit log summary ---
    print(f"\nAudit log:    {audit_path}")
    if audit_path.exists():
        logger = AuditLogger()
        all_entries = logger.read()
        total = len(all_entries)
        secrets = sum(1 for e in all_entries if e.get("eventType", e.get("event_type")) == "secret_detected")
        blocked = sum(1 for e in all_entries if e.get("eventType", e.get("event_type")) == "command_intercepted"
                      and (e.get("resolution") or {}).get("actionTaken", (e.get("resolution") or {}).get("action_taken")) == "blocked")
        print(f"Total events: {total}  |  Secrets detected: {secrets}  |  Commands blocked: {blocked}")

        recent = logger.read(limit=5)
        if recent:
            print("\nRecent events:")
            for e in reversed(recent):
                ts = e.get("timestamp", "")[:19].replace("T", " ")
                evt = e.get("eventType", e.get("event_type", "unknown"))
                action = (e.get("resolution") or {}).get("actionTaken", (e.get("resolution") or {}).get("action_taken", ""))
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
