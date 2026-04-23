"""Per-component install/uninstall/detect logic for `rafter agent list/enable/disable`.

Each Rafter integration with an AI platform breaks into up to four slots:
  * hooks         — the platform's PreTool/PostTool wiring
  * mcp           — an MCP server entry
  * instructions  — a Rafter instruction block in the platform's global prose file
  * skills        — Rafter SKILL.md files

A component is one (platform, slot) pair. Users can install/uninstall components
individually via `rafter agent enable/disable <id>`; `rafter agent list` reports
install state across all registered components.
"""
from __future__ import annotations

import importlib.resources
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..core.config_manager import ConfigManager


# ── instruction block (mirrors node/src/commands/agent/instruction-block.ts) ──

RAFTER_MARKER_START = "<!-- rafter:start -->"
RAFTER_MARKER_END = "<!-- rafter:end -->"

RAFTER_INSTRUCTION_BLOCK = f"""{RAFTER_MARKER_START}
## Security: Rafter

Rafter is installed here — security, policy, and agent-governance tooling for AI workflows. Four skills ship with this install: `rafter`, `rafter-secure-design`, `rafter-code-review`, `rafter-skill-review`.

**Invoke a rafter skill when:**
- Designing a feature that touches auth, payments, credentials, tokens, sessions, file upload, user data, or data deletion → `rafter-secure-design` (BEFORE you write the code)
- You just wrote code handling user input, SQL, shell, credentials, file paths, or serialization → `rafter-code-review` (BEFORE declaring the feature done)
- Asked to install a third-party SKILL.md, MCP server, Cursor rule, or agent config → `rafter-skill-review` (BEFORE copying it anywhere)
- You need scanning, audit, policy, or command-risk evaluation, or you're security-adjacent and the angle isn't obvious → `rafter`

The `rafter` skill is the entry point for all CLI usage (secret scanning, remote SAST + SCA, deep-dive analysis, audit, policy, command-risk). Invoke it rather than shelling out to `rafter <command>` blind — it picks the right mode for your task (the quick local scanner catches secrets only; the remote engine does the real code analysis). Set `RAFTER_API_KEY` to unlock the remote analysis engine; local features work without it.
{RAFTER_MARKER_END}"""


def _inject_instruction_file(file_path: Path) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    existing = file_path.read_text(encoding="utf-8") if file_path.exists() else ""
    start = existing.find(RAFTER_MARKER_START)
    end = existing.find(RAFTER_MARKER_END)
    if start != -1 and end != -1:
        next_content = existing[:start] + RAFTER_INSTRUCTION_BLOCK + existing[end + len(RAFTER_MARKER_END):]
    else:
        if existing and not existing.endswith("\n\n"):
            existing = existing + ("\n" if existing.endswith("\n") else "\n\n")
        next_content = existing + RAFTER_INSTRUCTION_BLOCK + "\n"
    file_path.write_text(next_content, encoding="utf-8")


def _has_marker_block(file_path: Path) -> bool:
    if not file_path.exists():
        return False
    content = file_path.read_text(encoding="utf-8")
    return RAFTER_MARKER_START in content and RAFTER_MARKER_END in content


def _strip_marker_block(file_path: Path) -> bool:
    if not file_path.exists():
        return False
    content = file_path.read_text(encoding="utf-8")
    start = content.find(RAFTER_MARKER_START)
    end = content.find(RAFTER_MARKER_END)
    if start == -1 or end == -1:
        return False
    before = content[:start].rstrip()
    after = content[end + len(RAFTER_MARKER_END):].lstrip("\n")
    next_content = (before + "\n" if before else "") + after
    file_path.write_text(next_content, encoding="utf-8")
    return True


# ── JSON helpers ──────────────────────────────────────────────────────

def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return {}


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _hook_entry_has_rafter(entry: Any, prefix: str) -> bool:
    hooks = entry.get("hooks") if isinstance(entry, dict) else None
    if not isinstance(hooks, list):
        return False
    return any(str(h.get("command", "")).startswith(prefix) for h in hooks if isinstance(h, dict))


def _filter_hooks(arr: list[Any] | None, predicate: Callable[[Any], bool]) -> list[Any]:
    if not isinstance(arr, list):
        return []
    return [e for e in arr if not predicate(e)]


RAFTER_MCP_ENTRY: dict[str, Any] = {"command": "rafter", "args": ["mcp", "serve"]}


# ── Skill template lookup ─────────────────────────────────────────────

def _skill_text(*segments: str) -> str | None:
    try:
        ref = importlib.resources.files("rafter_cli.resources").joinpath(*segments)
        return ref.read_text(encoding="utf-8")
    except Exception:
        return None


# ── Component spec dataclass ─────────────────────────────────────────

@dataclass
class ComponentSpec:
    id: str
    platform: str
    kind: str
    description: str
    detect_dir: Path
    path: Path
    is_installed: Callable[[], bool]
    install: Callable[[], None]
    uninstall: Callable[[], None]


# ── Per-component builders ────────────────────────────────────────────

def _claude_code_hooks() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".claude"
    settings_path = detect_dir / "settings.json"

    def is_installed() -> bool:
        if not settings_path.exists():
            return False
        s = _read_json(settings_path)
        for entry in s.get("hooks", {}).get("PreToolUse", []) or []:
            if _hook_entry_has_rafter(entry, "rafter hook pretool"):
                return True
        return False

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        s = _read_json(settings_path) if settings_path.exists() else {}
        s.setdefault("hooks", {})
        hooks = s["hooks"]
        hooks.setdefault("PreToolUse", [])
        hooks.setdefault("PostToolUse", [])
        pre = {"type": "command", "command": "rafter hook pretool"}
        post = {"type": "command", "command": "rafter hook posttool"}
        hooks["PreToolUse"] = _filter_hooks(hooks["PreToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        hooks["PostToolUse"] = _filter_hooks(hooks["PostToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        # Strip legacy SessionStart entry from <=0.7.4 installs.
        if isinstance(hooks.get("SessionStart"), list):
            hooks["SessionStart"] = _filter_hooks(hooks["SessionStart"], lambda e: _hook_entry_has_rafter(e, "rafter hook session-start"))
            if not hooks["SessionStart"]:
                del hooks["SessionStart"]
        hooks["PreToolUse"].extend([
            {"matcher": "Bash", "hooks": [pre]},
            {"matcher": "Write|Edit", "hooks": [pre]},
        ])
        hooks["PostToolUse"].append({"matcher": ".*", "hooks": [post]})
        _write_json(settings_path, s)

    def uninstall() -> None:
        if not settings_path.exists():
            return
        s = _read_json(settings_path)
        hooks = s.get("hooks") or {}
        if "PreToolUse" in hooks:
            hooks["PreToolUse"] = _filter_hooks(hooks["PreToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        if "PostToolUse" in hooks:
            hooks["PostToolUse"] = _filter_hooks(hooks["PostToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        if isinstance(hooks.get("SessionStart"), list):
            hooks["SessionStart"] = _filter_hooks(hooks["SessionStart"], lambda e: _hook_entry_has_rafter(e, "rafter hook session-start"))
            if not hooks["SessionStart"]:
                del hooks["SessionStart"]
        _write_json(settings_path, s)

    return ComponentSpec(
        id="claude-code.hooks",
        platform="claude-code",
        kind="hooks",
        description="Claude Code PreToolUse + PostToolUse hooks",
        detect_dir=detect_dir,
        path=settings_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _claude_code_instructions() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".claude"
    file_path = detect_dir / "CLAUDE.md"
    return ComponentSpec(
        id="claude-code.instructions",
        platform="claude-code",
        kind="instructions",
        description="Claude Code global instruction block (~/.claude/CLAUDE.md)",
        detect_dir=detect_dir,
        path=file_path,
        is_installed=lambda: _has_marker_block(file_path),
        install=lambda: _inject_instruction_file(file_path),
        uninstall=lambda: _strip_marker_block(file_path),
    )


# Canonical rafter-authored skills installed by a per-platform "skills"
# component. Mirrors node/src/commands/agent/components.ts. Keep in sync with
# the SKILL.md files shipped under rafter_cli/resources/skills/.
_COMPONENT_SKILL_NAMES: tuple[str, ...] = (
    "rafter",
    "rafter-secure-design",
    "rafter-code-review",
    "rafter-skill-review",
)


def _skills_component(
    *,
    cid: str,
    platform: str,
    description: str,
    detect_dir: Path,
    skills_base_dir: Path,
) -> ComponentSpec:
    dest_paths: list[Path] = [
        skills_base_dir / name / "SKILL.md" for name in _COMPONENT_SKILL_NAMES
    ]

    def is_installed() -> bool:
        return any(p.exists() for p in dest_paths)

    def install() -> None:
        for name in _COMPONENT_SKILL_NAMES:
            dest = skills_base_dir / name / "SKILL.md"
            content = _skill_text("skills", name, "SKILL.md")
            if content is None and name == "rafter":
                # Legacy fallback — older python packages used rafter-security-skill.md
                content = _skill_text("rafter-security-skill.md")
            if content is None:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

    def uninstall() -> None:
        for p in dest_paths:
            if p.exists():
                p.unlink()
                try:
                    if p.parent.exists() and not any(p.parent.iterdir()):
                        p.parent.rmdir()
                except OSError:
                    pass

    return ComponentSpec(
        id=cid,
        platform=platform,
        kind="skills",
        description=description,
        detect_dir=detect_dir,
        path=skills_base_dir,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _claude_code_skills() -> ComponentSpec:
    home = Path.home()
    return _skills_component(
        cid="claude-code.skills",
        platform="claude-code",
        description="Claude Code skills (rafter + rafter-secure-design + rafter-code-review + rafter-skill-review)",
        detect_dir=home / ".claude",
        skills_base_dir=home / ".claude" / "skills",
    )


def _codex_skills() -> ComponentSpec:
    home = Path.home()
    return _skills_component(
        cid="codex.skills",
        platform="codex",
        description="Codex CLI skills (~/.agents/skills/rafter*)",
        detect_dir=home / ".codex",
        skills_base_dir=home / ".agents" / "skills",
    )


def _codex_hooks() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".codex"
    hooks_path = detect_dir / "hooks.json"

    def is_installed() -> bool:
        if not hooks_path.exists():
            return False
        cfg = _read_json(hooks_path)
        for entry in cfg.get("hooks", {}).get("PreToolUse", []) or []:
            if _hook_entry_has_rafter(entry, "rafter hook pretool"):
                return True
        return False

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        cfg = _read_json(hooks_path) if hooks_path.exists() else {}
        cfg.setdefault("hooks", {})
        h = cfg["hooks"]
        h.setdefault("PreToolUse", [])
        h.setdefault("PostToolUse", [])
        pre = {"type": "command", "command": "rafter hook pretool"}
        post = {"type": "command", "command": "rafter hook posttool"}
        h["PreToolUse"] = _filter_hooks(h["PreToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        h["PostToolUse"] = _filter_hooks(h["PostToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        h["PreToolUse"].append({"matcher": "Bash", "hooks": [pre]})
        h["PostToolUse"].append({"matcher": ".*", "hooks": [post]})
        _write_json(hooks_path, cfg)

    def uninstall() -> None:
        if not hooks_path.exists():
            return
        cfg = _read_json(hooks_path)
        h = cfg.get("hooks") or {}
        if "PreToolUse" in h:
            h["PreToolUse"] = _filter_hooks(h["PreToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        if "PostToolUse" in h:
            h["PostToolUse"] = _filter_hooks(h["PostToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        _write_json(hooks_path, cfg)

    return ComponentSpec(
        id="codex.hooks",
        platform="codex",
        kind="hooks",
        description="Codex CLI hooks (~/.codex/hooks.json)",
        detect_dir=detect_dir,
        path=hooks_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _cursor_hooks() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".cursor"
    hooks_path = detect_dir / "hooks.json"

    def is_installed() -> bool:
        if not hooks_path.exists():
            return False
        cfg = _read_json(hooks_path)
        for entry in cfg.get("hooks", {}).get("beforeShellExecution", []) or []:
            if "rafter hook pretool" in str(entry.get("command", "") if isinstance(entry, dict) else ""):
                return True
        return False

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        cfg = _read_json(hooks_path) if hooks_path.exists() else {}
        cfg.setdefault("version", 1)
        cfg.setdefault("hooks", {})
        h = cfg["hooks"]
        h.setdefault("beforeShellExecution", [])
        h["beforeShellExecution"] = [
            e for e in h["beforeShellExecution"]
            if "rafter hook pretool" not in str(e.get("command", "") if isinstance(e, dict) else "")
        ]
        h["beforeShellExecution"].append({
            "command": "rafter hook pretool --format cursor",
            "type": "command",
            "timeout": 5000,
        })
        _write_json(hooks_path, cfg)

    def uninstall() -> None:
        if not hooks_path.exists():
            return
        cfg = _read_json(hooks_path)
        h = cfg.get("hooks") or {}
        if "beforeShellExecution" in h:
            h["beforeShellExecution"] = [
                e for e in h["beforeShellExecution"]
                if "rafter hook pretool" not in str(e.get("command", "") if isinstance(e, dict) else "")
            ]
        _write_json(hooks_path, cfg)

    return ComponentSpec(
        id="cursor.hooks",
        platform="cursor",
        kind="hooks",
        description="Cursor hooks (~/.cursor/hooks.json)",
        detect_dir=detect_dir,
        path=hooks_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _cursor_instructions() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".cursor"
    file_path = detect_dir / "rules" / "rafter-security.mdc"

    def uninstall() -> None:
        if file_path.exists():
            file_path.unlink()

    return ComponentSpec(
        id="cursor.instructions",
        platform="cursor",
        kind="instructions",
        description="Cursor global rule block (~/.cursor/rules/rafter-security.mdc)",
        detect_dir=detect_dir,
        path=file_path,
        is_installed=lambda: _has_marker_block(file_path),
        install=lambda: _inject_instruction_file(file_path),
        uninstall=uninstall,
    )


def _cursor_mcp() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".cursor"
    mcp_path = detect_dir / "mcp.json"

    def is_installed() -> bool:
        return bool(_read_json(mcp_path).get("mcpServers", {}).get("rafter"))

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        cfg = _read_json(mcp_path) if mcp_path.exists() else {}
        cfg.setdefault("mcpServers", {})
        cfg["mcpServers"]["rafter"] = dict(RAFTER_MCP_ENTRY)
        _write_json(mcp_path, cfg)

    def uninstall() -> None:
        if not mcp_path.exists():
            return
        cfg = _read_json(mcp_path)
        servers = cfg.get("mcpServers")
        if isinstance(servers, dict) and "rafter" in servers:
            del servers["rafter"]
            _write_json(mcp_path, cfg)

    return ComponentSpec(
        id="cursor.mcp",
        platform="cursor",
        kind="mcp",
        description="Cursor MCP server entry (~/.cursor/mcp.json)",
        detect_dir=detect_dir,
        path=mcp_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _gemini_hooks() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".gemini"
    settings_path = detect_dir / "settings.json"

    def is_installed() -> bool:
        if not settings_path.exists():
            return False
        s = _read_json(settings_path)
        for entry in s.get("hooks", {}).get("BeforeTool", []) or []:
            if _hook_entry_has_rafter(entry, "rafter hook pretool"):
                return True
        return False

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        s = _read_json(settings_path) if settings_path.exists() else {}
        s.setdefault("hooks", {})
        h = s["hooks"]
        h.setdefault("BeforeTool", [])
        h.setdefault("AfterTool", [])
        h["BeforeTool"] = _filter_hooks(h["BeforeTool"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        h["AfterTool"] = _filter_hooks(h["AfterTool"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        h["BeforeTool"].append({
            "matcher": "shell|write_file",
            "hooks": [{"type": "command", "command": "rafter hook pretool --format gemini", "timeout": 5000}],
        })
        h["AfterTool"].append({
            "matcher": ".*",
            "hooks": [{"type": "command", "command": "rafter hook posttool --format gemini", "timeout": 5000}],
        })
        _write_json(settings_path, s)

    def uninstall() -> None:
        if not settings_path.exists():
            return
        s = _read_json(settings_path)
        h = s.get("hooks") or {}
        if "BeforeTool" in h:
            h["BeforeTool"] = _filter_hooks(h["BeforeTool"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        if "AfterTool" in h:
            h["AfterTool"] = _filter_hooks(h["AfterTool"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        _write_json(settings_path, s)

    return ComponentSpec(
        id="gemini.hooks",
        platform="gemini",
        kind="hooks",
        description="Gemini CLI BeforeTool + AfterTool hooks",
        detect_dir=detect_dir,
        path=settings_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _gemini_mcp() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".gemini"
    settings_path = detect_dir / "settings.json"

    def is_installed() -> bool:
        return bool(_read_json(settings_path).get("mcpServers", {}).get("rafter"))

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        s = _read_json(settings_path) if settings_path.exists() else {}
        s.setdefault("mcpServers", {})
        s["mcpServers"]["rafter"] = dict(RAFTER_MCP_ENTRY)
        _write_json(settings_path, s)

    def uninstall() -> None:
        if not settings_path.exists():
            return
        s = _read_json(settings_path)
        servers = s.get("mcpServers")
        if isinstance(servers, dict) and "rafter" in servers:
            del servers["rafter"]
            _write_json(settings_path, s)

    return ComponentSpec(
        id="gemini.mcp",
        platform="gemini",
        kind="mcp",
        description="Gemini CLI MCP server entry (~/.gemini/settings.json)",
        detect_dir=detect_dir,
        path=settings_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _windsurf_hooks() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".codeium" / "windsurf"
    hooks_path = home / ".windsurf" / "hooks.json"

    def is_installed() -> bool:
        if not hooks_path.exists():
            return False
        cfg = _read_json(hooks_path)
        for entry in cfg.get("hooks", {}).get("pre_run_command", []) or []:
            if "rafter hook pretool" in str(entry.get("command", "") if isinstance(entry, dict) else ""):
                return True
        return False

    def install() -> None:
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        cfg = _read_json(hooks_path) if hooks_path.exists() else {}
        cfg.setdefault("hooks", {})
        h = cfg["hooks"]
        for k in ("pre_run_command", "pre_write_code"):
            h.setdefault(k, [])
            h[k] = [e for e in h[k] if "rafter hook pretool" not in str(e.get("command", "") if isinstance(e, dict) else "")]
            h[k].append({"command": "rafter hook pretool --format windsurf", "show_output": True})
        _write_json(hooks_path, cfg)

    def uninstall() -> None:
        if not hooks_path.exists():
            return
        cfg = _read_json(hooks_path)
        h = cfg.get("hooks") or {}
        for k in ("pre_run_command", "pre_write_code"):
            if k in h:
                h[k] = [e for e in h[k] if "rafter hook pretool" not in str(e.get("command", "") if isinstance(e, dict) else "")]
        _write_json(hooks_path, cfg)

    return ComponentSpec(
        id="windsurf.hooks",
        platform="windsurf",
        kind="hooks",
        description="Windsurf hooks (~/.windsurf/hooks.json)",
        detect_dir=detect_dir,
        path=hooks_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _windsurf_mcp() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".codeium" / "windsurf"
    mcp_path = detect_dir / "mcp_config.json"

    def is_installed() -> bool:
        return bool(_read_json(mcp_path).get("mcpServers", {}).get("rafter"))

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        cfg = _read_json(mcp_path) if mcp_path.exists() else {}
        cfg.setdefault("mcpServers", {})
        cfg["mcpServers"]["rafter"] = dict(RAFTER_MCP_ENTRY)
        _write_json(mcp_path, cfg)

    def uninstall() -> None:
        if not mcp_path.exists():
            return
        cfg = _read_json(mcp_path)
        servers = cfg.get("mcpServers")
        if isinstance(servers, dict) and "rafter" in servers:
            del servers["rafter"]
            _write_json(mcp_path, cfg)

    return ComponentSpec(
        id="windsurf.mcp",
        platform="windsurf",
        kind="mcp",
        description="Windsurf MCP server entry",
        detect_dir=detect_dir,
        path=mcp_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _continue_hooks() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".continue"
    settings_path = detect_dir / "settings.json"

    def is_installed() -> bool:
        if not settings_path.exists():
            return False
        s = _read_json(settings_path)
        for entry in s.get("hooks", {}).get("PreToolUse", []) or []:
            if _hook_entry_has_rafter(entry, "rafter hook pretool"):
                return True
        return False

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        s = _read_json(settings_path) if settings_path.exists() else {}
        s.setdefault("hooks", {})
        h = s["hooks"]
        h.setdefault("PreToolUse", [])
        h.setdefault("PostToolUse", [])
        pre = {"type": "command", "command": "rafter hook pretool"}
        post = {"type": "command", "command": "rafter hook posttool"}
        h["PreToolUse"] = _filter_hooks(h["PreToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        h["PostToolUse"] = _filter_hooks(h["PostToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        h["PreToolUse"].extend([
            {"matcher": "Bash", "hooks": [pre]},
            {"matcher": "Write|Edit", "hooks": [pre]},
        ])
        h["PostToolUse"].append({"matcher": ".*", "hooks": [post]})
        _write_json(settings_path, s)

    def uninstall() -> None:
        if not settings_path.exists():
            return
        s = _read_json(settings_path)
        h = s.get("hooks") or {}
        if "PreToolUse" in h:
            h["PreToolUse"] = _filter_hooks(h["PreToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook pretool"))
        if "PostToolUse" in h:
            h["PostToolUse"] = _filter_hooks(h["PostToolUse"], lambda e: _hook_entry_has_rafter(e, "rafter hook posttool"))
        _write_json(settings_path, s)

    return ComponentSpec(
        id="continue.hooks",
        platform="continue",
        kind="hooks",
        description="Continue.dev PreToolUse + PostToolUse hooks",
        detect_dir=detect_dir,
        path=settings_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _continue_mcp() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".continue"
    config_path = detect_dir / "config.json"

    def is_installed() -> bool:
        cfg = _read_json(config_path)
        servers = cfg.get("mcpServers")
        if isinstance(servers, list):
            return any(isinstance(s, dict) and s.get("name") == "rafter" for s in servers)
        if isinstance(servers, dict):
            return bool(servers.get("rafter"))
        return False

    def install() -> None:
        detect_dir.mkdir(parents=True, exist_ok=True)
        cfg = _read_json(config_path) if config_path.exists() else {}
        servers = cfg.get("mcpServers")
        if isinstance(servers, list):
            servers = [s for s in servers if not (isinstance(s, dict) and s.get("name") == "rafter")]
            servers.append({"name": "rafter", **RAFTER_MCP_ENTRY})
            cfg["mcpServers"] = servers
        else:
            cfg.setdefault("mcpServers", {})
            cfg["mcpServers"]["rafter"] = dict(RAFTER_MCP_ENTRY)
        _write_json(config_path, cfg)

    def uninstall() -> None:
        if not config_path.exists():
            return
        cfg = _read_json(config_path)
        servers = cfg.get("mcpServers")
        changed = False
        if isinstance(servers, list):
            new = [s for s in servers if not (isinstance(s, dict) and s.get("name") == "rafter")]
            if len(new) != len(servers):
                cfg["mcpServers"] = new
                changed = True
        elif isinstance(servers, dict) and "rafter" in servers:
            del servers["rafter"]
            changed = True
        if changed:
            _write_json(config_path, cfg)

    return ComponentSpec(
        id="continue.mcp",
        platform="continue",
        kind="mcp",
        description="Continue.dev MCP server entry (~/.continue/config.json)",
        detect_dir=detect_dir,
        path=config_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _aider_mcp() -> ComponentSpec:
    home = Path.home()
    config_path = home / ".aider.conf.yml"
    header = "# Rafter security MCP server"

    def is_installed() -> bool:
        return config_path.exists() and "rafter mcp serve" in config_path.read_text(encoding="utf-8")

    def install() -> None:
        existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        if "rafter mcp serve" in existing:
            return
        block = f"\n{header}\nmcp-server-command: rafter mcp serve\n"
        config_path.write_text(existing + block, encoding="utf-8")

    def uninstall() -> None:
        if not config_path.exists():
            return
        lines = config_path.read_text(encoding="utf-8").split("\n")
        filtered = []
        for line in lines:
            stripped = line.strip()
            if stripped == header:
                continue
            if stripped.startswith("mcp-server-command:") and "rafter mcp serve" in stripped:
                continue
            filtered.append(line)
        config_path.write_text("\n".join(filtered), encoding="utf-8")

    # Aider has no config dir; treat $HOME as always present so detection is true.
    return ComponentSpec(
        id="aider.mcp",
        platform="aider",
        kind="mcp",
        description="Aider MCP server entry (~/.aider.conf.yml)",
        detect_dir=home,
        path=config_path,
        is_installed=is_installed,
        install=install,
        uninstall=uninstall,
    )


def _openclaw_skill() -> ComponentSpec:
    home = Path.home()
    detect_dir = home / ".openclaw"
    skill_path = detect_dir / "skills" / "rafter-security.md"

    def install() -> None:
        skill_path.parent.mkdir(parents=True, exist_ok=True)
        # Try primary skill location, then legacy resource name.
        content = _skill_text("skills", "rafter", "SKILL.md") or _skill_text("rafter-security-skill.md")
        if content is not None:
            skill_path.write_text(content, encoding="utf-8")

    def uninstall() -> None:
        if skill_path.exists():
            skill_path.unlink()

    return ComponentSpec(
        id="openclaw.skills",
        platform="openclaw",
        kind="skills",
        description="OpenClaw rafter-security skill",
        detect_dir=detect_dir,
        path=skill_path,
        is_installed=lambda: skill_path.exists(),
        install=install,
        uninstall=uninstall,
    )


# ── Registry ─────────────────────────────────────────────────────────

_REGISTRY: list[ComponentSpec] | None = None


def get_registry() -> list[ComponentSpec]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = [
            _claude_code_hooks(),
            _claude_code_instructions(),
            _claude_code_skills(),
            _codex_hooks(),
            _codex_skills(),
            _cursor_hooks(),
            _cursor_instructions(),
            _cursor_mcp(),
            _gemini_hooks(),
            _gemini_mcp(),
            _windsurf_hooks(),
            _windsurf_mcp(),
            _continue_hooks(),
            _continue_mcp(),
            _aider_mcp(),
            _openclaw_skill(),
        ]
    return _REGISTRY


def reset_registry_cache() -> None:
    """Clear cached registry — tests mutate HOME between runs."""
    global _REGISTRY
    _REGISTRY = None


def resolve_component(raw: str) -> ComponentSpec | None:
    normalized = raw.strip().lower()
    # Allow short aliases: "claude.*" -> "claude-code.*", "continuedev.*" -> "continue.*"
    if normalized.startswith("claude."):
        normalized = "claude-code." + normalized[len("claude."):]
    elif normalized.startswith("continuedev."):
        normalized = "continue." + normalized[len("continuedev."):]
    for spec in get_registry():
        if spec.id == normalized:
            return spec
    return None


def snapshot_components() -> list[dict[str, Any]]:
    cm = ConfigManager()
    try:
        cfg_dict = cm._to_dict(cm.load())  # type: ignore[attr-defined]
    except Exception:
        cfg_dict = {}
    components_cfg = (cfg_dict.get("agent") or {}).get("components") or {}
    out: list[dict[str, Any]] = []
    for spec in get_registry():
        detected = spec.detect_dir.exists()
        installed = spec.is_installed()
        config_entry = components_cfg.get(spec.id)
        config_enabled = config_entry.get("enabled") if isinstance(config_entry, dict) else installed
        if installed:
            state = "installed"
        elif detected:
            state = "not-installed"
        else:
            state = "not-detected"
        out.append({
            "id": spec.id,
            "platform": spec.platform,
            "kind": spec.kind,
            "description": spec.description,
            "path": str(spec.path),
            "state": state,
            "installed": installed,
            "detected": detected,
            "configEnabled": bool(config_enabled) if config_enabled is not None else installed,
        })
    return out


def record_component_state(component_id: str, enabled: bool) -> None:
    """Record install/uninstall state for a single component.

    Writes the whole ``agent.components`` dict in one ``set`` call; if we used
    dot-notation ``set("agent.components.<id>", ...)`` the dot-path setter would
    split the component ID (e.g. ``claude-code.hooks``) into nested keys.
    """
    cm = ConfigManager()
    existing = cm.get("agent.components") or {}
    if not isinstance(existing, dict):
        existing = {}
    existing[component_id] = {
        "enabled": enabled,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }
    cm.set("agent.components", existing)
