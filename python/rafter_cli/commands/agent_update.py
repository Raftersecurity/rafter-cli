"""Installed-platform detection and staleness for `rafter agent update`.

`rafter agent update` re-applies every rafter integration that is already
installed, using this CLI's skills, rules, instruction blocks, hooks and MCP
entries. Platforms come from the install manifest and from rafter's own files
on disk (installs made before the manifest existed have only the latter); a
platform the user never installed is never added. The work is `agent init`
itself (`_run_agent_init` in agent.py) with those platforms' flags.
Mirrors node/src/commands/agent/update.ts.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .agent_components import RAFTER_MARKER_START
from .install_files import (
    RULE_SKILLS,
    WHOLE_FILE_PLATFORMS,
    InstallSession,
    cli_version,
    manifest_path,
    platform_artifacts,
)
from .skill import KNOWN_SKILL_NAMES

# Order matches the Node implementation.
UPDATE_PLATFORMS: tuple[str, ...] = (
    "claude-code", "codex", "gemini", "cursor", "windsurf", "continue",
    "aider", "hermes", "opencode", "openclaw",
)
_USER_ONLY = ("hermes", "opencode", "openclaw")


def _contains(path: Path, needle: str) -> bool:
    try:
        return needle in path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def _manifest_platforms(root: Path) -> set[str]:
    try:
        doc = json.loads(manifest_path(root).read_text(encoding="utf-8"))
        return {str((e or {}).get("platform", "")) for e in (doc.get("files") or {}).values()}
    except Exception:
        return set()


def detect_installed_platforms(root: Path, scope: str) -> list[str]:
    """Platforms rafter is installed for under `root`.

    A platform counts when the manifest lists a file for it or rafter's own
    entries are on disk: its skills, rules or sub-agent, its marker block, or
    a rafter hook / MCP entry in its config (the same signals `agent list`
    and `agent verify` read).
    """
    user = scope == "user"
    recorded = _manifest_platforms(root)

    def marker(p: Path) -> bool:
        return _contains(p, RAFTER_MARKER_START)

    def any_exists(paths) -> bool:
        return any(p.exists() for p in paths)

    def skill_files(d: str):
        return [root / d / "skills" / n / "SKILL.md" for n in KNOWN_SKILL_NAMES]

    def rules(d: str, ext: str):
        return [root / d / "rules" / f"{n}{ext}" for n in RULE_SKILLS]

    signals = {
        "claude-code": lambda: _contains(root / ".claude" / "settings.json", "hook pretool")
        or any_exists(skill_files(".claude") + [root / ".claude" / "agents" / "rafter.md"])
        or marker(root / ".claude" / "CLAUDE.md"),
        "codex": lambda: _contains(root / ".codex" / "hooks.json", "hook pretool")
        or (user and marker(root / ".codex" / "AGENTS.md")),
        "gemini": lambda: _contains(root / ".gemini" / "settings.json", "rafter")
        or marker(root / ".gemini" / "GEMINI.md" if user else root / "GEMINI.md"),
        "cursor": lambda: any_exists(rules(".cursor", ".mdc") + [root / ".cursor" / "agents" / "rafter.md"])
        or _contains(root / ".cursor" / "hooks.json", "hook pretool")
        or _contains(root / ".cursor" / "mcp.json", '"rafter"'),
        "windsurf": lambda: any_exists(rules(".windsurf", ".md"))
        or (user and _contains(root / ".codeium" / "windsurf" / "mcp_config.json", '"rafter"')),
        "continue": lambda: any_exists(rules(".continue", ".md"))
        or (user and _contains(root / ".continue" / "config.json", '"rafter"')),
        "aider": lambda: marker(root / "RAFTER.md") or _contains(root / ".aider.conf.yml", "RAFTER.md"),
        "hermes": lambda: _contains(root / ".hermes" / "config.yaml", "rafter"),
        "opencode": lambda: _contains(root / ".config" / "opencode" / "opencode.json", '"rafter"'),
        "openclaw": lambda: (root / ".openclaw" / "workspace" / "skills" / "rafter-security" / "SKILL.md").exists(),
    }
    return [
        name for name in UPDATE_PLATFORMS
        if not (scope == "project" and name in _USER_ONLY) and (name in recorded or signals[name]())
    ]


@dataclass
class InstallStaleness:
    stale: bool
    installed_version: str | None  # cliVersion from the manifest; None without one
    cli_version: str
    outdated_files: int  # installed rafter files older than what this CLI ships
    platforms: list[str] = field(default_factory=list)


def _version_older(a: str, b: str) -> bool:
    def parse(v: str):
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
        return tuple(int(x) for x in m.groups()) if m else None

    x, y = parse(a), parse(b)
    return bool(x and y and x < y)


class _Silent:
    def info(self, message: str = "") -> None:
        pass

    def warn(self, message: str) -> None:
        pass


def install_staleness(root: Path, scope: str) -> InstallStaleness:
    """Whether what is installed under `root` is older than what this CLI ships.

    Stale when the manifest names an older CLI version, when any installed
    rafter file would be updated (an unmodified older copy, by manifest or
    shipped hash), or when rafter's files are present with no manifest at all
    (they predate install records). Files the user modified do not count. No
    network, no writes.
    """
    version = cli_version()
    platforms = detect_installed_platforms(root, scope)
    session = InstallSession(root=root, out=_Silent(), dry_run=True, version=version)
    installed_version: str | None = None
    has_record = False
    try:
        doc = json.loads(manifest_path(root).read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("files"), dict):
            has_record = True
            v = doc.get("cliVersion")
            installed_version = v if isinstance(v, str) else None
    except Exception:
        pass
    outdated = present = 0
    for platform in WHOLE_FILE_PLATFORMS:
        if platform not in platforms:
            continue
        for a in platform_artifacts(platform, root):
            if a.dest.exists():
                present += 1
            if session.apply(a) == "updated":
                outdated += 1
    stale = (
        outdated > 0
        or (installed_version is not None and _version_older(installed_version, version))
        or (not has_record and present > 0)
    )
    return InstallStaleness(stale, installed_version, version, outdated, platforms)


def staleness_line(s: InstallStaleness) -> str:
    """The one line verify / status print when the install is stale."""
    origin = f"installed by rafter {s.installed_version}" if s.installed_version else "installed before rafter kept an install record"
    files = (
        f", {s.outdated_files} file{'' if s.outdated_files == 1 else 's'} older than this CLI ships"
        if s.outdated_files else ""
    )
    return f"Rafter integrations are out of date ({origin}; this CLI is {s.cli_version}{files}). Run: rafter agent update"
