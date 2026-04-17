"""`rafter skill list/install/uninstall` — manage rafter-authored skills.

Mirrors node/src/commands/skill/*. Skills shipped in this package live in
``rafter_cli/resources/skills/<name>/SKILL.md``. Lifecycle commands only operate
on the known, first-party skill names — not arbitrary third-party files.
"""
from __future__ import annotations

import importlib.resources
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer

from ..core.config_schema import get_config_path
from ..utils.formatter import fmt
from rich import print as rprint


skill_app = typer.Typer(
    name="skill",
    help="Manage rafter-authored skills (list / install / uninstall)",
    no_args_is_help=True,
)


# Rafter-authored skills shipped with this CLI.
KNOWN_SKILL_NAMES: tuple[str, ...] = (
    "rafter",
    "rafter-agent-security",
    "rafter-secure-design",
    "rafter-code-review",
)

SKILL_PLATFORMS: tuple[str, ...] = (
    "claude-code",
    "codex",
    "openclaw",
    "cursor",
)


@dataclass
class SkillMeta:
    name: str
    version: str
    description: str
    source_text: str  # the full SKILL.md content, cached at discovery time


def _load_bundled_skill(name: str) -> SkillMeta | None:
    """Read a bundled SKILL.md via importlib.resources. Returns None if missing."""
    try:
        ref = importlib.resources.files("rafter_cli.resources").joinpath(
            "skills", name, "SKILL.md"
        )
        content = ref.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return None
    fm = _parse_frontmatter(content)
    return SkillMeta(
        name=name,
        version=fm.get("version", "unknown"),
        description=fm.get("description", ""),
        source_text=content,
    )


def _parse_frontmatter(content: str) -> dict[str, str]:
    """Minimal YAML-frontmatter parser. Handles a flat key: value block."""
    match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return {}
    out: dict[str, str] = {}
    for line in match.group(1).splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if not m:
            continue
        val = m.group(2).strip()
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            val = val[1:-1]
        out[m.group(1)] = val
    return out


def _list_bundled() -> list[SkillMeta]:
    return [s for n in KNOWN_SKILL_NAMES if (s := _load_bundled_skill(n)) is not None]


def _resolve_skill(name: str) -> SkillMeta | None:
    return _load_bundled_skill(name.strip())


def _detect_dir(platform: str) -> Path:
    home = Path.home()
    return {
        "claude-code": home / ".claude",
        "codex": home / ".codex",
        "openclaw": home / ".openclaw",
        "cursor": home / ".cursor",
    }[platform]


def _dest_path(platform: str, skill_name: str) -> Path:
    home = Path.home()
    return {
        "claude-code": home / ".claude" / "skills" / skill_name / "SKILL.md",
        "codex": home / ".agents" / "skills" / skill_name / "SKILL.md",
        "openclaw": home / ".openclaw" / "skills" / f"{skill_name}.md",
        "cursor": home / ".cursor" / "rules" / f"{skill_name}.mdc",
    }[platform]


def _resolve_explicit_dest(dest: str, skill_name: str) -> Path:
    lower = dest.lower()
    if lower.endswith(".md") or lower.endswith(".mdc"):
        return Path(dest)
    return Path(dest) / skill_name / "SKILL.md"


def _write_skill(skill: SkillMeta, dest_path: Path) -> None:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(skill.source_text, encoding="utf-8")


def _delete_skill(dest_path: Path) -> bool:
    if not dest_path.exists():
        return False
    dest_path.unlink()
    try:
        parent = dest_path.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
    except OSError:
        pass
    return True


def _snapshot() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for skill in _list_bundled():
        for platform in SKILL_PLATFORMS:
            dest = _dest_path(platform, skill.name)
            detected = _detect_dir(platform).exists()
            installed = dest.exists()
            version: str | None = None
            if installed:
                try:
                    fm = _parse_frontmatter(dest.read_text(encoding="utf-8"))
                    version = fm.get("version")
                except OSError:
                    version = None
            rows.append({
                "name": skill.name,
                "platform": platform,
                "path": str(dest),
                "detected": detected,
                "installed": installed,
                "version": version,
            })
    return rows


def _record_state(platform: str, name: str, enabled: bool, version: str | None) -> None:
    """Persist install/uninstall state to ~/.rafter/config.json.

    Bypasses ConfigManager because its dataclass schema drops unknown top-level
    keys on save. We read/merge/write the raw JSON instead, preserving fields
    that the schema doesn't model.
    """
    cfg_path = get_config_path()
    cfg: dict[str, Any] = {}
    if cfg_path.exists():
        try:
            parsed = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                cfg = parsed
        except (json.JSONDecodeError, OSError):
            cfg = {}
    installs = cfg.setdefault("skillInstallations", {})
    if not isinstance(installs, dict):
        installs = {}
        cfg["skillInstallations"] = installs
    platform_map = installs.setdefault(platform, {})
    if not isinstance(platform_map, dict):
        platform_map = {}
        installs[platform] = platform_map
    entry: dict[str, Any] = {
        "enabled": enabled,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }
    if version is not None:
        entry["version"] = version
    platform_map[name] = entry
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ── Commands ──────────────────────────────────────────────────────────


@skill_app.command("list")
def list_cmd(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
    installed_only: bool = typer.Option(
        False, "--installed", help="Only show (skill, platform) pairs where installed"
    ),
    platform: str | None = typer.Option(
        None, "--platform", help=f"Limit to one platform (one of: {', '.join(SKILL_PLATFORMS)})"
    ),
):
    """List rafter-authored skills and their install state per platform."""
    bundled = _list_bundled()
    rows = _snapshot()

    if platform:
        if platform not in SKILL_PLATFORMS:
            rprint(fmt.error(f"Unknown platform: {platform}. Known: {', '.join(SKILL_PLATFORMS)}"), file=sys.stderr)
            raise typer.Exit(code=1)
        rows = [r for r in rows if r["platform"] == platform]
    if installed_only:
        rows = [r for r in rows if r["installed"]]

    if json_output:
        payload = {
            "skills": [
                {"name": s.name, "version": s.version, "description": s.description}
                for s in bundled
            ],
            "installations": rows,
        }
        print(json.dumps(payload, indent=2))
        return

    rprint(fmt.header("Rafter-authored skills"))
    for s in bundled:
        rprint(f"  {s.name.ljust(24)} v{s.version}")
    rprint()

    rprint(fmt.header("Installations by platform"))
    by_platform: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_platform.setdefault(r["platform"], []).append(r)
    for plat, items in by_platform.items():
        detected = items[0]["detected"] if items else False
        suffix = "" if detected else " (not detected)"
        rprint(f"\n{plat}{suffix}")
        for r in items:
            label = r["name"].ljust(24)
            if r["installed"]:
                ver = f" v{r['version']}" if r.get("version") else ""
                rprint(f"  {label} ● installed{ver}  ({r['path']})")
            else:
                rprint(f"  {label} ○ not installed")
    rprint()
    rprint(fmt.info(
        "Use `rafter skill install <name>` / `rafter skill uninstall <name>` to toggle skills.",
    ))


def _known_names_hint() -> str:
    return ", ".join(s.name for s in _list_bundled()) or "(none)"


@skill_app.command("install")
def install_cmd(
    name: str = typer.Argument(..., help="Skill name (e.g. rafter, rafter-secure-design)"),
    platforms: list[str] = typer.Option(
        [], "--platform",
        help=f"Target platform(s); repeatable. One or more of: {', '.join(SKILL_PLATFORMS)}. "
             "Default: all detected.",
    ),
    to: str | None = typer.Option(
        None, "--to",
        help="Explicit destination. If it ends in .md/.mdc, used as-is; otherwise treated as a skills-base directory.",
    ),
    force: bool = typer.Option(False, "--force", help="Install even if no target platform is detected"),
):
    """Install a rafter-authored skill to detected platform(s) or an explicit path."""
    skill = _resolve_skill(name)
    if skill is None:
        rprint(fmt.error(f"Unknown skill: {name}"), file=sys.stderr)
        rprint(fmt.info(f"Available: {_known_names_hint()}"), file=sys.stderr)
        raise typer.Exit(code=1)

    if to:
        dest_path = _resolve_explicit_dest(to, skill.name)
        try:
            _write_skill(skill, dest_path)
            rprint(fmt.success(f"Installed {skill.name} v{skill.version} → {dest_path}"))
            raise typer.Exit(code=0)
        except OSError as err:
            rprint(fmt.error(f"Failed to install {skill.name} to {dest_path}: {err}"), file=sys.stderr)
            raise typer.Exit(code=1)

    if platforms:
        targets: list[str] = []
        for raw in platforms:
            p = raw.strip()
            if p not in SKILL_PLATFORMS:
                rprint(fmt.error(f"Unknown platform: {raw}. Known: {', '.join(SKILL_PLATFORMS)}"), file=sys.stderr)
                raise typer.Exit(code=1)
            targets.append(p)
    else:
        targets = [p for p in SKILL_PLATFORMS if _detect_dir(p).exists()]
        if not targets:
            if not force:
                rprint(fmt.warning(
                    "No supported platform detected. Re-run with --platform <name> or --force "
                    "to install to all known platforms."
                ), file=sys.stderr)
                raise typer.Exit(code=2)
            targets = list(SKILL_PLATFORMS)

    exit_code = 0
    explicit_platforms = bool(platforms)
    for platform in targets:
        detected = _detect_dir(platform).exists()
        if not detected and explicit_platforms and not force:
            rprint(fmt.warning(
                f"{platform}: not detected ({_detect_dir(platform)}). "
                f"Re-run with --force to install anyway."
            ), file=sys.stderr)
            exit_code = exit_code or 2
            continue
        dest = _dest_path(platform, skill.name)
        try:
            _write_skill(skill, dest)
            _record_state(platform, skill.name, True, skill.version)
            rprint(fmt.success(f"Installed {skill.name} v{skill.version} → {dest} ({platform})"))
        except OSError as err:
            rprint(fmt.error(f"Failed to install {skill.name} for {platform}: {err}"), file=sys.stderr)
            exit_code = 1
    if exit_code:
        raise typer.Exit(code=exit_code)


@skill_app.command("uninstall")
def uninstall_cmd(
    name: str = typer.Argument(..., help="Skill name (e.g. rafter, rafter-secure-design)"),
    platforms: list[str] = typer.Option(
        [], "--platform",
        help=f"Target platform(s); repeatable. One or more of: {', '.join(SKILL_PLATFORMS)}. "
             "Default: all platforms where installed.",
    ),
):
    """Uninstall a rafter-authored skill from one or more platforms."""
    skill = _resolve_skill(name)
    if skill is None:
        rprint(fmt.error(f"Unknown skill: {name}"), file=sys.stderr)
        rprint(fmt.info(f"Available: {_known_names_hint()}"), file=sys.stderr)
        raise typer.Exit(code=1)

    if platforms:
        targets: list[str] = []
        for raw in platforms:
            p = raw.strip()
            if p not in SKILL_PLATFORMS:
                rprint(fmt.error(f"Unknown platform: {raw}. Known: {', '.join(SKILL_PLATFORMS)}"), file=sys.stderr)
                raise typer.Exit(code=1)
            targets.append(p)
    else:
        targets = [p for p in SKILL_PLATFORMS if _dest_path(p, skill.name).exists()]
        if not targets:
            rprint(fmt.info(f"{skill.name} is not installed on any known platform — no changes"))
            return

    exit_code = 0
    for platform in targets:
        dest = _dest_path(platform, skill.name)
        try:
            existed = _delete_skill(dest)
            _record_state(platform, skill.name, False, None)
            if existed:
                rprint(fmt.success(f"Uninstalled {skill.name} from {platform} ({dest})"))
            else:
                rprint(fmt.info(f"{skill.name} was not installed on {platform} — no changes"))
        except OSError as err:
            rprint(fmt.error(f"Failed to uninstall {skill.name} from {platform}: {err}"), file=sys.stderr)
            exit_code = 1
    if exit_code:
        raise typer.Exit(code=exit_code)
