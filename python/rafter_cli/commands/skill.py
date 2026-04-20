"""`rafter skill list/install/uninstall/review` — manage rafter-authored skills.

Mirrors node/src/commands/skill/*. Skills shipped in this package live in
``rafter_cli/resources/skills/<name>/SKILL.md``. Lifecycle commands only operate
on the known, first-party skill names — not arbitrary third-party files.
``review`` operates on any local path or git URL, not just first-party skills.
"""
from __future__ import annotations

import importlib.resources
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer

from ..core.config_schema import get_config_path
from ..core.pattern_engine import PatternEngine
from ..scanners.secret_patterns import DEFAULT_SECRET_PATTERNS
from ..utils.formatter import fmt
from rich import print as rprint
from . import skill_remote
from .skill_remote import (
    DEFAULT_CACHE_TTL_MS,
    ResolvedSource,
    find_skill_files,
    is_shorthand,
    parse_cache_ttl,
    parse_shorthand,
    resolve_shorthand,
)


skill_app = typer.Typer(
    name="skill",
    help="Manage rafter-authored skills (list / install / uninstall / review)",
    no_args_is_help=True,
)


# Rafter-authored skills shipped with this CLI.
KNOWN_SKILL_NAMES: tuple[str, ...] = (
    "rafter",
    "rafter-secure-design",
    "rafter-code-review",
    "rafter-skill-review",
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


def _skill_base_dir(platform: str) -> Path:
    """Base dir where INSTALLED skills live for each platform.

    claude-code / codex: <base>/<name>/SKILL.md  (per-skill subdir)
    openclaw:            <base>/<name>.md         (flat .md file)
    cursor:              <base>/<name>.mdc        (flat .mdc file)
    """
    home = Path.home()
    return {
        "claude-code": home / ".claude" / "skills",
        "codex": home / ".agents" / "skills",
        "openclaw": home / ".openclaw" / "skills",
        "cursor": home / ".cursor" / "rules",
    }[platform]


@dataclass
class DiscoveredSkill:
    platform: str
    name: str
    path: Path


def _discover_installed_skills(platform: str | None = None) -> list[DiscoveredSkill]:
    """Walk every platform's skill base and yield one entry per installed file.

    Missing dirs and unreadable entries are silently skipped so a single bad
    subdir can't abort the whole walk (needed for permission-denied tests).
    """
    targets = [platform] if platform else list(SKILL_PLATFORMS)
    out: list[DiscoveredSkill] = []
    for p in targets:
        base = _skill_base_dir(p)
        try:
            entries = list(base.iterdir())
        except (FileNotFoundError, PermissionError, NotADirectoryError, OSError):
            continue
        for entry in entries:
            try:
                if p in ("claude-code", "codex"):
                    if not entry.is_dir():
                        continue
                    skill_file = entry / "SKILL.md"
                    if not skill_file.is_file():
                        continue
                    out.append(DiscoveredSkill(platform=p, name=entry.name, path=skill_file))
                elif p == "openclaw":
                    if not entry.is_file() or entry.suffix.lower() != ".md":
                        continue
                    out.append(DiscoveredSkill(platform=p, name=entry.stem, path=entry))
                elif p == "cursor":
                    if not entry.is_file() or entry.suffix.lower() != ".mdc":
                        continue
                    out.append(DiscoveredSkill(platform=p, name=entry.stem, path=entry))
            except (PermissionError, OSError):
                continue
    out.sort(key=lambda d: (d.platform, d.name))
    return out


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


# ── review ───────────────────────────────────────────────────────────
#
# `rafter skill review <path-or-url>` — security review of a third-party skill,
# plugin, or extension before installing it. Emits a structured JSON report
# per shared-docs/CLI_SPEC.md. Mirrors node/src/commands/skill/review.ts.

_TEXT_EXT = frozenset({
    ".md", ".mdx", ".mdc", ".txt", ".json", ".yaml", ".yml", ".toml",
    ".ts", ".tsx", ".js", ".jsx", ".py", ".sh", ".bash", ".zsh",
    ".rb", ".go", ".rs", ".java", ".kt", ".swift",
    ".html", ".css", ".ini", ".env", ".cfg", ".conf",
})

_SUSPICIOUS_EXT = frozenset({
    ".so", ".dylib", ".dll", ".node", ".exe", ".wasm", ".bin",
})

_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_FILES = 2000

_HIGH_RISK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"rm\s+-rf\s+/(?!\w)", re.IGNORECASE), "rm -rf /"),
    (re.compile(r"sudo\s+rm", re.IGNORECASE), "sudo rm"),
    (re.compile(r"curl[^|]*\|\s*(?:ba)?sh", re.IGNORECASE), "curl | sh"),
    (re.compile(r"wget[^|]*\|\s*(?:ba)?sh", re.IGNORECASE), "wget | sh"),
    (re.compile(r"iwr[^|]*\|\s*iex", re.IGNORECASE), "iwr | iex"),
    (re.compile(r"eval\s*\(", re.IGNORECASE), "eval()"),
    (re.compile(r"exec\s*\(", re.IGNORECASE), "exec()"),
    (re.compile(r"Function\s*\(\s*['\"`]"), "new Function(...)"),
    (re.compile(r"chmod\s+777", re.IGNORECASE), "chmod 777"),
    (re.compile(r":\(\)\{\s*:\|:&\s*\};:"), "fork bomb"),
    (re.compile(r"dd\s+if=/dev/(?:zero|random)\s+of=/dev", re.IGNORECASE), "dd to device"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b", re.IGNORECASE), "mkfs (format)"),
    (re.compile(r"base64\s+-d[^|]*\|\s*(?:ba)?sh", re.IGNORECASE), "base64 decode | sh"),
    (re.compile(r"\b(?:crontab|systemctl|launchctl)\s+(?:-e|edit|enable|load)", re.IGNORECASE), "persistence primitive"),
]

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
_BIDI_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_ROPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_URL_RE = re.compile(r"https?://[^\s<>\"'`)]+", re.IGNORECASE)
_HTML_IMPERATIVE_RE = re.compile(
    r"<!--[\s\S]{0,400}?\b(?:ignore|disregard|pretend|you are|system:|assistant:)\b[\s\S]{0,400}?-->",
    re.IGNORECASE,
)
_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
_FM_LINE_RE = re.compile(r"^([A-Za-z0-9_-]+):\s*(.*)$")


def _is_git_url(input_: str) -> bool:
    if input_.startswith("git@"):
        return True
    if input_.endswith(".git"):
        return True
    if re.match(r"^(https?|ssh)://", input_) and re.search(
        r"github\.com|gitlab\.com|bitbucket\.org|codeberg\.org", input_
    ):
        return True
    return False


def _clone_shallow(url: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="rafter-skill-review-"))
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, str(tmp)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as err:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"Failed to clone {url}: {err}") from err
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        msg = (result.stderr or "").strip() or "git clone failed"
        raise RuntimeError(f"Failed to clone {url}: {msg}")
    return tmp


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def _walk_files(root: Path) -> list[Path]:
    out: list[Path] = []
    skip = {".git", "node_modules", ".venv"}
    for child in root.rglob("*"):
        if out and len(out) >= _MAX_FILES:
            break
        if any(part in skip for part in child.parts):
            continue
        if child.is_file():
            out.append(child)
    return out


def _parse_frontmatter(content: str) -> dict[str, str]:
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}
    out: dict[str, str] = {}
    for line in match.group(1).splitlines():
        m = _FM_LINE_RE.match(line)
        if not m:
            continue
        val = m.group(2).strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        out[m.group(1)] = val
    return out


def _parse_allowed_tools(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    trimmed = raw.strip()
    if trimmed.startswith("[") and trimmed.endswith("]"):
        return [s.strip() for s in trimmed[1:-1].split(",") if s.strip()]
    return [s for s in re.split(r"[,\s]+", trimmed) if s]


def _line_of(content: str, index: int) -> int:
    return content[:index].count("\n") + 1


@dataclass
class _Report:
    target: dict[str, Any] = field(default_factory=dict)
    frontmatter: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    high_risk_commands: list[dict[str, Any]] = field(default_factory=list)
    obfuscation: list[dict[str, Any]] = field(default_factory=list)
    inventory: dict[str, Any] = field(
        default_factory=lambda: {"textFiles": 0, "binaryFiles": 0, "suspiciousFiles": []}
    )
    summary: dict[str, Any] = field(
        default_factory=lambda: {"severity": "clean", "findings": 0, "reasons": []}
    )

    def to_json(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "frontmatter": self.frontmatter,
            "secrets": self.secrets,
            "urls": self.urls,
            "highRiskCommands": self.high_risk_commands,
            "obfuscation": self.obfuscation,
            "inventory": self.inventory,
            "summary": self.summary,
        }


def _scan_content(rel_path: str, content: str, engine: PatternEngine, report: _Report) -> None:
    for pm in engine.scan(content):
        report.secrets.append({
            "pattern": pm.pattern.name,
            "severity": pm.pattern.severity,
            "file": rel_path,
            "line": pm.line,
            "redacted": pm.redacted,
        })

    for m in _URL_RE.finditer(content):
        cleaned = re.sub(r"[).,;:]+$", "", m.group(0))
        report.urls.append(cleaned)

    for pattern, name in _HIGH_RISK_PATTERNS:
        for m in pattern.finditer(content):
            report.high_risk_commands.append({
                "command": name,
                "file": rel_path,
                "line": _line_of(content, m.start()),
            })

    m = _ZERO_WIDTH_RE.search(content)
    if m:
        cp = ord(m.group(0)[0])
        report.obfuscation.append({
            "kind": "zero-width-char",
            "file": rel_path,
            "line": _line_of(content, m.start()),
            "sample": f"U+{cp:04X}",
        })
    m = _BIDI_RE.search(content)
    if m:
        cp = ord(m.group(0)[0])
        report.obfuscation.append({
            "kind": "bidi-override",
            "file": rel_path,
            "line": _line_of(content, m.start()),
            "sample": f"U+{cp:04X}",
        })

    for m in _BASE64_BLOB_RE.finditer(content):
        report.obfuscation.append({
            "kind": "base64-blob",
            "file": rel_path,
            "line": _line_of(content, m.start()),
            "sample": f"{len(m.group(0))} chars",
        })
    for m in _HEX_ROPE_RE.finditer(content):
        report.obfuscation.append({
            "kind": "hex-escape-rope",
            "file": rel_path,
            "line": _line_of(content, m.start()),
            "sample": f"{len(m.group(0))} chars",
        })
    for m in _HTML_IMPERATIVE_RE.finditer(content):
        sample = re.sub(r"\s+", " ", m.group(0))[:80]
        report.obfuscation.append({
            "kind": "html-comment-imperative",
            "file": rel_path,
            "line": _line_of(content, m.start()),
            "sample": sample,
        })


def _summarize(report: _Report) -> None:
    reasons: list[str] = []
    sev = "clean"
    order = ["clean", "low", "medium", "high", "critical"]

    highest_secret: str | None = None
    for s in report.secrets:
        if highest_secret is None or order.index(s["severity"]) > order.index(highest_secret):
            highest_secret = s["severity"]

    if report.secrets:
        reasons.append(f"{len(report.secrets)} secret finding(s)")
        if highest_secret and order.index(highest_secret) > order.index(sev):
            sev = highest_secret
    if report.high_risk_commands:
        reasons.append(f"{len(report.high_risk_commands)} high-risk command(s)")
        if order.index("high") > order.index(sev):
            sev = "high"
    hard = [o for o in report.obfuscation if o["kind"] in ("bidi-override", "html-comment-imperative")]
    if hard:
        reasons.append(f"{len(hard)} hard obfuscation signal(s)")
        sev = "critical"
    soft = [o for o in report.obfuscation if o["kind"] in ("zero-width-char", "base64-blob", "hex-escape-rope")]
    if soft:
        reasons.append(f"{len(soft)} obfuscation signal(s)")
        if order.index("medium") > order.index(sev):
            sev = "medium"
    if report.inventory["suspiciousFiles"]:
        reasons.append(f"{len(report.inventory['suspiciousFiles'])} suspicious file(s)")
        if order.index("medium") > order.index(sev):
            sev = "medium"

    report.summary = {
        "severity": sev,
        "findings": (
            len(report.secrets)
            + len(report.high_risk_commands)
            + len(report.obfuscation)
            + len(report.inventory["suspiciousFiles"])
        ),
        "reasons": reasons,
    }


def _build_report(
    root_input: str,
    resolved: Path,
    kind: str,
    source: dict[str, Any] | None = None,
    skill_rel_dir: str | None = None,
) -> _Report:
    target: dict[str, Any] = {"input": root_input, "kind": kind, "resolvedPath": str(resolved)}
    if source is not None:
        target["source"] = source
    if skill_rel_dir is not None:
        target["skillRelDir"] = skill_rel_dir
    report = _Report(target=target)
    engine = PatternEngine(DEFAULT_SECRET_PATTERNS)

    if kind == "file":
        files = [resolved]
        rel_base = resolved.parent
    else:
        files = _walk_files(resolved)
        rel_base = resolved

    urls: set[str] = set()
    for f in files:
        try:
            stat = f.stat()
        except OSError:
            continue
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        rel = str(f.relative_to(rel_base)) if rel_base in f.parents or rel_base == f.parent else f.name
        if ext in _SUSPICIOUS_EXT or stat.st_size > _MAX_FILE_BYTES:
            report.inventory["suspiciousFiles"].append({"path": rel, "bytes": stat.st_size, "kind": "binary"})
            report.inventory["binaryFiles"] += 1
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if _looks_binary(data):
            report.inventory["binaryFiles"] += 1
            if ext not in _TEXT_EXT:
                report.inventory["suspiciousFiles"].append({"path": rel, "bytes": stat.st_size, "kind": "binary"})
            continue

        report.inventory["textFiles"] += 1
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            content = data.decode("utf-8", errors="replace")

        if f.name.lower() == "skill.md":
            fm = _parse_frontmatter(content)
            report.frontmatter.append({
                "file": rel,
                "name": fm.get("name"),
                "version": fm.get("version"),
                "description": fm.get("description"),
                "allowedTools": _parse_allowed_tools(fm.get("allowed-tools")),
            })
        _scan_content(rel, content, engine, report)

    for u in report.urls:
        urls.add(u)
    report.urls = sorted(urls)
    report.inventory["suspiciousFiles"].sort(key=lambda e: e["path"])
    _summarize(report)
    return report


def _render_text(report: _Report) -> None:
    rprint(fmt.header(f"Skill review: {report.target['input']}"))
    rprint(fmt.divider())
    fm0 = report.frontmatter[0] if report.frontmatter else None
    if fm0 and fm0.get("name"):
        ver = f" v{fm0['version']}" if fm0.get("version") else ""
        rprint(f"Skill: {fm0['name']}{ver}")
        if fm0.get("allowedTools"):
            rprint(f"allowed-tools: {', '.join(fm0['allowedTools'])}")
    inv = report.inventory
    rprint(f"Files: {inv['textFiles']} text, {inv['binaryFiles']} binary, {len(inv['suspiciousFiles'])} suspicious")
    rprint()

    def line(ok: bool, label: str) -> None:
        rprint(fmt.success(label) if ok else fmt.warning(label))

    line(not report.secrets, f"Secrets: {len(report.secrets)}")
    for s in report.secrets[:5]:
        rprint(f"   - [{s['severity']}] {s['pattern']} at {s['file']}{':' + str(s['line']) if s['line'] else ''}")
    if len(report.secrets) > 5:
        rprint(f"   ... and {len(report.secrets) - 5} more")

    line(not report.high_risk_commands, f"High-risk commands: {len(report.high_risk_commands)}")
    for c in report.high_risk_commands[:5]:
        rprint(f"   - {c['command']} at {c['file']}:{c['line']}")
    if len(report.high_risk_commands) > 5:
        rprint(f"   ... and {len(report.high_risk_commands) - 5} more")

    line(not report.obfuscation, f"Obfuscation signals: {len(report.obfuscation)}")
    for o in report.obfuscation[:5]:
        rprint(f"   - {o['kind']} at {o['file']}:{o['line']} ({o['sample']})")
    if len(report.obfuscation) > 5:
        rprint(f"   ... and {len(report.obfuscation) - 5} more")

    line(not inv["suspiciousFiles"], f"Suspicious files: {len(inv['suspiciousFiles'])}")
    for f in inv["suspiciousFiles"][:5]:
        rprint(f"   - {f['path']} ({f['bytes']} bytes)")

    line(not report.urls, f"External URLs: {len(report.urls)}")
    for u in report.urls[:8]:
        rprint(f"   - {u}")
    if len(report.urls) > 8:
        rprint(f"   ... and {len(report.urls) - 8} more")

    rprint()
    sev = report.summary["severity"].upper()
    label = f"Overall: {sev}"
    if report.summary["severity"] == "clean":
        rprint(fmt.success(label))
    elif report.summary["severity"] in ("critical", "high"):
        rprint(fmt.error(label), file=sys.stderr)
    else:
        rprint(fmt.warning(label))
    if report.summary["reasons"]:
        rprint(f"  {', '.join(report.summary['reasons'])}")
    rprint()
    rprint(fmt.info(
        "Deterministic checks only. Pair with the `rafter-skill-review` skill for provenance / prompt-injection / data-practices review."
    ))


_MULTI_SEVERITY_ORDER: tuple[str, ...] = ("clean", "low", "medium", "high", "critical")


def _build_multi_report(
    root_input: str,
    resolved: Path,
    kind: str,
    locations: list[skill_remote.SkillLocation],
    source: dict[str, Any] | None,
) -> dict[str, Any]:
    severity_counts: dict[str, int] = {s: 0 for s in _MULTI_SEVERITY_ORDER}
    worst = "clean"
    findings = 0
    entries: list[dict[str, Any]] = []
    for loc in locations:
        sub = _build_report(root_input, loc.dir, "directory", source)
        sub.target["kind"] = kind
        sub.target["skillRelDir"] = loc.rel_dir
        fm_list = sub.frontmatter
        fm0 = None
        for f in fm_list:
            fpath = f.get("file") or ""
            if fpath.lower().endswith("skill.md"):
                fm0 = f
                break
        entries.append({
            "relDir": loc.rel_dir,
            "name": (fm0 or {}).get("name"),
            "version": (fm0 or {}).get("version"),
            "report": sub.to_json(),
        })
        sev = sub.summary["severity"]
        severity_counts[sev] += 1
        findings += sub.summary["findings"]
        if _MULTI_SEVERITY_ORDER.index(sev) > _MULTI_SEVERITY_ORDER.index(worst):
            worst = sev

    reasons: list[str] = []
    if severity_counts["critical"] > 0:
        reasons.append(f"{severity_counts['critical']} critical skill(s)")
    if severity_counts["high"] > 0:
        reasons.append(f"{severity_counts['high']} high-severity skill(s)")
    if severity_counts["medium"] > 0:
        reasons.append(f"{severity_counts['medium']} medium-severity skill(s)")
    if severity_counts["low"] > 0:
        reasons.append(f"{severity_counts['low']} low-severity skill(s)")
    if not reasons:
        reasons.append(f"{severity_counts['clean']} clean skill(s)")

    target: dict[str, Any] = {
        "input": root_input,
        "kind": kind,
        "resolvedPath": str(resolved),
        "mode": "multi-skill",
    }
    if source is not None:
        target["source"] = source

    return {
        "target": target,
        "skills": entries,
        "summary": {
            "totalSkills": len(entries),
            "severityCounts": severity_counts,
            "findings": findings,
            "worst": worst,
            "reasons": reasons,
        },
    }


def _render_multi_text(report: dict[str, Any]) -> None:
    rprint(fmt.header(f"Skill review: {report['target']['input']}"))
    rprint(fmt.divider())
    rprint(f"Mode: multi-skill ({report['summary']['totalSkills']} SKILL.md files)")
    src = report["target"].get("source") or {}
    if src.get("sha"):
        rprint(f"Commit: {src['sha'][:12]}")
    if src.get("version"):
        rprint(f"Version: {src['version']}")
    if src.get("cacheHit"):
        rprint("Cache: hit")
    rprint()
    for s in report["skills"]:
        sev = s["report"]["summary"]["severity"]
        findings = s["report"]["summary"]["findings"]
        rel = str(s["relDir"]).ljust(40)
        line = f"  {rel}  [{sev.upper()}]  {findings} finding(s)"
        if sev in ("critical", "high"):
            rprint(fmt.error(line), file=sys.stderr)
        elif sev in ("medium", "low"):
            rprint(fmt.warning(line))
        else:
            rprint(fmt.success(line))
    rprint()
    rprint(
        f"Worst severity: {report['summary']['worst'].upper()} — "
        f"{', '.join(report['summary']['reasons'])}"
    )


def run_skill_review(
    input_: str,
    *,
    json_out: bool = False,
    format_: str = "text",
    no_cache: bool = False,
    cache_ttl_ms: int = DEFAULT_CACHE_TTL_MS,
    cache_root: Path | None = None,
    ops: skill_remote.RemoteOps | None = None,
) -> tuple[dict[str, Any], int]:
    """Implementation entry point — returns (report_dict, exit_code)."""
    cleanup = None
    source: dict[str, Any] | None = None
    resolved: Path
    kind: str
    tree_root: Path | None = None

    if is_shorthand(input_):
        try:
            parsed = parse_shorthand(input_)
        except ValueError as err:
            rprint(fmt.error(str(err)), file=sys.stderr)
            return {}, 2
        try:
            rs: ResolvedSource = resolve_shorthand(
                input_,
                parsed,
                no_cache=no_cache,
                cache_ttl_ms=cache_ttl_ms,
                cache_root=cache_root,
                ops=ops,
            )
        except RuntimeError as err:
            rprint(fmt.error(str(err)), file=sys.stderr)
            return {}, 2
        except Exception as err:  # noqa: BLE001
            rprint(fmt.error(f"{err}"), file=sys.stderr)
            return {}, 2
        resolved = rs.resolved_path
        kind = rs.kind
        source = rs.source
        cleanup = rs.cleanup
        tree_root = rs.tree_root
    elif _is_git_url(input_):
        try:
            resolved = _clone_shallow(input_)
        except RuntimeError as err:
            rprint(fmt.error(str(err)), file=sys.stderr)
            return {}, 2
        _resolved_ref = resolved

        def _cleanup_clone() -> None:
            shutil.rmtree(_resolved_ref, ignore_errors=True)

        cleanup = _cleanup_clone
        kind = "git-url"
        tree_root = resolved
    else:
        p = Path(input_)
        if not p.exists():
            rprint(fmt.error(f"Not found: {input_}"), file=sys.stderr)
            return {}, 2
        resolved = p.resolve()
        kind = "directory" if resolved.is_dir() else "file"
        tree_root = resolved if resolved.is_dir() else resolved.parent

    try:
        # Multi-SKILL.md handling.
        report_obj: dict[str, Any]
        if kind != "file" and tree_root is not None:
            locations = find_skill_files(resolved)
            if len(locations) > 1:
                report_obj = _build_multi_report(
                    input_, resolved, kind, locations, source
                )
            else:
                rep = _build_report(input_, resolved, kind, source)
                report_obj = rep.to_json()
        else:
            rep = _build_report(input_, resolved, kind, source)
            report_obj = rep.to_json()

        fmt_ = "json" if json_out else format_
        if fmt_ == "json":
            print(json.dumps(report_obj, indent=2))
        else:
            if "skills" in report_obj and isinstance(report_obj.get("skills"), list):
                _render_multi_text(report_obj)
            else:
                # Hydrate _Report for existing _render_text
                r = _Report()
                r.target = report_obj["target"]
                r.frontmatter = report_obj["frontmatter"]
                r.secrets = report_obj["secrets"]
                r.urls = report_obj["urls"]
                r.high_risk_commands = report_obj["highRiskCommands"]
                r.obfuscation = report_obj["obfuscation"]
                r.inventory = report_obj["inventory"]
                r.summary = report_obj["summary"]
                _render_text(r)

        if "skills" in report_obj:
            sev = report_obj["summary"]["worst"]
        else:
            sev = report_obj["summary"]["severity"]
        exit_code = 0 if sev == "clean" else 1
        return report_obj, exit_code
    finally:
        if cleanup is not None:
            try:
                cleanup()
            except Exception:  # noqa: BLE001
                pass


_SEVERITY_ORDER: tuple[str, ...] = ("clean", "low", "medium", "high", "critical")


def run_skill_review_installed(agent: str | None = None) -> tuple[dict[str, Any], int]:
    """Audit every installed skill across detected agent skill directories.

    Exit 1 iff any HIGH or CRITICAL finding. Lower severities do not fail the
    audit — use `rafter skill review <path>` for a stricter per-skill gate.
    """
    if agent is not None and agent not in SKILL_PLATFORMS:
        raise ValueError(
            f"Unknown agent: {agent}. Known: {', '.join(SKILL_PLATFORMS)}"
        )
    discovered = _discover_installed_skills(agent)
    installations: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    platform_counts: dict[str, int] = {}
    findings = 0
    worst = "clean"

    for d in discovered:
        report = _build_report(str(d.path), d.path, "file")
        installations.append({
            "platform": d.platform,
            "skill": d.name,
            "path": str(d.path),
            "report": report.to_json(),
        })
        sev = report.summary["severity"]
        severity_counts[sev] += 1
        platform_counts[d.platform] = platform_counts.get(d.platform, 0) + 1
        findings += report.summary["findings"]
        if _SEVERITY_ORDER.index(sev) > _SEVERITY_ORDER.index(worst):
            worst = sev

    aggregate = {
        "target": {"mode": "installed", "agent": agent if agent else "all"},
        "installations": installations,
        "summary": {
            "totalSkills": len(installations),
            "severityCounts": severity_counts,
            "platformCounts": platform_counts,
            "findings": findings,
            "worst": worst,
        },
    }
    exit_code = 1 if severity_counts["high"] + severity_counts["critical"] > 0 else 0
    return aggregate, exit_code


def _render_installed_summary(report: dict[str, Any]) -> None:
    rprint(fmt.header("Installed skill audit"))
    rprint(fmt.divider())
    rprint(f"Agent filter: {report['target']['agent']}")
    rprint(f"Skills audited: {report['summary']['totalSkills']}")
    rprint()

    if not report["installations"]:
        rprint(fmt.info("No installed skills found across the requested platform(s)."))
        return

    plat_w, skill_w, sev_w = 11, 28, 8
    head = (
        "PLATFORM".ljust(plat_w)
        + "  "
        + "SKILL".ljust(skill_w)
        + "  "
        + "SEVERITY".ljust(sev_w)
        + "  "
        + "FINDINGS"
    )
    rprint(head)
    rprint("-" * len(head))
    for row in report["installations"]:
        skill = row["skill"]
        if len(skill) > skill_w:
            skill = skill[: skill_w - 1] + "…"
        sev = row["report"]["summary"]["severity"]
        line = (
            row["platform"].ljust(plat_w)
            + "  "
            + skill.ljust(skill_w)
            + "  "
            + sev.ljust(sev_w)
            + "  "
            + str(row["report"]["summary"]["findings"])
        )
        if sev in ("critical", "high"):
            rprint(fmt.error(line), file=sys.stderr)
        elif sev in ("medium", "low"):
            rprint(fmt.warning(line))
        else:
            rprint(fmt.success(line))

    rprint()
    sc = report["summary"]["severityCounts"]
    rprint(
        f"Totals: {sc['clean']} clean · {sc['low']} low · {sc['medium']} medium · "
        f"{sc['high']} high · {sc['critical']} critical"
    )
    if sc["high"] + sc["critical"] > 0:
        rprint(
            fmt.error(
                f"Worst severity: {report['summary']['worst'].upper()} — "
                "review flagged skills before trusting them."
            ),
            file=sys.stderr,
        )
    else:
        rprint(fmt.success(f"Worst severity: {report['summary']['worst'].upper()}"))


@skill_app.command("review")
def review_cmd(
    path_or_url: str | None = typer.Argument(
        None,
        help=(
            "Local path (file or directory) OR git URL (https/ssh/.git) OR "
            "shorthand (github:owner/repo[/subpath], gitlab:owner/repo[/subpath], "
            "npm:pkg[@version]). Omit when using --installed."
        ),
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON report to stdout (shortcut for --format json)"
    ),
    format_: str = typer.Option(
        "text", "--format", help="Output format: text | json", case_sensitive=False
    ),
    installed: bool = typer.Option(
        False,
        "--installed",
        help="Audit every installed skill across detected agent skill directories instead of a path.",
    ),
    agent: str | None = typer.Option(
        None,
        "--agent",
        help=f"Restrict --installed to a single agent. One of: {', '.join(SKILL_PLATFORMS)}",
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help="Print a terse human-readable table instead of JSON (only with --installed).",
    ),
    cache_ttl: str = typer.Option(
        "24h",
        "--cache-ttl",
        help=(
            "TTL for the persistent skill-cache resolution entries "
            "(e.g. 24h, 30m, 3600s). Default: 24h."
        ),
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Bypass the persistent skill-cache; fetch fresh and skip writes.",
    ),
):
    """Security review of a skill/plugin/extension before installing it (path, git URL, or shorthand), or --installed to audit every skill on this machine."""
    if installed:
        if path_or_url:
            rprint(
                fmt.error("Cannot pass both <path-or-url> and --installed. Use one."),
                file=sys.stderr,
            )
            raise typer.Exit(code=1)
        try:
            aggregate, exit_code = run_skill_review_installed(agent)
        except ValueError as err:
            rprint(fmt.error(str(err)), file=sys.stderr)
            raise typer.Exit(code=1)
        if summary:
            _render_installed_summary(aggregate)
        else:
            print(json.dumps(aggregate, indent=2))
        if exit_code != 0:
            raise typer.Exit(code=exit_code)
        return

    if not path_or_url:
        rprint(
            fmt.error(
                "Missing <path-or-url>. Pass a path / git URL / shorthand, or use --installed to audit installed skills."
            ),
            file=sys.stderr,
        )
        raise typer.Exit(code=2)

    try:
        ttl_ms = parse_cache_ttl(cache_ttl)
    except ValueError as err:
        rprint(fmt.error(str(err)), file=sys.stderr)
        raise typer.Exit(code=2)

    _, exit_code = run_skill_review(
        path_or_url,
        json_out=json_output,
        format_=format_,
        no_cache=no_cache,
        cache_ttl_ms=ttl_ms,
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)
