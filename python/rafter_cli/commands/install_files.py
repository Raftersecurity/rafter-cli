"""Whole-file artifacts that `rafter agent init` installs (skill files and
their docs/, per-skill rule files, sub-agent files, the OpenClaw skill), and
the policy for writing them over whatever is already on disk.

A re-run used to overwrite these silently, so a user's hand edit vanished
behind the same "Installed" line as a fresh install. Now init overwrites a
file only when it can prove the file still holds rafter's own content:

- the install manifest, <root>/.rafter/installed.json, records the sha256 of
  every file init wrote; or
- resources/shipped-hashes.json lists the sha256 of every bundled resource in
  every published release (regenerate with scripts/gen-shipped-hashes.py),
  which covers installs made before the manifest existed.

Anything else is treated as the user's and kept; the new version lands beside
it as <file>.rafter-new. Marker-block files (CLAUDE.md, AGENTS.md, ...) and
merged JSON/YAML configs are not whole-file artifacts and do not pass through
here. Mirrors node/src/commands/agent/install-files.ts.
"""
from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from rich.console import Console

from ..utils.formatter import fmt
from .skill import (
    KNOWN_SKILL_NAMES,
    RETIRED_SKILL_NAMES,
    _is_rafter_authored_skill_dir,
    remove_retired_skills,
)

FileOutcome = Literal["added", "updated", "unchanged", "kept", "replaced"]

# What init does with an installed file the user has modified (or that it
# cannot prove it wrote). "keep" leaves the file alone and writes the new
# version to <file>.rafter-new; "replace-with-backup" saves the old file as
# <file>.bak and installs the new one, which is what --force does. Switching
# the default is a one-line change here.
MODIFIED_FILE_POLICY: Literal["keep", "replace-with-backup"] = "keep"

MANIFEST_SCHEMA = 1
NEW_VERSION_SUFFIX = ".rafter-new"
BACKUP_SUFFIX = ".bak"


class InstallOutput:
    """`info` is dropped under --quiet; `warn` goes to stderr under --quiet."""

    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet

    def info(self, message: str = "") -> None:
        if not self.quiet:
            Console(soft_wrap=True).print(message)

    def warn(self, message: str) -> None:
        Console(soft_wrap=True, stderr=self.quiet).print(message)


@dataclass
class FileArtifact:
    dest: Path
    content: bytes
    # Key into shipped-hashes.json: resource path, or "<path>#<variant>" when transformed.
    resource_key: str
    component: str
    platform: str


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resources():
    return importlib.resources.files("rafter_cli.resources")


def cli_version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "unknown"


_shipped_cache: dict[str, set[str]] | None = None


def shipped_hashes() -> dict[str, set[str]]:
    """sha256 sets per resource key. Missing or bad table -> empty (fail safe: files are kept)."""
    global _shipped_cache
    if _shipped_cache is not None:
        return _shipped_cache
    table: dict[str, set[str]] = {}
    try:
        doc = json.loads(_resources().joinpath("shipped-hashes.json").read_text(encoding="utf-8"))
        for key, shas in (doc.get("files") or {}).items():
            if isinstance(shas, list):
                table[key] = set(shas)
    except Exception:
        pass
    _shipped_cache = table
    return table


def manifest_path(root: Path) -> Path:
    return root / ".rafter" / "installed.json"


def manifest_key(root: Path, dest: Path) -> str:
    """Forward-slash path of `dest` relative to `root` (the manifest key)."""
    try:
        return Path(dest).relative_to(root).as_posix()
    except ValueError:
        return Path(dest).resolve().as_posix()


def _write_no_follow(p: Path, content: bytes) -> None:
    """Write `p` without following a symlink at `p`: a temp file in the same
    directory, renamed over it. rename replaces a link instead of writing
    through it, so a link a repo planted at one of rafter's files cannot aim
    the write at ~/.bashrc; the write is atomic too."""
    tmp = p.parent / f".{p.name}.{secrets.token_hex(6)}.tmp"
    with open(tmp, "xb") as f:
        f.write(content)
    try:
        os.replace(tmp, p)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


@dataclass
class InstallSession:
    """One init run's view of the install root.

    Holds the manifest (loaded once, so a corrupt file warns once), the
    --force / --dry-run switches, and every outcome so far. In a dry run
    nothing is written; `_virtual` holds what the run would have written so a
    path planned twice (Codex and Gemini share .agents/skills) is predicted
    the way the real run will see it.
    """

    root: Path
    out: InstallOutput = field(default_factory=InstallOutput)
    force: bool = False
    dry_run: bool = False
    version: str = field(default_factory=cli_version)
    outcomes: list[tuple[Path, str]] = field(default_factory=list)
    _manifest: dict | None = None
    _dirty: bool = False
    _virtual: dict[Path, bytes] = field(default_factory=dict)

    @property
    def manifest(self) -> dict:
        if self._manifest is not None:
            return self._manifest
        files: dict = {}
        p = manifest_path(self.root)
        if p.exists():
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
                if not isinstance(doc, dict) or not isinstance(doc.get("files"), dict):
                    raise ValueError("no files map")
                files = doc["files"]
            except Exception as e:  # noqa: BLE001 — any unreadable manifest is treated as absent
                self.out.warn(fmt.warning(
                    f"Ignoring unreadable install manifest {p} ({e}); "
                    "installed files are checked against shipped versions instead."
                ))
        self._manifest = {"schema": MANIFEST_SCHEMA, "cliVersion": self.version, "files": files}
        return self._manifest

    def owns(self, dest: Path, resource_key: str, data: bytes) -> bool:
        """True when `data` at `dest` is provably content rafter wrote."""
        sha = sha256(data)
        entry = self.manifest["files"].get(manifest_key(self.root, dest))
        if isinstance(entry, dict) and entry.get("sha256") == sha:
            return True
        return sha in shipped_hashes().get(resource_key, ())

    def _read(self, dest: Path) -> bytes | None:
        if dest in self._virtual:
            return self._virtual[dest]
        try:
            return dest.read_bytes()
        except OSError:
            return None

    def classify(self, a: FileArtifact) -> FileOutcome:
        """The outcome writing `a` would have, without writing anything."""
        current = self._read(a.dest)
        # A symlink is never written through: what sits at its target is not
        # rafter's to update, and a dangling one is not a free path to create.
        link = a.dest not in self._virtual and a.dest.is_symlink()
        if current is None and not link:
            return "added"
        if current == a.content:
            return "unchanged"
        if current is not None and not link and self.owns(a.dest, a.resource_key, current):
            return "updated"
        if self.force or MODIFIED_FILE_POLICY == "replace-with-backup":
            return "replaced"
        return "kept"

    def _record(self, a: FileArtifact) -> None:
        self.manifest["files"][manifest_key(self.root, a.dest)] = {
            "sha256": sha256(a.content),
            "component": a.component,
            "platform": a.platform,
            "cliVersion": self.version,
        }
        self._dirty = True

    def apply(self, a: FileArtifact) -> FileOutcome:
        """Install one artifact under the write policy (or, in a dry run, predict it)."""
        outcome = self.classify(a)
        self.outcomes.append((a.dest, outcome))
        if self.dry_run:
            if outcome != "kept":
                self._virtual[a.dest] = a.content
            return outcome
        self._make_dir(a.dest.parent)
        # Bytes, not text: text mode would translate newlines on Windows, and
        # the bytes on disk would no longer match the hash tables.
        if outcome in ("added", "updated"):
            _write_no_follow(a.dest, a.content)
            self._record(a)
        elif outcome == "unchanged":
            self._record(a)
        elif outcome == "replaced":
            # Moving the old file (or link) aside, not copying it, never reads or writes through a link.
            os.replace(a.dest, Path(str(a.dest) + BACKUP_SUFFIX))
            _write_no_follow(a.dest, a.content)
            self._record(a)
        else:  # kept
            _write_no_follow(Path(str(a.dest) + NEW_VERSION_SUFFIX), a.content)
        if outcome != "unchanged":
            report_outcome(self.out, a.dest, outcome)
        return outcome

    def _make_dir(self, directory: Path) -> None:
        """mkdir -p, refusing in project scope when the directory resolves
        outside the root: a repo can make `.claude/skills` a link to anywhere."""
        if Path(self.root).resolve() == Path.home().resolve():
            directory.mkdir(parents=True, exist_ok=True)
            return
        root = Path(self.root).resolve()

        def check(d: Path) -> None:
            real = d.resolve()
            if real != root and root not in real.parents:
                raise OSError(f"refusing to write in {directory}: it resolves to {real}, outside {self.root}")

        existing = directory
        while not existing.exists():
            existing = existing.parent
        check(existing)
        directory.mkdir(parents=True, exist_ok=True)
        check(directory)

    def apply_all(self, artifacts: list[FileArtifact]) -> list[FileOutcome]:
        return [self.apply(a) for a in artifacts]

    def forget(self, dest: Path) -> None:
        if self.manifest["files"].pop(manifest_key(self.root, dest), None) is not None:
            self._dirty = True

    def forget_under(self, directory: Path) -> None:
        prefix = manifest_key(self.root, directory) + "/"
        for key in [k for k in self.manifest["files"] if k.startswith(prefix)]:
            del self.manifest["files"][key]
            self._dirty = True

    def save(self) -> None:
        if self.dry_run or not self._dirty:
            return
        p = manifest_path(self.root)
        self._make_dir(p.parent)
        files = dict(sorted(self.manifest["files"].items()))
        doc = {"schema": MANIFEST_SCHEMA, "cliVersion": self.version, "files": files}
        _write_no_follow(p, (json.dumps(doc, indent=2) + "\n").encode("utf-8"))
        self._dirty = False

    def count(self, outcome: str) -> int:
        return sum(1 for _, o in self.outcomes if o == outcome)


def outcome_line(dest: Path, outcome: str) -> str:
    label = outcome.ljust(9)
    if outcome == "kept":
        return f"{label} {dest} (modified; new version at {dest}{NEW_VERSION_SUFFIX})"
    if outcome == "replaced":
        return f"{label} {dest} (backup at {dest}{BACKUP_SUFFIX})"
    return f"{label} {dest}"


def report_outcome(out: InstallOutput, dest: Path, outcome: str) -> None:
    """One line per file that changed or needs attention.

    Unchanged files are summed into one line instead (report_unchanged_summary).
    kept / replaced print even under --quiet (to stderr).
    """
    line = outcome_line(dest, outcome)
    if outcome in ("kept", "replaced"):
        out.warn(fmt.warning(line))
    else:
        out.info(fmt.success(line))


def unchanged_line(n: int) -> str:
    return f"{n} file{'' if n == 1 else 's'} unchanged"


def report_unchanged_summary(session: InstallSession) -> None:
    n = session.count("unchanged")
    if n > 0:
        session.out.info(fmt.success(unchanged_line(n)))


FORCE_HINT = f"re-run with --force to replace (the old version is saved as {BACKUP_SUFFIX})"


def report_kept_summary(session: InstallSession, replace_hint: str = FORCE_HINT) -> None:
    """Closing hint when any modified files were kept. `replace_hint` says how to replace them instead."""
    n = session.count("kept")
    if n == 0:
        return
    session.out.warn(fmt.warning(
        f"{n} installed file{'' if n == 1 else 's'} had local changes and {'was' if n == 1 else 'were'} kept. "
        f"Compare each with its {NEW_VERSION_SUFFIX} copy, or {replace_hint}."
    ))


# ── artifact builders ────────────────────────────────────────────────

_SKIP_NAMES = {"__init__.py", "__pycache__"}


def _walk(node, rel: str = ""):
    for child in sorted(node.iterdir(), key=lambda c: c.name):
        if child.name in _SKIP_NAMES:
            continue
        child_rel = f"{rel}/{child.name}" if rel else child.name
        if child.is_dir():
            yield from _walk(child, child_rel)
        elif child.is_file():
            yield child_rel, child


def skill_artifacts(
    skills_dir: Path, platform: str, component: str, out: InstallOutput | None = None
) -> list[FileArtifact]:
    """Every file of every shipped skill (SKILL.md plus docs/), installed under `skills_dir`."""
    artifacts: list[FileArtifact] = []
    for name in KNOWN_SKILL_NAMES:
        src = _resources().joinpath("skills", name)
        if not src.joinpath("SKILL.md").is_file():
            if out:
                out.warn(fmt.warning(f"{name} skill template not found in package resources"))
            continue
        for rel, node in _walk(src):
            artifacts.append(FileArtifact(
                dest=skills_dir / name / Path(*rel.split("/")),
                content=node.read_bytes(),
                resource_key=f"skills/{name}/{rel}",
                component=component,
                platform=platform,
            ))
    return artifacts


RULE_SKILLS: tuple[str, ...] = ("rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review")

RuleKind = Literal["cursor", "windsurf", "continue"]

_RULE_LAYOUT: dict[str, dict] = {
    "cursor": {"res_dir": "cursor-rules", "dest_dir": (".cursor", "rules"), "ext": ".mdc", "component": "cursor.instructions", "label": "Cursor"},
    "windsurf": {"res_dir": "windsurf-rules", "dest_dir": (".windsurf", "rules"), "ext": ".md", "component": "windsurf.rules", "label": "Windsurf"},
    "continue": {"res_dir": "continue-rules", "dest_dir": (".continue", "rules"), "ext": ".md", "component": "continue.rules", "label": "Continue.dev"},
}


def rule_dest(kind: str, root: Path, name: str) -> Path:
    layout = _RULE_LAYOUT[kind]
    return root.joinpath(*layout["dest_dir"], f"{name}{layout['ext']}")


def rule_artifacts(kind: str, root: Path, out: InstallOutput | None = None) -> list[FileArtifact]:
    layout = _RULE_LAYOUT[kind]
    artifacts: list[FileArtifact] = []
    for name in RULE_SKILLS:
        fname = f"{name}{layout['ext']}"
        src = _resources().joinpath(layout["res_dir"], fname)
        if not src.is_file():
            if out:
                out.warn(fmt.warning(f"{layout['label']} rule template missing: {fname}"))
            continue
        artifacts.append(FileArtifact(
            dest=rule_dest(kind, root, name),
            content=src.read_bytes(),
            resource_key=f"{layout['res_dir']}/{fname}",
            component=layout["component"],
            platform=kind,
        ))
    return artifacts


def strip_frontmatter_field(content: str, field_name: str) -> str:
    """Drop single-line `<field>:` entries from a markdown file's frontmatter.

    Line-based, matching Node's stripToolsFromFrontmatter byte for byte. (A
    regex substitution used here through 0.11.x left a blank line when the
    field was the last frontmatter line; shipped-hashes.json covers that
    output so those installs still upgrade.)
    """
    if not content.startswith("---\n"):
        return content
    fm_end = content.find("\n---", 4)
    if fm_end == -1:
        return content
    frontmatter = content[4:fm_end]
    body = content[fm_end:]
    pattern = re.compile(rf"^{re.escape(field_name)}:\s")
    cleaned = "\n".join(line for line in frontmatter.split("\n") if not pattern.match(line))
    return f"---\n{cleaned}{body}"


# Sub-agents shipped for Claude Code; keep in sync with the Node installer.
CLAUDE_CODE_SUBAGENTS: tuple[str, ...] = ("rafter",)


def claude_agent_artifacts(root: Path, out: InstallOutput | None = None) -> list[FileArtifact]:
    artifacts: list[FileArtifact] = []
    for name in CLAUDE_CODE_SUBAGENTS:
        src = _resources().joinpath("agents", f"{name}.md")
        if not src.is_file():
            if out:
                out.warn(fmt.warning(f"{name} sub-agent template not found in package resources"))
            continue
        artifacts.append(FileArtifact(
            dest=root / ".claude" / "agents" / f"{name}.md",
            content=src.read_bytes(),
            resource_key=f"agents/{name}.md",
            component="claude-code.agents",
            platform="claude-code",
        ))
    return artifacts


def cursor_agent_artifacts(root: Path, out: InstallOutput | None = None) -> list[FileArtifact]:
    src = _resources().joinpath("agents", "rafter.md")
    if not src.is_file():
        if out:
            out.warn(fmt.warning("Rafter sub-agent template not found in resources/agents/"))
        return []
    content = strip_frontmatter_field(src.read_bytes().decode("utf-8"), "tools")
    return [FileArtifact(
        dest=root / ".cursor" / "agents" / "rafter.md",
        content=content.encode("utf-8"),
        resource_key="agents/rafter.md#cursor",
        component="cursor.instructions",
        platform="cursor",
    )]


def openclaw_skill_path(home: Path) -> Path:
    return home / ".openclaw" / "workspace" / "skills" / "rafter-security" / "SKILL.md"


def openclaw_legacy_skill_path(home: Path) -> Path:
    """Where rafter <= 0.7.7 put the OpenClaw skill, a path OpenClaw never reads."""
    return home / ".openclaw" / "skills" / "rafter-security.md"


def openclaw_skill_artifacts(home: Path, out: InstallOutput | None = None) -> list[FileArtifact]:
    """The OpenClaw skill, at the ClawHub workspace path OpenClaw discovers. User scope only."""
    src = _resources().joinpath("rafter-security-skill.md")
    if not src.is_file():
        if out:
            out.warn(fmt.warning("OpenClaw skill template not found in package resources"))
        return []
    return [FileArtifact(
        dest=openclaw_skill_path(home),
        content=src.read_bytes(),
        resource_key="rafter-security-skill.md",
        component="openclaw.skills",
        platform="openclaw",
    )]


# ── retired artifacts ────────────────────────────────────────────────


def _owns_skill_dir(session: InstallSession, skill_dir: Path, name: str) -> bool:
    """Every file in `skill_dir` is provably rafter's own content for skill `name`."""
    files = [p for p in sorted(skill_dir.rglob("*")) if p.is_file()]
    return bool(files) and all(
        session.owns(p, f"skills/{name}/{p.relative_to(skill_dir).as_posix()}", p.read_bytes())
        for p in files
    )


@dataclass
class RetiredResult:
    removed: list[Path] = field(default_factory=list)
    kept: list[Path] = field(default_factory=list)


def cleanup_retired_skills(
    session: InstallSession,
    skills_dir: Path,
    names: tuple[str, ...] | None = None,
) -> RetiredResult:
    """Remove retired rafter skill directories under `skills_dir`.

    A directory goes when its SKILL.md carries rafter's publisher tag or every
    file in it hashes to content rafter shipped or recorded; anything else is
    the user's and is kept (and reported). In a dry run, reports what would
    happen.
    """
    if names is None:
        names = RETIRED_SKILL_NAMES
    present = tuple(n for n in names if (skills_dir / n / "SKILL.md").exists())
    if not present:
        return RetiredResult()

    def owned(d: Path, n: str) -> bool:
        return _owns_skill_dir(session, d, n)

    if session.dry_run:
        removed = [n for n in present if _is_rafter_authored_skill_dir(skills_dir / n) or owned(skills_dir / n, n)]
    else:
        removed = remove_retired_skills(skills_dir, present, owned)
        for n in removed:
            session.forget_under(skills_dir / n)
    kept = [n for n in present if n not in removed]
    if not session.dry_run:
        for n in removed:
            session.out.info(fmt.info(f"Removed retired skill {n} from {skills_dir}"))
        for n in kept:
            session.out.warn(fmt.warning(
                f"Kept retired skill {skills_dir / n} (modified or not rafter's; remove it yourself if unused)"
            ))
    return RetiredResult(removed=[skills_dir / n for n in removed], kept=[skills_dir / n for n in kept])


def cleanup_retired_rules(
    session: InstallSession,
    kind: str,
    names: tuple[str, ...] | None = None,
) -> RetiredResult:
    """Remove retired per-skill rule files of `kind` that hash to rafter's own content; keep and report the rest."""
    if names is None:
        names = RETIRED_SKILL_NAMES
    layout = _RULE_LAYOUT[kind]
    result = RetiredResult()
    for name in names:
        dest = rule_dest(kind, session.root, name)
        if not dest.exists():
            continue
        if session.owns(dest, f"{layout['res_dir']}/{name}{layout['ext']}", dest.read_bytes()):
            result.removed.append(dest)
            if not session.dry_run:
                dest.unlink()
                session.forget(dest)
                session.out.info(fmt.info(f"Removed retired rule {dest}"))
        else:
            result.kept.append(dest)
            if not session.dry_run:
                session.out.warn(fmt.warning(f"Kept retired rule {dest} (modified; remove it yourself if unused)"))
    return result


def cleanup_legacy_openclaw(session: InstallSession) -> RetiredResult:
    """Remove the legacy OpenClaw skill file if it hashes to rafter's own content; otherwise keep and report it."""
    result = RetiredResult()
    dest = openclaw_legacy_skill_path(session.root)
    if not dest.exists():
        return result
    if session.owns(dest, "rafter-security-skill.md", dest.read_bytes()):
        result.removed.append(dest)
        if not session.dry_run:
            dest.unlink()
            session.forget(dest)
            session.out.info(fmt.info(f"Removed legacy {dest} (OpenClaw reads {openclaw_skill_path(session.root)})"))
            try:
                if not any(dest.parent.iterdir()):
                    dest.parent.rmdir()
            except OSError:
                pass
    else:
        result.kept.append(dest)
        if not session.dry_run:
            session.out.warn(fmt.warning(f"Kept legacy {dest} (modified; OpenClaw never reads it, remove it yourself)"))
    return result


# ── per-platform artifact sets ───────────────────────────────────────

# Platforms that install whole-file artifacts, in init's install order.
WHOLE_FILE_PLATFORMS: tuple[str, ...] = ("claude-code", "codex", "gemini", "cursor", "windsurf", "continue", "openclaw")


def platform_artifacts(platform: str, root: Path) -> list[FileArtifact]:
    """Every whole-file artifact `agent init` installs for `platform` under `root`."""
    if platform == "claude-code":
        return skill_artifacts(root / ".claude" / "skills", "claude-code", "claude-code.skills") + claude_agent_artifacts(root)
    if platform == "codex":
        return skill_artifacts(root / ".agents" / "skills", "codex", "codex.skills")
    if platform == "gemini":
        return skill_artifacts(root / ".agents" / "skills", "gemini", "gemini.skills")
    if platform == "cursor":
        return rule_artifacts("cursor", root) + cursor_agent_artifacts(root)
    if platform in ("windsurf", "continue"):
        return rule_artifacts(platform, root)
    if platform == "openclaw":
        return openclaw_skill_artifacts(root)
    return []
