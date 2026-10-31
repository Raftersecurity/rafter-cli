"""The pretool hook's auto-update: after a CLI upgrade, bring installed skill,
rule and sub-agent files up to this version without waiting for the user to
run `rafter agent update`.

It only rewrites files whose hash proves they hold rafter's own content (the
InstallSession policy); a file the user modified is kept, with the new version
written beside it as <file>.rafter-new and reported. Hooks, MCP entries and
instruction blocks are left to `rafter agent update`, so the manifest keeps
its old cliVersion and `agent status` still says to run it.

Runs at most once a day per CLI version (stamp file), user scope only, never
raises, and writes nothing to stdout (stdout is the hook's decision).
RAFTER_DISABLE_AUTO_UPDATE=1 turns it off. Mirrors
node/src/commands/agent/auto-update.ts.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .agent_update import detect_installed_platforms, version_older
from .install_files import (
    NEW_VERSION_SUFFIX,
    WHOLE_FILE_PLATFORMS,
    FileArtifact,
    InstallSession,
    cleanup_legacy_openclaw,
    cleanup_retired_rules,
    cli_version,
    manifest_path,
    platform_artifacts,
)

AUTO_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000
# A lock older than this is from a hook that died mid-update.
_LOCK_STALE_MS = 60 * 1000


@dataclass
class AutoUpdateResult:
    updated: int  # files rewritten (or added to a skill that is installed) with this version's content
    needs_reconcile: list[Path]  # modified files kept, each with a newer version in <file>.rafter-new
    version: str


def auto_update_stamp_path(home: Path) -> Path:
    return home / ".rafter" / ".update-check"


def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _checked_recently(home: Path, version: str, now: int) -> bool:
    """True when the stamp says this version was checked within the interval."""
    stamp = _read_json(auto_update_stamp_path(home))
    if not isinstance(stamp, dict) or stamp.get("version") != version:
        return False
    checked = stamp.get("checkedAt")
    return isinstance(checked, (int, float)) and 0 <= now - checked < AUTO_UPDATE_INTERVAL_MS


def _write_stamp(home: Path, version: str, now: int) -> None:
    p = auto_update_stamp_path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"version": version, "checkedAt": now}) + "\n", encoding="utf-8")


def _acquire_lock(lock: Path, now: int) -> bool:
    """Take the update lock; False when another hook holds a live one."""
    for _ in range(2):
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return True
        except FileExistsError:
            try:
                if now - lock.stat().st_mtime * 1000 < _LOCK_STALE_MS:
                    return False
                lock.unlink()
            except OSError:
                return False
        except OSError:
            return False
    return False


def _unit_of(a: FileArtifact) -> Path:
    """The installed unit an artifact belongs to: a skill directory for skill
    files, otherwise the file itself. A unit with no file on disk was never
    installed or was removed by the user, and the hook does not bring it back.
    """
    m = re.match(r"^skills/([^/]+)/(.+)$", a.resource_key)
    if not m:
        return a.dest
    dest = a.dest
    for _ in m.group(2).split("/"):
        dest = dest.parent
    return dest


def maybe_auto_update(
    home: Path | None = None, now: int | None = None, version: str | None = None,
) -> AutoUpdateResult | None:
    """Apply this CLI's whole-file content to the user-scope install if it is older.

    Returns None when nothing ran (checked recently, already current, nothing
    installed, disabled, or another hook is running it).
    """
    if re.match(r"^(1|true|yes)$", os.environ.get("RAFTER_DISABLE_AUTO_UPDATE", ""), re.I):
        return None
    home = home if home is not None else Path.home()
    now = now if now is not None else int(time.time() * 1000)
    version = version or cli_version()
    if _checked_recently(home, version, now):
        return None

    manifest = _read_json(manifest_path(home))
    recorded = manifest.get("cliVersion") if isinstance(manifest, dict) else None
    if isinstance(recorded, str) and not version_older(recorded, version):
        _write_stamp(home, version, now)
        return None
    platforms = [p for p in detect_installed_platforms(home, "user") if p in WHOLE_FILE_PLATFORMS]
    if not platforms:
        _write_stamp(home, version, now)
        return None

    lock = home / ".rafter" / ".update-lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    if not _acquire_lock(lock, now):
        return None
    try:
        # Stamp first: an update that fails is not retried on every tool call.
        _write_stamp(home, version, now)
        session = InstallSession(root=home, out=_Silent(), version=version, keep_manifest_version=True)
        for platform in platforms:
            artifacts = platform_artifacts(platform, home)
            present = {_unit_of(a) for a in artifacts if a.dest.exists()}
            # A symlink at a file or its .rafter-new is skipped: an unattended
            # write must not follow a link to a path nobody chose. `agent update` still does.
            session.apply_all([
                a for a in artifacts
                if _unit_of(a) in present and not a.dest.is_symlink()
                and not Path(f"{a.dest}{NEW_VERSION_SUFFIX}").is_symlink()
            ])
        # Retired rule files and the legacy OpenClaw file go only when their
        # hash is rafter's. Retired skill directories are left to `agent
        # update`: there a publisher tag alone is enough to remove one, and
        # that is not hash proof.
        for kind in ("cursor", "windsurf", "continue"):
            if kind in platforms:
                cleanup_retired_rules(session, kind)
        if "openclaw" in platforms:
            cleanup_legacy_openclaw(session)
        session.save()
        return AutoUpdateResult(
            updated=session.count("updated") + session.count("added"),
            needs_reconcile=session.kept_files(),
            version=version,
        )
    finally:
        try:
            lock.unlink()
        except OSError:
            pass


class _Silent:
    def info(self, message: str = "") -> None:
        pass

    def warn(self, message: str) -> None:
        pass


def auto_update_line(r: AutoUpdateResult | None) -> str | None:
    """The one stderr line the hook prints after an auto-update; None when there is nothing to say."""
    if r is None or (r.updated == 0 and not r.needs_reconcile):
        return None
    parts: list[str] = []
    if r.updated:
        parts.append(f"updated {r.updated} skill/rule file{'' if r.updated == 1 else 's'} to {r.version}")
    n = len(r.needs_reconcile)
    if n:
        parts.append(
            f"{n} file{'' if n == 1 else 's'} you modified need{'s' if n == 1 else ''} reconciling with "
            f"{r.needs_reconcile[0]}{NEW_VERSION_SUFFIX}{' and others' if n > 1 else ''} (run 'rafter agent status')"
        )
    return "rafter: " + "; ".join(parts)


def run_hook_auto_update() -> None:
    """Hook entry point: run the auto-update and print its line to stderr. Never raises."""
    try:
        line = auto_update_line(maybe_auto_update())
        if line:
            sys.stderr.write(line + "\n")
    except Exception:
        pass  # the hook's decision is already written; an update failure must not change it
