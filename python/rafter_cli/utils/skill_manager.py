"""Skill manager for OpenClaw integration — Python port of Node skill-manager.ts."""
from __future__ import annotations

from pathlib import Path


class SkillManager:
    """Manage OpenClaw skill installation and detection.

    OpenClaw auto-discovers ClawHub-shaped skills from
    ``<workspace>/skills/<skill>/SKILL.md`` (default workspace
    ``~/.openclaw/workspace/``). rafter ≤ 0.7.7 wrote a loose
    ``~/.openclaw/skills/<name>.md`` file that OpenClaw never read; the canonical
    path was adopted in rf-zgwj. Detection here must match the installer and
    ``agent verify`` — checking the legacy path is a false negative.
    """

    def get_openclaw_root(self) -> Path:
        return Path.home() / ".openclaw"

    def get_openclaw_skills_dir(self) -> Path:
        return self.get_openclaw_root() / "workspace" / "skills"

    def get_rafter_skill_dir(self) -> Path:
        return self.get_openclaw_skills_dir() / "rafter-security"

    def get_rafter_skill_path(self) -> Path:
        return self.get_rafter_skill_dir() / "SKILL.md"

    def get_legacy_rafter_skill_path(self) -> Path:
        """Legacy install path used by rafter ≤ 0.7.7. Removed on reinstall."""
        return self.get_openclaw_root() / "skills" / "rafter-security.md"

    def is_openclaw_installed(self) -> bool:
        """Detect the platform root (~/.openclaw). A fresh OpenClaw install has
        no workspace skills dir yet, so checking the skills dir gives a
        false-negative until at least one skill is written."""
        return self.get_openclaw_root().exists()

    def has_legacy_rafter_skill(self) -> bool:
        """True when the rafter ≤ 0.7.7 flat file is present (migration note)."""
        return self.get_legacy_rafter_skill_path().exists()

    def is_rafter_skill_installed(self) -> bool:
        return self.get_rafter_skill_path().exists()
