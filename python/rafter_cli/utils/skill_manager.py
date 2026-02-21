"""Skill manager for OpenClaw integration — Python port of Node skill-manager.ts."""
from __future__ import annotations

import importlib.resources
import re
from pathlib import Path


class SkillManager:
    """Manage OpenClaw skill installation and detection."""

    def get_openclaw_skills_dir(self) -> Path:
        return Path.home() / ".openclaw" / "skills"

    def get_rafter_skill_path(self) -> Path:
        return self.get_openclaw_skills_dir() / "rafter-security.md"

    def is_openclaw_installed(self) -> bool:
        return self.get_openclaw_skills_dir().exists()

    def is_rafter_skill_installed(self) -> bool:
        return self.get_rafter_skill_path().exists()
