"""Tests for rafter agent status."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from rafter_cli.commands.agent import agent_app


runner = CliRunner()


class TestAgentStatusJson:
    def test_outputs_machine_readable_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = runner.invoke(agent_app, ["status", "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["installed"] is False
        assert isinstance(payload["version"], str)
        assert payload["agents_detected"] == []
        assert isinstance(payload["hooks_installed"], list)
        assert isinstance(payload["betterleaks_available"], bool)
        assert payload["config_path"] == "~/.rafter/config.json"
        assert payload["audit_log_path"] == "~/.rafter/audit.jsonl"
        assert "Rafter Agent Status" not in result.output

    def test_reports_detected_agents_and_installed_git_hooks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rafter_dir = tmp_path / ".rafter"
        rafter_dir.mkdir()
        (rafter_dir / "config.json").write_text("{}", encoding="utf-8")
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".cursor").mkdir()

        hooks_dir = rafter_dir / "git-hooks"
        hooks_dir.mkdir()
        hook = hooks_dir / "pre-commit"
        hook.write_text("#!/bin/sh\n# Rafter Security Pre-Commit Hook\n", encoding="utf-8")
        hook.chmod(0o755)

        result = runner.invoke(agent_app, ["status", "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["installed"] is True
        assert {"claude-code", "cursor"}.issubset(set(payload["agents_detected"]))
        assert "pre-commit" in payload["hooks_installed"]


class TestAgentStatusOpenClaw:
    """sable-1vq — `agent status` must report OpenClaw via the canonical
    ClawHub workspace path (rf-zgwj), matching the installer and `agent verify`.
    Checking the legacy flat path was a false negative."""

    def test_reports_skill_installed_at_canonical_path_after_init(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _install_openclaw_skill
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".openclaw").mkdir()

        ok, _src, _dest, _err = _install_openclaw_skill()
        assert ok

        result = runner.invoke(agent_app, ["status"])
        assert result.exit_code == 0, result.output
        assert "OpenClaw:     skill installed" in result.output
        assert "workspace/skills/rafter-security/SKILL.md" in result.output
        assert "detected but skill missing" not in result.output

    def test_reports_detected_but_missing_when_no_skill(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".openclaw").mkdir()

        result = runner.invoke(agent_app, ["status"])
        assert result.exit_code == 0, result.output
        assert "OpenClaw:     detected but skill missing" in result.output

    def test_surfaces_migration_hint_for_legacy_only_install(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        legacy = tmp_path / ".openclaw" / "skills" / "rafter-security.md"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("---\nname: rafter-security\nversion: 0.6.0\n---\n# old\n")

        result = runner.invoke(agent_app, ["status"])
        assert result.exit_code == 0, result.output
        assert "legacy skill at" in result.output
        assert "(not loaded)" in result.output

    def test_reports_not_detected_without_openclaw(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = runner.invoke(agent_app, ["status"])
        assert result.exit_code == 0, result.output
        assert "OpenClaw:     not detected" in result.output


class TestSkillManagerCanonicalPaths:
    """SkillManager must use canonical ClawHub paths in parity with the Node
    implementation (node/src/utils/skill-manager.ts)."""

    def test_paths_point_at_workspace_skills(self, tmp_path, monkeypatch):
        from rafter_cli.utils.skill_manager import SkillManager
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        sm = SkillManager()
        assert sm.get_openclaw_root() == tmp_path / ".openclaw"
        assert sm.get_openclaw_skills_dir() == tmp_path / ".openclaw" / "workspace" / "skills"
        assert sm.get_rafter_skill_path() == tmp_path / ".openclaw" / "workspace" / "skills" / "rafter-security" / "SKILL.md"
        assert sm.get_legacy_rafter_skill_path() == tmp_path / ".openclaw" / "skills" / "rafter-security.md"

    def test_is_openclaw_installed_detects_root_not_skills_dir(self, tmp_path, monkeypatch):
        from rafter_cli.utils.skill_manager import SkillManager
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        sm = SkillManager()
        assert not sm.is_openclaw_installed()
        (tmp_path / ".openclaw").mkdir()
        # Fresh OpenClaw root with no skills dir yet must still detect.
        assert sm.is_openclaw_installed()

    def test_detection_round_trip_via_installer(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _install_openclaw_skill
        from rafter_cli.utils.skill_manager import SkillManager
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".openclaw").mkdir()
        sm = SkillManager()
        assert not sm.is_rafter_skill_installed()

        ok, _src, _dest, _err = _install_openclaw_skill()
        assert ok
        assert sm.is_rafter_skill_installed()
        assert not sm.has_legacy_rafter_skill()

    def test_has_legacy_rafter_skill(self, tmp_path, monkeypatch):
        from rafter_cli.utils.skill_manager import SkillManager
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        legacy = tmp_path / ".openclaw" / "skills" / "rafter-security.md"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("legacy")
        sm = SkillManager()
        assert sm.has_legacy_rafter_skill()
        assert not sm.is_rafter_skill_installed()
