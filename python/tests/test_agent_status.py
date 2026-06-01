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
