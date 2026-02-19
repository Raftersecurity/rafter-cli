"""Tests for agent init Claude Code hook installation."""
from __future__ import annotations

import json
from pathlib import Path

from rafter_cli.commands.agent import _install_claude_code_hooks


class TestInstallClaudeCodeHooks:
    def test_creates_settings_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        _install_claude_code_hooks()

        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()

        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]
        assert len(settings["hooks"]["PreToolUse"]) == 2

        matchers = [e["matcher"] for e in settings["hooks"]["PreToolUse"]]
        assert "Bash" in matchers
        assert "Write|Edit" in matchers

    def test_preserves_existing_hooks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool check"}]}
                ]
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        _install_claude_code_hooks()

        settings = json.loads((claude_dir / "settings.json").read_text())
        # Should have 3 entries: existing other-tool + 2 Rafter hooks
        assert len(settings["hooks"]["PreToolUse"]) == 3

    def test_deduplicates_rafter_hooks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        # Pre-existing Rafter hooks
        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "rafter hook pretool"}]},
                    {"matcher": "Write|Edit", "hooks": [{"type": "command", "command": "rafter hook pretool"}]},
                ]
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        _install_claude_code_hooks()

        settings = json.loads((claude_dir / "settings.json").read_text())
        # Old ones removed, 2 new ones added = exactly 2
        assert len(settings["hooks"]["PreToolUse"]) == 2

    def test_preserves_non_hook_settings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        existing = {"theme": "dark", "hooks": {}}
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        _install_claude_code_hooks()

        settings = json.loads((claude_dir / "settings.json").read_text())
        assert settings["theme"] == "dark"
        assert len(settings["hooks"]["PreToolUse"]) == 2
