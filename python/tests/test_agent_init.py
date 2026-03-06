"""Tests for agent init hook and MCP installation."""
from __future__ import annotations

import json
from pathlib import Path

from rafter_cli.commands.agent import (
    _install_claude_code_hooks,
    _install_gemini_mcp,
    _install_cursor_mcp,
    _install_windsurf_mcp,
    _install_continue_dev_mcp,
    _install_aider_mcp,
)


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


class TestInstallGeminiMcp:
    def test_creates_settings_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_gemini_mcp()

        settings_path = tmp_path / ".gemini" / "settings.json"
        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert settings["mcpServers"]["rafter"]["command"] == "rafter"
        assert settings["mcpServers"]["rafter"]["args"] == ["mcp", "serve"]

    def test_preserves_existing_settings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        (gemini_dir / "settings.json").write_text(json.dumps({"model": "gemini-pro"}))

        _install_gemini_mcp()

        settings = json.loads((gemini_dir / "settings.json").read_text())
        assert settings["model"] == "gemini-pro"
        assert "rafter" in settings["mcpServers"]


class TestInstallCursorMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_cursor_mcp()

        mcp_path = tmp_path / ".cursor" / "mcp.json"
        assert mcp_path.exists()
        config = json.loads(mcp_path.read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"

    def test_preserves_existing_servers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}))

        _install_cursor_mcp()

        config = json.loads((cursor_dir / "mcp.json").read_text())
        assert "other" in config["mcpServers"]
        assert "rafter" in config["mcpServers"]


class TestInstallWindsurfMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_windsurf_mcp()

        mcp_path = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        assert mcp_path.exists()
        config = json.loads(mcp_path.read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"


class TestInstallContinueDevMcp:
    def test_creates_config_with_array_format(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_continue_dev_mcp()

        config_path = tmp_path / ".continue" / "config.json"
        assert config_path.exists()
        config = json.loads(config_path.read_text())
        assert isinstance(config["mcpServers"], list)
        assert any(s["name"] == "rafter" for s in config["mcpServers"])

    def test_deduplicates_on_reinstall(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()
        existing = {"mcpServers": [{"name": "rafter", "command": "old"}]}
        (continue_dir / "config.json").write_text(json.dumps(existing))

        _install_continue_dev_mcp()

        config = json.loads((continue_dir / "config.json").read_text())
        rafter_entries = [s for s in config["mcpServers"] if s["name"] == "rafter"]
        assert len(rafter_entries) == 1
        assert rafter_entries[0]["command"] == "rafter"

    def test_handles_object_format(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()
        existing = {"mcpServers": {"other": {"command": "other"}}}
        (continue_dir / "config.json").write_text(json.dumps(existing))

        _install_continue_dev_mcp()

        config = json.loads((continue_dir / "config.json").read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"
        assert config["mcpServers"]["other"]["command"] == "other"


class TestInstallAiderMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_aider_mcp()

        config_path = tmp_path / ".aider.conf.yml"
        assert config_path.exists()
        content = config_path.read_text()
        assert "rafter mcp serve" in content

    def test_skips_if_already_configured(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("mcp-server-command: rafter mcp serve\n")

        assert _install_aider_mcp()

        content = config_path.read_text()
        assert content.count("rafter mcp serve") == 1

    def test_appends_to_existing_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("model: gpt-4\n")

        _install_aider_mcp()

        content = config_path.read_text()
        assert "model: gpt-4" in content
        assert "rafter mcp serve" in content
