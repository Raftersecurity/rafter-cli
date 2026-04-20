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
        _install_claude_code_hooks(tmp_path)

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

        _install_claude_code_hooks(tmp_path)

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

        _install_claude_code_hooks(tmp_path)

        settings = json.loads((claude_dir / "settings.json").read_text())
        # Old ones removed, 2 new ones added = exactly 2
        assert len(settings["hooks"]["PreToolUse"]) == 2

    def test_preserves_non_hook_settings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        existing = {"theme": "dark", "hooks": {}}
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        _install_claude_code_hooks(tmp_path)

        settings = json.loads((claude_dir / "settings.json").read_text())
        assert settings["theme"] == "dark"
        assert len(settings["hooks"]["PreToolUse"]) == 2


class TestInstallGeminiMcp:
    def test_creates_settings_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_gemini_mcp(tmp_path)

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

        _install_gemini_mcp(tmp_path)

        settings = json.loads((gemini_dir / "settings.json").read_text())
        assert settings["model"] == "gemini-pro"
        assert "rafter" in settings["mcpServers"]


class TestInstallCursorMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_cursor_mcp(tmp_path)

        mcp_path = tmp_path / ".cursor" / "mcp.json"
        assert mcp_path.exists()
        config = json.loads(mcp_path.read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"

    def test_preserves_existing_servers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}))

        _install_cursor_mcp(tmp_path)

        config = json.loads((cursor_dir / "mcp.json").read_text())
        assert "other" in config["mcpServers"]
        assert "rafter" in config["mcpServers"]


class TestInstallWindsurfMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_windsurf_mcp(tmp_path)

        mcp_path = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        assert mcp_path.exists()
        config = json.loads(mcp_path.read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"


class TestInstallContinueDevMcp:
    def test_creates_config_with_array_format(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_continue_dev_mcp(tmp_path)

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

        _install_continue_dev_mcp(tmp_path)

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

        _install_continue_dev_mcp(tmp_path)

        config = json.loads((continue_dir / "config.json").read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"
        assert config["mcpServers"]["other"]["command"] == "other"


class TestInstallAiderMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_aider_mcp(tmp_path)

        config_path = tmp_path / ".aider.conf.yml"
        assert config_path.exists()
        content = config_path.read_text()
        assert "rafter mcp serve" in content

    def test_skips_if_already_configured(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("mcp-server-command: rafter mcp serve\n")

        assert _install_aider_mcp(tmp_path)

        content = config_path.read_text()
        assert content.count("rafter mcp serve") == 1

    def test_appends_to_existing_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("model: gpt-4\n")

        _install_aider_mcp(tmp_path)

        content = config_path.read_text()
        assert "model: gpt-4" in content
        assert "rafter mcp serve" in content


# ── Flag rejection tests ─────────────────────────────────────────────


class TestFlagRejection:
    """--skip-openclaw and --skip-claude-code are NOT valid flags for `agent init`."""

    def test_skip_openclaw_rejected(self):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--skip-openclaw"])
        assert result.exit_code != 0, f"Expected non-zero exit code, got {result.exit_code}"

    def test_skip_claude_code_rejected(self):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--skip-claude-code"])
        assert result.exit_code != 0, f"Expected non-zero exit code, got {result.exit_code}"


# ── Opt-in gating tests ──────────────────────────────────────────────


class TestOptInGating:
    """Running init without --with-* flags should NOT install any platform configs."""

    def test_no_flags_skips_all_installations(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Create directories so environments are "detected" but no --with-* flags
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".openclaw").mkdir()
        (tmp_path / ".codex").mkdir()
        (tmp_path / ".gemini").mkdir()
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
        (tmp_path / ".continue").mkdir()
        (tmp_path / ".aider.conf.yml").write_text("")

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init"])

        # Claude Code hooks should NOT be installed
        settings_path = tmp_path / ".claude" / "settings.json"
        assert not settings_path.exists(), "Claude Code settings.json should not be created without --with-claude-code"

        # OpenClaw skill should NOT be installed
        openclaw_skill = tmp_path / ".openclaw" / "skills" / "rafter-security.md"
        assert not openclaw_skill.exists(), "OpenClaw skill should not be installed without --with-openclaw"

        # Codex skills should NOT be installed
        codex_skill = tmp_path / ".agents" / "skills" / "rafter" / "SKILL.md"
        assert not codex_skill.exists(), "Codex skill should not be installed without --with-codex"

        # Gemini MCP should NOT be installed
        gemini_settings = tmp_path / ".gemini" / "settings.json"
        assert not gemini_settings.exists(), "Gemini settings.json should not be created without --with-gemini"

        # Cursor MCP should NOT be installed
        cursor_mcp = tmp_path / ".cursor" / "mcp.json"
        assert not cursor_mcp.exists(), "Cursor mcp.json should not be created without --with-cursor"

        # Windsurf MCP should NOT be installed
        windsurf_mcp = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        assert not windsurf_mcp.exists(), "Windsurf mcp_config.json should not be created without --with-windsurf"

        # Continue.dev MCP should NOT be installed
        continue_config = tmp_path / ".continue" / "config.json"
        assert not continue_config.exists(), "Continue config.json should not be created without --with-continue"

        # Aider MCP should NOT be appended
        aider_content = (tmp_path / ".aider.conf.yml").read_text()
        assert "rafter" not in aider_content, "Aider config should not be modified without --with-aider"


# ── Codex skill installation tests ───────────────────────────────────

from rafter_cli.commands.agent import _install_codex_skills


class TestInstallCodexSkills:
    def test_creates_skills_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        ok, error = _install_codex_skills(tmp_path)
        assert ok, f"Expected success, got error: {error}"
        assert error == ""

        # Must mirror _AGENT_SKILLS in python/rafter_cli/commands/agent.py.
        for name in ("rafter", "rafter-secure-design", "rafter-code-review"):
            skill_path = tmp_path / ".agents" / "skills" / name / "SKILL.md"
            assert skill_path.exists(), f"{name} SKILL.md should be installed"
            assert skill_path.read_text().strip(), f"{name} SKILL.md should not be empty"

    def test_overwrites_existing_skills(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Pre-create with stale content
        backend_dir = tmp_path / ".agents" / "skills" / "rafter"
        backend_dir.mkdir(parents=True)
        (backend_dir / "SKILL.md").write_text("old content")

        ok, error = _install_codex_skills(tmp_path)
        assert ok

        content = (backend_dir / "SKILL.md").read_text()
        assert content != "old content", "Skill should be updated on reinstall"


# ── OpenClaw skill installation tests ────────────────────────────────

from rafter_cli.commands.agent import _install_openclaw_skill


class TestInstallOpenClawSkill:
    def test_installs_skill_when_openclaw_dir_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".openclaw").mkdir()

        ok, source, dest, error = _install_openclaw_skill()
        assert ok, f"Expected success, got error: {error}"
        assert error == ""

        dest_path = tmp_path / ".openclaw" / "skills" / "rafter-security.md"
        assert dest_path.exists(), "Skill file should be installed"
        assert dest_path.read_text().strip(), "Skill file should not be empty"
        assert str(dest_path) == dest

    def test_fails_when_openclaw_dir_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # Do NOT create .openclaw directory

        ok, source, dest, error = _install_openclaw_skill()
        assert not ok, "Should fail when .openclaw directory is missing"
        assert "not found" in error.lower()

    def test_overwrites_existing_skill(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir()
        skills_dir = openclaw_dir / "skills"
        skills_dir.mkdir()
        (skills_dir / "rafter-security.md").write_text("old content")

        ok, source, dest, error = _install_openclaw_skill()
        assert ok

        content = (skills_dir / "rafter-security.md").read_text()
        assert content != "old content", "Skill should be updated on reinstall"

    def test_creates_skills_subdirectory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".openclaw").mkdir()
        # skills/ subdirectory does NOT exist yet

        ok, source, dest, error = _install_openclaw_skill()
        assert ok

        assert (tmp_path / ".openclaw" / "skills").is_dir(), "Should create skills subdirectory"


# ── Codex AGENTS.md instruction file tests ──────────────────────────


class TestCodexAgentsInstructionFile:
    """`rafter agent init --with-codex` should write AGENTS.md with the rafter marker block."""

    def test_writes_user_scope_agents_md(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-codex"])
        assert result.exit_code == 0, result.output

        agents_path = tmp_path / ".codex" / "AGENTS.md"
        assert agents_path.exists(), "~/.codex/AGENTS.md should be created"

        content = agents_path.read_text()
        assert "<!-- rafter:start -->" in content
        assert "<!-- rafter:end -->" in content

    def test_idempotent_on_repeat_install(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-codex"])
        first = (tmp_path / ".codex" / "AGENTS.md").read_text()
        runner.invoke(app, ["agent", "init", "--with-codex"])
        second = (tmp_path / ".codex" / "AGENTS.md").read_text()

        assert first == second

    def test_preserves_existing_user_content(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()
        agents_path = tmp_path / ".codex" / "AGENTS.md"
        agents_path.write_text("# My personal instructions\n\nDo the thing.\n")

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-codex"])

        content = agents_path.read_text()
        assert "# My personal instructions" in content
        assert "Do the thing." in content
        assert "<!-- rafter:start -->" in content

    def test_skipped_without_with_codex(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()
        (tmp_path / ".claude").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-claude-code"])

        assert not (tmp_path / ".codex" / "AGENTS.md").exists()


# ── Gemini GEMINI.md instruction file tests ─────────────────────────


class TestGeminiInstructionFile:
    """`rafter agent init --with-gemini` should write GEMINI.md with the rafter marker block."""

    def test_writes_user_scope_gemini_md(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-gemini"])
        assert result.exit_code == 0, result.output

        gemini_path = tmp_path / ".gemini" / "GEMINI.md"
        assert gemini_path.exists(), "~/.gemini/GEMINI.md should be created"

        content = gemini_path.read_text()
        assert "<!-- rafter:start -->" in content
        assert "<!-- rafter:end -->" in content

    def test_idempotent_on_repeat_install(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-gemini"])
        first = (tmp_path / ".gemini" / "GEMINI.md").read_text()
        runner.invoke(app, ["agent", "init", "--with-gemini"])
        second = (tmp_path / ".gemini" / "GEMINI.md").read_text()

        assert first == second

    def test_preserves_existing_user_content(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()
        gemini_path = tmp_path / ".gemini" / "GEMINI.md"
        gemini_path.write_text("# My personal instructions\n\nDo the thing.\n")

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-gemini"])

        content = gemini_path.read_text()
        assert "# My personal instructions" in content
        assert "Do the thing." in content
        assert "<!-- rafter:start -->" in content

    def test_skipped_without_with_gemini(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()
        (tmp_path / ".claude").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-claude-code"])

        assert not (tmp_path / ".gemini" / "GEMINI.md").exists()
