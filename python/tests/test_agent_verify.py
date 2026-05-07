"""Tests for rafter agent verify command."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from rafter_cli.commands.agent import (
    agent_app,
    _check_config,
    _check_betterleaks,
    _check_claude_code,
    _check_openclaw,
    _check_codex,
    _check_gemini,
    _check_cursor,
    _check_windsurf,
    _check_continue_dev,
    _check_aider,
    _probe_claude_code,
    _CheckResult,
)

runner = CliRunner()


# ── _check_config ──────────────────────────────────────────────────────

class TestCheckConfig:
    def test_passes_when_config_exists_and_valid(self, tmp_path):
        config = tmp_path / ".rafter" / "config.json"
        config.parent.mkdir()
        config.write_text('{"riskLevel": "moderate"}')
        with patch("rafter_cli.commands.agent.Path") as mock_path:
            # Redirect Path.home() to tmp_path
            mock_path.home.return_value = tmp_path
            mock_path.side_effect = lambda *a: Path(*a)
            result = _check_config()
        # Direct call with real filesystem via tmp_path
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_config()
        assert r.passed
        assert not r.optional

    def test_fails_when_config_missing(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_config()
        assert not r.passed
        assert not r.optional  # hard failure
        assert "Not found" in r.detail

    def test_fails_when_config_invalid_json(self, tmp_path):
        config = tmp_path / ".rafter" / "config.json"
        config.parent.mkdir()
        config.write_text("not-json{{{")
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_config()
        assert not r.passed
        assert not r.optional
        assert "Invalid" in r.detail


# ── _check_betterleaks ────────────────────────────────────────────────────

class TestCheckBetterleaks:
    def test_passes_when_betterleaks_on_path(self):
        verify_result = {"ok": True, "stdout": "betterleaks 1.1.2", "stderr": ""}
        with patch("shutil.which", return_value="/usr/local/bin/betterleaks"), \
             patch("rafter_cli.commands.agent.BinaryManager") as MockBM:
            MockBM.return_value.verify_betterleaks_verbose.return_value = verify_result
            r = _check_betterleaks()
        assert r.passed
        assert "betterleaks" in r.detail

    def test_passes_when_betterleaks_in_rafter_bin(self, tmp_path):
        rafter_bin = tmp_path / ".rafter" / "bin" / "betterleaks"
        rafter_bin.parent.mkdir(parents=True)
        rafter_bin.touch()
        verify_result = {"ok": True, "stdout": "betterleaks 1.1.2", "stderr": ""}
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.home", return_value=tmp_path), \
             patch("rafter_cli.commands.agent.BinaryManager") as MockBM:
            MockBM.return_value.verify_betterleaks_verbose.return_value = verify_result
            r = _check_betterleaks()
        assert r.passed

    def test_fails_when_not_found_anywhere(self, tmp_path):
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_betterleaks()
        assert not r.passed
        assert not r.optional  # hard failure
        assert "Not found" in r.detail

    def test_fails_with_diagnostics_when_binary_broken(self):
        verify_result = {"ok": False, "stdout": "", "stderr": "exec format error"}
        with patch("shutil.which", return_value="/usr/local/bin/betterleaks"), \
             patch("rafter_cli.commands.agent.BinaryManager") as MockBM:
            MockBM.return_value.verify_betterleaks_verbose.return_value = verify_result
            MockBM.return_value.collect_binary_diagnostics.return_value = "  file: ELF 64-bit"
            r = _check_betterleaks()
        assert not r.passed
        assert not r.optional
        assert "failed to execute" in r.detail


# ── _check_claude_code ────────────────────────────────────────────────

class TestCheckClaudeCode:
    def test_warns_when_claude_dir_missing(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_claude_code()
        assert not r.passed
        assert r.optional  # must be optional, not hard failure
        assert "Not detected" in r.detail

    def test_warns_when_settings_missing(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_claude_code()
        assert not r.passed
        assert r.optional

    def test_warns_when_hooks_not_installed(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "settings.json").write_text('{"hooks": {}}')
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_claude_code()
        assert not r.passed
        assert r.optional
        assert "rafter agent init" in r.detail

    def test_passes_when_hooks_installed(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"command": "rafter hook pretool"}]}
                ]
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(settings))
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_claude_code()
        assert r.passed
        assert not r.optional


# ── _check_openclaw ───────────────────────────────────────────────────

class TestCheckOpenClaw:
    """rf-zgwj — OpenClaw verify reads the ClawHub-shaped skill at
    ~/.openclaw/workspace/skills/rafter-security/SKILL.md."""

    def test_warns_when_openclaw_not_installed(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_openclaw()
        assert not r.passed
        assert r.optional
        assert "Not detected" in r.detail

    def test_warns_when_rafter_skill_missing(self, tmp_path):
        (tmp_path / ".openclaw").mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_openclaw()
        assert not r.passed
        assert r.optional
        assert "not installed" in r.detail.lower()

    def test_warns_with_legacy_path_when_only_legacy_present(self, tmp_path):
        legacy_dir = tmp_path / ".openclaw" / "skills"
        legacy_dir.mkdir(parents=True)
        (legacy_dir / "rafter-security.md").write_text("# old\nversion: 0.6.0\n")
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_openclaw()
        assert not r.passed
        assert r.optional
        assert "Legacy skill" in r.detail
        assert "rafter-security/SKILL.md" in r.detail

    def test_passes_when_clawhub_skill_installed(self, tmp_path):
        skill_dir = tmp_path / ".openclaw" / "workspace" / "skills" / "rafter-security"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: rafter-security\nversion: 0.7.7\n---\n# body\n"
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_openclaw()
        assert r.passed
        assert "0.7.7" in r.detail


# ── _check_codex ─────────────────────────────────────────────────────

class TestCheckCodex:
    def test_warns_when_codex_not_detected(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_codex()
        assert not r.passed
        assert r.optional
        assert "Not detected" in r.detail

    def test_warns_when_skills_missing(self, tmp_path):
        (tmp_path / ".codex").mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_codex()
        assert not r.passed
        assert r.optional
        assert "not installed" in r.detail.lower()

    def test_passes_when_skills_installed(self, tmp_path):
        (tmp_path / ".codex").mkdir()
        skill_dir = tmp_path / ".agents" / "skills" / "rafter"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# Rafter Backend")
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_codex()
        assert r.passed


# ── _check_gemini / _check_cursor / _check_windsurf (rf-65zg parity) ─


class TestCheckGemini:
    def test_warns_when_gemini_absent(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_gemini()
        assert not r.passed and r.optional and "Not detected" in r.detail

    def test_warns_when_settings_missing(self, tmp_path):
        (tmp_path / ".gemini").mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_gemini()
        assert not r.passed and r.optional

    def test_warns_when_mcp_absent(self, tmp_path):
        (tmp_path / ".gemini").mkdir()
        (tmp_path / ".gemini" / "settings.json").write_text(json.dumps({"hooks": {}}))
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_gemini()
        assert not r.passed and r.optional

    def test_passes_when_mcp_configured(self, tmp_path):
        (tmp_path / ".gemini").mkdir()
        (tmp_path / ".gemini" / "settings.json").write_text(
            json.dumps({"mcpServers": {"rafter": {"command": "rafter"}}})
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_gemini()
        assert r.passed


class TestCheckCursor:
    def test_warns_when_cursor_absent(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_cursor()
        assert not r.passed and r.optional

    def test_passes_when_mcp_configured(self, tmp_path):
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".cursor" / "mcp.json").write_text(
            json.dumps({"mcpServers": {"rafter": {"command": "rafter"}}})
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_cursor()
        assert r.passed


class TestCheckWindsurf:
    def test_warns_when_windsurf_absent(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_windsurf()
        assert not r.passed and r.optional

    def test_passes_when_mcp_configured(self, tmp_path):
        wdir = tmp_path / ".codeium" / "windsurf"
        wdir.mkdir(parents=True)
        (wdir / "mcp_config.json").write_text(
            json.dumps({"mcpServers": {"rafter": {"command": "rafter"}}})
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_windsurf()
        assert r.passed


class TestCheckContinueDev:
    def test_warns_when_absent(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_continue_dev()
        assert not r.passed and r.optional

    def test_warns_when_mcp_absent(self, tmp_path):
        (tmp_path / ".continue").mkdir()
        (tmp_path / ".continue" / "config.json").write_text(json.dumps({"mcpServers": []}))
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_continue_dev()
        assert not r.passed and r.optional

    def test_passes_with_array_format(self, tmp_path):
        (tmp_path / ".continue").mkdir()
        (tmp_path / ".continue" / "config.json").write_text(
            json.dumps({"mcpServers": [{"name": "rafter", "command": "rafter"}]})
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_continue_dev()
        assert r.passed

    def test_passes_with_object_format(self, tmp_path):
        (tmp_path / ".continue").mkdir()
        (tmp_path / ".continue" / "config.json").write_text(
            json.dumps({"mcpServers": {"rafter": {"command": "rafter"}}})
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_continue_dev()
        assert r.passed


class TestCheckAider:
    def test_warns_when_no_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_aider()
        assert not r.passed and r.optional

    def test_warns_when_rafter_md_not_in_read(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".aider.conf.yml").write_text("model: gpt-5\n")
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_aider()
        assert not r.passed and r.optional and "RAFTER.md" in r.detail

    def test_warns_when_rafter_md_missing_on_disk(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".aider.conf.yml").write_text("read:\n  - RAFTER.md\n")
        # No RAFTER.md file written.
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_aider()
        assert not r.passed and r.optional and "missing" in r.detail.lower()

    def test_passes_when_rafter_md_listed_and_present(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".aider.conf.yml").write_text("read:\n  - RAFTER.md\n")
        (tmp_path / "RAFTER.md").write_text("<!-- rafter:start -->\n<!-- rafter:end -->\n")
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_aider()
        assert r.passed


# ── _probe_claude_code (rf-65zg) ──────────────────────────────────────


class TestProbeClaudeCode:
    def test_warns_when_claude_code_not_installed(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _probe_claude_code()
        assert not r.passed and r.optional and "Not installed" in r.detail


# ── verify command (exit code contract) ──────────────────────────────

class TestVerifyCommand:
    def _make_check(self, passed: bool, optional: bool = False) -> _CheckResult:
        return _CheckResult("Test", passed, "detail", optional=optional)

    def test_exits_0_when_all_core_checks_pass(self, tmp_path):
        """All core checks pass, optional absent → exit 0."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_betterleaks",
                   return_value=_CheckResult("Betterleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "not configured", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "not installed", optional=True)), \
             patch("rafter_cli.commands.agent._check_codex",
                   return_value=_CheckResult("Codex CLI", False, "not detected", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 0

    def test_exits_0_with_all_checks_passing(self, tmp_path):
        """All checks pass → exit 0, no warnings."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_betterleaks",
                   return_value=_CheckResult("Betterleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", True, "ok")), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", True, "ok")), \
             patch("rafter_cli.commands.agent._check_codex",
                   return_value=_CheckResult("Codex CLI", True, "ok")):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 0

    def test_exits_1_when_config_missing(self):
        """Config failure (hard) → exit 1."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", False, "Not found")), \
             patch("rafter_cli.commands.agent._check_betterleaks",
                   return_value=_CheckResult("Betterleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "not configured", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "not installed", optional=True)), \
             patch("rafter_cli.commands.agent._check_codex",
                   return_value=_CheckResult("Codex CLI", False, "not detected", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 1

    def test_exits_1_when_betterleaks_broken(self):
        """Betterleaks failure (hard) → exit 1."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_betterleaks",
                   return_value=_CheckResult("Betterleaks", False, "binary broken")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "absent", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "absent", optional=True)), \
             patch("rafter_cli.commands.agent._check_codex",
                   return_value=_CheckResult("Codex CLI", False, "absent", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 1

    def test_exits_0_when_only_optional_checks_fail(self):
        """Only optional checks absent → exit 0 (WARN not FAIL)."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_betterleaks",
                   return_value=_CheckResult("Betterleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "absent", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "absent", optional=True)), \
             patch("rafter_cli.commands.agent._check_codex",
                   return_value=_CheckResult("Codex CLI", False, "absent", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 0
        assert "optional" in result.output.lower() or "not configured" in result.output.lower()
