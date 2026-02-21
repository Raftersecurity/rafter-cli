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
    _check_gitleaks,
    _check_claude_code,
    _check_openclaw,
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


# ── _check_gitleaks ────────────────────────────────────────────────────

class TestCheckGitleaks:
    def test_passes_when_gitleaks_on_path(self):
        verify_result = {"ok": True, "stdout": "gitleaks version 8.18.2", "stderr": ""}
        with patch("shutil.which", return_value="/usr/local/bin/gitleaks"), \
             patch("rafter_cli.commands.agent.BinaryManager") as MockBM:
            MockBM.return_value.verify_gitleaks_verbose.return_value = verify_result
            r = _check_gitleaks()
        assert r.passed
        assert "gitleaks version" in r.detail

    def test_passes_when_gitleaks_in_rafter_bin(self, tmp_path):
        rafter_bin = tmp_path / ".rafter" / "bin" / "gitleaks"
        rafter_bin.parent.mkdir(parents=True)
        rafter_bin.touch()
        verify_result = {"ok": True, "stdout": "gitleaks version 8.18.2", "stderr": ""}
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.home", return_value=tmp_path), \
             patch("rafter_cli.commands.agent.BinaryManager") as MockBM:
            MockBM.return_value.verify_gitleaks_verbose.return_value = verify_result
            r = _check_gitleaks()
        assert r.passed

    def test_fails_when_not_found_anywhere(self, tmp_path):
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_gitleaks()
        assert not r.passed
        assert not r.optional  # hard failure
        assert "Not found" in r.detail

    def test_fails_with_diagnostics_when_binary_broken(self):
        verify_result = {"ok": False, "stdout": "", "stderr": "exec format error"}
        with patch("shutil.which", return_value="/usr/local/bin/gitleaks"), \
             patch("rafter_cli.commands.agent.BinaryManager") as MockBM:
            MockBM.return_value.verify_gitleaks_verbose.return_value = verify_result
            MockBM.return_value.collect_binary_diagnostics.return_value = "  file: ELF 64-bit"
            r = _check_gitleaks()
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
    def test_warns_when_openclaw_not_installed(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_openclaw()
        assert not r.passed
        assert r.optional  # must be optional
        assert "Not detected" in r.detail

    def test_warns_when_rafter_skill_missing(self, tmp_path):
        (tmp_path / ".openclaw" / "skills").mkdir(parents=True)
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_openclaw()
        assert not r.passed
        assert r.optional

    def test_passes_when_skill_installed(self, tmp_path):
        skills_dir = tmp_path / ".openclaw" / "skills"
        skills_dir.mkdir(parents=True)
        (skills_dir / "rafter-security.md").write_text("# Rafter\nversion: 0.5.2\n")
        with patch("pathlib.Path.home", return_value=tmp_path):
            r = _check_openclaw()
        assert r.passed
        assert "0.5.2" in r.detail


# ── verify command (exit code contract) ──────────────────────────────

class TestVerifyCommand:
    def _make_check(self, passed: bool, optional: bool = False) -> _CheckResult:
        return _CheckResult("Test", passed, "detail", optional=optional)

    def test_exits_0_when_all_core_checks_pass(self, tmp_path):
        """All core checks pass, optional absent → exit 0."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_gitleaks",
                   return_value=_CheckResult("Gitleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "not configured", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "not installed", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 0

    def test_exits_0_with_all_checks_passing(self, tmp_path):
        """All four checks pass → exit 0, no warnings."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_gitleaks",
                   return_value=_CheckResult("Gitleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", True, "ok")), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", True, "ok")):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 0

    def test_exits_1_when_config_missing(self):
        """Config failure (hard) → exit 1."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", False, "Not found")), \
             patch("rafter_cli.commands.agent._check_gitleaks",
                   return_value=_CheckResult("Gitleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "not configured", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "not installed", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 1

    def test_exits_1_when_gitleaks_broken(self):
        """Gitleaks failure (hard) → exit 1."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_gitleaks",
                   return_value=_CheckResult("Gitleaks", False, "binary broken")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "absent", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "absent", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 1

    def test_exits_0_when_only_optional_checks_fail(self):
        """Only optional checks absent → exit 0 (WARN not FAIL)."""
        with patch("rafter_cli.commands.agent._check_config",
                   return_value=_CheckResult("Config", True, "ok")), \
             patch("rafter_cli.commands.agent._check_gitleaks",
                   return_value=_CheckResult("Gitleaks", True, "ok")), \
             patch("rafter_cli.commands.agent._check_claude_code",
                   return_value=_CheckResult("Claude Code", False, "absent", optional=True)), \
             patch("rafter_cli.commands.agent._check_openclaw",
                   return_value=_CheckResult("OpenClaw", False, "absent", optional=True)):
            result = runner.invoke(agent_app, ["verify"])
        assert result.exit_code == 0
        assert "optional" in result.output.lower() or "not configured" in result.output.lower()
