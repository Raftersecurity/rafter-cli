"""Tests for rafter upgrade / rafter update commands."""
from __future__ import annotations

import sys
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from rafter_cli.__main__ import app
from rafter_cli.commands.upgrade import (
    _is_ci,
    _is_newer,
    _detect_installer,
    _build_upgrade_command,
    _fetch_latest_version,
)

runner = CliRunner()


class TestIsCI:
    def test_ci_env_true(self, monkeypatch):
        monkeypatch.setenv("CI", "true")
        assert _is_ci() is True

    def test_github_actions(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        assert _is_ci() is True

    def test_no_ci_env(self, monkeypatch):
        for var in ("CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI",
                    "CIRCLECI", "TRAVIS", "JENKINS_URL"):
            monkeypatch.delenv(var, raising=False)
        assert _is_ci() is False


class TestIsNewer:
    def test_newer_patch(self):
        assert _is_newer("0.8.0", "0.8.1") is True

    def test_newer_minor(self):
        assert _is_newer("0.7.9", "0.8.0") is True

    def test_same_version(self):
        assert _is_newer("0.8.1", "0.8.1") is False

    def test_current_is_newer(self):
        assert _is_newer("1.0.0", "0.9.9") is False


class TestDetectInstaller:
    def test_pipx_via_home(self, monkeypatch, tmp_path):
        pipx_home = str(tmp_path / "pipx")
        monkeypatch.setenv("PIPX_HOME", pipx_home)
        monkeypatch.setattr(sys, "executable", f"{pipx_home}/venvs/rafter-cli/bin/python")
        assert _detect_installer() == "pipx"

    def test_uv_via_lock(self, monkeypatch, tmp_path):
        venv = tmp_path / ".venv"
        venv.mkdir()
        (tmp_path / "uv.lock").write_text("")
        monkeypatch.setenv("VIRTUAL_ENV", str(venv))
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(sys, "executable", str(venv / "bin" / "python"))
        assert _detect_installer() == "uv"

    def test_poetry_via_lock(self, monkeypatch, tmp_path):
        venv = tmp_path / ".venv"
        venv.mkdir()
        (tmp_path / "poetry.lock").write_text("")
        monkeypatch.setenv("VIRTUAL_ENV", str(venv))
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(sys, "executable", str(venv / "bin" / "python"))
        assert _detect_installer() == "poetry"

    def test_unknown_returns_none(self, monkeypatch):
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setattr(sys, "executable", "/usr/bin/python3")
        assert _detect_installer() is None


class TestBuildUpgradeCommand:
    def test_pipx(self):
        cmds = _build_upgrade_command("pipx")
        assert cmds == [["pipx", "upgrade", "rafter-cli"]]

    def test_uv(self):
        cmds = _build_upgrade_command("uv")
        assert cmds == [["uv", "tool", "upgrade", "rafter-cli"]]

    def test_pip_fallback(self):
        cmds = _build_upgrade_command(None)
        assert cmds[0][-1] == "rafter-cli"
        assert "--upgrade" in cmds[0]


class TestUpgradeCommand:
    def test_ci_noop(self, monkeypatch):
        monkeypatch.setenv("CI", "true")
        result = runner.invoke(app, ["upgrade"])
        assert result.exit_code == 0
        assert "CI environment" in result.output

    def test_update_alias_ci_noop(self, monkeypatch):
        monkeypatch.setenv("CI", "true")
        result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        assert "CI environment" in result.output

    def test_check_flag_returns_version(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        with patch("rafter_cli.commands.upgrade._fetch_latest_version", return_value="9.9.9"):
            result = runner.invoke(app, ["upgrade", "--check"])
        assert result.exit_code == 0
        assert "9.9.9" in result.output

    def test_update_check_flag_returns_version(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        with patch("rafter_cli.commands.upgrade._fetch_latest_version", return_value="9.9.9"):
            result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 0
        assert "9.9.9" in result.output

    def test_already_up_to_date(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        from rafter_cli import __version__
        with patch("rafter_cli.commands.upgrade._fetch_latest_version", return_value=__version__):
            result = runner.invoke(app, ["upgrade"])
        assert result.exit_code == 0
        assert "up to date" in result.output.lower()

    def test_shows_upgrade_command_when_update_available(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        with patch("rafter_cli.commands.upgrade._fetch_latest_version", return_value="999.0.0"):
            result = runner.invoke(app, ["upgrade"])
        assert result.exit_code == 0
        # Should show pip/pipx/uv commands
        assert "pip" in result.output or "pipx" in result.output or "uv" in result.output

    def test_network_error_exits_1(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        with patch("rafter_cli.commands.upgrade._fetch_latest_version", side_effect=Exception("Network error")):
            result = runner.invoke(app, ["upgrade"])
        assert result.exit_code == 1

    def test_yes_flag_runs_command(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        with patch("rafter_cli.commands.upgrade._fetch_latest_version", return_value="999.0.0"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                result = runner.invoke(app, ["upgrade", "--yes"])
        assert result.exit_code == 0
        mock_run.assert_called_once()


class TestFetchLatestVersion:
    def test_returns_semver_string(self):
        version = _fetch_latest_version()
        parts = version.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)
