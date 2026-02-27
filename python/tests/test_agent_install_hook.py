"""Tests for rafter agent install-hook command."""
from __future__ import annotations

import stat
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from rafter_cli.commands.agent import agent_app, _get_hook_template, _install_local_hook, _install_global_hook


runner = CliRunner()

HOOK_MARKER = "Rafter Security Pre-Commit Hook"


class TestGetHookTemplate:
    def test_returns_shell_script(self):
        content = _get_hook_template()
        assert content.startswith("#!/bin/bash")
        assert HOOK_MARKER in content

    def test_includes_scan_command(self):
        content = _get_hook_template()
        assert "rafter scan local" in content


class TestInstallLocalHook:
    def test_installs_hook_in_git_repo(self, tmp_path):
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
        original_cwd = Path.cwd()
        import os
        os.chdir(tmp_path)
        try:
            result = runner.invoke(agent_app, ["install-hook"])
            assert result.exit_code == 0
            hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
            assert hook_path.exists()
            assert HOOK_MARKER in hook_path.read_text()
            # Must be executable
            mode = hook_path.stat().st_mode
            assert mode & stat.S_IXUSR
        finally:
            os.chdir(original_cwd)

    def test_idempotent_if_already_installed(self, tmp_path):
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
        import os
        original_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            runner.invoke(agent_app, ["install-hook"])
            result = runner.invoke(agent_app, ["install-hook"])
            assert result.exit_code == 0
            assert "already installed" in result.output
        finally:
            os.chdir(original_cwd)

    def test_backs_up_existing_non_rafter_hook(self, tmp_path):
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
        hooks_dir = tmp_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        existing_hook = hooks_dir / "pre-commit"
        existing_hook.write_text("#!/bin/bash\necho 'existing hook'\n")

        import os
        original_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(agent_app, ["install-hook"])
            assert result.exit_code == 0
            # Backup created
            backups = list(hooks_dir.glob("pre-commit.backup-*"))
            assert len(backups) == 1
            # New hook installed
            assert HOOK_MARKER in existing_hook.read_text()
        finally:
            os.chdir(original_cwd)

    def test_fails_outside_git_repo(self, tmp_path):
        import os
        original_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(agent_app, ["install-hook"])
            assert result.exit_code != 0
        finally:
            os.chdir(original_cwd)


class TestInstallGlobalHook:
    def test_installs_globally(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0

            result = runner.invoke(agent_app, ["install-hook", "--global"])
            assert result.exit_code == 0

            hook_path = tmp_path / ".rafter" / "git-hooks" / "pre-commit"
            assert hook_path.exists()
            assert HOOK_MARKER in hook_path.read_text()
            mode = hook_path.stat().st_mode
            assert mode & stat.S_IXUSR

            # Verify git config was called
            git_calls = [c for c in mock_run.call_args_list
                         if c.args and "git" in str(c.args[0])]
            assert any("core.hooksPath" in str(c) for c in git_calls)
