"""Regression tests for issue #31: quiet agent commands."""

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rafter_cli.__main__ import app


runner = CliRunner()

_INHERITED_GIT_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR")


def _isolated_env(home: Path) -> dict[str, str]:
    """Copy of os.environ with a temp HOME/git config and no repo-pointing vars."""
    env = os.environ.copy()
    for var in _INHERITED_GIT_VARS:
        env.pop(var, None)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["GIT_CONFIG_GLOBAL"] = str(home / ".gitconfig")
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def _isolate_process_env(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    """Apply the same isolation to os.environ for in-process CliRunner tests."""
    for var in _INHERITED_GIT_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / ".gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def test_agent_init_quiet_has_no_stdout(tmp_path, monkeypatch):
    """Quiet init should succeed without informational output."""
    _isolate_process_env(monkeypatch, tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["agent", "init", "--quiet"])

    assert result.exit_code == 0
    assert result.stdout == ""

    config_path = tmp_path / ".rafter" / "config.json"
    assert config_path.exists(), "Quiet init should still create a config file"


def test_agent_install_hook_quiet_has_no_stdout(tmp_path, monkeypatch):
    """Quiet hook installation should succeed without status output."""
    import subprocess

    _isolate_process_env(monkeypatch, tmp_path)
    monkeypatch.chdir(tmp_path)

    subprocess.run(
        ["git", "init", str(tmp_path)],
        env=_isolated_env(tmp_path),
        capture_output=True,
        check=True,
    )

    result = runner.invoke(app, ["agent", "install-hook", "--quiet"])

    assert result.exit_code == 0
    assert result.stdout == ""

    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    assert hook_path.exists()
    assert "Rafter Security Pre-Commit Hook" in hook_path.read_text()


def test_install_hook_quiet_keeps_errors_on_stderr(tmp_path):
    """Quiet mode must preserve real stderr and nonzero exit status."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "agent", "install-hook", "--quiet"],
        cwd=tmp_path,
        env=_isolated_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Not in a git repository" in result.stderr


def test_install_hook_push_quiet(tmp_path):
    """Quiet pre-push installation should succeed without stdout."""
    import os
    import subprocess
    import sys

    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()

    env = os.environ.copy()
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(var, None)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["GIT_CONFIG_GLOBAL"] = str(home / ".gitconfig")
    env["GIT_CONFIG_NOSYSTEM"] = "1"

    subprocess.run(
        ["git", "init", str(repo)],
        env=env,
        capture_output=True,
        check=True,
        timeout=15,
    )

    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "agent", "install-hook", "--push", "--quiet"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

    hook_path = repo / ".git" / "hooks" / "pre-push"
    assert hook_path.exists()
    assert "Rafter Security Pre-Push Hook" in hook_path.read_text()


def test_install_hook_global_quiet(tmp_path):
    """Quiet global installation should succeed without stdout."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    home = tmp_path / "home"
    home.mkdir()
    workdir = tmp_path / "work"
    workdir.mkdir()

    env = os.environ.copy()
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(var, None)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["GIT_CONFIG_GLOBAL"] = str(home / ".gitconfig")
    env["GIT_CONFIG_NOSYSTEM"] = "1"

    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "agent", "install-hook", "--global", "--quiet"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

    hooks_dir = home / ".rafter" / "git-hooks"
    assert (hooks_dir / "pre-commit").exists()

    config = subprocess.run(
        ["git", "config", "--global", "--get", "core.hooksPath"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert Path(config.stdout.strip()).resolve() == hooks_dir.resolve()


def test_agent_init_dry_run_quiet_with_cursor(tmp_path):
    """Quiet dry-run keeps the plan on stdout and the warning on stderr."""
    import os
    import subprocess
    import sys

    home = tmp_path / "home"
    home.mkdir()
    workdir = tmp_path / "work"
    workdir.mkdir()

    env = os.environ.copy()
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(var, None)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["GIT_CONFIG_GLOBAL"] = str(home / ".gitconfig")
    env["GIT_CONFIG_NOSYSTEM"] = "1"

    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "agent", "init", "--dry-run", "--quiet", "--with-cursor"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert "DRY RUN" in result.stdout
    assert "Rafter Agent Security Setup" not in result.stdout
    assert "No agent environments detected" not in result.stdout
    assert "Cursor requested but not detected (~/.cursor not found)" in result.stderr

    assert not (home / ".rafter" / "config.json").exists()
