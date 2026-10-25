"""Regression tests for issue #31: quiet agent commands."""

from typer.testing import CliRunner

from rafter_cli.__main__ import app


runner = CliRunner()


def test_agent_init_quiet_has_no_stdout(tmp_path, monkeypatch):
    """Quiet init should succeed without informational output."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["agent", "init", "--quiet"])

    assert result.exit_code == 0
    assert result.stdout == ""


def test_agent_install_hook_quiet_has_no_stdout(tmp_path, monkeypatch):
    """Quiet hook installation should succeed without status output."""
    import subprocess

    subprocess.run(
        ["git", "init", str(tmp_path)],
        capture_output=True,
        check=True,
    )

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["agent", "install-hook", "--quiet"])

    assert result.exit_code == 0
    assert result.stdout == ""
