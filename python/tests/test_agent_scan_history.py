"""Parity tests for --history flag on `rafter agent scan` and `rafter scan local`."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from rafter_cli.commands.agent import agent_app
from rafter_cli.__main__ import app as root_app


runner = CliRunner()


def test_agent_scan_accepts_history_flag(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("x = 1\n")

    with patch("rafter_cli.commands.agent._scan_directory") as m:
        m.return_value = []
        result = runner.invoke(agent_app, ["scan", str(tmp_path), "--history", "--quiet"])

    assert result.exit_code == 0, result.stdout
    assert m.called
    assert m.call_args.kwargs.get("history") is True


def test_agent_scan_default_history_is_false(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("x = 1\n")

    with patch("rafter_cli.commands.agent._scan_directory") as m:
        m.return_value = []
        result = runner.invoke(agent_app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == 0, result.stdout
    assert m.called
    assert m.call_args.kwargs.get("history") is False


def test_scan_local_accepts_history_flag(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("x = 1\n")

    with patch("rafter_cli.commands.agent._scan_directory") as m:
        m.return_value = []
        result = runner.invoke(root_app, ["scan", "local", str(tmp_path), "--history", "--quiet"])

    assert result.exit_code == 0, result.stdout
    assert m.called
    assert m.call_args.kwargs.get("history") is True
