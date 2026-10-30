"""Issue #34 — `rafter usage` errors go through fmt.error on stderr.

Mirrors node/tests/backend-usage-errors.test.ts.
"""
from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch

import pytest
import typer
from rich.console import Console

from rafter_cli.commands.backend import register_backend_commands
from rafter_cli.utils import formatter
from rafter_cli.utils.api import EXIT_GENERAL_ERROR
from rafter_cli.utils.formatter import set_agent_mode

BRACKETED = "key [/] revoked [bold]now[/bold]"


def _resp(status_code: int, text: str = "", json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body if json_body is not None else {}
    return resp


def _unauthorized(error: str = "invalid api key") -> MagicMock:
    return _resp(401, text=json.dumps({"error": error}))


def _usage_command():
    app = typer.Typer()
    register_backend_commands(app)
    return next(c.callback for c in app.registered_commands if c.callback.__name__ == "usage")


def _run_usage_failing() -> int:
    """Invoke `rafter usage` and return the exit code it raised."""
    with pytest.raises(typer.Exit) as exc:
        _usage_command()(api_key="test-key")
    return exc.value.exit_code


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    set_agent_mode(False)
    monkeypatch.delenv("RAFTER_API_URL", raising=False)
    yield
    set_agent_mode(False)


@pytest.fixture
def human_stderr(monkeypatch) -> io.StringIO:
    """Real Rich rendering into a buffer: wide and colorless, so assertions are exact."""
    buf = io.StringIO()
    monkeypatch.setattr(
        formatter, "_stderr_console", Console(file=buf, width=200, color_system=None)
    )
    return buf


def test_structured_http_error_reports_status_and_detail(capsys):
    set_agent_mode(True)
    with patch("rafter_cli.commands.backend.api_get", return_value=_unauthorized()):
        code = _run_usage_failing()

    assert code == EXIT_GENERAL_ERROR
    captured = capsys.readouterr()
    assert captured.err == "[ERROR] HTTP 401 — invalid api key\n"
    assert captured.out == ""


def test_human_mode_shows_bracketed_text_literally(human_stderr):
    with patch("rafter_cli.commands.backend.api_get", return_value=_unauthorized(BRACKETED)):
        code = _run_usage_failing()

    assert code == EXIT_GENERAL_ERROR
    assert human_stderr.getvalue() == f"✗ HTTP 401 — {BRACKETED}\n"


def test_agent_mode_does_not_escape_bracketed_text(capsys):
    set_agent_mode(True)
    with patch("rafter_cli.commands.backend.api_get", return_value=_unauthorized(BRACKETED)):
        code = _run_usage_failing()

    assert code == EXIT_GENERAL_ERROR
    assert capsys.readouterr().err == f"[ERROR] HTTP 401 — {BRACKETED}\n"


def test_success_prints_usage_json_unchanged(capsys):
    data = {"used": 3, "limit": 10}
    with patch("rafter_cli.commands.backend.api_get", return_value=_resp(200, json_body=data)):
        _usage_command()(api_key="test-key")

    captured = capsys.readouterr()
    assert captured.out == json.dumps(data, indent=2) + "\n"
    assert captured.err == ""
