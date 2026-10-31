"""Issue #34 — `rafter get` errors go through fmt.error on stderr.

Agent mode prints `[ERROR] ...` verbatim; human mode prints `✗ ...` through
Rich, with server-supplied text escaped so bracketed content shows literally.

Mirrors node/tests/backend-get-errors.test.ts.
"""
from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch

import pytest
import typer
from rich.console import Console

from rafter_cli.commands.backend import (
    MAX_TRANSIENT_POLL_FAILURES,
    _handle_scan_status_interactive,
    register_backend_commands,
)
from rafter_cli.utils import formatter
from rafter_cli.utils.api import EXIT_GENERAL_ERROR, EXIT_SCAN_NOT_FOUND
from rafter_cli.utils.formatter import set_agent_mode

HEADERS = {"x-api-key": "test-key"}
BRACKETED = "token [/] revoked [bold]now[/bold]"


def _resp(status_code: int, text: str = "", json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body if json_body is not None else {}
    return resp


def _forbidden(error: str = "Invalid API key") -> MagicMock:
    return _resp(403, text=json.dumps({"error": error}))


def _get_command():
    app = typer.Typer()
    register_backend_commands(app)
    return next(c.callback for c in app.registered_commands if c.callback.__name__ == "get")


def _run_get(scan_id: str = "s1", interactive: bool = False) -> int:
    """Invoke `rafter get` and return the exit code it raised."""
    with pytest.raises(typer.Exit) as exc:
        _get_command()(
            scan_id=scan_id, api_key="test-key", fmt="md", interactive=interactive, quiet=True
        )
    return exc.value.exit_code


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    set_agent_mode(False)
    monkeypatch.delenv("RAFTER_API_URL", raising=False)
    with patch("rafter_cli.commands.backend.time.sleep"):
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


class TestNotFound:
    def test_agent_mode(self, capsys):
        set_agent_mode(True)
        with patch("rafter_cli.commands.backend.api_get", return_value=_resp(404, "{}")):
            code = _run_get("missing-scan")

        assert code == EXIT_SCAN_NOT_FOUND
        assert capsys.readouterr().err == "[ERROR] Scan 'missing-scan' not found\n"

    def test_human_mode(self, human_stderr):
        with patch("rafter_cli.commands.backend.api_get", return_value=_resp(404, "{}")):
            code = _run_get("missing-scan")

        assert code == EXIT_SCAN_NOT_FOUND
        assert human_stderr.getvalue() == "✗ Scan 'missing-scan' not found\n"

    def test_interactive_agent_mode(self, capsys):
        set_agent_mode(True)
        with patch("rafter_cli.commands.backend.api_get", return_value=_resp(404, "{}")):
            code = _run_get("missing-scan", interactive=True)

        assert code == EXIT_SCAN_NOT_FOUND
        assert capsys.readouterr().err == "[ERROR] Scan 'missing-scan' not found\n"


class TestOtherFailures:
    def test_non_404_reports_status_and_detail(self, capsys):
        set_agent_mode(True)
        with patch("rafter_cli.commands.backend.api_get", return_value=_forbidden()) as get:
            code = _run_get()

        assert code == EXIT_GENERAL_ERROR
        assert get.call_count == 1
        assert capsys.readouterr().err == "[ERROR] HTTP 403 — Invalid API key\n"

    def test_gave_up_polling_is_formatted(self, capsys):
        set_agent_mode(True)
        server_500 = _resp(500, text=json.dumps({"error": "Object not found"}))
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [server_500] * MAX_TRANSIENT_POLL_FAILURES
            code = _run_get()

        assert code == EXIT_GENERAL_ERROR
        err = capsys.readouterr().err
        assert err.startswith("[ERROR] Rafter could not read the report for scan s1")
        assert "Object not found" in err
        assert "Error: " not in err

    def test_interactive_midpoll_failure_is_formatted(self, capsys):
        set_agent_mode(True)
        processing = _resp(200, json_body={"status": "processing"})
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [processing, _forbidden()]
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert exc.value.exit_code == EXIT_GENERAL_ERROR
        assert capsys.readouterr().err == "[ERROR] HTTP 403 — Invalid API key\n"


class TestBracketedServerText:
    def test_human_mode_shows_brackets_literally(self, human_stderr):
        with patch("rafter_cli.commands.backend.api_get", return_value=_forbidden(BRACKETED)):
            code = _run_get()

        assert code == EXIT_GENERAL_ERROR
        assert human_stderr.getvalue() == f"✗ HTTP 403 — {BRACKETED}\n"

    def test_agent_mode_is_not_escaped(self, capsys):
        set_agent_mode(True)
        with patch("rafter_cli.commands.backend.api_get", return_value=_forbidden(BRACKETED)):
            code = _run_get()

        assert code == EXIT_GENERAL_ERROR
        assert capsys.readouterr().err == f"[ERROR] HTTP 403 — {BRACKETED}\n"
