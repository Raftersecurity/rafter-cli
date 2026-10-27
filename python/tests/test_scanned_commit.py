"""Tests for the "Scanned commit" info/warning line printed when a remote
scan finishes with a completed status (`rafter run`, `rafter get`, and
`rafter get --interactive`).

Mocks `api_get` (no network) and `_run` (the HEAD lookup; no real git
subprocess) so these tests don't depend on this checkout's actual commit.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import typer
from typer.testing import CliRunner

from rafter_cli.commands.backend import (
    _handle_scan_status_interactive,
    register_backend_commands,
)
from rafter_cli.utils.api import EXIT_SUCCESS

runner = CliRunner()


def _mock_response(status_code: int, json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.text = json.dumps(json_body) if json_body else ""
    return resp


# Fake 40-char SHAs, distinct from whatever this checkout's real HEAD is — if
# the `_run` patch below were not actually intercepted, production code would
# shell out to the real `git rev-parse HEAD` and these would not line up,
# turning the "matches HEAD" case red instead of green.
LOCAL_HEAD = "a" * 40
SCANNED = "b" * 40


class TestReportScannedCommitViaInteractiveHandler:
    """Covers the scan-status.ts-equivalent call site, shared by `run` and
    `get --interactive`."""

    @patch("rafter_cli.commands.backend._run", return_value=LOCAL_HEAD)
    @patch("rafter_cli.commands.backend.api_get")
    def test_matches_head_prints_info_no_warning(self, mock_get, _mock_run, capsys):
        mock_get.return_value = _mock_response(
            200, {"status": "completed", "markdown": "# ok", "scanned_commit": LOCAL_HEAD}
        )

        result = _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", False)

        assert result == EXIT_SUCCESS
        err = capsys.readouterr().err
        assert f"Scanned commit: {LOCAL_HEAD[:12]}" in err
        assert "Warning: the scan covers commit" not in err

    @patch("rafter_cli.commands.backend._run", return_value=LOCAL_HEAD)
    @patch("rafter_cli.commands.backend.api_get")
    def test_mismatch_warns(self, mock_get, _mock_run, capsys):
        mock_get.return_value = _mock_response(
            200, {"status": "completed", "markdown": "# ok", "scanned_commit": SCANNED}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", False)

        err = capsys.readouterr().err
        assert f"Scanned commit: {SCANNED[:12]}" in err
        assert (
            f"Warning: the scan covers commit {SCANNED[:12]}, but your checkout is at {LOCAL_HEAD[:12]}."
            in err
        )

    @patch("rafter_cli.commands.backend._run")
    @patch("rafter_cli.commands.backend.api_get")
    def test_null_scanned_commit_not_recorded_skips_git(self, mock_get, mock_run, capsys):
        mock_get.return_value = _mock_response(
            200, {"status": "completed", "markdown": "# ok", "scanned_commit": None}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", False)

        err = capsys.readouterr().err
        assert "Scanned commit: not recorded" in err
        mock_run.assert_not_called()

    @patch("rafter_cli.commands.backend._run", return_value=LOCAL_HEAD)
    @patch("rafter_cli.commands.backend.api_get")
    def test_quiet_hides_info_but_not_mismatch_warning(self, mock_get, _mock_run, capsys):
        mock_get.return_value = _mock_response(
            200, {"status": "completed", "markdown": "# ok", "scanned_commit": SCANNED}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", True)

        err = capsys.readouterr().err
        assert "Scanned commit:" not in err
        assert (
            f"Warning: the scan covers commit {SCANNED[:12]}, but your checkout is at {LOCAL_HEAD[:12]}."
            in err
        )

    @patch("rafter_cli.commands.backend._run", side_effect=OSError("not a git repository"))
    @patch("rafter_cli.commands.backend.api_get")
    def test_no_checkout_stays_silent_about_mismatch(self, mock_get, _mock_run, capsys):
        mock_get.return_value = _mock_response(
            200, {"status": "completed", "markdown": "# ok", "scanned_commit": SCANNED}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", False)

        err = capsys.readouterr().err
        assert f"Scanned commit: {SCANNED[:12]}" in err
        assert "Warning:" not in err


class TestReportScannedCommitViaPlainGet:
    """Covers the plain (non-interactive) `rafter get` call site."""

    def _app(self) -> typer.Typer:
        app = typer.Typer()
        register_backend_commands(app)
        return app

    @patch("rafter_cli.commands.backend._run", return_value=LOCAL_HEAD)
    @patch("rafter_cli.commands.backend.api_get")
    def test_prints_scanned_commit_for_completed_scan(self, mock_get, _mock_run):
        mock_get.return_value = _mock_response(
            200, {"status": "completed", "markdown": "# ok", "scanned_commit": LOCAL_HEAD}
        )

        result = runner.invoke(
            self._app(), ["get", "s1", "--api-key", "test-key", "--format", "md"]
        )

        assert result.exit_code == EXIT_SUCCESS, result.output
        assert f"Scanned commit: {LOCAL_HEAD[:12]}" in result.output


@patch("rafter_cli.commands.backend._run")
@patch("rafter_cli.commands.backend.api_get")
def test_does_not_compare_against_a_checkout_of_a_different_repository(mock_get, mock_run, capsys):
    mock_run.side_effect = lambda args: "https://github.com/acme/other.git" if "remote" in args else LOCAL_HEAD
    mock_get.return_value = _mock_response(200, json_body={
        "status": "completed", "markdown": "# ok", "scanned_commit": SCANNED, "repository_name": "acme/app"})
    _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", False)
    err = capsys.readouterr().err
    assert f"Scanned commit: {SCANNED[:12]}" in err
    assert "Warning:" not in err
