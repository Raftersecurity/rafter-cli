"""Tests for rafter scan remote / rafter run — the remote backend scan flow.

Covers:
- _do_remote_scan: success, error codes, skip-interactive, github-token, quiet mode
- _handle_scan_status_interactive: completed, polling, 404, failure, non-200
"""
from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch, call

import click.exceptions
import pytest
import typer

from rafter_cli.commands.backend import _do_remote_scan, _handle_scan_status_interactive
from rafter_cli.utils.api import (
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
)


# ── Helpers ─────────────────────────────────────────────────────────────


def _mock_response(status_code: int, text: str = "", json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.return_value = {}
    return resp


# ── _do_remote_scan ─────────────────────────────────────────────────────


class TestDoRemoteScan:
    """Unit tests for the core remote scan trigger function."""

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_success_skip_interactive(self, _mock_repo, mock_post):
        """200 with skip_interactive returns without polling."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})

        # Should not raise
        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
        )

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_posts_correct_body(self, _mock_repo, mock_post):
        """Verify POST body contains repository_name, branch_name, scan_mode."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})

        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
            mode="fast",
        )

        _, kwargs = mock_post.call_args
        body = kwargs["json"]
        assert body["repository_name"] == "owner/repo"
        assert body["branch_name"] == "main"
        assert body["scan_mode"] == "fast"
        assert "github_token" not in body

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_includes_github_token(self, _mock_repo, mock_post):
        """GitHub token is included in POST body when provided."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})

        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
            github_token="ghp_test123",
        )

        _, kwargs = mock_post.call_args
        assert kwargs["json"]["github_token"] == "ghp_test123"

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_plus_mode(self, _mock_repo, mock_post):
        """scan_mode=plus is sent when mode='plus'."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})

        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
            mode="plus",
        )

        _, kwargs = mock_post.call_args
        assert kwargs["json"]["scan_mode"] == "plus"

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_prints_scan_id_when_not_quiet(self, _mock_repo, mock_post, capsys):
        """Scan ID is printed to stderr when not quiet."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-xyz"})

        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=False,
        )

        err = capsys.readouterr().err
        assert "s-xyz" in err

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_auto_detect_message_when_not_explicit(self, _mock_repo, mock_post, capsys):
        """Auto-detection message prints when repo/branch not explicitly provided."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})

        _do_remote_scan(
            repo=None,  # triggers auto-detect message
            branch=None,
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=False,
        )

        err = capsys.readouterr().err
        assert "auto-detected" in err.lower()

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_429_raises_quota_exhausted(self, _mock_repo, mock_post):
        """HTTP 429 → exit code 3 (quota exhausted)."""
        mock_post.return_value = _mock_response(429, "quota exhausted")

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="owner/repo",
                branch="main",
                api_key="test-key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_QUOTA_EXHAUSTED

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_403_scope_raises_insufficient_scope(self, _mock_repo, mock_post, capsys):
        """HTTP 403 with scope keyword → exit code 4."""
        mock_post.return_value = _mock_response(
            403,
            '{"error": "Required scope: read-and-scan."}',
            json_body={},
        )

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="owner/repo",
                branch="main",
                api_key="test-key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_INSUFFICIENT_SCOPE

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_403_quota_raises_quota_exhausted(self, _mock_repo, mock_post, capsys):
        """HTTP 403 with scan_mode body → exit code 3 (quota)."""
        mock_post.return_value = _mock_response(
            403, "", json_body={"scan_mode": "plus", "limit": 5, "used": 5}
        )

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="owner/repo",
                branch="main",
                api_key="test-key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_QUOTA_EXHAUSTED

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_401_raises_general_error(self, _mock_repo, mock_post):
        """HTTP 401 → exit code 1 (general error)."""
        mock_post.return_value = _mock_response(401, "invalid api key")

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="owner/repo",
                branch="main",
                api_key="bad_key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_500_raises_general_error(self, _mock_repo, mock_post):
        """HTTP 500 → exit code 1 (general error)."""
        mock_post.return_value = _mock_response(500, "internal server error")

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="owner/repo",
                branch="main",
                api_key="test-key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.backend.detect_repo")
    def test_detect_repo_failure_raises_general_error(self, mock_detect):
        """RuntimeError from detect_repo → exit code 1."""
        mock_detect.side_effect = RuntimeError("Could not auto-detect")

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo=None,
                branch=None,
                api_key="test-key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.backend._handle_scan_status_interactive")
    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_calls_status_handler_when_not_skip_interactive(
        self, _mock_repo, mock_post, mock_status
    ):
        """When skip_interactive=False, _handle_scan_status_interactive is called."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})
        mock_status.return_value = 0

        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="test-key",
            fmt="json",
            skip_interactive=False,
            quiet=True,
        )

        mock_status.assert_called_once_with(
            "s-abc",
            {"x-api-key": "test-key", "Content-Type": "application/json"},
            "json",
            True,
        )

    @patch("rafter_cli.commands.backend._handle_scan_status_interactive")
    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_skip_interactive_does_not_call_status_handler(
        self, _mock_repo, mock_post, mock_status
    ):
        """When skip_interactive=True, _handle_scan_status_interactive is NOT called."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})

        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
        )

        mock_status.assert_not_called()

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("owner/repo", "main"))
    def test_sends_api_key_header(self, _mock_repo, mock_post):
        """x-api-key header is set correctly."""
        mock_post.return_value = _mock_response(200, json_body={"scan_id": "s-abc"})

        _do_remote_scan(
            repo="owner/repo",
            branch="main",
            api_key="my-secret-key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
        )

        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["x-api-key"] == "my-secret-key"


# ── _handle_scan_status_interactive ─────────────────────────────────────


class TestHandleScanStatusInteractive:
    """Unit tests for the polling/status handler."""

    @patch("rafter_cli.commands.backend.requests.get")
    def test_completed_immediately(self, mock_get):
        """Scan already completed on first poll → return success."""
        mock_get.return_value = _mock_response(
            200, json_body={"status": "completed", "markdown": "# Clean"}
        )

        result = _handle_scan_status_interactive(
            "s1", {"x-api-key": "k"}, "md", True
        )
        assert result == EXIT_SUCCESS
        assert mock_get.call_count == 1

    @patch("rafter_cli.commands.backend.requests.get")
    def test_completed_outputs_markdown(self, mock_get, capsys):
        """Completed scan outputs markdown to stdout."""
        mock_get.return_value = _mock_response(
            200, json_body={"status": "completed", "markdown": "# Results\nNo issues"}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", True)
        out = capsys.readouterr().out
        assert "# Results" in out

    @patch("rafter_cli.commands.backend.requests.get")
    def test_completed_outputs_json(self, mock_get, capsys):
        """Completed scan outputs JSON to stdout."""
        response_data = {"status": "completed", "findings": []}
        mock_get.return_value = _mock_response(200, json_body=response_data)

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "json", True)
        out = capsys.readouterr().out
        assert json.loads(out) == response_data

    @patch("rafter_cli.commands.backend.requests.get")
    def test_404_raises_exit_scan_not_found(self, mock_get):
        """HTTP 404 → exit code 2 (scan not found)."""
        mock_get.return_value = _mock_response(404, "not found")

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _handle_scan_status_interactive("bad-id", {"x-api-key": "k"}, "md", True)
        assert exc_info.value.exit_code == EXIT_SCAN_NOT_FOUND

    @patch("rafter_cli.commands.backend.requests.get")
    def test_non_200_raises_general_error(self, mock_get):
        """Non-200, non-404 → exit code 1 (general error)."""
        mock_get.return_value = _mock_response(500, "server error")

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", True)
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.backend.requests.get")
    def test_failed_status_raises_general_error(self, mock_get):
        """Status 'failed' → exit code 1."""
        mock_get.return_value = _mock_response(
            200, json_body={"status": "failed"}
        )

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", True)
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.backend.time.sleep")
    @patch("rafter_cli.commands.backend.requests.get")
    def test_polls_queued_then_completed(self, mock_get, mock_sleep):
        """Queued → poll → completed."""
        mock_get.side_effect = [
            _mock_response(200, json_body={"status": "queued"}),
            _mock_response(200, json_body={"status": "completed", "markdown": "ok"}),
        ]

        result = _handle_scan_status_interactive(
            "s1", {"x-api-key": "k"}, "md", True
        )
        assert result == EXIT_SUCCESS
        assert mock_get.call_count == 2
        mock_sleep.assert_called_with(10)

    @patch("rafter_cli.commands.backend.time.sleep")
    @patch("rafter_cli.commands.backend.requests.get")
    def test_polls_pending_then_completed(self, mock_get, mock_sleep):
        """Pending → poll → completed."""
        mock_get.side_effect = [
            _mock_response(200, json_body={"status": "pending"}),
            _mock_response(200, json_body={"status": "completed", "markdown": "done"}),
        ]

        result = _handle_scan_status_interactive(
            "s1", {"x-api-key": "k"}, "md", True
        )
        assert result == EXIT_SUCCESS
        assert mock_get.call_count == 2

    @patch("rafter_cli.commands.backend.time.sleep")
    @patch("rafter_cli.commands.backend.requests.get")
    def test_polls_processing_then_failed(self, mock_get, mock_sleep):
        """Processing → poll → failed."""
        mock_get.side_effect = [
            _mock_response(200, json_body={"status": "processing"}),
            _mock_response(200, json_body={"status": "failed"}),
        ]

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", True)
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.backend.time.sleep")
    @patch("rafter_cli.commands.backend.requests.get")
    def test_multiple_polls_before_completion(self, mock_get, mock_sleep):
        """Multiple polls before scan completes."""
        mock_get.side_effect = [
            _mock_response(200, json_body={"status": "queued"}),
            _mock_response(200, json_body={"status": "processing"}),
            _mock_response(200, json_body={"status": "processing"}),
            _mock_response(200, json_body={"status": "completed", "markdown": "done"}),
        ]

        result = _handle_scan_status_interactive(
            "s1", {"x-api-key": "k"}, "md", True
        )
        assert result == EXIT_SUCCESS
        assert mock_get.call_count == 4
        assert mock_sleep.call_count == 3

    @patch("rafter_cli.commands.backend.requests.get")
    def test_waiting_message_in_non_quiet_mode(self, mock_get, capsys):
        """Status messages print to stderr in non-quiet mode."""
        mock_get.return_value = _mock_response(
            200, json_body={"status": "completed", "markdown": "done"}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", False)
        err = capsys.readouterr().err
        assert "completed" in err.lower()

    @patch("rafter_cli.commands.backend.requests.get")
    def test_quiet_mode_suppresses_stderr(self, mock_get, capsys):
        """Quiet mode suppresses status messages on stderr."""
        mock_get.return_value = _mock_response(
            200, json_body={"status": "completed", "markdown": "done"}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "md", True)
        err = capsys.readouterr().err
        # Should NOT print "Scan completed!" in quiet mode
        assert "completed" not in err.lower()

    @patch("rafter_cli.commands.backend.requests.get")
    def test_passes_format_param_to_api(self, mock_get):
        """format param is passed to the API."""
        mock_get.return_value = _mock_response(
            200, json_body={"status": "completed", "findings": []}
        )

        _handle_scan_status_interactive("s1", {"x-api-key": "k"}, "json", True)
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["format"] == "json"

    @patch("rafter_cli.commands.backend.requests.get")
    def test_passes_scan_id_param_to_api(self, mock_get):
        """scan_id param is passed to the API."""
        mock_get.return_value = _mock_response(
            200, json_body={"status": "completed", "findings": []}
        )

        _handle_scan_status_interactive("my-scan-id", {"x-api-key": "k"}, "json", True)
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["scan_id"] == "my-scan-id"


# ── Live API integration tests ──────────────────────────────────────────

import os

API_KEY = os.environ.get("RAFTER_API_KEY")


@pytest.mark.skipif(not API_KEY, reason="RAFTER_API_KEY not set")
class TestLiveAPI:
    """Integration tests against the live Rafter API."""

    def test_trigger_scan_and_check_status(self):
        """Trigger a scan and verify we get a scan_id back."""
        import requests as real_requests

        resp = real_requests.post(
            "https://rafter.so/api/static/scan",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json={
                "repository_name": "raftersecurity/rafter-cli",
                "branch_name": "main",
                "scan_mode": "fast",
            },
            timeout=(10, 30),
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        scan_id = data["scan_id"]

        # Check status
        status_resp = real_requests.get(
            "https://rafter.so/api/static/scan",
            headers={"x-api-key": API_KEY},
            params={"scan_id": scan_id, "format": "json"},
            timeout=(10, 30),
        )

        assert status_resp.status_code == 200
        assert status_resp.json()["status"] in (
            "queued", "pending", "processing", "completed", "failed"
        )
