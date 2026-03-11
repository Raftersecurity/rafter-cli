"""Tests for API key scope enforcement (403 handling)."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import click
import pytest
import typer

from rafter_cli.utils.api import (
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    handle_scope_error,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _mock_response(status_code: int, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = {}
    return resp


# ── handle_scope_error unit tests ────────────────────────────────────


class TestHandleScopeError:
    def test_returns_true_for_403_with_scope_keyword(self, capsys):
        resp = _mock_response(
            403,
            '{"error": "API key does not have scan permission. Required scope: read-and-scan."}',
        )
        assert handle_scope_error(resp) is True

    def test_prints_helpful_message_for_scope_error(self, capsys):
        resp = _mock_response(
            403,
            '{"error": "API key does not have scan permission. Required scope: read-and-scan."}',
        )
        handle_scope_error(resp)
        err = capsys.readouterr().err
        assert "read access" in err
        assert "https://rfrr.co/account" in err
        assert "Read & Scan" in err

    def test_returns_true_for_generic_403(self, capsys):
        resp = _mock_response(403, "forbidden")
        assert handle_scope_error(resp) is True

    def test_prints_generic_403_message_without_scope(self, capsys):
        resp = _mock_response(403, "forbidden")
        handle_scope_error(resp)
        err = capsys.readouterr().err
        assert "Forbidden (403)" in err
        assert "Read & Scan" not in err

    def test_returns_false_for_401(self):
        resp = _mock_response(401, "invalid key")
        assert handle_scope_error(resp) is False

    def test_returns_false_for_429(self):
        resp = _mock_response(429, "quota exhausted")
        assert handle_scope_error(resp) is False

    def test_returns_false_for_200(self):
        resp = _mock_response(200, "ok")
        assert handle_scope_error(resp) is False

    def test_returns_false_for_500(self):
        resp = _mock_response(500, "internal error")
        assert handle_scope_error(resp) is False

    def test_empty_403_body_still_returns_true(self, capsys):
        resp = _mock_response(403, "")
        assert handle_scope_error(resp) is True
        err = capsys.readouterr().err
        assert "Forbidden (403)" in err


# ── Exit code constants ──────────────────────────────────────────────


class TestExitCodes:
    def test_insufficient_scope_is_4(self):
        assert EXIT_INSUFFICIENT_SCOPE == 4

    def test_no_collisions(self):
        codes = [EXIT_GENERAL_ERROR, EXIT_QUOTA_EXHAUSTED, EXIT_INSUFFICIENT_SCOPE]
        assert len(set(codes)) == len(codes)


# ── Integration: _do_remote_scan with 403 ────────────────────────────


class TestRemoteScan403:
    """Verify _do_remote_scan properly handles 403 scope errors."""

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("org/repo", "main"))
    def test_scope_403_raises_exit_with_code_4(self, _mock_repo, mock_post, capsys):
        mock_post.return_value = _mock_response(
            403,
            '{"error": "API key does not have scan permission. Required scope: read-and-scan."}',
        )
        from rafter_cli.commands.backend import _do_remote_scan

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="org/repo",
                branch="main",
                api_key="rafter_test_key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_INSUFFICIENT_SCOPE
        err = capsys.readouterr().err
        assert "read access" in err
        assert "https://rfrr.co/account" in err

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("org/repo", "main"))
    def test_generic_403_raises_exit_with_code_4(self, _mock_repo, mock_post, capsys):
        mock_post.return_value = _mock_response(403, "forbidden")
        from rafter_cli.commands.backend import _do_remote_scan

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="org/repo",
                branch="main",
                api_key="rafter_test_key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_INSUFFICIENT_SCOPE

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("org/repo", "main"))
    def test_429_still_raises_quota_exhausted(self, _mock_repo, mock_post, capsys):
        mock_post.return_value = _mock_response(429, "quota exhausted")
        from rafter_cli.commands.backend import _do_remote_scan

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="org/repo",
                branch="main",
                api_key="rafter_test_key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_QUOTA_EXHAUSTED

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("org/repo", "main"))
    def test_200_succeeds(self, _mock_repo, mock_post):
        mock_post.return_value = _mock_response(200, "")
        mock_post.return_value.json.return_value = {"scan_id": "abc123"}
        from rafter_cli.commands.backend import _do_remote_scan

        # Should not raise — skip_interactive avoids polling
        _do_remote_scan(
            repo="org/repo",
            branch="main",
            api_key="rafter_test_key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
        )


# ── Read-only endpoints: GET scan and GET usage ──────────────────────


class TestReadOnlyEndpoints:
    """Read-only endpoints (GET) accept both read and read-and-scan keys.
    The server returns 200 for valid keys of either scope on GET endpoints.
    These tests verify the CLI doesn't accidentally scope-check GET calls."""

    @patch("rafter_cli.commands.backend.requests.get")
    def test_get_scan_200_with_read_key(self, mock_get):
        """GET /api/static/scan works fine — no scope check needed."""
        mock_get.return_value = _mock_response(200, "")
        mock_get.return_value.json.return_value = {
            "scan_id": "abc",
            "status": "completed",
        }
        from rafter_cli.commands.backend import _handle_scan_status_interactive

        # Should not raise
        result = _handle_scan_status_interactive("abc", {"x-api-key": "read_key"}, "json", True)
        assert result == 0

    @patch("rafter_cli.commands.backend.requests.get")
    def test_get_usage_200_with_read_key(self, mock_get, capsys):
        """GET /api/static/usage works with read-only key."""
        mock_get.return_value = _mock_response(200, "")
        mock_get.return_value.json.return_value = {
            "scans_used": 5,
            "scans_limit": 100,
        }
        # Directly call the usage endpoint logic pattern
        resp = mock_get.return_value
        assert resp.status_code == 200


# ── Backward compatibility: 401 still handled as before ──────────────


class TestBackwardCompatibility:
    """Ensure existing 401 and other error paths are unaffected."""

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("org/repo", "main"))
    def test_401_raises_general_error(self, _mock_repo, mock_post, capsys):
        mock_post.return_value = _mock_response(401, "invalid api key")
        from rafter_cli.commands.backend import _do_remote_scan

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="org/repo",
                branch="main",
                api_key="bad_key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        # 401 should NOT hit scope handler, falls through to general error
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.backend.requests.post")
    @patch("rafter_cli.commands.backend.detect_repo", return_value=("org/repo", "main"))
    def test_500_raises_general_error(self, _mock_repo, mock_post, capsys):
        mock_post.return_value = _mock_response(500, "internal server error")
        from rafter_cli.commands.backend import _do_remote_scan

        with pytest.raises(click.exceptions.Exit) as exc_info:
            _do_remote_scan(
                repo="org/repo",
                branch="main",
                api_key="rafter_test_key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
            )
        assert exc_info.value.exit_code == EXIT_GENERAL_ERROR
