"""Tests for handle_403 (structured 403 handling)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from rafter_cli.utils.api import (
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    handle_403,
    handle_scope_error,
)


def _mock_response(status_code: int, text: str = "", json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


class TestHandle403:
    def test_returns_negative_for_non_403(self):
        assert handle_403(_mock_response(401, "bad key")) == -1
        assert handle_403(_mock_response(429, "quota")) == -1
        assert handle_403(_mock_response(200, "ok")) == -1
        assert handle_403(_mock_response(500, "error")) == -1

    def test_scan_mode_returns_quota_exhausted(self):
        resp = _mock_response(403, "", json_body={"scan_mode": "fast", "limit": 10, "used": 10})
        assert handle_403(resp) == EXIT_QUOTA_EXHAUSTED

    def test_scan_mode_prints_quota_message(self, capsys):
        resp = _mock_response(403, "", json_body={"scan_mode": "deep", "limit": 5, "used": 5})
        handle_403(resp)
        err = capsys.readouterr().err
        assert "Deep scan limit reached" in err
        assert "5/5" in err
        assert "Upgrade your plan" in err

    def test_scan_mode_uses_used_field(self, capsys):
        resp = _mock_response(403, "", json_body={"scan_mode": "fast", "limit": 10, "used": 8})
        handle_403(resp)
        err = capsys.readouterr().err
        assert "8/10" in err

    def test_scan_mode_defaults_used_to_limit(self, capsys):
        resp = _mock_response(403, "", json_body={"scan_mode": "fast", "limit": 10})
        handle_403(resp)
        err = capsys.readouterr().err
        assert "10/10" in err

    def test_scope_error_returns_insufficient_scope(self):
        resp = _mock_response(
            403,
            '{"error": "Required scope: read-and-scan."}',
            json_body={},
        )
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE

    def test_scope_error_prints_upgrade_message(self, capsys):
        resp = _mock_response(
            403,
            "Required scope: read-and-scan.",
            json_body={},
        )
        handle_403(resp)
        err = capsys.readouterr().err
        assert "read access" in err
        assert "Read & Scan" in err

    def test_generic_403_returns_insufficient_scope(self):
        resp = _mock_response(403, "forbidden", json_body={})
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE

    def test_generic_403_prints_forbidden_message(self, capsys):
        resp = _mock_response(403, "forbidden", json_body={})
        handle_403(resp)
        err = capsys.readouterr().err
        assert "Forbidden (403)" in err

    def test_empty_403_body(self, capsys):
        resp = _mock_response(403, "", json_body={})
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE
        err = capsys.readouterr().err
        assert "access denied" in err

    def test_non_json_403_body(self, capsys):
        resp = _mock_response(403, "plain text forbidden")
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE


class TestHandleScopeErrorDeprecated:
    def test_returns_true_for_403(self):
        resp = _mock_response(403, "forbidden", json_body={})
        assert handle_scope_error(resp) is True

    def test_returns_true_for_scan_mode_403(self):
        resp = _mock_response(403, "", json_body={"scan_mode": "fast", "limit": 5})
        assert handle_scope_error(resp) is True

    def test_returns_false_for_non_403(self):
        assert handle_scope_error(_mock_response(200, "ok")) is False
        assert handle_scope_error(_mock_response(429, "quota")) is False
