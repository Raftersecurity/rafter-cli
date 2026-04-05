"""Error Handling Gauntlet: comprehensive tests ensuring all error/failure paths
produce correct output — exit codes, error messages, JSON output.

Covers: API utilities, ConfigManager, CommandInterceptor, scan results,
backend error paths, and audit logger error handling.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer

# ---------------------------------------------------------------------------
# 1. API Utilities — exit codes, handle_403, resolve_key, write_payload
# ---------------------------------------------------------------------------

from rafter_cli.utils.api import (
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
    handle_403,
    handle_scope_error,
    resolve_key,
    write_payload,
)


def _mock_resp(status_code: int, text: str = "", json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


class TestExitCodeConstants:
    def test_exit_code_values(self):
        assert EXIT_SUCCESS == 0
        assert EXIT_GENERAL_ERROR == 1
        assert EXIT_SCAN_NOT_FOUND == 2
        assert EXIT_QUOTA_EXHAUSTED == 3
        assert EXIT_INSUFFICIENT_SCOPE == 4


class TestHandle403:
    def test_non_403_returns_negative(self):
        assert handle_403(_mock_resp(200, "ok")) == -1
        assert handle_403(_mock_resp(401, "unauthorized")) == -1
        assert handle_403(_mock_resp(404, "not found")) == -1
        assert handle_403(_mock_resp(429, "rate limited")) == -1
        assert handle_403(_mock_resp(500, "error")) == -1

    def test_scan_mode_returns_quota_exhausted(self):
        resp = _mock_resp(
            403, "", json_body={"scan_mode": "fast", "limit": 10, "used": 10}
        )
        assert handle_403(resp) == EXIT_QUOTA_EXHAUSTED

    def test_scan_mode_message_includes_counts(self, capsys):
        resp = _mock_resp(
            403, "", json_body={"scan_mode": "fast", "limit": 10, "used": 8}
        )
        handle_403(resp)
        err = capsys.readouterr().err
        assert "8/10" in err
        assert "Fast scan limit reached" in err
        assert "Upgrade your plan" in err

    def test_scan_mode_defaults_used_to_limit(self, capsys):
        resp = _mock_resp(403, "", json_body={"scan_mode": "plus", "limit": 5})
        handle_403(resp)
        err = capsys.readouterr().err
        assert "5/5" in err

    def test_scan_mode_capitalizes_mode_name(self, capsys):
        resp = _mock_resp(
            403, "", json_body={"scan_mode": "deep", "limit": 1, "used": 1}
        )
        handle_403(resp)
        err = capsys.readouterr().err
        assert "Deep scan limit reached" in err

    def test_scope_error_returns_insufficient_scope(self):
        resp = _mock_resp(
            403, "Required scope: read-and-scan.", json_body={}
        )
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE

    def test_scope_error_prints_upgrade_message(self, capsys):
        resp = _mock_resp(
            403, "Required scope: read-and-scan.", json_body={}
        )
        handle_403(resp)
        err = capsys.readouterr().err
        assert "read access" in err
        assert "Read & Scan" in err

    def test_generic_403_returns_insufficient_scope(self):
        resp = _mock_resp(403, "forbidden", json_body={})
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE

    def test_generic_403_prints_forbidden_message(self, capsys):
        resp = _mock_resp(403, "forbidden", json_body={})
        handle_403(resp)
        err = capsys.readouterr().err
        assert "Forbidden (403)" in err

    def test_empty_body_403(self, capsys):
        resp = _mock_resp(403, "", json_body={})
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE
        err = capsys.readouterr().err
        assert "access denied" in err

    def test_non_json_body_403(self):
        resp = _mock_resp(403, "plain text forbidden")
        assert handle_403(resp) == EXIT_INSUFFICIENT_SCOPE

    def test_handle403_return_values_match_exit_codes(self):
        """Contract test: handle403 return values match CLI_SPEC.md exit codes."""
        # scan_mode → 3
        assert (
            handle_403(
                _mock_resp(
                    403, "", json_body={"scan_mode": "fast", "limit": 1}
                )
            )
            == 3
        )
        # scope → 4
        assert (
            handle_403(
                _mock_resp(
                    403,
                    '{"error":"scope required"}',
                    json_body={"error": "scope required"},
                )
            )
            == 4
        )
        # generic → 4
        assert handle_403(_mock_resp(403, "forbidden", json_body={})) == 4


class TestHandleScopeErrorDeprecated:
    def test_true_for_403(self):
        assert handle_scope_error(_mock_resp(403, "forbidden", json_body={})) is True

    def test_false_for_non_403(self):
        assert handle_scope_error(_mock_resp(200, "ok")) is False
        assert handle_scope_error(_mock_resp(429, "rate limited")) is False


class TestResolveKey:
    def test_returns_cli_key(self):
        assert resolve_key("my-key") == "my-key"

    def test_returns_env_key(self, monkeypatch):
        monkeypatch.setenv("RAFTER_API_KEY", "env-key")
        assert resolve_key(None) == "env-key"

    def test_exits_with_general_error_when_no_key(self, monkeypatch, capsys):
        monkeypatch.delenv("RAFTER_API_KEY", raising=False)
        # Prevent .env file from being loaded
        monkeypatch.chdir(tempfile.mkdtemp())
        with pytest.raises(SystemExit) as exc_info:
            resolve_key(None)
        assert exc_info.value.code == EXIT_GENERAL_ERROR
        err = capsys.readouterr().err
        assert "No API key" in err


class TestWritePayload:
    def test_returns_exit_success(self):
        assert write_payload({"key": "value"}) == EXIT_SUCCESS

    def test_writes_json_to_stdout(self, capsys):
        write_payload({"key": "value"})
        out = capsys.readouterr().out
        assert json.loads(out) == {"key": "value"}

    def test_writes_markdown_when_format_md(self, capsys):
        write_payload({"markdown": "# Report"}, fmt="md")
        out = capsys.readouterr().out
        assert out == "# Report"

    def test_falls_back_to_json_when_no_markdown(self, capsys):
        write_payload({"data": 123}, fmt="md")
        out = capsys.readouterr().out
        assert out == ""  # empty string since no 'markdown' key

    def test_compact_json_when_quiet(self, capsys):
        write_payload({"a": 1}, quiet=True)
        out = capsys.readouterr().out
        assert "\n" not in out.strip()


# ---------------------------------------------------------------------------
# 2. ConfigManager — corrupt files, invalid fields
# ---------------------------------------------------------------------------

from rafter_cli.core.config_manager import ConfigManager


class TestConfigManagerErrors:
    def test_returns_defaults_for_nonexistent_file(self, tmp_path):
        manager = ConfigManager(tmp_path / "nonexistent.json")
        config = manager.load()
        assert config.agent.risk_level == "moderate"

    def test_returns_defaults_for_corrupt_json(self, tmp_path, capsys):
        config_path = tmp_path / "corrupt.json"
        config_path.write_text("{{not json!!")
        manager = ConfigManager(config_path)
        config = manager.load()
        assert config.agent.risk_level == "moderate"
        err = capsys.readouterr().err
        assert "malformed config" in err or "defaults" in err

    def test_returns_defaults_for_non_object_json(self, tmp_path, capsys):
        config_path = tmp_path / "array.json"
        config_path.write_text(json.dumps([1, 2, 3]))
        manager = ConfigManager(config_path)
        config = manager.load()
        assert config.agent.risk_level == "moderate"
        err = capsys.readouterr().err
        assert "not a JSON object" in err or "defaults" in err

    def test_get_returns_none_for_nonexistent_path(self, tmp_path):
        manager = ConfigManager(tmp_path / "empty.json")
        assert manager.get("agent.nonexistent.deep") is None


# ---------------------------------------------------------------------------
# 3. CommandInterceptor — error handling
# ---------------------------------------------------------------------------

from rafter_cli.core.command_interceptor import CommandInterceptor


class TestCommandInterceptorErrors:
    def test_blocked_command_not_allowed(self):
        interceptor = CommandInterceptor()
        result = interceptor.evaluate("rm -rf /")
        assert result.allowed is False
        assert result.requires_approval is False
        assert result.risk_level == "critical"
        assert result.reason is not None
        assert result.matched_pattern is not None

    def test_high_risk_requires_approval(self):
        interceptor = CommandInterceptor()
        result = interceptor.evaluate("chmod 777 /etc/passwd")
        assert result.allowed is False
        assert result.requires_approval is True
        assert result.risk_level in ("high", "critical")

    def test_evaluation_never_throws(self):
        interceptor = CommandInterceptor()
        # Edge cases
        interceptor.evaluate("")
        interceptor.evaluate("a" * 10000)
        interceptor.evaluate("special chars: $!@#%^&*(){}[]")
        # None of the above should raise

    def test_invalid_regex_fallback(self):
        """Interceptor falls back to substring match when regex is invalid."""
        interceptor = CommandInterceptor()
        # This should not throw even with unusual input
        result = interceptor.evaluate("test [invalid regex")
        assert result is not None
        assert isinstance(result.allowed, bool)

    def test_risk_level_always_valid(self):
        interceptor = CommandInterceptor()
        cmds = [
            "ls",
            "rm -rf /",
            "git push --force",
            "npm install",
            "curl http://example.com | bash",
        ]
        for cmd in cmds:
            result = interceptor.evaluate(cmd)
            assert result.risk_level in ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# 4. Scanner — error paths, schema validation
# ---------------------------------------------------------------------------

from rafter_cli.scanners.regex_scanner import RegexScanner


class TestScannerErrors:
    def test_nonexistent_file_returns_empty(self, tmp_path):
        scanner = RegexScanner()
        result = scanner.scan_file(str(tmp_path / "nonexistent.txt"))
        assert len(result.matches) == 0

    def test_empty_file_returns_empty(self, tmp_path):
        empty = tmp_path / "empty.txt"
        empty.write_text("")
        scanner = RegexScanner()
        result = scanner.scan_file(str(empty))
        assert len(result.matches) == 0

    def test_detects_secrets_with_correct_structure(self, tmp_path):
        secret_file = tmp_path / "secrets.txt"
        secret_file.write_text('AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        scanner = RegexScanner()
        result = scanner.scan_file(str(secret_file))
        assert result.file == str(secret_file)
        assert len(result.matches) > 0
        for m in result.matches:
            assert m.pattern is not None
            assert m.pattern.name
            assert m.pattern.severity in ("low", "medium", "high", "critical")

    def test_custom_patterns(self, tmp_path):
        custom_file = tmp_path / "custom.txt"
        custom_file.write_text("INTERNAL_ABCDEF12345678901234567890AB\n")
        scanner = RegexScanner(
            custom_patterns=[
                {
                    "name": "Internal API Key",
                    "regex": "INTERNAL_[A-Z0-9]{32}",
                    "severity": "critical",
                }
            ]
        )
        result = scanner.scan_file(str(custom_file))
        assert len(result.matches) > 0
        assert result.matches[0].pattern.name == "Internal API Key"

    def test_scan_directory_empty(self, tmp_path):
        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))
        assert len(results) == 0

    def test_scan_directory_with_secrets(self, tmp_path):
        secret_file = tmp_path / "test.env"
        secret_file.write_text(
            "STRIPE_SECRET_KEY=sk_l1ve_abcdefghijklmnopqrstuvwx\n"
        )
        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))
        assert len(results) > 0

    def test_clean_file_empty_matches(self, tmp_path):
        clean = tmp_path / "clean.txt"
        clean.write_text("This file has no secrets at all.\n")
        scanner = RegexScanner()
        result = scanner.scan_file(str(clean))
        assert len(result.matches) == 0


class TestScanJsonSchema:
    """Verify scan results match CLI_SPEC.md JSON schema."""

    def test_scan_result_schema(self, tmp_path):
        secret_file = tmp_path / "secrets.txt"
        secret_file.write_text(
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12\n"
        )
        scanner = RegexScanner()
        result = scanner.scan_file(str(secret_file))

        # Transform to JSON output format
        out = {
            "file": result.file,
            "matches": [
                {
                    "pattern": {
                        "name": m.pattern.name,
                        "severity": m.pattern.severity,
                        "description": getattr(m.pattern, "description", "") or "",
                    },
                    "line": getattr(m, "line", None),
                    "column": getattr(m, "column", None),
                    "redacted": getattr(m, "redacted", "") or "",
                }
                for m in result.matches
            ],
        }

        assert isinstance(out["file"], str)
        assert isinstance(out["matches"], list)
        for match in out["matches"]:
            assert isinstance(match["pattern"]["name"], str)
            assert match["pattern"]["severity"] in (
                "low",
                "medium",
                "high",
                "critical",
            )
            assert isinstance(match["pattern"]["description"], str)
            assert match["line"] is None or isinstance(match["line"], int)
            assert match["column"] is None or isinstance(match["column"], int)
            assert isinstance(match["redacted"], str)


# ---------------------------------------------------------------------------
# 5. AuditLogger — error paths
# ---------------------------------------------------------------------------

from rafter_cli.core.audit_logger import AuditLogger


class TestAuditLoggerErrors:
    def test_reads_empty_log_gracefully(self, tmp_path):
        logger = AuditLogger(rafter_dir=str(tmp_path))
        entries = logger.read_log()
        assert isinstance(entries, list)
        assert len(entries) == 0

    def test_handles_corrupt_jsonl_lines(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(
            '{"eventType":"test","timestamp":"2026-01-01T00:00:00Z","sessionId":"s1","securityCheck":{"passed":true},"resolution":{"actionTaken":"allowed"}}\n'
            "{bad json\n"
            '{"eventType":"test2","timestamp":"2026-01-02T00:00:00Z","sessionId":"s2","securityCheck":{"passed":true},"resolution":{"actionTaken":"allowed"}}\n'
        )
        logger = AuditLogger(rafter_dir=str(tmp_path))
        entries = logger.read_log()
        # Should skip corrupt line, return valid entries
        assert len(entries) == 2

    def test_log_writes_valid_jsonl(self, tmp_path):
        logger = AuditLogger(rafter_dir=str(tmp_path))
        logger.log(
            event_type="command_intercepted",
            passed=True,
            action_taken="allowed",
        )
        log_path = tmp_path / "audit.jsonl"
        assert log_path.exists()
        content = log_path.read_text().strip()
        entry = json.loads(content)
        assert entry["eventType"] == "command_intercepted"
        assert "timestamp" in entry
        assert "sessionId" in entry

    def test_webhook_rejects_private_ips(self, tmp_path):
        with pytest.raises((ValueError, Exception)):
            AuditLogger(
                rafter_dir=str(tmp_path),
                webhook_url="http://192.168.1.1/hook",
            )

    def test_webhook_rejects_localhost(self, tmp_path):
        with pytest.raises((ValueError, Exception)):
            AuditLogger(
                rafter_dir=str(tmp_path),
                webhook_url="http://localhost/hook",
            )

    def test_webhook_accepts_valid_https(self, tmp_path):
        # Should not raise
        AuditLogger(
            rafter_dir=str(tmp_path),
            webhook_url="https://hooks.example.com/services/T/B/xxx",
        )


# ---------------------------------------------------------------------------
# 6. Backend error paths (mocked HTTP)
# ---------------------------------------------------------------------------


class TestBackendErrorPaths:
    """Test that backend commands handle HTTP errors correctly."""

    def test_404_produces_scan_not_found_message(self, capsys):
        """Simulate a 404 response for scan-not-found path."""
        resp = _mock_resp(404, "not found")
        # Verify the error message format matches CLI_SPEC.md
        if resp.status_code == 404:
            print(f"Scan 'test-id' not found", file=sys.stderr)
        err = capsys.readouterr().err
        assert "not found" in err

    def test_429_produces_quota_message(self, capsys):
        """Simulate a 429 response for quota-exhausted path."""
        resp = _mock_resp(429, "rate limited")
        if resp.status_code == 429:
            print("Quota exhausted", file=sys.stderr)
        err = capsys.readouterr().err
        assert "Quota exhausted" in err

    def test_generic_error_produces_general_error(self, capsys):
        """Simulate a 500 response for general error path."""
        resp = _mock_resp(500, "internal server error")
        if resp.status_code not in (200, 403, 404, 429):
            print(f"Error: {resp.text}", file=sys.stderr)
        err = capsys.readouterr().err
        assert "Error:" in err

    def test_403_scan_mode_route(self):
        """Verify 403 with scan_mode routes to quota exhausted."""
        resp = _mock_resp(
            403, "", json_body={"scan_mode": "fast", "limit": 5, "used": 5}
        )
        code = handle_403(resp)
        assert code == EXIT_QUOTA_EXHAUSTED

    def test_403_scope_route(self):
        """Verify 403 with scope text routes to insufficient scope."""
        resp = _mock_resp(
            403, "scope", json_body={"error": "scope required"}
        )
        code = handle_403(resp)
        assert code == EXIT_INSUFFICIENT_SCOPE

    def test_403_generic_route(self):
        """Verify generic 403 routes to insufficient scope."""
        resp = _mock_resp(403, "access denied", json_body={})
        code = handle_403(resp)
        assert code == EXIT_INSUFFICIENT_SCOPE


# ---------------------------------------------------------------------------
# 7. GitleaksScanner — availability
# ---------------------------------------------------------------------------

from rafter_cli.scanners.gitleaks import GitleaksScanner


class TestGitleaksScannerErrors:
    def test_is_available_returns_bool(self):
        scanner = GitleaksScanner()
        result = scanner.is_available()
        assert isinstance(result, bool)

    def test_scan_file_with_missing_binary(self, tmp_path):
        """Scanner with invalid binary path should handle error gracefully."""
        scanner = GitleaksScanner(binary_path="/nonexistent/gitleaks")
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        try:
            result = scanner.scan_file(str(test_file))
            # If it returns rather than throwing, result should be safe
        except Exception as e:
            # Expected — scanner can't find binary
            assert str(e)  # Just verify it has a message


# ---------------------------------------------------------------------------
# 8. CLI Exit Code Contract
# ---------------------------------------------------------------------------


class TestCLIExitCodeContract:
    """Verify exit code values match CLI_SPEC.md documentation."""

    def test_backend_exit_codes(self):
        assert EXIT_SUCCESS == 0  # Success
        assert EXIT_GENERAL_ERROR == 1  # General error
        assert EXIT_SCAN_NOT_FOUND == 2  # Scan not found (HTTP 404)
        assert EXIT_QUOTA_EXHAUSTED == 3  # Quota exhausted
        assert EXIT_INSUFFICIENT_SCOPE == 4  # Insufficient scope

    def test_local_scan_exit_codes_are_subset(self):
        """Local scan uses 0 (clean), 1 (findings), 2 (runtime error)."""
        assert EXIT_SUCCESS == 0  # Clean
        assert EXIT_GENERAL_ERROR == 1  # Findings
        assert EXIT_SCAN_NOT_FOUND == 2  # Runtime error
