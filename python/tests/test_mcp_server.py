"""Tests for MCP server tool handlers."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from rafter_cli.commands.mcp_server import (
    handle_evaluate_command,
    handle_get_config,
    handle_read_audit_log,
    handle_scan_secrets,
)


class TestScanSecrets:
    def test_scan_file_with_secret(self, tmp_path):
        f = tmp_path / "creds.txt"
        f.write_text("aws_key = AKIAIOSFODNN7EXAMPLE1\n")
        results = handle_scan_secrets(str(f), engine="patterns")
        assert len(results) == 1
        assert results[0]["file"] == str(f)
        assert len(results[0]["matches"]) > 0
        match = results[0]["matches"][0]
        assert "severity" in match
        assert "pattern" in match
        assert "redacted" in match

    def test_scan_directory(self, tmp_path):
        (tmp_path / "clean.txt").write_text("nothing here\n")
        (tmp_path / "secret.env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE2\n")
        results = handle_scan_secrets(str(tmp_path), engine="patterns")
        files_with_matches = [r for r in results if r["matches"]]
        assert len(files_with_matches) >= 1

    def test_scan_clean_file(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1 + 2\n")
        results = handle_scan_secrets(str(f), engine="patterns")
        assert results[0]["matches"] == []

    def test_gitleaks_not_available_falls_back(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE1\n")
        with patch("rafter_cli.commands.mcp_server.GitleaksScanner") as mock_gl:
            mock_gl.return_value.is_available.return_value = False
            results = handle_scan_secrets(str(f), engine="auto")
            assert len(results) == 1

    def test_gitleaks_only_raises_when_unavailable(self):
        with patch("rafter_cli.commands.mcp_server.GitleaksScanner") as mock_gl:
            mock_gl.return_value.is_available.return_value = False
            with pytest.raises(RuntimeError, match="not installed"):
                handle_scan_secrets("/tmp", engine="gitleaks")


class TestEvaluateCommand:
    def test_safe_command_allowed(self):
        result = handle_evaluate_command("ls -la")
        assert result["allowed"] is True
        assert result["risk_level"] == "low"
        assert result["requires_approval"] is False

    def test_dangerous_command_denied(self):
        result = handle_evaluate_command("rm -rf /")
        assert result["allowed"] is False

    def test_result_has_reason_when_denied(self):
        result = handle_evaluate_command("rm -rf /")
        assert "reason" in result

    def test_moderate_command(self):
        result = handle_evaluate_command("chmod 777 /tmp/test")
        assert result["risk_level"] in ("medium", "high", "critical")


class TestReadAuditLog:
    def test_empty_log(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        with patch("rafter_cli.commands.mcp_server.AuditLogger") as mock_cls:
            mock_cls.return_value.read.return_value = []
            entries = handle_read_audit_log(limit=10)
            assert entries == []

    def test_passes_filters(self, tmp_path):
        with patch("rafter_cli.commands.mcp_server.AuditLogger") as mock_cls:
            mock_cls.return_value.read.return_value = [{"event_type": "secret_detected"}]
            entries = handle_read_audit_log(
                limit=5,
                event_type="secret_detected",
                since="2026-01-01T00:00:00Z",
            )
            mock_cls.return_value.read.assert_called_once()
            call_kwargs = mock_cls.return_value.read.call_args[1]
            assert call_kwargs["event_type"] == "secret_detected"
            assert call_kwargs["limit"] == 5
            assert call_kwargs["since"] is not None


class TestGetConfig:
    def test_full_config(self):
        result = handle_get_config()
        assert "version" in result
        assert "agent" in result

    def test_specific_key(self):
        result = handle_get_config(key="agent.risk_level")
        assert result["key"] == "agent.risk_level"
        assert result["value"] is not None

    def test_missing_key_returns_none(self):
        result = handle_get_config(key="nonexistent.path")
        assert result["value"] is None
