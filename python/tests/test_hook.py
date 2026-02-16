"""Tests for rafter hook pretool command."""
from __future__ import annotations

import json
from unittest.mock import patch

from rafter_cli.commands.hook import _evaluate_bash, _evaluate_write


class TestEvaluateBash:
    def test_allowed_command(self):
        result = _evaluate_bash("ls -la")
        assert result["decision"] == "allow"

    def test_blocked_command(self):
        result = _evaluate_bash("rm -rf /")
        assert result["decision"] == "deny"
        assert "Rafter policy" in result["reason"]

    def test_empty_command_allowed(self):
        result = _evaluate_bash("")
        assert result["decision"] == "allow"

    def test_git_commit_no_staged(self):
        with patch("rafter_cli.commands.hook._scan_staged_files") as mock_scan:
            mock_scan.return_value = {"secrets_found": False, "count": 0, "files": 0}
            result = _evaluate_bash("git commit -m 'test'")
            assert result["decision"] == "allow"

    def test_git_commit_with_secrets(self):
        with patch("rafter_cli.commands.hook._scan_staged_files") as mock_scan:
            mock_scan.return_value = {"secrets_found": True, "count": 2, "files": 1}
            result = _evaluate_bash("git commit -m 'test'")
            assert result["decision"] == "deny"
            assert "2 secret(s)" in result["reason"]

    def test_git_push_scans_staged(self):
        with patch("rafter_cli.commands.hook._scan_staged_files") as mock_scan:
            mock_scan.return_value = {"secrets_found": False, "count": 0, "files": 0}
            result = _evaluate_bash("git push origin main")
            assert result["decision"] == "allow"
            mock_scan.assert_called_once()


class TestEvaluateWrite:
    def test_clean_content(self):
        result = _evaluate_write({"content": "normal text content", "file_path": "test.py"})
        assert result["decision"] == "allow"

    def test_secret_in_content(self):
        result = _evaluate_write({
            "content": "AKIAIOSFODNN7EXAMPLE1",
            "file_path": "config.py",
        })
        assert result["decision"] == "deny"
        assert "Secret detected" in result["reason"]

    def test_secret_in_new_string(self):
        result = _evaluate_write({
            "new_string": "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc",
            "file_path": "payment.py",
        })
        assert result["decision"] == "deny"

    def test_empty_content(self):
        result = _evaluate_write({"content": "", "file_path": "empty.py"})
        assert result["decision"] == "allow"

    def test_no_content_fields(self):
        result = _evaluate_write({"file_path": "test.py"})
        assert result["decision"] == "allow"
