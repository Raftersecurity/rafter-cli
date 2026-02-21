"""Tests for rafter hook pretool command."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from rafter_cli.commands.hook import _evaluate_bash, _evaluate_write, posttool
from rafter_cli.core.config_schema import get_default_config


@pytest.fixture(autouse=True)
def _use_default_config():
    """Ensure tests use default config, not the real disk config."""
    with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=get_default_config()), \
         patch("rafter_cli.core.config_manager.ConfigManager.load_with_policy", return_value=get_default_config()):
        yield


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


class TestPosttool:
    """Tests for the posttool hook command."""

    def _run_posttool(self, payload: dict) -> dict:
        """Invoke posttool with a JSON payload over stdin and return parsed stdout."""
        import io
        from unittest.mock import patch as _patch
        import json

        captured_output = []

        def fake_write(data):
            captured_output.append(data)

        stdin_data = json.dumps(payload)

        import sys
        from rafter_cli.commands.hook import posttool as _posttool

        with _patch("rafter_cli.commands.hook._read_stdin", return_value=stdin_data), \
             _patch("rafter_cli.commands.hook._write_decision", side_effect=lambda d: captured_output.append(json.dumps(d))):
            from typer.testing import CliRunner
            from rafter_cli.commands.hook import hook_app
            runner = CliRunner(mix_stderr=False)
            result = runner.invoke(hook_app, ["posttool"], input=stdin_data)

        # Parse the last JSON written (the decision)
        for line in reversed(result.output.strip().splitlines()):
            try:
                return json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
        return {}

    def test_no_tool_response_passes_through(self):
        import json
        from unittest.mock import patch
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["action"] == "continue"

    def test_clean_output_passes_through(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"output": "file1.txt\nfile2.txt\n", "error": ""},
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["action"] == "continue"

    def test_secret_in_output_is_redacted(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env"},
            "tool_response": {
                "output": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nother stuff",
                "error": "",
            },
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["action"] == "modify"
        assert "tool_response" in data
        assert "AKIAIOSFODNN7EXAMPLE" not in data["tool_response"]["output"]
        assert "****" in data["tool_response"]["output"]

    def test_secret_in_content_is_redacted(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "tool_name": "Read",
            "tool_input": {"file_path": "config.json"},
            "tool_response": {
                "content": '{"api_key": "AKIAIOSFODNN7EXAMPLE"}',
            },
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["action"] == "modify"
        assert "AKIAIOSFODNN7EXAMPLE" not in data["tool_response"]["content"]

    def test_error_field_preserved_when_output_redacted(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "cat secrets.txt"},
            "tool_response": {
                "output": "AKIAIOSFODNN7EXAMPLE1B",
                "error": "some stderr message",
            },
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["action"] == "modify"
        assert data["tool_response"]["error"] == "some stderr message"

    def test_invalid_json_passes_through(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool"], input="not valid json{{")
        data = json.loads(result.output.strip())
        assert data["action"] == "continue"
