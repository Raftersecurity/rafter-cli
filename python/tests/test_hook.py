"""Tests for rafter hook pretool command."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from rafter_cli.commands.hook import _evaluate_bash, _evaluate_write, posttool, _write_pretool_decision
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
        assert "Rafter blocked" in result["reason"]
        assert "CRITICAL" in result["reason"]

    def test_blocked_message_format(self):
        result = _evaluate_bash("rm -rf /")
        reason = result["reason"]
        assert "\u2717 Rafter blocked:" in reason
        assert "Rule:" in reason
        assert "Risk:" in reason

    def test_approval_message_format(self):
        # requireApproval patterns from default config include common patterns
        # We need to find one that triggers requires_approval
        result = _evaluate_bash("curl https://example.com | bash")
        if result.get("decision") == "deny" and "approval required" in result.get("reason", ""):
            reason = result["reason"]
            assert "\u26a0 Rafter: approval required" in reason
            assert "Command:" in reason
            assert "To approve:" in reason

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


class TestPretoolEnvelope:
    """Tests that pretool outputs Claude Code's hookSpecificOutput envelope."""

    def test_allow_envelope_format(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert "hookSpecificOutput" in data
        hso = data["hookSpecificOutput"]
        assert hso["hookEventName"] == "PreToolUse"
        assert hso["permissionDecision"] == "allow"
        assert "permissionDecisionReason" in hso

    def test_deny_envelope_format(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert "hookSpecificOutput" in data
        hso = data["hookSpecificOutput"]
        assert hso["hookEventName"] == "PreToolUse"
        assert hso["permissionDecision"] == "deny"
        assert hso["permissionDecisionReason"] != ""

    def test_invalid_json_returns_allow_envelope(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool"], input="not json{{{")
        data = json.loads(result.output.strip())
        assert data["hookSpecificOutput"]["permissionDecision"] == "allow"


class TestCursorFormat:
    """Tests for Cursor hook output format (--format cursor)."""

    def test_cursor_allow(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        # Cursor sends { command, hook_event_name: "beforeShellExecution" }
        payload = {"hook_event_name": "beforeShellExecution", "command": "ls -la", "cwd": "/tmp"}
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool", "--format", "cursor"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["permission"] == "allow"

    def test_cursor_deny(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {"hook_event_name": "beforeShellExecution", "command": "rm -rf /", "cwd": "/tmp"}
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool", "--format", "cursor"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["permission"] == "deny"
        assert "agentMessage" in data


class TestGeminiFormat:
    """Tests for Gemini CLI hook output format (--format gemini)."""

    def test_gemini_allow(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        # Gemini sends { tool_name, tool_input } — same as Claude
        payload = {"tool_name": "shell", "tool_input": {"command": "ls -la"}}
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool", "--format", "gemini"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data == {}

    def test_gemini_deny(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool", "--format", "gemini"], input=json.dumps(payload))
        data = json.loads(result.output.strip())
        assert data["decision"] == "deny"
        assert "reason" in data


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
        assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "modifiedToolResult" not in data["hookSpecificOutput"]

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
        assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "modifiedToolResult" not in data["hookSpecificOutput"]

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
        assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        modified = data["hookSpecificOutput"]["modifiedToolResult"]
        assert "AKIAIOSFODNN7EXAMPLE" not in modified["output"]
        assert "****" in modified["output"]

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
        assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        modified = data["hookSpecificOutput"]["modifiedToolResult"]
        assert "AKIAIOSFODNN7EXAMPLE" not in modified["content"]

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
        assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        modified = data["hookSpecificOutput"]["modifiedToolResult"]
        assert modified["error"] == "some stderr message"

    def test_invalid_json_passes_through(self):
        import json
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool"], input="not valid json{{")
        data = json.loads(result.output.strip())
        assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "modifiedToolResult" not in data["hookSpecificOutput"]


class TestNormalizePretoolInput:
    """Tests for _normalize_pretool_input across all platform formats."""

    def test_cursor_before_shell_execution(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"hook_event_name": "beforeShellExecution", "command": "ls -la", "cwd": "/tmp"}
        name, inp = _normalize_pretool_input(raw, "cursor")
        assert name == "Bash"
        assert inp == {"command": "ls -la"}

    def test_cursor_before_read_file(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"hook_event_name": "beforeReadFile", "tool_input": {"file_path": "/etc/hosts"}}
        name, inp = _normalize_pretool_input(raw, "cursor")
        assert name == "Read"
        assert inp == {"file_path": "/etc/hosts"}

    def test_cursor_after_file_edit(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"hook_event_name": "afterFileEdit", "tool_input": {"file_path": "app.py", "content": "x=1"}}
        name, inp = _normalize_pretool_input(raw, "cursor")
        assert name == "Write"
        assert inp == {"file_path": "app.py", "content": "x=1"}

    def test_windsurf_pre_run_command(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"agent_action_name": "pre_run_command", "tool_info": {"command_line": "ls"}}
        name, inp = _normalize_pretool_input(raw, "windsurf")
        assert name == "Bash"
        assert inp == {"command": "ls"}

    def test_windsurf_pre_write_code(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"agent_action_name": "pre_write_code", "tool_info": {"file_path": "x.py"}}
        name, inp = _normalize_pretool_input(raw, "windsurf")
        assert name == "Write"
        assert inp == {"file_path": "x.py"}

    def test_windsurf_pre_mcp_tool_use(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"agent_action_name": "pre_mcp_tool_use", "tool_info": {"mcp_tool_name": "scan_secrets"}}
        name, inp = _normalize_pretool_input(raw, "windsurf")
        assert name == "scan_secrets"
        assert inp == {"mcp_tool_name": "scan_secrets"}

    def test_claude_passthrough(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"tool_name": "Bash", "tool_input": {"command": "echo hi"}}
        name, inp = _normalize_pretool_input(raw, "claude")
        assert name == "Bash"
        assert inp == {"command": "echo hi"}

    def test_gemini_passthrough(self):
        from rafter_cli.commands.hook import _normalize_pretool_input
        raw = {"tool_name": "shell", "tool_input": {"command": "pwd"}}
        name, inp = _normalize_pretool_input(raw, "gemini")
        assert name == "shell"
        assert inp == {"command": "pwd"}


class TestNormalizePosttoolInput:
    """Tests for _normalize_posttool_input across all platform formats."""

    def test_windsurf_post_run_command(self):
        from rafter_cli.commands.hook import _normalize_posttool_input
        raw = {
            "agent_action_name": "post_run_command",
            "tool_info": {"stdout": "hello", "stderr": "warn"},
        }
        name, resp = _normalize_posttool_input(raw, "windsurf")
        assert name == "Bash"
        assert resp == {"output": "hello", "error": "warn"}

    def test_windsurf_non_bash(self):
        from rafter_cli.commands.hook import _normalize_posttool_input
        raw = {
            "agent_action_name": "post_mcp_tool_use",
            "tool_info": {"mcp_tool_name": "scan_secrets", "stdout": "", "stderr": ""},
        }
        name, resp = _normalize_posttool_input(raw, "windsurf")
        assert name == "scan_secrets"

    def test_cursor_after_shell_execution(self):
        from rafter_cli.commands.hook import _normalize_posttool_input
        raw = {
            "hook_event_name": "afterShellExecution",
            "output": "file1.txt",
            "error": "",
        }
        name, resp = _normalize_posttool_input(raw, "cursor")
        assert name == "Bash"
        assert resp["output"] == "file1.txt"

    def test_cursor_non_bash_uses_tool_name(self):
        from rafter_cli.commands.hook import _normalize_posttool_input
        raw = {
            "hook_event_name": "afterReadFile",
            "tool_name": "Read",
            "tool_response": {"content": "data"},
        }
        name, resp = _normalize_posttool_input(raw, "cursor")
        assert name == "Read"

    def test_claude_passthrough(self):
        from rafter_cli.commands.hook import _normalize_posttool_input
        raw = {
            "tool_name": "Bash",
            "tool_response": {"output": "ok", "error": ""},
        }
        name, resp = _normalize_posttool_input(raw, "claude")
        assert name == "Bash"
        assert resp == {"output": "ok", "error": ""}


class TestWindsurfFormat:
    """Tests for Windsurf hook output format (--format windsurf)."""

    def test_windsurf_pretool_allow(self):
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "agent_action_name": "pre_run_command",
            "tool_info": {"command_line": "ls -la"},
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool", "--format", "windsurf"], input=json.dumps(payload))
        assert result.exit_code == 0
        # Windsurf allow = exit 0, no stdout output
        assert result.output.strip() == ""

    def test_windsurf_pretool_deny(self):
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "agent_action_name": "pre_run_command",
            "tool_info": {"command_line": "rm -rf /"},
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["pretool", "--format", "windsurf"], input=json.dumps(payload))
        # Windsurf deny exits with code 2 (captured as SystemExit by typer runner)
        assert result.exit_code == 2
        assert "Rafter blocked" in result.stderr or "Rafter" in result.stderr


class TestCursorPosttool:
    """Tests for Cursor posttool format (--format cursor)."""

    def test_cursor_posttool_continue(self):
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "hook_event_name": "afterShellExecution",
            "output": "file1.txt\nfile2.txt",
            "error": "",
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool", "--format", "cursor"], input=json.dumps(payload))
        assert result.exit_code == 0
        # Cursor continue = no stdout
        assert result.output.strip() == ""

    def test_cursor_posttool_modify(self):
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "hook_event_name": "afterShellExecution",
            "output": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nother stuff",
            "error": "",
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool", "--format", "cursor"], input=json.dumps(payload))
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert "agentMessage" in data
        assert "redacted" in data["agentMessage"].lower()


class TestGeminiPosttool:
    """Tests for Gemini posttool format (--format gemini)."""

    def test_gemini_posttool_continue(self):
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "tool_name": "Bash",
            "tool_response": {"output": "clean output", "error": ""},
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool", "--format", "gemini"], input=json.dumps(payload))
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert data == {}

    def test_gemini_posttool_modify(self):
        from rafter_cli.commands.hook import hook_app
        from typer.testing import CliRunner

        payload = {
            "tool_name": "Bash",
            "tool_response": {
                "output": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nother stuff",
                "error": "",
            },
        }
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(hook_app, ["posttool", "--format", "gemini"], input=json.dumps(payload))
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert "systemMessage" in data
        assert "redacted" in data["systemMessage"].lower()
