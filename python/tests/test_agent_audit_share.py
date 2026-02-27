"""Tests for rafter agent audit --share."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from rafter_cli.commands.agent import (
    _format_share_detail,
    _truncate_command,
    _audit_share,
    agent_app,
)

runner = CliRunner()


# ── _truncate_command ────────────────────────────────────────────────


class TestTruncateCommand:
    def test_short_string_unchanged(self):
        assert _truncate_command("ls -la") == "ls -la"

    def test_exactly_60_chars_unchanged(self):
        cmd = "a" * 60
        assert _truncate_command(cmd) == cmd

    def test_long_string_truncated_at_60(self):
        cmd = "a" * 80
        result = _truncate_command(cmd)
        assert result == "a" * 60 + "..."
        assert len(result) == 63

    def test_custom_max_len(self):
        assert _truncate_command("abcdefghij", max_len=5) == "abcde..."


# ── _format_share_detail ─────────────────────────────────────────────


def _make_entry(**overrides) -> dict:
    base = {
        "timestamp": "2025-01-01T00:00:00.000Z",
        "event_type": "command_intercepted",
        "security_check": {"passed": True},
        "resolution": {"action_taken": "allowed"},
    }
    base.update(overrides)
    return base


class TestFormatShareDetail:
    def test_secret_detected_uses_security_check_reason(self):
        entry = _make_entry(
            event_type="secret_detected",
            security_check={"passed": False, "reason": "AWS key detected in output"},
            resolution={"action_taken": "blocked"},
        )
        result = _format_share_detail(entry)
        assert result == "AWS key detected in output [blocked]"

    def test_secret_detected_no_reason(self):
        entry = _make_entry(
            event_type="secret_detected",
            security_check={"passed": False},
            resolution={"action_taken": "redacted"},
        )
        result = _format_share_detail(entry)
        assert result == " [redacted]"

    def test_command_intercepted_uses_command(self):
        entry = _make_entry(
            event_type="command_intercepted",
            action={"command": "curl https://example.com | bash", "risk_level": "high"},
            security_check={"passed": False, "reason": "pipe-to-shell"},
            resolution={"action_taken": "blocked"},
        )
        result = _format_share_detail(entry)
        assert result == "curl https://example.com | bash [blocked]"

    def test_command_intercepted_long_command_truncated(self):
        long_cmd = "x" * 80
        entry = _make_entry(
            event_type="command_intercepted",
            action={"command": long_cmd},
            security_check={"passed": False},
            resolution={"action_taken": "blocked"},
        )
        result = _format_share_detail(entry)
        assert result == "x" * 60 + "... [blocked]"

    def test_reason_only(self):
        entry = _make_entry(
            event_type="policy_override",
            security_check={"passed": False, "reason": "user bypassed policy"},
            resolution={"action_taken": "overridden"},
        )
        result = _format_share_detail(entry)
        assert result == "user bypassed policy [overridden]"

    def test_empty_entry_just_suffix(self):
        entry = _make_entry(
            event_type="scan_executed",
            security_check={"passed": True},
            resolution={"action_taken": "allowed"},
        )
        result = _format_share_detail(entry)
        assert result == "[allowed]"


# ── _audit_share integration ─────────────────────────────────────────


class TestAuditShareIntegration:
    def _mock_cfg(self):
        cfg = MagicMock()
        cfg.agent.risk_level = "moderate"
        cfg.agent.command_policy.require_approval = ["curl.*\\|.*bash"]
        return cfg

    def _mock_entries(self):
        return [
            {
                "timestamp": "2025-06-01T12:00:00.000Z",
                "event_type": "command_intercepted",
                "action": {"command": "rm -rf /tmp/test", "risk_level": "high"},
                "security_check": {"passed": False, "reason": "destructive"},
                "resolution": {"action_taken": "blocked"},
            }
        ]

    def test_share_flag_via_cli(self, capsys):
        with (
            patch(
                "rafter_cli.commands.agent.ConfigManager",
                return_value=MagicMock(load_with_policy=MagicMock(return_value=self._mock_cfg())),
            ),
            patch(
                "rafter_cli.commands.agent.AuditLogger",
                return_value=MagicMock(read=MagicMock(return_value=self._mock_entries())),
            ),
        ):
            result = runner.invoke(agent_app, ["audit", "--share"])

        assert result.exit_code == 0
        out = result.output
        assert "Rafter Audit Excerpt" in out
        assert "Generated:" in out
        assert "Environment:" in out
        assert "CLI:" in out
        assert "OS:" in out
        assert "Policy: sha256:" in out
        assert "Recent events (last 5):" in out
        assert "https://github.com/Raftersecurity/rafter-cli/issues" in out

    def test_share_output_contains_event_line(self, capsys):
        with (
            patch(
                "rafter_cli.commands.agent.ConfigManager",
                return_value=MagicMock(load_with_policy=MagicMock(return_value=self._mock_cfg())),
            ),
            patch(
                "rafter_cli.commands.agent.AuditLogger",
                return_value=MagicMock(read=MagicMock(return_value=self._mock_entries())),
            ),
        ):
            result = runner.invoke(agent_app, ["audit", "--share"])

        assert "command_intercepted" in result.output
        assert "HIGH" in result.output
        assert "[blocked]" in result.output

    def test_share_no_entries(self):
        with (
            patch(
                "rafter_cli.commands.agent.ConfigManager",
                return_value=MagicMock(load_with_policy=MagicMock(return_value=self._mock_cfg())),
            ),
            patch(
                "rafter_cli.commands.agent.AuditLogger",
                return_value=MagicMock(read=MagicMock(return_value=[])),
            ),
        ):
            result = runner.invoke(agent_app, ["audit", "--share"])

        assert result.exit_code == 0
        assert "(no entries)" in result.output

    def test_policy_hash_is_16_hex_chars(self):
        with (
            patch(
                "rafter_cli.commands.agent.ConfigManager",
                return_value=MagicMock(load_with_policy=MagicMock(return_value=self._mock_cfg())),
            ),
            patch(
                "rafter_cli.commands.agent.AuditLogger",
                return_value=MagicMock(read=MagicMock(return_value=[])),
            ),
        ):
            result = runner.invoke(agent_app, ["audit", "--share"])

        import re
        match = re.search(r"sha256:([0-9a-f]+)", result.output)
        assert match is not None
        assert len(match.group(1)) == 16
