"""Tests for rafter policy export command."""
from __future__ import annotations

import json

from rafter_cli.commands.policy import _generate_claude_config


class TestGenerateClaudeConfig:
    def test_valid_json(self):
        output = _generate_claude_config()
        config = json.loads(output)
        assert "hooks" in config
        assert "PreToolUse" in config["hooks"]

    def test_has_bash_matcher(self):
        config = json.loads(_generate_claude_config())
        matchers = [entry["matcher"] for entry in config["hooks"]["PreToolUse"]]
        assert "Bash" in matchers

    def test_has_write_edit_matcher(self):
        config = json.loads(_generate_claude_config())
        matchers = [entry["matcher"] for entry in config["hooks"]["PreToolUse"]]
        assert "Write|Edit" in matchers

    def test_hook_command(self):
        config = json.loads(_generate_claude_config())
        for entry in config["hooks"]["PreToolUse"]:
            for hook in entry["hooks"]:
                assert hook["command"] == "rafter hook pretool"
                assert hook["type"] == "command"
