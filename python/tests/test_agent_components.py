"""Tests for `rafter agent list / enable / disable` — the granular
component-control commands. Mirrors node/tests/agent-components.test.ts.

Each test gets a fake HOME so on-disk side effects are inspectable and the
developer's real configs aren't touched.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _run_cli(args: str, home: Path) -> tuple[str, str, int]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args.split()],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path


class TestAgentList:
    def test_json_has_expected_shape(self, home: Path):
        stdout, _, code = _run_cli("agent list --json", home)
        assert code == 0
        payload = json.loads(stdout)
        assert isinstance(payload["components"], list)
        by_id = {c["id"]: c for c in payload["components"]}
        for cid in [
            "claude-code.hooks",
            "claude-code.instructions",
            "claude-code.skills",
            "cursor.hooks",
            "cursor.mcp",
            "gemini.hooks",
            "gemini.mcp",
            "windsurf.hooks",
            "windsurf.mcp",
            "continue.hooks",
            "continue.mcp",
            "aider.mcp",
            "codex.hooks",
            "codex.skills",
            "openclaw.skills",
        ]:
            c = by_id.get(cid)
            assert c is not None, f"missing {cid}"
            assert c["state"] in {"installed", "not-installed", "not-detected"}
            assert c["kind"] in {"hooks", "mcp", "instructions", "skills"}
            assert isinstance(c["path"], str)
            assert isinstance(c["detected"], bool)
            assert isinstance(c["installed"], bool)

    def test_reports_not_detected_for_absent_dirs(self, home: Path):
        stdout, _, _ = _run_cli("agent list --json", home)
        payload = json.loads(stdout)
        by_id = {c["id"]: c for c in payload["components"]}
        assert by_id["cursor.mcp"]["state"] == "not-detected"
        assert by_id["gemini.mcp"]["state"] == "not-detected"
        # aider's "platform detected" is HOME — always exists
        assert by_id["aider.mcp"]["detected"] is True

    def test_installed_filter_only_returns_installed(self, home: Path):
        (home / ".cursor").mkdir()
        _run_cli("agent enable cursor.mcp", home)
        stdout, _, _ = _run_cli("agent list --json --installed", home)
        payload = json.loads(stdout)
        ids = [c["id"] for c in payload["components"]]
        assert "cursor.mcp" in ids
        assert all(c["installed"] for c in payload["components"])


class TestAgentEnableDisable:
    def test_unknown_component_exits_1_and_lists_known(self, home: Path):
        _, stderr, code = _run_cli("agent enable bogus.whatever", home)
        assert code == 1
        assert "Unknown component" in stderr
        assert "cursor.mcp" in stderr or "claude-code.mcp" in stderr

    def test_undetected_platform_exits_2_without_force(self, home: Path):
        _, stderr, code = _run_cli("agent enable cursor.mcp", home)
        assert code == 2
        assert "platform not detected" in stderr

    def test_force_installs_even_when_undetected(self, home: Path):
        _, _, code = _run_cli("agent enable cursor.mcp --force", home)
        assert code == 0
        mcp = json.loads((home / ".cursor" / "mcp.json").read_text())
        assert mcp["mcpServers"]["rafter"]["command"] == "rafter"

    def test_cursor_mcp_round_trip_preserves_unrelated_entries(self, home: Path):
        (home / ".cursor").mkdir()
        (home / ".cursor" / "mcp.json").write_text(
            json.dumps({"mcpServers": {"keep": {"command": "keep"}}}, indent=2)
        )
        _, _, code = _run_cli("agent enable cursor.mcp", home)
        assert code == 0
        cfg = json.loads((home / ".cursor" / "mcp.json").read_text())
        assert "rafter" in cfg["mcpServers"]
        assert "keep" in cfg["mcpServers"]

        _, _, code = _run_cli("agent disable cursor.mcp", home)
        assert code == 0
        cfg = json.loads((home / ".cursor" / "mcp.json").read_text())
        assert "rafter" not in cfg["mcpServers"]
        assert "keep" in cfg["mcpServers"]

    def test_claude_code_hooks_install_preserves_and_is_idempotent(self, home: Path):
        (home / ".claude").mkdir()
        settings_path = home / ".claude" / "settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [{"type": "command", "command": "other hook"}],
                            }
                        ]
                    }
                },
                indent=2,
            )
        )

        _run_cli("agent enable claude-code.hooks", home)
        _run_cli("agent enable claude-code.hooks", home)  # idempotent

        s = json.loads(settings_path.read_text())
        pre_commands = [
            h["command"] for e in s["hooks"]["PreToolUse"] for h in e["hooks"]
        ]
        assert "other hook" in pre_commands
        rafter_pre_count = sum(1 for c in pre_commands if c == "rafter hook pretool")
        # Installer adds 2 PreToolUse entries; idempotent install stays at 2 (not 4).
        assert rafter_pre_count == 2

    def test_aider_mcp_appends_once_and_disable_strips_block(self, home: Path):
        conf = home / ".aider.conf.yml"
        conf.write_text("# pre-existing line\nmodel: gpt-5\n")

        _run_cli("agent enable aider.mcp", home)
        _run_cli("agent enable aider.mcp", home)  # idempotent
        after = conf.read_text()
        assert after.count("rafter mcp serve") == 1
        assert "model: gpt-5" in after

        _run_cli("agent disable aider.mcp", home)
        cleaned = conf.read_text()
        assert "rafter mcp serve" not in cleaned
        assert "model: gpt-5" in cleaned

    def test_records_enabled_state_in_global_config(self, home: Path):
        (home / ".cursor").mkdir()
        _run_cli("agent enable cursor.mcp", home)

        cfg_path = home / ".rafter" / "config.json"
        assert cfg_path.exists()
        cfg = json.loads(cfg_path.read_text())
        assert cfg["agent"]["components"]["cursor.mcp"]["enabled"] is True

        _run_cli("agent disable cursor.mcp", home)
        cfg = json.loads(cfg_path.read_text())
        assert cfg["agent"]["components"]["cursor.mcp"]["enabled"] is False

    def test_claude_alias_for_claude_code_hooks(self, home: Path):
        (home / ".claude").mkdir()
        _, _, code = _run_cli("agent enable claude.hooks", home)
        assert code == 0
        settings = json.loads((home / ".claude" / "settings.json").read_text())
        assert len(settings["hooks"]["PreToolUse"]) > 0

    def test_instructions_strip_leaves_surrounding_content(self, home: Path):
        (home / ".claude").mkdir()
        file_path = home / ".claude" / "CLAUDE.md"
        file_path.write_text("# My notes\nkeep this\n")

        _run_cli("agent enable claude-code.instructions", home)
        after = file_path.read_text()
        assert "# My notes" in after
        assert "rafter:start" in after

        _run_cli("agent disable claude-code.instructions", home)
        cleaned = file_path.read_text()
        assert "# My notes" in cleaned
        assert "keep this" in cleaned
        assert "rafter:start" not in cleaned
