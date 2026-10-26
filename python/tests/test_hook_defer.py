"""The PreToolUse hook may only ever deny.

When rafter has no objection it must defer to the platform's own permission
flow, never approve: in Claude Code (and Codex) a PreToolUse "allow" skips the
permission prompt, so an approving hook would make an agent more permissive
than it is without rafter. Runs the real CLI in a subprocess, as the agent
platform would. Parity: node/tests/hook-defer.test.ts.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# One benign shell command, one benign file write and one blocked command,
# in each platform's own stdin shape.
_PAYLOADS = {
    "claude": {
        "bash": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        "write": {"hook_event_name": "PreToolUse", "tool_name": "Write",
                  "tool_input": {"file_path": "notes.txt", "content": "hello"}},
        "blocked": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
    },
    "cursor": {
        "bash": {"hook_event_name": "beforeShellExecution", "command": "ls -la", "cwd": "."},
        "write": {"hook_event_name": "preToolUse", "tool_name": "Write",
                  "tool_input": {"file_path": "notes.txt", "content": "hello"}},
        "blocked": {"hook_event_name": "beforeShellExecution", "command": "rm -rf /", "cwd": "."},
    },
    "gemini": {
        "bash": {"hook_event_name": "BeforeTool", "tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        "write": {"hook_event_name": "BeforeTool", "tool_name": "Write",
                  "tool_input": {"file_path": "notes.txt", "content": "hello"}},
        "blocked": {"hook_event_name": "BeforeTool", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
    },
    "windsurf": {
        "bash": {"agent_action_name": "pre_run_command", "tool_info": {"command_line": "ls -la", "cwd": "."}},
        "write": {"agent_action_name": "pre_write_code",
                  "tool_info": {"file_path": "notes.txt", "content": "hello"}},
        "blocked": {"agent_action_name": "pre_run_command", "tool_info": {"command_line": "rm -rf /", "cwd": "."}},
    },
}


@pytest.fixture(scope="module")
def home(tmp_path_factory):
    return str(tmp_path_factory.mktemp("rafter-defer"))


def _run(home: str, fmt: str, payload: dict) -> subprocess.CompletedProcess:
    # Isolate HOME so a developer's ~/.rafter config cannot change the result.
    # Moving HOME also moves user site-packages, so pass sys.path through.
    env = {
        **os.environ,
        "HOME": home,
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "PYTHONPATH": os.pathsep.join([_PKG_ROOT, *(p for p in sys.path if p)]),
    }
    return subprocess.run(
        [sys.executable, "-m", "rafter_cli", "hook", "pretool", "--format", fmt],
        input=json.dumps(payload), capture_output=True, text=True, cwd=home, env=env, timeout=30,
    )


@pytest.mark.parametrize("kind", ["bash", "write"])
def test_claude_benign_gets_no_permission_decision(home, kind):
    r = _run(home, "claude", _PAYLOADS["claude"][kind])
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {}


@pytest.mark.parametrize("kind", ["bash", "write"])
def test_gemini_benign_gets_no_decision(home, kind):
    r = _run(home, "gemini", _PAYLOADS["gemini"][kind])
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {}


@pytest.mark.parametrize("kind", ["bash", "write"])
def test_windsurf_benign_exits_zero_with_no_output(home, kind):
    r = _run(home, "windsurf", _PAYLOADS["windsurf"][kind])
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == ""


# Cursor has no neutral answer: its permission hooks block on an empty or
# schema-invalid response, so "allow" is the only way to let a call proceed.
@pytest.mark.parametrize("kind", ["bash", "write"])
def test_cursor_benign_still_returns_required_permission(home, kind):
    r = _run(home, "cursor", _PAYLOADS["cursor"][kind])
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"permission": "allow"}


def test_blocked_command_still_denied_in_every_format(home):
    out = json.loads(_run(home, "claude", _PAYLOADS["claude"]["blocked"]).stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "Rafter blocked" in out["permissionDecisionReason"]
    assert json.loads(_run(home, "cursor", _PAYLOADS["cursor"]["blocked"]).stdout)["permission"] == "deny"
    assert json.loads(_run(home, "gemini", _PAYLOADS["gemini"]["blocked"]).stdout)["decision"] == "deny"
    w = _run(home, "windsurf", _PAYLOADS["windsurf"]["blocked"])
    assert w.returncode == 2
    assert "Rafter blocked" in w.stderr
