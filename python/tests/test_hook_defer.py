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
    return _cli(home, ["hook", "pretool", "--format", fmt], json.dumps(payload))


def _cli(home: str, args: list[str], stdin: str = "") -> subprocess.CompletedProcess:
    # Isolate HOME so a developer's ~/.rafter config cannot change the result.
    # Moving HOME also moves user site-packages, so pass sys.path through.
    env = {
        **os.environ,
        "HOME": home,
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "PYTHONPATH": os.pathsep.join([_PKG_ROOT, *(p for p in sys.path if p)]),
    }
    return subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args],
        input=stdin, capture_output=True, text=True, cwd=home, env=env, timeout=60,
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


# Each platform names its shell and file-write tools differently. The same
# policy must apply whatever the tool is called: a blocked command (or a write
# carrying a secret) through the platform's own tool name is denied, and a
# benign one gets the usual no-objection answer.
_FAKE_KEY = "AKIA" + "IOSFODNN7" + "ABCDEFG"


def _patch(line: str) -> str:
    return f"*** Begin Patch\n*** Add File: a.ts\n+{line}\n*** End Patch"


_NATIVE_TOOLS = {
    "gemini run_shell_command": ("gemini", lambda bad, home: {
        "tool_name": "run_shell_command", "tool_input": {"command": "rm -rf /" if bad else "ls -la"}}),
    "gemini write_file": ("gemini", lambda bad, home: {
        "tool_name": "write_file", "tool_input": {"file_path": "a.ts", "content": _FAKE_KEY if bad else "hello"}}),
    "gemini replace": ("gemini", lambda bad, home: {
        "tool_name": "replace",
        "tool_input": {"file_path": "a.ts", "old_string": "x", "new_string": _FAKE_KEY if bad else "hello"}}),
    "cursor Shell": ("cursor", lambda bad, home: {
        "hook_event_name": "preToolUse", "tool_name": "Shell",
        "tool_input": {"command": "rm -rf /" if bad else "ls -la"}}),
    "codex apply_patch": ("claude", lambda bad, home: {
        "tool_name": "apply_patch", "tool_input": {"command": _patch(_FAKE_KEY if bad else "hello")}}),
    # Continue's Write names its path "filepath"; the rafter-config guard must still see it.
    "continue Write": ("claude", lambda bad, home: {
        "tool_name": "Write",
        "tool_input": {"filepath": os.path.join(home, ".rafter", "config.json") if bad else "a.ts", "content": "{}"}}),
    "continue MultiEdit": ("claude", lambda bad, home: {
        "tool_name": "MultiEdit",
        "tool_input": {"file_path": "a.ts", "edits": [{"old_string": "x", "new_string": _FAKE_KEY if bad else "hello"}]}}),
    # apply_patch names its files only in its headers; the rafter-config guard
    # must see each one: Add (~), Update + Move to (absolute), Delete (relative).
    "codex apply_patch Add File": ("claude", lambda bad, home: {
        "tool_name": "apply_patch", "tool_input": {"command": (
            f"*** Begin Patch\n*** Add File: {'~/.rafter/config.json' if bad else 'a.json'}\n+{{}}\n*** End Patch")}}),
    "codex apply_patch Move to": ("claude", lambda bad, home: {
        "tool_name": "apply_patch", "tool_input": {"command": (
            "*** Begin Patch\n*** Update File: a.json\n"
            f"*** Move to: {os.path.join(home, '.rafter', 'config.json') if bad else 'b.json'}\n@@\n-x\n+{{}}\n*** End Patch")}}),
    "codex apply_patch Delete File": ("claude", lambda bad, home: {
        "tool_name": "apply_patch", "tool_input": {"command": (
            f"*** Begin Patch\n*** Delete File: {'.rafter/config.json' if bad else 'a.json'}\n*** End Patch")}}),
    "windsurf pre_write_code edits": ("windsurf", lambda bad, home: {
        "agent_action_name": "pre_write_code",
        "tool_info": {"file_path": "a.ts", "edits": [{"old_string": "x", "new_string": _FAKE_KEY if bad else "hello"}]}}),
}


def _is_deny(fmt: str, r: subprocess.CompletedProcess) -> bool:
    if fmt == "windsurf":
        return r.returncode == 2
    out = json.loads(r.stdout)
    if fmt == "cursor":
        return out.get("permission") == "deny"
    if fmt == "gemini":
        return out.get("decision") == "deny"
    return out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


@pytest.mark.parametrize("name", list(_NATIVE_TOOLS))
def test_platform_tool_names_are_evaluated(home, name):
    fmt, payload = _NATIVE_TOOLS[name]
    assert _is_deny(fmt, _run(home, fmt, payload(True, home)))
    ok = _run(home, fmt, payload(False, home))
    assert ok.returncode == 0, ok.stderr
    assert not _is_deny(fmt, ok)


def test_apply_patch_to_rafter_config_gets_the_write_guard_reason(home):
    r = _run(home, "claude", {"tool_name": "apply_patch", "tool_input": {
        "command": "*** Begin Patch\n*** Update File: ~/.rafter/config.json\n@@\n-x\n+{}\n*** End Patch"}})
    reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "write to rafter's own configuration" in reason


# The platform only calls the hook for tools its matcher names, so each
# installer's matcher must name the write tools the hook evaluates.
@pytest.mark.parametrize("args,settings,event,expected", [
    (["agent", "init", "--with-claude-code"], ".claude/settings.json", "PreToolUse",
     ["Bash", "Write|Edit|MultiEdit"]),
    (["agent", "enable", "gemini.hooks", "--force"], ".gemini/settings.json", "BeforeTool",
     ["run_shell_command|write_file|replace"]),
])
def test_installer_registers_every_evaluated_write_tool(tmp_path, args, settings, event, expected):
    r = _cli(str(tmp_path), args)
    assert r.returncode == 0, r.stderr
    hooks = json.loads((tmp_path / settings).read_text())["hooks"]
    assert [e["matcher"] for e in hooks[event]] == expected
