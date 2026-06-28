"""Regression: hook subcommands must tolerate harness-appended flags/args.

Claude Code appends `--hook-json <data>` to the hook command; hook input comes
from stdin, so the extra flag must be discarded, not rejected (#180). The
context_settings must live on the SUBCOMMAND (pretool/posttool), not only the
hook_app group — a group-level setting does not reach subcommand parsing.
"""
from __future__ import annotations

import json

from typer.testing import CliRunner

from rafter_cli.commands.hook import hook_app

runner = CliRunner()

_PRETOOL_IN = '{"tool_name":"Bash","tool_input":{"command":"ls"}}'
_POSTTOOL_IN = '{"tool_name":"Bash","tool_response":{"output":"ok"}}'


def test_pretool_tolerates_hook_json():
    r = runner.invoke(hook_app, ["pretool", "--hook-json", "{}"], input=_PRETOOL_IN)
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_posttool_tolerates_hook_json():
    r = runner.invoke(hook_app, ["posttool", "--hook-json", '{"x":1}'], input=_POSTTOOL_IN)
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["hookSpecificOutput"]["hookEventName"] == "PostToolUse"


def test_real_format_option_still_honored():
    # gemini "allow" emits an empty object — proves --format wasn't swallowed.
    r = runner.invoke(
        hook_app, ["pretool", "--format", "gemini", "--hook-json", "{}"], input=_PRETOOL_IN
    )
    assert r.exit_code == 0, r.output
    assert r.stdout.strip() == "{}"


def test_no_extra_flag_unchanged():
    r = runner.invoke(hook_app, ["pretool"], input=_PRETOOL_IN)
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"
