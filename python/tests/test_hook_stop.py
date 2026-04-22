"""Tests for the Stop hook — enforcement layer that blocks completion until the
agent has engaged rafter (scan or rafter-* skill) at least once per session."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from rafter_cli.commands.hook import STOP_DIRECTIVE, _transcript_touched_rafter


def _run_stop(payload: dict) -> dict:
    """Invoke the real CLI so we exercise the full commander/typer wiring."""
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "hook", "stop"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=5,
    )
    return json.loads(result.stdout)


def test_blocks_when_transcript_has_no_rafter_engagement():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "t.jsonl"
        t.write_text("")
        out = _run_stop({"transcript_path": str(t), "stop_hook_active": False})
        assert out["decision"] == "block"
        assert out["reason"] == STOP_DIRECTIVE


def test_allows_when_transcript_has_rafter_scan():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "t.jsonl"
        t.write_text(json.dumps({
            "message": {"content": [{
                "type": "tool_use", "name": "Bash",
                "input": {"command": "rafter scan local ."},
            }]}
        }) + "\n")
        out = _run_stop({"transcript_path": str(t), "stop_hook_active": False})
        assert out == {}


def test_allows_when_transcript_has_rafter_skill():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "t.jsonl"
        t.write_text(json.dumps({
            "message": {"content": [{
                "type": "tool_use", "name": "Skill",
                "input": {"skill": "rafter-secure-design"},
            }]}
        }) + "\n")
        out = _run_stop({"transcript_path": str(t), "stop_hook_active": False})
        assert out == {}


def test_always_allows_when_stop_hook_active_true():
    """Second-pass guard — never loop the agent."""
    out = _run_stop({"transcript_path": "/dev/null", "stop_hook_active": True})
    assert out == {}


def test_transcript_touched_rafter_fails_closed_on_missing_file():
    assert _transcript_touched_rafter("/no/such/path.jsonl") is False


def test_detects_engagement_in_subagent_transcript():
    """Claude Code delegates to subagents; their transcripts must count."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        main = root / "main.jsonl"
        main.write_text("")
        sub_dir = root / "main" / "subagents"
        sub_dir.mkdir(parents=True)
        (sub_dir / "sub.jsonl").write_text(json.dumps({
            "message": {"content": [{
                "type": "tool_use", "name": "Skill",
                "input": {"skill": "rafter-secure-design"},
            }]}
        }) + "\n")
        out = _run_stop({"transcript_path": str(main), "stop_hook_active": False})
        assert out == {}


def test_stop_directive_is_lean():
    words = [w for w in STOP_DIRECTIVE.split() if w]
    assert len(words) < 70
