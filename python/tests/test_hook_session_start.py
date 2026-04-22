"""Tests for rafter hook session-start command."""
from __future__ import annotations

import io
import json
from unittest.mock import patch

from rafter_cli.commands.hook import SESSION_START_DIRECTIVE, session_start


def _capture_session_start(stdin_text: str = "") -> dict:
    stdout_buf = io.StringIO()
    with patch("rafter_cli.commands.hook._read_stdin", return_value=stdin_text), \
         patch("sys.stdout", stdout_buf):
        session_start(format="claude")
    return json.loads(stdout_buf.getvalue())


class TestSessionStart:
    def test_emits_hook_specific_output_envelope(self):
        parsed = _capture_session_start()
        assert "hookSpecificOutput" in parsed
        assert parsed["hookSpecificOutput"]["hookEventName"] == "SessionStart"
        assert parsed["hookSpecificOutput"]["additionalContext"] == SESSION_START_DIRECTIVE

    def test_handles_payload_on_stdin_without_parsing(self):
        # Claude Code sends a JSON payload (source, session_id, etc.) — we ignore it.
        parsed = _capture_session_start('{"source":"startup","session_id":"abc"}')
        assert parsed["hookSpecificOutput"]["additionalContext"] == SESSION_START_DIRECTIVE

    def test_directive_is_lean(self):
        # Per-session token budget: keep the directive short.
        assert len(SESSION_START_DIRECTIVE.split()) < 80

    def test_directive_mentions_organic_uptake_levers(self):
        # Both triggers — scan and the secure-design skill — must survive any edit.
        assert "rafter scan local" in SESSION_START_DIRECTIVE
        assert "rafter-secure-design" in SESSION_START_DIRECTIVE
