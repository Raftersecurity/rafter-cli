"""Tests for the output formatter — validates both human (Rich markup) and agent
(plain text) modes produce correct output across all formatter methods."""
from __future__ import annotations

import re
from io import StringIO
from unittest.mock import patch

import pytest

from rafter_cli.utils.formatter import fmt, set_agent_mode, is_agent_mode, print_stderr


# Regex matching common emoji ranges
EMOJI_RE = re.compile(
    "[\u2600-\u27BF"
    "\U0001F300-\U0001F9FF"
    "\U0001FA00-\U0001FAFF"
    "]"
)

# Regex matching Rich markup tags like [bold], [green], [/red], etc.
RICH_MARKUP_RE = re.compile(r"\[/?[a-z][\w\s]*\]")


@pytest.fixture(autouse=True)
def _reset_agent_mode():
    """Ensure agent mode is reset after every test."""
    set_agent_mode(False)
    yield
    set_agent_mode(False)


# ── agent mode toggle ────────────────────────────────────────────────


class TestAgentModeToggle:
    def test_defaults_to_false(self):
        set_agent_mode(False)
        assert is_agent_mode() is False

    def test_can_be_enabled(self):
        set_agent_mode(True)
        assert is_agent_mode() is True

    def test_can_be_toggled_back_and_forth(self):
        set_agent_mode(True)
        assert is_agent_mode() is True
        set_agent_mode(False)
        assert is_agent_mode() is False
        set_agent_mode(True)
        assert is_agent_mode() is True


# ── agent mode output (plain text, no Rich markup) ───────────────────


class TestAgentModeOutput:
    @pytest.fixture(autouse=True)
    def _enable_agent_mode(self):
        set_agent_mode(True)

    def test_header_wraps_text_in_delimiters(self):
        assert fmt.header("Test") == "=== Test ==="

    def test_success_prefixes_with_ok(self):
        assert fmt.success("done") == "[OK] done"

    def test_warning_prefixes_with_warn(self):
        assert fmt.warning("caution") == "[WARN] caution"

    def test_error_prefixes_with_error(self):
        assert fmt.error("failed") == "[ERROR] failed"

    def test_severity_wraps_level_in_brackets(self):
        assert fmt.severity("critical") == "[CRITICAL]"
        assert fmt.severity("high") == "[HIGH]"
        assert fmt.severity("medium") == "[MEDIUM]"
        assert fmt.severity("low") == "[LOW]"

    def test_divider_returns_dashes(self):
        assert fmt.divider() == "---"

    def test_info_returns_plain_text(self):
        assert fmt.info("hello") == "hello"

    # ── edge cases ────────────────────────────────────────────────────

    def test_empty_string_input(self):
        assert fmt.header("") == "===  ==="
        assert fmt.success("") == "[OK] "
        assert fmt.warning("") == "[WARN] "
        assert fmt.error("") == "[ERROR] "
        assert fmt.info("") == ""

    def test_special_characters_in_input(self):
        assert fmt.success('file: /tmp/<test> & "quotes"') == \
            '[OK] file: /tmp/<test> & "quotes"'

    def test_severity_uppercases_mixed_case_input(self):
        assert fmt.severity("Critical") == "[CRITICAL]"
        assert fmt.severity("HIGH") == "[HIGH]"

    def test_severity_handles_unknown_level(self):
        assert fmt.severity("unknown") == "[UNKNOWN]"
        assert fmt.severity("custom") == "[CUSTOM]"


# ── human mode output (Rich markup) ──────────────────────────────────


class TestHumanModeOutput:
    @pytest.fixture(autouse=True)
    def _disable_agent_mode(self):
        set_agent_mode(False)

    def test_success_contains_check_mark(self):
        assert "\u2713" in fmt.success("done")  # ✓

    def test_warning_contains_warning_sign(self):
        assert "\u26a0" in fmt.warning("caution")  # ⚠

    def test_error_contains_x_mark(self):
        assert "\u2717" in fmt.error("failed")  # ✗

    def test_severity_returns_nonempty_for_all_levels(self):
        for level in ("critical", "high", "medium", "low"):
            assert len(fmt.severity(level)) > 0

    def test_severity_handles_unknown_level(self):
        assert fmt.severity("unknown") == "[UNKNOWN]"

    # ── Rich markup present ───────────────────────────────────────────

    def test_header_contains_rich_markup(self):
        out = fmt.header("Report")
        assert RICH_MARKUP_RE.search(out)

    def test_header_contains_box_drawing(self):
        out = fmt.header("Report")
        assert "\u250c" in out  # ┌
        assert "\u2510" in out  # ┐
        assert "Report" in out

    def test_success_contains_green_markup(self):
        out = fmt.success("ok")
        assert "[green]" in out

    def test_warning_contains_yellow_markup(self):
        out = fmt.warning("warn")
        assert "[yellow]" in out

    def test_error_contains_red_markup(self):
        out = fmt.error("fail")
        assert "[red]" in out

    def test_info_contains_cyan_markup(self):
        out = fmt.info("details")
        assert "[cyan]" in out

    def test_divider_uses_double_line_chars(self):
        out = fmt.divider()
        assert "\u2550" in out  # ═
        # Should be ~50 chars of ═
        assert out.count("\u2550") >= 50

    def test_severity_critical_has_red_background(self):
        out = fmt.severity("critical")
        assert "on red" in out

    def test_severity_high_has_yellow_background(self):
        out = fmt.severity("high")
        assert "on yellow" in out

    def test_severity_medium_has_blue_background(self):
        out = fmt.severity("medium")
        assert "on blue" in out

    def test_severity_low_has_green_background(self):
        out = fmt.severity("low")
        assert "on green" in out

    # ── text preservation ─────────────────────────────────────────────

    def test_success_preserves_user_text(self):
        assert "all clear" in fmt.success("all clear")

    def test_warning_preserves_user_text(self):
        assert "be careful" in fmt.warning("be careful")

    def test_error_preserves_user_text(self):
        assert "it broke" in fmt.error("it broke")

    def test_info_preserves_user_text(self):
        assert "details here" in fmt.info("details here")

    def test_severity_includes_level_name(self):
        for level in ("critical", "high", "medium", "low"):
            assert level.upper() in fmt.severity(level)


# ── human vs agent produce different output ──────────────────────────


class TestModeDifferences:
    @pytest.mark.parametrize(
        "name,call",
        [
            ("header", lambda: fmt.header("Test")),
            ("success", lambda: fmt.success("ok")),
            ("warning", lambda: fmt.warning("warn")),
            ("error", lambda: fmt.error("err")),
            ("divider", lambda: fmt.divider()),
            ("info", lambda: fmt.info("text")),
            ("severity:critical", lambda: fmt.severity("critical")),
            ("severity:high", lambda: fmt.severity("high")),
            ("severity:medium", lambda: fmt.severity("medium")),
            ("severity:low", lambda: fmt.severity("low")),
        ],
    )
    def test_differs_between_modes(self, name, call):
        set_agent_mode(False)
        human = call()
        set_agent_mode(True)
        agent = call()
        assert human != agent, f"{name} same in both modes"


# ── mode switching mid-stream ────────────────────────────────────────


class TestModeSwitching:
    def test_switches_live_not_cached(self):
        set_agent_mode(True)
        agent_out = fmt.success("test")
        assert agent_out == "[OK] test"

        set_agent_mode(False)
        human_out = fmt.success("test")
        assert "\u2713" in human_out
        assert human_out != agent_out


# ── print_stderr ─────────────────────────────────────────────────────


class TestPrintStderr:
    def test_agent_mode_prints_raw_to_stderr(self):
        set_agent_mode(True)
        captured = StringIO()
        with patch("sys.stderr", captured):
            print_stderr("plain message")
        assert "plain message" in captured.getvalue()

    def test_human_mode_uses_rich_console(self):
        set_agent_mode(False)
        # In human mode, print_stderr goes through Rich Console(stderr=True).
        # We can't easily capture Rich console output, but we can verify
        # that the function doesn't raise and that it calls Console.print.
        with patch("rafter_cli.utils.formatter._stderr_console") as mock_console:
            print_stderr("styled message")
            mock_console.print.assert_called_once_with("styled message")


# ── audit event indicators ───────────────────────────────────────────


class TestAuditEventIndicators:
    """Test the agent/human mode event indicator dicts used by the audit command."""

    def test_agent_indicators_are_bracket_format(self):
        from rafter_cli.commands.agent import _EVENT_INDICATORS_AGENT

        for event_type, indicator in _EVENT_INDICATORS_AGENT.items():
            assert indicator.startswith("["), f"{event_type}: {indicator!r}"
            assert indicator.endswith("]"), f"{event_type}: {indicator!r}"
            assert not EMOJI_RE.search(indicator), f"Emoji in agent indicator: {indicator!r}"

    def test_human_indicators_are_emoji(self):
        from rafter_cli.commands.agent import _EVENT_INDICATORS_HUMAN

        for event_type, indicator in _EVENT_INDICATORS_HUMAN.items():
            # Human indicators should contain at least one non-ASCII character (emoji)
            assert any(ord(c) > 127 for c in indicator), \
                f"{event_type}: expected emoji, got {indicator!r}"

    def test_agent_and_human_cover_same_event_types(self):
        from rafter_cli.commands.agent import (
            _EVENT_INDICATORS_AGENT,
            _EVENT_INDICATORS_HUMAN,
        )
        assert set(_EVENT_INDICATORS_AGENT.keys()) == set(_EVENT_INDICATORS_HUMAN.keys())

    def test_all_expected_event_types_present(self):
        from rafter_cli.commands.agent import _EVENT_INDICATORS_AGENT

        expected = {
            "command_intercepted",
            "secret_detected",
            "content_sanitized",
            "policy_override",
            "scan_executed",
            "config_changed",
        }
        assert expected == set(_EVENT_INDICATORS_AGENT.keys())
