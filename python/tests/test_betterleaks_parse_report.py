"""Tests for BetterleaksScanner._parse_report.

Mirrors node/tests/betterleaks-parse-report.test.ts — keep the two in sync.
Exercises the parser directly so the tests stay hermetic and run without the
betterleaks binary installed.
"""
from __future__ import annotations

import json

import pytest

from rafter_cli.scanners.betterleaks import BetterleaksScanner


@pytest.fixture
def write_report(tmp_path):
    def _write(content: str) -> str:
        p = tmp_path / "report.json"
        p.write_text(content)
        return str(p)

    return _write


class TestParseReport:
    # #217 — betterleaks >=1.1.2 writes the literal `null` for a clean scan via
    # the `dir`/`git` subcommands. Regression guard: this is an empty result,
    # not a version mismatch, and must not emit warning noise on every clean
    # file scanned.
    def test_null_report_is_empty_result(self, write_report, capsys):
        assert BetterleaksScanner._parse_report(write_report("null")) == []
        assert capsys.readouterr().err == ""

    def test_null_report_with_trailing_whitespace(self, write_report, capsys):
        assert BetterleaksScanner._parse_report(write_report("null\n")) == []
        assert capsys.readouterr().err == ""

    def test_empty_report(self, write_report, capsys):
        assert BetterleaksScanner._parse_report(write_report("")) == []
        assert capsys.readouterr().err == ""

    def test_array_report_returns_findings(self, write_report, capsys):
        findings = [{"RuleID": "aws-secret-key", "Description": "AWS key", "StartLine": 3}]
        assert BetterleaksScanner._parse_report(write_report(json.dumps(findings))) == findings
        assert capsys.readouterr().err == ""

    def test_empty_array_report(self, write_report, capsys):
        assert BetterleaksScanner._parse_report(write_report("[]")) == []
        assert capsys.readouterr().err == ""

    # sable-o4k — the stale-binary guard must survive the #217 fix.
    def test_non_array_object_still_warns(self, write_report, capsys):
        assert BetterleaksScanner._parse_report(write_report('{"findings": []}')) == []
        assert "possible version mismatch" in capsys.readouterr().err

    def test_malformed_json_still_warns(self, write_report, capsys):
        assert BetterleaksScanner._parse_report(write_report("{not json")) == []
        assert "Failed to parse" in capsys.readouterr().err
