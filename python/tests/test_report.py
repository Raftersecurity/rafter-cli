"""Tests for the rafter report command — HTML security report generation."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rafter_cli.__main__ import app
from rafter_cli.commands.report import generate_html_report, _escape_html, _severity_rank

runner = CliRunner()

SAMPLE_RESULTS = [
    {
        "file": "/app/src/config.ts",
        "matches": [
            {
                "pattern": {
                    "name": "AWS Access Key",
                    "severity": "critical",
                    "description": "Detects AWS access key IDs",
                },
                "line": 42,
                "column": 7,
                "redacted": "AKIA****MPLE",
            },
        ],
    },
    {
        "file": "/app/src/utils.ts",
        "matches": [
            {
                "pattern": {
                    "name": "Generic API Key",
                    "severity": "medium",
                    "description": "Generic API key pattern",
                },
                "line": 10,
                "column": 1,
                "redacted": "api_****_key",
            },
            {
                "pattern": {
                    "name": "GitHub Token",
                    "severity": "high",
                    "description": "GitHub personal access token",
                },
                "line": 25,
                "column": 3,
                "redacted": "ghp_****xxxx",
            },
        ],
    },
]

EMPTY_RESULTS: list = []


class TestReportCli:
    """Test the report CLI command via typer runner."""

    def test_generates_html_from_piped_input(self):
        result = runner.invoke(app, ["report"], input=json.dumps(SAMPLE_RESULTS))
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.stdout
        assert "Rafter Security Report" in result.stdout
        assert "Executive Summary" in result.stdout
        assert "AWS Access Key" in result.stdout

    def test_generates_html_from_file_argument(self, tmp_path: Path):
        input_file = tmp_path / "scan.json"
        input_file.write_text(json.dumps(SAMPLE_RESULTS), encoding="utf-8")

        result = runner.invoke(app, ["report", str(input_file)])
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.stdout
        assert "AWS Access Key" in result.stdout

    def test_writes_to_output_file(self, tmp_path: Path):
        input_file = tmp_path / "scan.json"
        output_file = tmp_path / "report.html"
        input_file.write_text(json.dumps(SAMPLE_RESULTS), encoding="utf-8")

        result = runner.invoke(app, ["report", str(input_file), "-o", str(output_file)])
        assert result.exit_code == 0
        assert output_file.exists()

        html = output_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "Executive Summary" in html

    def test_custom_title(self):
        result = runner.invoke(
            app, ["report", "--title", "My Audit Report"], input=json.dumps(SAMPLE_RESULTS)
        )
        assert result.exit_code == 0
        assert "My Audit Report" in result.stdout

    def test_severity_breakdown(self):
        result = runner.invoke(app, ["report"], input=json.dumps(SAMPLE_RESULTS))
        assert result.exit_code == 0
        assert "Severity Breakdown" in result.stdout
        assert "Critical" in result.stdout
        assert "High" in result.stdout
        assert "Medium" in result.stdout

    def test_empty_results_no_findings(self):
        result = runner.invoke(app, ["report"], input=json.dumps(EMPTY_RESULTS))
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.stdout
        assert "No Security Findings" in result.stdout

    def test_critical_risk_level(self):
        result = runner.invoke(app, ["report"], input=json.dumps(SAMPLE_RESULTS))
        assert result.exit_code == 0
        assert "Critical" in result.stdout
        assert "Overall Risk" in result.stdout

    def test_detailed_findings_table(self):
        result = runner.invoke(app, ["report"], input=json.dumps(SAMPLE_RESULTS))
        assert result.exit_code == 0
        assert "Detailed Findings" in result.stdout
        assert "/app/src/config.ts" in result.stdout
        assert "/app/src/utils.ts" in result.stdout
        assert "AKIA****MPLE" in result.stdout

    def test_invalid_json_errors(self):
        result = runner.invoke(app, ["report"], input="not valid json")
        assert result.exit_code == 2
        assert "Invalid JSON" in result.output

    def test_nonexistent_file_errors(self):
        result = runner.invoke(app, ["report", "/nonexistent/path.json"])
        assert result.exit_code == 2
        assert "File not found" in result.output

    def test_non_array_json_errors(self):
        result = runner.invoke(app, ["report"], input='{"not": "an array"}')
        assert result.exit_code == 2
        assert "Invalid JSON" in result.output

    def test_html_escaping_xss(self):
        xss_results = [
            {
                "file": '/app/<script>alert("xss")</script>.ts',
                "matches": [
                    {
                        "pattern": {
                            "name": '<img onerror="alert(1)">',
                            "severity": "high",
                            "description": 'Test "injection"',
                        },
                        "line": 1,
                        "redacted": "secret",
                    },
                ],
            },
        ]
        result = runner.invoke(app, ["report"], input=json.dumps(xss_results))
        assert result.exit_code == 0
        assert "<script>" not in result.stdout
        assert "&lt;script&gt;" in result.stdout

    def test_report_help(self):
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "HTML" in result.stdout or "report" in result.stdout.lower()


class TestGenerateHtmlReport:
    """Unit tests for the HTML generation function."""

    def test_total_findings_count(self):
        html = generate_html_report(SAMPLE_RESULTS, "Test Report")
        assert "3" in html  # 1 + 2 findings

    def test_files_affected_count(self):
        html = generate_html_report(SAMPLE_RESULTS, "Test Report")
        # 2 files affected
        assert "2" in html

    def test_risk_level_high_only(self):
        high_only = [
            {
                "file": "test.py",
                "matches": [
                    {
                        "pattern": {"name": "Token", "severity": "high"},
                        "line": 1,
                        "redacted": "***",
                    }
                ],
            }
        ]
        html = generate_html_report(high_only, "Test")
        assert "High" in html
        assert "#ea580c" in html  # high risk color

    def test_risk_level_medium_only(self):
        medium_only = [
            {
                "file": "test.py",
                "matches": [
                    {
                        "pattern": {"name": "Key", "severity": "medium"},
                        "line": 1,
                        "redacted": "***",
                    }
                ],
            }
        ]
        html = generate_html_report(medium_only, "Test")
        assert "Medium" in html
        assert "#2563eb" in html  # medium risk color

    def test_risk_level_low_only(self):
        low_only = [
            {
                "file": "test.py",
                "matches": [
                    {
                        "pattern": {"name": "Info", "severity": "low"},
                        "line": 1,
                        "redacted": "***",
                    }
                ],
            }
        ]
        html = generate_html_report(low_only, "Test")
        assert "#16a34a" in html  # low/none risk color

    def test_risk_level_none_for_empty(self):
        html = generate_html_report([], "Test")
        assert "None" in html
        assert "No Security Findings" in html

    def test_top_patterns_bar_chart(self):
        html = generate_html_report(SAMPLE_RESULTS, "Test")
        assert "Top Finding Types" in html
        assert "AWS Access Key" in html
        assert "bar-chart" in html

    def test_no_bar_chart_for_empty(self):
        html = generate_html_report([], "Test")
        assert "Top Finding Types" not in html

    def test_findings_sorted_by_severity(self):
        html = generate_html_report(SAMPLE_RESULTS, "Test")
        # Critical should come before high, high before medium
        crit_pos = html.index("sev-critical")
        high_pos = html.index("sev-high")
        medium_pos = html.index("sev-medium")
        assert crit_pos < high_pos < medium_pos

    def test_version_in_footer(self):
        html = generate_html_report(SAMPLE_RESULTS, "Test")
        assert "Rafter CLI v" in html

    def test_null_line_shows_dash(self):
        results = [
            {
                "file": "test.py",
                "matches": [
                    {
                        "pattern": {"name": "Secret", "severity": "high"},
                        "line": None,
                        "redacted": "***",
                    }
                ],
            }
        ]
        html = generate_html_report(results, "Test")
        assert "\u2014" in html  # em dash for null line


class TestEscapeHtml:
    def test_escapes_ampersand(self):
        assert _escape_html("a & b") == "a &amp; b"

    def test_escapes_angle_brackets(self):
        assert _escape_html("<script>") == "&lt;script&gt;"

    def test_escapes_quotes(self):
        assert _escape_html('"hello"') == "&quot;hello&quot;"

    def test_escapes_single_quotes(self):
        assert _escape_html("it's") == "it&#39;s"

    def test_empty_string(self):
        assert _escape_html("") == ""

    def test_no_escaping_needed(self):
        assert _escape_html("hello world") == "hello world"


class TestSeverityRank:
    def test_critical_is_zero(self):
        assert _severity_rank("critical") == 0

    def test_high_is_one(self):
        assert _severity_rank("high") == 1

    def test_medium_is_two(self):
        assert _severity_rank("medium") == 2

    def test_low_is_three(self):
        assert _severity_rank("low") == 3

    def test_unknown_is_four(self):
        assert _severity_rank("unknown") == 4

    def test_case_insensitive(self):
        assert _severity_rank("CRITICAL") == 0
        assert _severity_rank("High") == 1
