"""Tests for write_payload — report_url injection and JSON/markdown output."""
from __future__ import annotations

import json

import pytest

from rafter_cli.utils.api import EXIT_SUCCESS, write_payload


class TestWritePayload:
    def test_json_output_passthrough(self, capsys):
        data = {"scan_id": "s1", "findings": []}
        result = write_payload(data, "json")
        out = capsys.readouterr().out
        assert json.loads(out) == data
        assert result == EXIT_SUCCESS

    def test_markdown_output(self, capsys):
        data = {"markdown": "# Results\nNo issues", "findings": []}
        write_payload(data, "md")
        out = capsys.readouterr().out
        assert out == "# Results\nNo issues"

    def test_markdown_returns_empty_string_when_no_markdown_field(self, capsys):
        data = {"findings": []}
        write_payload(data, "md")
        out = capsys.readouterr().out
        assert out == ""

    def test_quiet_mode_compact_json(self, capsys):
        data = {"a": 1}
        write_payload(data, "json", quiet=True)
        out = capsys.readouterr().out
        assert out == '{"a": 1}'

    def test_non_quiet_pretty_prints(self, capsys):
        data = {"a": 1}
        write_payload(data, "json", quiet=False)
        out = capsys.readouterr().out
        assert "\n" in out

    def test_injects_report_url_when_report_id_present(self, capsys):
        data = {"scan_id": "s1", "report_id": "rpt-xyz", "findings": []}
        write_payload(data, "json")
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["report_url"] == "https://rafter.so/report/rpt-xyz"
        assert parsed["report_id"] == "rpt-xyz"

    def test_no_report_url_when_report_id_absent(self, capsys):
        data = {"scan_id": "s1", "findings": []}
        write_payload(data, "json")
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert "report_url" not in parsed

    def test_no_report_url_in_markdown_mode_even_if_report_id_present(self, capsys):
        data = {"report_id": "rpt-xyz", "markdown": "# Results"}
        write_payload(data, "md")
        out = capsys.readouterr().out
        assert out == "# Results"
        assert "report_url" not in out

    def test_report_url_snapshot_format(self, capsys):
        """URL format is exactly https://rafter.so/report/<id>."""
        data = {"scan_id": "s1", "report_id": "abc-123"}
        write_payload(data, "json")
        out = capsys.readouterr().out
        assert json.loads(out)["report_url"] == "https://rafter.so/report/abc-123"

    def test_does_not_mutate_original_data(self, capsys):
        data = {"scan_id": "s1", "report_id": "rpt-xyz"}
        write_payload(data, "json")
        capsys.readouterr()
        assert "report_url" not in data
