"""sable-j85 — CLI scan `both` engine path in agent.py.

`auto` resolves to `both` when betterleaks is usable; `_scan_file` /
`_scan_directory` then run both engines and union. Here we mock betterleaks
and let the real RegexScanner read tmp files, so the union is exercised with
genuine patterns-engine output.
"""
from __future__ import annotations

from unittest.mock import patch

from rafter_cli.commands.agent import _scan_directory, _scan_file
from rafter_cli.core.pattern_engine import Pattern, PatternMatch
from rafter_cli.scanners.regex_scanner import ScanResult


def _bl_match(name: str, match: str, line: int) -> PatternMatch:
    return PatternMatch(
        pattern=Pattern(name=name, regex="", severity="high"),
        match=match, line=line, redacted=match,
    )


def test_scan_file_both_unions_betterleaks_and_patterns(tmp_path):
    f = tmp_path / "creds.txt"
    # An AWS key the patterns engine catches but betterleaks 1.1.x misses.
    f.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

    with patch("rafter_cli.commands.agent.BetterleaksScanner") as mock_bl:
        # betterleaks finds nothing on this file (its AKIA blind spot).
        mock_bl.return_value.scan_file.return_value = ScanResult(file=str(f), matches=[])
        results = _scan_file(str(f), "both")

    all_matches = [m for r in results for m in r.matches]
    aws = [m for m in all_matches if "aws" in m.pattern.name.lower()]
    assert aws, "patterns engine must still surface the AWS key under both-mode"
    assert aws[0].engines == ["patterns"]


def test_scan_directory_both_attributes_betterleaks_only_finding(tmp_path):
    (tmp_path / "clean.txt").write_text("nothing to see\n")

    bl_only = [ScanResult(file=str(tmp_path / "x.pem"), matches=[
        _bl_match("private-key", "-----BEGIN PRIVATE KEY-----", 1),
    ])]
    with patch("rafter_cli.commands.agent.BetterleaksScanner") as mock_bl:
        mock_bl.return_value.scan_directory.return_value = bl_only
        results = _scan_directory(str(tmp_path), "both")

    matches = [m for r in results for m in r.matches]
    priv = [m for m in matches if m.pattern.name == "private-key"]
    assert priv and priv[0].engines == ["betterleaks"]


def test_scan_directory_both_degrades_when_betterleaks_errors(tmp_path):
    (tmp_path / "creds.txt").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

    with patch("rafter_cli.commands.agent.BetterleaksScanner") as mock_bl:
        mock_bl.return_value.scan_directory.side_effect = RuntimeError("boom")
        results = _scan_directory(str(tmp_path), "both")

    # patterns still runs; the AWS key is found and attributed to patterns.
    aws = [m for r in results for m in r.matches if "aws" in m.pattern.name.lower()]
    assert aws and aws[0].engines == ["patterns"]
