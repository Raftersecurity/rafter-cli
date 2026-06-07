"""Tests for the betterleaks+patterns union (sable-j85).

Mirror of node/tests/union.test.ts — covers the dedup key
(file, line, matched-text), engine attribution, and deterministic ordering.
"""
from __future__ import annotations

from rafter_cli.core.pattern_engine import Pattern, PatternMatch
from rafter_cli.scanners.regex_scanner import ScanResult
from rafter_cli.scanners.union import union_scan_results


def _m(name: str, match: str, line: int, column: int | None = None) -> PatternMatch:
    return PatternMatch(
        pattern=Pattern(name=name, regex="", severity="high"),
        match=match,
        line=line,
        column=column,
        redacted=match,
    )


def test_keeps_engine_unique_findings_and_attributes_each():
    bl = [ScanResult(file="a.env", matches=[_m("private-key", "KEY", 2)])]
    pat = [ScanResult(file="b.txt", matches=[_m("AWS Access Key ID", "AKIA...", 1)])]

    out = union_scan_results(bl, pat)

    assert [r.file for r in out] == ["a.env", "b.txt"]
    assert out[0].matches[0].engines == ["betterleaks"]
    assert out[1].matches[0].engines == ["patterns"]


def test_dedups_a_secret_both_engines_report_and_keeps_betterleaks_match():
    bl = [ScanResult(file="a.env", matches=[_m("private-key", "SAME", 5)])]
    pat = [ScanResult(file="a.env", matches=[_m("Private Key", "SAME", 5)])]

    out = union_scan_results(bl, pat)

    assert len(out) == 1
    assert len(out[0].matches) == 1
    # betterleaks rule-id format wins.
    assert out[0].matches[0].pattern.name == "private-key"
    assert out[0].matches[0].engines == ["betterleaks", "patterns"]


def test_does_not_dedup_same_text_on_different_lines():
    bl = [ScanResult(file="a.env", matches=[_m("k", "DUP", 1)])]
    pat = [ScanResult(file="a.env", matches=[_m("k", "DUP", 2)])]

    out = union_scan_results(bl, pat)

    assert len(out[0].matches) == 2


def test_does_not_dedup_same_text_line_at_different_columns():
    # e.g. `K1=AKIA... K2=AKIA...` — same token pasted twice on one line.
    bl = [ScanResult(file="a.env", matches=[_m("k", "AKIA", 1, 4)])]
    pat = [ScanResult(file="a.env", matches=[_m("k", "AKIA", 1, 20)])]

    out = union_scan_results(bl, pat)

    assert len(out[0].matches) == 2


def test_merges_into_one_file_group_betterleaks_first():
    bl = [ScanResult(file="a.env", matches=[_m("bl-only", "X", 1)])]
    pat = [ScanResult(file="a.env", matches=[_m("pat-only", "Y", 2)])]

    out = union_scan_results(bl, pat)

    assert len(out) == 1
    assert [m.pattern.name for m in out[0].matches] == ["bl-only", "pat-only"]


def test_empty_when_neither_engine_finds_anything():
    assert union_scan_results([], []) == []


def test_does_not_mutate_input_matches():
    src = _m("k", "V", 1)
    bl = [ScanResult(file="a.env", matches=[src])]
    union_scan_results(bl, [])
    # dataclasses.replace must produce a copy — the original stays unattributed.
    assert src.engines is None
