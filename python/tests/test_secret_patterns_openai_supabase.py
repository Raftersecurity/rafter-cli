"""OpenAI + Supabase secret rules, and the runtime parity they were missing.

rf-f5is / se-wagv (external report). The hook's Write gate is regex-only, and
secret_patterns had NO OpenAI rule at all — so `sk-proj-` and legacy keys were
ALLOWED through the gate at any length, while `rafter secrets` caught them via
betterleaks. Two engines, disagreeing, and the one guarding writes was blind.
`sb_secret_` was caught by neither at any length.

Fixtures come from the SHARED rf-f5is-key-fixtures.json so both runtimes assert
on byte-identical input; the node twin is
node/tests/secret-patterns-openai-supabase.test.ts.

The keys are ASSEMBLED at runtime rather than stored literally. A file of
real-shaped keys in the repo would be flagged by rafter's own scanner — these
rules would see to that — and a fixture that trips the product's CI is a fixture
someone deletes.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from rafter_cli.scanners.regex_scanner import RegexScanner

FIXTURES = json.loads(
    (Path(__file__).resolve().parents[2] / "rf-f5is-key-fixtures.json").read_text()
)


def _build(row: dict) -> str:
    return row["prefix"] + row["fill"] * row["len"] + row["suffix"]


def _names(matches) -> set[str]:
    out = set()
    for m in matches or []:
        p = getattr(m, "pattern", None)
        out.add(p.name if p is not None else getattr(m, "name", "?"))
    return out


@pytest.mark.parametrize("row", FIXTURES, ids=[r["label"] for r in FIXTURES])
def test_shared_key_fixtures(row):
    found = _names(RegexScanner().scan_text(_build(row)))
    if row["expect"] is None:
        assert found == set(), f"{row['label']}: expected no match, got {found}"
    else:
        assert row["expect"] in found, f"{row['label']}: expected {row['expect']}, got {found}"


def test_control_an_unrelated_rule_still_fires():
    # Without this, every row above could pass with the scanner broken outright.
    found = _names(RegexScanner().scan_text('GH = "ghp_16CharsMinimumxxxxxxxxxxxxxxxxxxxxxx"'))
    assert "GitHub Personal Access Token" in found


def test_rules_are_case_sensitive():
    # These prefixes are case-sensitive, and the convention for prefixed vendor
    # tokens here (ghp_, AKIA, AIza, xox) is to match case-sensitively. An
    # uppercased prefix is not a key, and matching it would only add noise.
    assert _names(RegexScanner().scan_text("X = \"SB_SECRET_" + "A" * 32 + "\"")) == set()
