"""rf-zvll: the shell-route gate, and proof that its baseline is not a suppression list.

The corpus enumerates routes by which an argument reaches a shell. `executes` is
ground truth recorded by a sandboxed oracle -- bash adjudicated whether the
payload actually ran, so the corpus contains shapes nobody thought to write
down (a `trap ... EXIT`, a `bash < file`, a `>(...)`).

36 of those routes currently execute while the classifier rates them low. They
are pinned as an EXPECTED-FAILURES baseline rather than deleted or asserted as
passes: a new bypass breaks the build from day one, while the known 36 block
nobody, and every fix SHRINKS the list.

The two tests that matter are the last two. A baseline that can only grow is a
suppression list wearing a gate's clothes, so we assert both directions:
removing a row while it still disagrees must FAIL, and a fresh disagreeing row
must FAIL.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
GATE = REPO / "tools" / "shell-route-sweep" / "gate.py"
CORPUS = REPO / "rf-zvll-corpus.json"
UNDER = REPO / "rf-zvll-underblock-baseline.json"
OVER = REPO / "rf-zvll-overblock-baseline.json"
RR = REPO / "python" / "rafter_cli" / "core" / "risk_rules.py"


def _gate():
    spec = importlib.util.spec_from_file_location("gate", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _run(tmp_path, corpus=None, under=None, over=None):
    g = _gate()
    cp = tmp_path / "c.json"; cp.write_text(json.dumps(corpus or json.loads(CORPUS.read_text())))
    up = tmp_path / "u.json"; up.write_text(json.dumps(under or json.loads(UNDER.read_text())))
    op = tmp_path / "o.json"; op.write_text(json.dumps(over or json.loads(OVER.read_text())))
    return g.run(str(cp), str(RR), str(up), str(op))


def test_gate_passes_against_the_committed_baseline(tmp_path):
    r = _run(tmp_path)
    assert r["new_under"] == [], f"unbaselined under-blocks: {r['new_under'][:5]}"
    assert r["new_over"] == [], f"unbaselined over-blocks: {r['new_over'][:5]}"


def test_the_corpus_still_contains_the_known_families():
    """If the corpus loses these, the gate is guarding an empty room."""
    cmds = " ".join(r["cmd"] for r in json.loads(CORPUS.read_text())["rows"])
    assert "<(__PAYLOAD__)" in cmds                      # process substitution
    assert "| xargs bash -c" in cmds or "xargs bash" in cmds
    assert "cat {FILE}" in cmds                          # unreadable payload
    assert "trap '__PAYLOAD__' EXIT" in cmds             # deferred execution
    assert "\n__PAYLOAD__" in cmds                       # newline as separator


def test_baseline_cannot_hide_a_row_that_still_disagrees(tmp_path):
    """ASSERTION 1 — removing a row while it still disagrees must FAIL.

    Without this the baseline could be trimmed to make the gate green while the
    bypass is still live, which is the failure mode of every suppression list.
    """
    under = json.loads(UNDER.read_text())
    assert under["keys"], "baseline is empty; this test would be vacuous"
    dropped = under["keys"][0]
    under["keys"] = under["keys"][1:]
    r = _run(tmp_path, under=under)
    assert dropped in r["new_under"], (
        "dropping a still-disagreeing row from the baseline did NOT fail the gate — "
        "the baseline is a suppression list"
    )


def test_a_fresh_disagreeing_row_fails_the_gate(tmp_path):
    """ASSERTION 2 — a new bypass must break the build from day one."""
    corpus = json.loads(CORPUS.read_text())
    corpus["rows"].append({
        "key": "synthetic/new-bypass#deadbeef",
        "tag": "synthetic/new-bypass",
        # A shape that executes its payload and that the classifier does not see.
        "cmd": "trap '__PAYLOAD__' EXIT; true",
        "executes": True,
    })
    r = _run(tmp_path, corpus=corpus)
    assert "synthetic/new-bypass#deadbeef" in r["new_under"], (
        "a fresh disagreeing row did NOT fail the gate"
    )


def test_over_and_under_baselines_are_separate_files():
    """Merged, a fix could trade an under-block for an over-block silently and
    the total would not move. They have opposite urgencies; keep them apart."""
    assert UNDER.exists() and OVER.exists()
    assert set(json.loads(UNDER.read_text())["keys"]).isdisjoint(
        json.loads(OVER.read_text())["keys"]
    )
