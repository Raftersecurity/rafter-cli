"""issue #231 item 6 — `rafter secrets .` printed `(both)` for the engine
label with no explanation of what "both" means. The label must name the
two engines; single-engine values are already self-explanatory and pass
through unchanged.
"""
from __future__ import annotations

from rafter_cli.commands.agent import _engine_label


def test_names_both_engines_instead_of_the_bare_word_both():
    label = _engine_label("both")
    assert "betterleaks" in label
    assert "patterns" in label
    assert label != "both"


def test_leaves_single_engine_values_unchanged():
    assert _engine_label("betterleaks") == "betterleaks"
    assert _engine_label("patterns") == "patterns"
