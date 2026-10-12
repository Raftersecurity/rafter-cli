"""Union betterleaks + patterns findings for auto-mode scans (sable-j85).

Mirror of ``node/src/scanners/union.ts``. ``auto`` mode now runs BOTH engines
because each misses what the other catches: betterleaks 1.1.x does not detect
AWS access keys (sable-h2y), while the regex patterns lack betterleaks's
entropy/context heuristics. Running only one silently degrades coverage; the
union restores it.
"""
from __future__ import annotations

import dataclasses

from ..core.pattern_engine import PatternMatch
from .regex_scanner import ScanResult


def union_scan_results(
    betterleaks: list[ScanResult],
    patterns: list[ScanResult],
) -> list[ScanResult]:
    """Merge two engines' findings into one result set.

    Dedup: two findings are "the same secret" when they share
    ``(file, line, column, matched-text)``. The key is deliberately
    conservative — it errs toward keeping both findings rather than collapsing
    two genuinely distinct secrets (e.g. the same token value pasted twice on
    one line at different columns), because dropping a real finding is a
    security regression for a scanner. The flip side: when the two engines
    extract slightly different text/columns for the same secret it is reported
    twice (once per engine) rather than merged — safe over-reporting, not a
    miss. When both engines DO agree on ``(line, column, text)`` we keep the
    betterleaks match — its ``RuleID``-style ``pattern.name`` is the canonical
    id — and record both engines in ``engines``. Ordering is deterministic:
    betterleaks findings first (in betterleaks's own order), then any
    patterns-only findings, grouped by the file each first appeared in.
    """
    file_order: list[str] = []
    by_file: dict[str, dict[str, PatternMatch]] = {}

    def ingest(results: list[ScanResult], engine: str) -> None:
        for r in results:
            file_map = by_file.get(r.file)
            if file_map is None:
                file_map = {}
                by_file[r.file] = file_map
                file_order.append(r.file)
            for m in r.matches:
                # Two secrets cannot start at the same line and column, so a
                # known position alone identifies the secret: the engines
                # extract different text for it (betterleaks a whole PEM
                # block, the regex pattern only its header). Without a
                # position, fall back to the matched text.
                if m.line is not None and m.column is not None:
                    key = f"{m.line} {m.column}"
                else:
                    key = f"{m.line} {m.column} {m.match}"
                existing = file_map.get(key)
                if existing is not None:
                    if engine not in existing.engines:
                        existing.engines.append(engine)
                else:
                    file_map[key] = dataclasses.replace(m, engines=[engine])

    ingest(betterleaks, "betterleaks")
    ingest(patterns, "patterns")

    return [
        ScanResult(file=f, matches=list(by_file[f].values()))
        for f in file_order
    ]
