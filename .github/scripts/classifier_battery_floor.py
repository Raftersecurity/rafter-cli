#!/usr/bin/env python3
"""Drift check for the command-classifier battery.

The battery and the differential catch different things, and CI needs both:

  * The DIFFERENTIAL (PR vs origin/main) catches a REGRESSION — this branch
    weaker than main. It is what a hand-written battery misses, because a
    battery only asks the questions someone thought to ask.
  * The BATTERY catches a MISSING fix and an OVER-BLOCK. It is what the
    differential misses, because a fix absent on BOTH sides is not a permissive
    *move* and shows up as nothing: the differential ran CLEAN against a branch
    that had lost a live P0 fix entirely.

That makes the battery's CONTENTS load-bearing, and a load-bearing list nobody
can see shrink is a list that will shrink. This is sable-d2x2 rule C applied to
the gate itself rather than to the suite it guards.

Three assertions:

  * the battery has not shrunk below the floor;
  * it still has rows gating the UNDER-block direction (want includes
    "critical") — the rows that catch a fix going missing;
  * it still has rows gating the OVER-block direction (want is exactly
    ["low"]) — without them, blocking everything passes the gate. #230 was an
    over-block report, so a battery with no low rows would have been happy to
    ship it.

Lower the floor in the same PR that removes cases, so a shrink is a reviewed
decision rather than an accident.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BATTERY = os.path.join(HERE, "..", "..", "rf-6pqx-newline-heredoc-battery.json")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-cases", type=int, required=True)
    ap.add_argument("--min-critical", type=int, default=15)
    ap.add_argument("--min-low", type=int, default=10)
    ap.add_argument("--battery", default=BATTERY)
    args = ap.parse_args()

    try:
        cases = json.load(open(args.battery))
    except (OSError, ValueError) as e:
        print(f"FAIL: battery unreadable at {args.battery}: {e}")
        return 1

    if not isinstance(cases, list) or not cases:
        print(
            "FAIL: battery is not a non-empty list — a gate with no cases "
            "passes everything, which is worse than no gate at all"
        )
        return 1

    critical = [c for c in cases if "critical" in c.get("want", [])]
    low = [c for c in cases if c.get("want") == ["low"]]

    failures = []
    if len(cases) < args.min_cases:
        failures.append(
            f"battery shrank: {len(cases)} cases, floor is {args.min_cases}. "
            "If cases were removed on purpose, lower the floor in the same PR."
        )
    if len(critical) < args.min_critical:
        failures.append(
            f"only {len(critical)} rows gate the under-block direction "
            f"(want includes 'critical'), floor is {args.min_critical}. Those "
            "are the rows that catch a fix going missing."
        )
    if len(low) < args.min_low:
        failures.append(
            f"only {len(low)} rows gate the over-block direction "
            f"(want is exactly ['low']), floor is {args.min_low}. Without "
            "those, blocking everything passes the gate."
        )

    # A malformed row is a row that cannot fail. Catch it here rather than
    # letting a harness quietly skip it.
    for i, c in enumerate(cases):
        if not isinstance(c.get("cmd"), str) or not c["cmd"]:
            failures.append(f"case {i} ({c.get('label', '?')!r}) has no command")
        want = c.get("want")
        if not isinstance(want, list) or not want:
            failures.append(f"case {i} ({c.get('label', '?')!r}) has no expectations")

    if failures:
        print("FAIL: command-classifier battery drift")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(
        f"PASS: battery has {len(cases)} cases "
        f"({len(critical)} gate under-blocking, {len(low)} gate over-blocking)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
