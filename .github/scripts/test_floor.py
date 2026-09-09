#!/usr/bin/env python3
"""Fail CI when the test suite quietly shrinks or a file's tests all skip.

sable-d2x2 detection rule C ("assert non-emptiness"). Two ways a green run can
be vacuous that the runner's own exit code does not catch:

  1. A whole file's tests are skipped. sable-cazq: 40 parity tests were
     `describe.skip`'d because Python was missing, and the release path exited
     0. A total-count floor does NOT catch this (2112 - 40 is still a big
     number); a per-file "every test skipped" rule does.
  2. The suite shrinks sharply: a config change, a renamed directory, a broken
     glob, and the runner cheerfully runs the 30 tests it found.

Reads a vitest JSON report (--vitest) or a pytest JUnit XML written with
`-o junit_family=xunit1` (--junit; xunit1 is what carries the per-test `file`
attribute). Exits 1 when:

  * executed tests (passed + failed) < --min-executed, or
  * any file has >= 1 test and every one of them was skipped, unless that
    file is listed in --allow-all-skipped (a visible, reviewed exception).

Always writes the executed / skipped counts and every skipped test's name to
$GITHUB_STEP_SUMMARY when set, so a skip is never invisible even when it is
allowed. Stdlib only: this runs before any project dependency is guaranteed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

SKIPPED_STATES = {"skipped", "pending", "todo", "disabled"}


def read_vitest(path: str) -> dict[str, dict[str, list[str]]]:
    """{file: {"executed": [names], "skipped": [names]}} from a vitest JSON report."""
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    files: dict[str, dict[str, list[str]]] = {}
    cwd = os.getcwd() + os.sep
    for result in report.get("testResults", []):
        name = result.get("name", "")
        rel = name[len(cwd):] if name.startswith(cwd) else name
        bucket = files.setdefault(rel, {"executed": [], "skipped": []})
        for case in result.get("assertionResults", []):
            title = case.get("fullName") or case.get("title") or "<unnamed>"
            state = case.get("status", "")
            (bucket["skipped"] if state in SKIPPED_STATES else bucket["executed"]).append(title)
    return files


def read_junit(path: str) -> dict[str, dict[str, list[str]]]:
    """Same shape from a pytest JUnit XML (xunit1 family, which carries `file`)."""
    root = ET.parse(path).getroot()
    files: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"executed": [], "skipped": []})
    missing_file_attr = 0
    for case in root.iter("testcase"):
        file_attr = case.get("file")
        if not file_attr:
            missing_file_attr += 1
            # xunit2 drops `file`; fall back to the module part of classname so
            # the per-file rule still has something to group by.
            classname = case.get("classname", "")
            parts = [p for p in classname.split(".") if p and not p[:1].isupper()]
            file_attr = "/".join(parts) + ".py" if parts else "<unknown>"
        title = f'{case.get("classname", "")}::{case.get("name", "")}'
        skipped = case.find("skipped") is not None
        (files[file_attr]["skipped"] if skipped else files[file_attr]["executed"]).append(title)
    if missing_file_attr:
        print(
            f"::warning::{missing_file_attr} testcase(s) had no `file` attribute; "
            "run pytest with `-o junit_family=xunit1` for exact per-file grouping.",
            flush=True,
        )
    return dict(files)


def summarize(label: str, files: dict[str, dict[str, list[str]]], executed: int,
              skipped: int, min_executed: int, all_skipped: list[str],
              allowed: set[str]) -> str:
    lines = [f"### Test floor — {label}", ""]
    lines.append("| Executed | Skipped | Floor | Files |")
    lines.append("|---------:|--------:|------:|------:|")
    lines.append(f"| {executed} | {skipped} | {min_executed} | {len(files)} |")
    lines.append("")
    if all_skipped:
        lines.append("**Files with every test skipped:**")
        for f in all_skipped:
            tag = " (allowed by --allow-all-skipped)" if f in allowed else " **← FAIL**"
            lines.append(f"- `{f}`{tag}")
        lines.append("")
    if skipped:
        lines.append("<details><summary>Skipped tests</summary>")
        lines.append("")
        for f, bucket in sorted(files.items()):
            for name in bucket["skipped"]:
                lines.append(f"- `{f}` — {name}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--vitest", help="vitest JSON report (--reporter=json)")
    src.add_argument("--junit", help="pytest JUnit XML (-o junit_family=xunit1 --junitxml=...)")
    ap.add_argument("--min-executed", type=int, required=True,
                    help="fail if fewer than this many tests actually ran (passed + failed)")
    ap.add_argument("--allow-all-skipped", default="",
                    help="comma-separated files allowed to have every test skipped")
    ap.add_argument("--label", default=None, help="label for the step summary")
    args = ap.parse_args(argv)

    if args.vitest:
        files = read_vitest(args.vitest)
        label = args.label or "vitest"
    else:
        files = read_junit(args.junit)
        label = args.label or "pytest"

    allowed = {f.strip() for f in args.allow_all_skipped.split(",") if f.strip()}
    executed = sum(len(b["executed"]) for b in files.values())
    skipped = sum(len(b["skipped"]) for b in files.values())
    all_skipped = sorted(f for f, b in files.items() if b["skipped"] and not b["executed"])
    offending = [f for f in all_skipped if f not in allowed]

    summary = summarize(label, files, executed, skipped, args.min_executed, all_skipped, allowed)
    print(summary, flush=True)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")

    failed = False
    if not files:
        print(f"::error::{label}: the report lists no test files at all — nothing ran.", flush=True)
        failed = True
    if executed < args.min_executed:
        print(
            f"::error::{label}: only {executed} tests executed, floor is {args.min_executed}. "
            "If tests were deliberately removed, lower the floor in the workflow in the same PR "
            "so the shrink is a reviewed decision, not a silent one.",
            flush=True,
        )
        failed = True
    for f in offending:
        print(
            f"::error::{label}: every test in {f} was skipped ({len(files[f]['skipped'])} tests). "
            "A file that runs nothing is a broken prerequisite, not a passing file. Fix the "
            "prerequisite, or list the file in --allow-all-skipped with a reason in the workflow.",
            flush=True,
        )
        failed = True
    if not failed:
        allowed_note = (
            f", {len(all_skipped)} fully-skipped file(s) on the allow-list" if all_skipped
            else ", no file fully skipped"
        )
        print(f"OK: {label}: {executed} executed (floor {args.min_executed}), "
              f"{skipped} skipped{allowed_note}.", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
