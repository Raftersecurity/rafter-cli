"""Parse unified git diff output for added/modified lines (+ side only)."""
from __future__ import annotations

import re
from dataclasses import dataclass

HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
NO_NEWLINE_RE = re.compile(r"^\\ No newline at end of file$")


@dataclass(frozen=True)
class AddedDiffLine:
    """One added line from a unified diff."""

    file: str  # repo-relative, forward slashes
    line: int  # 1-based line in the post-change file
    text: str  # content without leading '+'


def normalize_diff_path(raw: str) -> str:
    """Strip git's a/ or b/ prefix from a diff path header."""
    p = raw.strip().replace("\\", "/")
    if p.startswith("b/"):
        p = p[2:]
    elif p.startswith("a/"):
        p = p[2:]
    return p


def parse_unified_diff_added_lines(patch: str) -> list[AddedDiffLine]:
    """Extract added lines from a unified diff. Ignores context and deletions."""
    results: list[AddedDiffLine] = []
    current_file: str | None = None
    new_line = 0

    for raw_line in patch.splitlines():
        if NO_NEWLINE_RE.match(raw_line):
            continue

        if raw_line.startswith("diff --git "):
            current_file = None
            new_line = 0
            continue

        if raw_line.startswith("Binary files ") and raw_line.endswith(" differ"):
            current_file = None
            new_line = 0
            continue

        if raw_line.startswith("+++ "):
            path_part = raw_line[4:].strip()
            if path_part == "/dev/null":
                current_file = None
            else:
                current_file = normalize_diff_path(path_part)
            new_line = 0
            continue

        if raw_line.startswith("--- "):
            continue

        hunk = HUNK_HEADER_RE.match(raw_line)
        if hunk:
            new_line = int(hunk.group(1))
            continue

        if not current_file or new_line <= 0:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            results.append(
                AddedDiffLine(file=current_file, line=new_line, text=raw_line[1:])
            )
            new_line += 1
            continue

        if raw_line.startswith("-"):
            continue

        if raw_line.startswith(" "):
            new_line += 1

    return results
