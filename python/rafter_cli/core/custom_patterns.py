"""Load custom secret patterns from ~/.rafter/patterns/ and suppression rules from .rafterignore."""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config_schema import get_rafter_dir
from ..core.pattern_engine import Pattern


# ---------------------------------------------------------------------------
# Custom pattern loading
# ---------------------------------------------------------------------------

def load_custom_patterns() -> list[Pattern]:
    """Load user-defined patterns from ~/.rafter/patterns/*.txt and *.json.

    .txt  — one regex per line (lines starting with # are comments)
    .json — array of {name, pattern, severity?} objects
    """
    patterns_dir = get_rafter_dir() / "patterns"
    if not patterns_dir.is_dir():
        return []

    results: list[Pattern] = []
    for entry in sorted(patterns_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix == ".txt":
            results.extend(_load_txt(entry))
        elif entry.suffix == ".json":
            results.extend(_load_json(entry))
    return results


def _load_txt(path: Path) -> list[Pattern]:
    try:
        patterns: list[Pattern] = []
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(Pattern(
                name=f"Custom ({path.stem})",
                regex=line,
                severity="high",
            ))
        return patterns
    except OSError:
        return []


_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _load_json(path: Path) -> list[Pattern]:
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, list):
            return []
        patterns: list[Pattern] = []
        for entry in data:
            if not isinstance(entry.get("pattern"), str) or not entry["pattern"]:
                continue
            try:
                re.compile(entry["pattern"])
            except re.error:
                print(f"Warning: skipping custom pattern in {path.name} — invalid regex: {entry['pattern']}", file=sys.stderr)
                continue
            severity = entry.get("severity", "high")
            if severity not in _VALID_SEVERITIES:
                print(f"Warning: skipping custom pattern in {path.name} — invalid severity: {severity}", file=sys.stderr)
                continue
            patterns.append(Pattern(
                name=entry.get("name", f"Custom ({path.stem})"),
                regex=entry["pattern"],
                severity=severity,
                description=entry.get("description"),
            ))
        return patterns
    except (OSError, json.JSONDecodeError, KeyError):
        return []


# ---------------------------------------------------------------------------
# .rafterignore suppression
# ---------------------------------------------------------------------------

@dataclass
class Suppression:
    path_glob: str
    pattern_name: Optional[str] = None
    reason: Optional[str] = None
    source: str = ".rafterignore"


@dataclass
class SuppressedFinding:
    file: str
    line: Optional[int]
    column: Optional[int]
    rule: str
    severity: str
    reason: Optional[str]
    source: str


def load_suppressions(project_root: str | Path | None = None) -> list[Suppression]:
    """Parse .rafterignore from project_root (defaults to cwd).

    Format — one entry per line:
        path/glob                 → suppress all findings in matching files
        path/glob:pattern-name    → suppress specific pattern in matching files

    Lines starting with # are comments.
    """
    root = Path(project_root) if project_root else Path.cwd()
    ignore_file = root / ".rafterignore"
    if not ignore_file.exists():
        return []

    suppressions: list[Suppression] = []
    try:
        for raw in ignore_file.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            colon = line.find(":")
            if colon == -1:
                suppressions.append(Suppression(path_glob=line, source=".rafterignore"))
            else:
                suppressions.append(Suppression(
                    path_glob=line[:colon].strip(),
                    pattern_name=line[colon + 1:].strip() or None,
                    source=".rafterignore",
                ))
    except OSError:
        pass
    return suppressions


def policy_ignore_to_suppressions(rules) -> list[Suppression]:
    """Flatten ScanIgnoreRule[] into Suppression[] (cross-product paths × rules)."""
    if not rules:
        return []
    out: list[Suppression] = []
    for rule in rules:
        paths = getattr(rule, "paths", None) or (rule.get("paths") if isinstance(rule, dict) else None)
        if not paths:
            continue
        rule_names = getattr(rule, "rules", None) if not isinstance(rule, dict) else rule.get("rules")
        reason = getattr(rule, "reason", None) if not isinstance(rule, dict) else rule.get("reason")
        names_iter = list(rule_names) if rule_names else [None]
        for path_glob in paths:
            for name in names_iter:
                out.append(Suppression(
                    path_glob=path_glob,
                    pattern_name=name,
                    reason=reason,
                    source=".rafter.yml",
                ))
    return out


def find_suppression(file_path: str, pattern_name: str, suppressions: list[Suppression]) -> Optional[Suppression]:
    """Return the first matching suppression, or None. First-match wins."""
    for s in suppressions:
        if _match_glob(s.path_glob, file_path):
            if s.pattern_name is None or s.pattern_name.lower() == pattern_name.lower():
                return s
    return None


def is_suppressed(file_path: str, pattern_name: str, suppressions: list[Suppression]) -> bool:
    """Return True if this finding should be suppressed."""
    return find_suppression(file_path, pattern_name, suppressions) is not None


def apply_suppressions(results, suppressions: list[Suppression]):
    """Split a list of ScanResult-like records into kept + suppressed findings.

    Each result must have `.file` and `.matches` (list of PatternMatch).
    Returns (filtered_results, suppressed_list).
    """
    if not suppressions:
        return results, []
    suppressed: list[SuppressedFinding] = []
    filtered = []
    for r in results:
        kept = []
        for m in r.matches:
            hit = find_suppression(r.file, m.pattern.name, suppressions)
            if hit is not None:
                suppressed.append(SuppressedFinding(
                    file=r.file,
                    line=m.line,
                    column=m.column,
                    rule=m.pattern.name,
                    severity=m.pattern.severity,
                    reason=hit.reason,
                    source=hit.source,
                ))
            else:
                kept.append(m)
        if kept:
            # Preserve original type by mutating a copy
            r_copy = type(r)(file=r.file, matches=kept)
            filtered.append(r_copy)
    return filtered, suppressed


def _match_glob(glob_pattern: str, file_path: str) -> bool:
    """Match a file path against a glob pattern.

    Uses fnmatch.fnmatch for well-tested glob semantics. Patterns without
    a path separator are matched against the basename so e.g. "*.env"
    matches "config/.env". Relative path-globs like "tests/fixtures/**"
    are auto-anchored to match anywhere in the path so they line up with
    absolute scan paths.
    """
    g = glob_pattern.replace("\\", "/")
    f = file_path.replace("\\", "/")

    # Bare basename pattern — match against the file basename.
    if "/" not in g:
        return fnmatch.fnmatch(f.rsplit("/", 1)[-1], g)

    # Translate `**` (recursive) for fnmatch — fnmatch only supports `*`/`?`.
    # Rewrite "tests/fixtures/**" → check via `tests/fixtures/*` over each path
    # prefix. Cheaper: try "in path" check.
    if _glob_in_path(g, f):
        return True

    # Auto-anchor to "anywhere in the path" if user didn't already anchor.
    if g.startswith("/") or g.startswith("**/") or g.startswith("**"):
        return False
    return _glob_in_path(g, f, anchored_anywhere=True)


def _glob_in_path(pattern: str, path: str, anchored_anywhere: bool = False) -> bool:
    """Translate `**` to `.*` and use a regex match on the path.

    This is a small subset of glob with `**` recursion that fnmatch lacks.
    """
    pat = pattern
    if anchored_anywhere:
        pat = "**/" + pat
    # Convert glob to regex piece-by-piece. Keep it deliberately simple — we
    # only need `**`, `*`, and `?` semantics for path matching.
    regex = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*" and i + 1 < len(pat) and pat[i + 1] == "*":
            # `**` — match across path segments
            regex.append(".*")
            i += 2
            # Consume optional trailing slash to allow "**/foo" patterns
            if i < len(pat) and pat[i] == "/":
                i += 1
        elif c == "*":
            regex.append("[^/]*")
            i += 1
        elif c == "?":
            regex.append("[^/]")
            i += 1
        elif c in ".+()|^$":
            regex.append(re.escape(c))
            i += 1
        else:
            regex.append(c)
            i += 1
    return re.fullmatch("".join(regex), path) is not None
