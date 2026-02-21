"""Load custom secret patterns from ~/.rafter/patterns/ and suppression rules from .rafterignore."""
from __future__ import annotations

import json
import os
import re
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


def _load_json(path: Path) -> list[Pattern]:
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, list):
            return []
        patterns: list[Pattern] = []
        for entry in data:
            if not isinstance(entry.get("pattern"), str):
                continue
            patterns.append(Pattern(
                name=entry.get("name", f"Custom ({path.stem})"),
                regex=entry["pattern"],
                severity=entry.get("severity", "high"),
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
                suppressions.append(Suppression(path_glob=line))
            else:
                suppressions.append(Suppression(
                    path_glob=line[:colon].strip(),
                    pattern_name=line[colon + 1:].strip() or None,
                ))
    except OSError:
        pass
    return suppressions


def is_suppressed(file_path: str, pattern_name: str, suppressions: list[Suppression]) -> bool:
    """Return True if this finding should be suppressed."""
    for s in suppressions:
        if _match_glob(s.path_glob, file_path):
            if s.pattern_name is None or s.pattern_name.lower() == pattern_name.lower():
                return True
    return False


def _match_glob(glob: str, file_path: str) -> bool:
    """Minimal glob matcher: supports * (within segment) and ** (cross-segment)."""
    g = glob.replace("\\", "/")
    f = file_path.replace("\\", "/")

    # Escape regex special chars except * which we handle
    escaped = re.escape(g)
    # re.escape turns * into \* — undo that for our glob handling
    escaped = escaped.replace(r"\*\*", "\x00").replace(r"\*", "[^/]*").replace("\x00", ".*")

    try:
        return bool(re.search(rf"(^|/){escaped}(/|$)", f))
    except re.error:
        return False
