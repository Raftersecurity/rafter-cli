"""Regex-based secret scanner."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..core.pattern_engine import Pattern, PatternEngine, PatternMatch
from .secret_patterns import DEFAULT_SECRET_PATTERNS
from ..core.custom_patterns import load_custom_patterns


@dataclass
class ScanResult:
    file: str
    matches: list[PatternMatch] = field(default_factory=list)


BINARY_EXTENSIONS = frozenset([
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".avi", ".mov",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".class", ".o", ".a",
])

DEFAULT_EXCLUDE = [
    "node_modules", ".git", "dist", "build",
    ".next", "coverage", ".vscode", ".idea",
    "__pycache__", ".mypy_cache", ".ruff_cache",
]


class RegexScanner:
    def __init__(self, custom_patterns: list[dict] | None = None):
        patterns: list[Pattern] = list(DEFAULT_SECRET_PATTERNS) + load_custom_patterns()
        if custom_patterns:
            for cp in custom_patterns:
                patterns.append(Pattern(
                    name=cp.get("name", "Custom"),
                    regex=cp.get("regex", ""),
                    severity=cp.get("severity", "high"),
                ))
        self._engine = PatternEngine(patterns)
        self._skipped: list[dict[str, str]] = []

    def scan_file(self, file_path: str) -> ScanResult:
        # Suppression is applied at the scan command boundary (engine-agnostic).
        try:
            content = Path(file_path).read_text(errors="ignore")
        except (OSError, UnicodeDecodeError) as exc:
            # A path we could not read is NOT a path with no secrets in it.
            # Record it so the caller can say so; an empty match list on its
            # own is indistinguishable from a clean file.
            self._skipped.append(
                {"path": file_path, "reason": getattr(exc, "strerror", None) or type(exc).__name__}
            )
            return ScanResult(file=file_path)
        matches = self._engine.scan_with_position(content)
        return ScanResult(file=file_path, matches=matches)

    def scan_files(self, file_paths: list[str]) -> list[ScanResult]:
        results: list[ScanResult] = []
        for fp in file_paths:
            r = self.scan_file(fp)
            if r.matches:
                results.append(r)
        return results

    def scan_directory(
        self,
        dir_path: str,
        exclude_paths: list[str] | None = None,
        max_depth: int = 10,
        respect_gitignore: bool = True,
    ) -> list[ScanResult]:
        exclude = list(DEFAULT_EXCLUDE)
        if exclude_paths:
            for ep in exclude_paths:
                cleaned = ep.rstrip("/")
                if cleaned not in exclude:
                    exclude.append(cleaned)

        files = self._walk(dir_path, exclude, max_depth)
        if respect_gitignore:
            files = _filter_gitignored(files, dir_path)
        return self.scan_files(files)

    def scan_text(self, text: str) -> list[PatternMatch]:
        return self._engine.scan(text)

    def scan_line(self, text: str, line_number: int) -> list[PatternMatch]:
        """Scan a single line at a known file line number (git diff + side)."""
        return [
            PatternMatch(
                pattern=m.pattern,
                match=m.match,
                line=line_number,
                column=m.column,
                redacted=m.redacted,
                engines=m.engines,
            )
            for m in self._engine.scan_with_position(text)
        ]

    def redact(self, text: str) -> str:
        return self._engine.redact_text(text)

    def has_secrets(self, text: str) -> bool:
        return self._engine.has_matches(text)

    # ------------------------------------------------------------------

    def take_skipped(self) -> list[dict[str, str]]:
        """Paths this scanner could not read, drained (and cleared) by the caller.

        Both skip sites — an unreadable file and an unreadable directory — used
        to be silent, so ``rafter secrets <unreadable>`` returned exit 0 with
        empty results, byte-identical to a genuinely clean scan. The directory
        a scanner cannot enter is exactly where an unnoticed credential is most
        likely to be.
        """
        out = self._skipped
        self._skipped = []
        return out

    def _walk(self, directory: str, exclude: list[str], max_depth: int, depth: int = 0) -> list[str]:
        if depth >= max_depth:
            return []
        files: list[str] = []
        try:
            for entry in os.scandir(directory):
                if entry.name in exclude:
                    continue
                # Skip symlinks to prevent traversal outside intended scope
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    files.extend(self._walk(entry.path, exclude, max_depth, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    ext = os.path.splitext(entry.name)[1].lower()
                    if ext not in BINARY_EXTENSIONS:
                        files.append(entry.path)
        except PermissionError as exc:
            # A directory we can't read is not an empty directory — record it
            # so the caller can report coverage honestly.
            self._skipped.append(
                {"path": directory, "reason": getattr(exc, "strerror", None) or "PermissionError"}
            )
        return files


def _filter_gitignored(files: list[str], scan_root: str) -> list[str]:
    """Drop files git would ignore relative to ``scan_root``.

    Shells out to ``git check-ignore --stdin --no-index -z`` inside the scan
    root's work tree so every gitignore semantic git supports (nested
    .gitignores, negations, .git/info/exclude, the configured global excludes
    file, the full pattern grammar) is honored exactly. Zero new
    dependencies. Bails out silently — returning the input unchanged — when
    git is missing or the scan root sits outside a work tree.
    """
    if not files:
        return files
    # Locate the work tree that owns scan_root.
    try:
        probe = subprocess.run(
            ["git", "-C", scan_root, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return files
    if probe.returncode != 0:
        return files
    work_tree = probe.stdout.strip()
    if not work_tree:
        return files

    # Batch every candidate through one `git check-ignore --stdin` call.
    # Null-delimited I/O preserves paths containing newlines / spaces.
    stdin = ("\0".join(files) + "\0").encode("utf-8")
    try:
        result = subprocess.run(
            ["git", "-C", work_tree, "check-ignore", "--stdin", "--no-index", "-z"],
            input=stdin,
            capture_output=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return files
    # Exit codes: 0 = at least one path ignored; 1 = none; 128 = error.
    # Anything else => abandon the filter rather than break the scan.
    if result.returncode not in (0, 1):
        return files
    ignored = {p.decode("utf-8") for p in result.stdout.split(b"\0") if p}
    if not ignored:
        return files
    return [f for f in files if f not in ignored]
