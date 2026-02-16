"""Regex-based secret scanner."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ..core.pattern_engine import Pattern, PatternEngine, PatternMatch
from .secret_patterns import DEFAULT_SECRET_PATTERNS


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
        patterns: list[Pattern] = list(DEFAULT_SECRET_PATTERNS)
        if custom_patterns:
            for cp in custom_patterns:
                patterns.append(Pattern(
                    name=cp.get("name", "Custom"),
                    regex=cp.get("regex", ""),
                    severity=cp.get("severity", "high"),
                ))
        self._engine = PatternEngine(patterns)

    def scan_file(self, file_path: str) -> ScanResult:
        try:
            content = Path(file_path).read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
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
    ) -> list[ScanResult]:
        exclude = list(DEFAULT_EXCLUDE)
        if exclude_paths:
            for ep in exclude_paths:
                cleaned = ep.rstrip("/")
                if cleaned not in exclude:
                    exclude.append(cleaned)

        files = self._walk(dir_path, exclude, max_depth)
        return self.scan_files(files)

    def scan_text(self, text: str) -> list[PatternMatch]:
        return self._engine.scan(text)

    def redact(self, text: str) -> str:
        return self._engine.redact_text(text)

    def has_secrets(self, text: str) -> bool:
        return self._engine.has_matches(text)

    # ------------------------------------------------------------------

    @staticmethod
    def _walk(directory: str, exclude: list[str], max_depth: int, depth: int = 0) -> list[str]:
        if depth >= max_depth:
            return []
        files: list[str] = []
        try:
            for entry in os.scandir(directory):
                if entry.name in exclude:
                    continue
                if entry.is_dir(follow_symlinks=False):
                    files.extend(RegexScanner._walk(entry.path, exclude, max_depth, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    ext = os.path.splitext(entry.name)[1].lower()
                    if ext not in BINARY_EXTENSIONS:
                        files.append(entry.path)
        except PermissionError:
            pass
        return files
