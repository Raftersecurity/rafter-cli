"""Regex pattern engine for secret detection."""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Sequence


@dataclass
class Pattern:
    name: str
    regex: str
    severity: str  # low | medium | high | critical
    description: str = ""


@dataclass
class PatternMatch:
    pattern: Pattern
    match: str
    line: int | None = None
    column: int | None = None
    redacted: str = ""


_GENERIC_PATTERN_NAMES = frozenset({"Generic API Key", "Generic Secret"})

_VARIABLE_NAME_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_LOWERCASE_IDENT_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
_QUOTED_VALUE_RE = re.compile(r"""['\"]([^'\"]+)['\"]""")


class PatternEngine:
    def __init__(self, patterns: Sequence[Pattern]):
        self._patterns = list(patterns)
        # Compile each pattern's regex once. Malformed patterns are skipped
        # with a stderr warning so a single bad regex can't take down the engine.
        self._compiled: list[tuple[Pattern, re.Pattern[str]]] = []
        for pattern in self._patterns:
            compiled = self._compile(pattern.regex)
            if compiled is None:
                continue
            self._compiled.append((pattern, compiled))

    def scan(self, text: str) -> list[PatternMatch]:
        """Scan text for pattern matches (no line info)."""
        matches: list[PatternMatch] = []
        for pattern, compiled in self._compiled:
            for m in compiled.finditer(text):
                if self._is_false_positive(pattern, m.group(0)):
                    continue
                matches.append(PatternMatch(
                    pattern=pattern,
                    match=m.group(0),
                    redacted=self._redact(m.group(0)),
                ))
        return matches

    def scan_with_position(self, text: str) -> list[PatternMatch]:
        """Scan text with line/column information."""
        matches: list[PatternMatch] = []
        for line_num, line in enumerate(text.split("\n"), start=1):
            for pattern, compiled in self._compiled:
                for m in compiled.finditer(line):
                    if self._is_false_positive(pattern, m.group(0)):
                        continue
                    matches.append(PatternMatch(
                        pattern=pattern,
                        match=m.group(0),
                        line=line_num,
                        column=m.start() + 1,
                        redacted=self._redact(m.group(0)),
                    ))
        return matches

    def redact_text(self, text: str) -> str:
        """Replace all pattern matches in *text* with redacted versions."""
        result = text
        for pattern, compiled in self._compiled:
            result = compiled.sub(
                lambda m, p=pattern: m.group(0) if self._is_false_positive(p, m.group(0)) else self._redact(m.group(0)),
                result,
            )
        return result

    def has_matches(self, text: str) -> bool:
        return len(self.scan(text)) > 0

    # ------------------------------------------------------------------

    @staticmethod
    def _is_false_positive(pattern: Pattern, match_text: str) -> bool:
        """Return True if match looks like a variable name rather than a real secret."""
        if pattern.name not in _GENERIC_PATTERN_NAMES:
            return False
        m = _QUOTED_VALUE_RE.search(match_text)
        if not m:
            return False
        value = m.group(1)
        if _VARIABLE_NAME_RE.match(value):
            return True
        if _LOWERCASE_IDENT_RE.match(value):
            return True
        return False

    @staticmethod
    def _compile(regex_str: str) -> re.Pattern[str] | None:
        flags = 0
        pattern = regex_str
        if pattern.startswith("(?i)"):
            flags |= re.IGNORECASE
            pattern = pattern[4:]
        try:
            return re.compile(pattern, flags)
        except re.error:
            # Skip malformed patterns rather than crashing the engine
            print(f"Invalid regex pattern: {regex_str}", file=sys.stderr)
            return None

    @staticmethod
    def _redact(match: str) -> str:
        if len(match) <= 8:
            return "*" * len(match)
        visible = 4
        return match[:visible] + "*" * (len(match) - visible * 2) + match[-visible:]
