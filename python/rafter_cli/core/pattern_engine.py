"""Regex pattern engine for secret detection."""
from __future__ import annotations

import re
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


class PatternEngine:
    def __init__(self, patterns: Sequence[Pattern]):
        self._patterns = list(patterns)

    def scan(self, text: str) -> list[PatternMatch]:
        """Scan text for pattern matches (no line info)."""
        matches: list[PatternMatch] = []
        for pattern in self._patterns:
            compiled = self._compile(pattern.regex)
            if compiled is None:
                continue
            for m in compiled.finditer(text):
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
            for pattern in self._patterns:
                compiled = self._compile(pattern.regex)
                if compiled is None:
                    continue
                for m in compiled.finditer(line):
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
        for pattern in self._patterns:
            compiled = self._compile(pattern.regex)
            if compiled is None:
                continue
            result = compiled.sub(lambda m: self._redact(m.group(0)), result)
        return result

    def has_matches(self, text: str) -> bool:
        return len(self.scan(text)) > 0

    # ------------------------------------------------------------------

    @staticmethod
    def _compile(regex_str: str) -> re.Pattern | None:
        flags = 0
        pattern = regex_str
        if pattern.startswith("(?i)"):
            flags |= re.IGNORECASE
            pattern = pattern[4:]
        try:
            return re.compile(pattern, flags)
        except re.error:
            return None

    @staticmethod
    def _redact(match: str) -> str:
        if len(match) < 16:
            return "*" * len(match)
        visible = 4
        return match[:visible] + "*" * (len(match) - visible * 2) + match[-visible:]
