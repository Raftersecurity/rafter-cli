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
    # Which scan engine(s) surfaced this finding (sable-j85). Set only when a
    # scan runs more than one engine (``auto`` mode → ``both``). Single-engine
    # scans leave it None — the engine is already implied by ``--engine``.
    engines: list[str] | None = None


_GENERIC_PATTERN_NAMES = frozenset({"Generic API Key", "Generic Secret"})

_VARIABLE_NAME_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_LOWERCASE_IDENT_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
_QUOTED_VALUE_RE = re.compile(r"""['\"]([^'\"]+)['\"]""")

# Matches an environment-assignment prefix in a command line: an identifier
# followed immediately by ``=`` and a run of non-whitespace (the value). Used
# to find ``NAME=VALUE`` tokens like ``RAFTER_API_KEY=<secret> rafter ...`` so
# their value can be redacted before the command is written to the audit log.
_ENV_ASSIGN_RE = re.compile(r"(^|\s)([A-Za-z_][A-Za-z0-9_]*)=(\S+)")

# A ``NAME`` in a ``NAME=VALUE`` assignment is treated as secret-bearing when
# it ends in a credential-suggesting word (RAFTER_API_KEY, GITHUB_TOKEN,
# DB_PASSWORD, AUTH, ...). Values behind such names are redacted even when they
# don't match any known secret pattern -- the value of a bespoke API key won't
# match a built-in pattern, but it's still a secret. Plain names like FOO or
# NODE_ENV do not match, so ``FOO=bar`` is left intact.
_SECRET_ENV_NAME_RE = re.compile(
    r"(?:^|_)(KEY|TOKEN|SECRET|SECRETS|PASSWORD|PASSWD|PWD|API[_-]?KEY|ACCESS[_-]?KEY|CREDENTIALS?|AUTH)$",
    re.IGNORECASE,
)


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
            for pattern in self._patterns:
                compiled = self._compile(pattern.regex)
                if compiled is None:
                    continue
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
        """Replace all pattern matches in *text* with redacted versions.

        Two layers, both additive:
          1. Env-assignment redaction: any ``NAME=VALUE`` whose NAME looks
             secret-bearing has its VALUE masked, even if the VALUE matches no
             known pattern. This catches leaks like
             ``RAFTER_API_KEY=<key> rafter ...`` in a logged command line,
             where the key's shape is unknown.
          2. Pattern-based redaction: values matching a built-in secret
             pattern are masked wherever they appear.
        """
        result = self._redact_env_assignments(text)
        for pattern in self._patterns:
            compiled = self._compile(pattern.regex)
            if compiled is None:
                continue
            result = compiled.sub(
                lambda m, p=pattern: m.group(0) if self._is_false_positive(p, m.group(0)) else self._redact(m.group(0)),
                result,
            )
        return result

    @staticmethod
    def _redact_env_assignments(text: str) -> str:
        """Mask the VALUE of every ``NAME=VALUE`` token whose NAME looks
        secret-bearing. Non-secret names (FOO, NODE_ENV, ...) are untouched."""
        def _sub(m: re.Match) -> str:
            prefix, name, value = m.group(1), m.group(2), m.group(3)
            if _SECRET_ENV_NAME_RE.search(name):
                return f"{prefix}{name}={PatternEngine._redact(value)}"
            return m.group(0)

        return _ENV_ASSIGN_RE.sub(_sub, text)

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
        if len(match) <= 8:
            return "*" * len(match)
        visible = 4
        return match[:visible] + "*" * (len(match) - visible * 2) + match[-visible:]
