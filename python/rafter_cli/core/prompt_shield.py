"""Shared prompt-shield detection + rewriting helpers.

Used by:
  - rafter hook user-prompt-submit (Claude Code, Codex)
  - rafter hook before-model       (Gemini CLI — full body rewrite)

Pure: no I/O, no env-writer calls. Callers handle persistence so they can
share .env state across multiple text fields in a single hook invocation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..scanners.prompt_shield_patterns import (
    CREDENTIAL_KEYWORD_RE,
    DEFAULT_PATTERN_ENV_NAMES,
    PROMPT_SHIELD_PATTERNS,
)
from ..scanners.regex_scanner import RegexScanner


@dataclass(frozen=True)
class DetectedSecret:
    pattern_name: str
    env_base_name: str
    value: str


_PLACEHOLDER_LITERALS = {
    "changeme", "change-me",
    "replace-me", "replaceme", "replace-this",
    "fixme", "placeholder", "redacted",
    "your-secret", "your_secret",
    "your-key", "your_key",
    "your-token", "your_token",
    "your-password", "your_password",
    "your-api-key", "your_api_key",
    "your-api-secret", "your_api_secret",
}
_PLACEHOLDER_BRACKET_RE = re.compile(r"^<.+>$")
_PLACEHOLDER_VAR_RE = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$")
# `xxx`/`xxxx`/... as the *whole* value (optional `-suffix`); replaces the old
# substring rule that dropped real-looking values containing `xxx` (e.g.
# `Mxxx2024aB`).
_PLACEHOLDER_XXX_RE = re.compile(r"^x{3,}([-_][a-z]+)?$")
# `example` as a whole token, optionally with a credential-shape suffix; the
# old prefix rule dropped real values like `example4Hunter2!`.
_PLACEHOLDER_EXAMPLE_RE = re.compile(
    r"^example([-_]?(key|secret|token|value|password|placeholder|api[-_]?key|api[-_]?secret))?$"
)


def detect_secrets(text: str) -> list[DetectedSecret]:
    if not text:
        return []
    seen: set[tuple[str, str]] = set()
    out: list[DetectedSecret] = []

    # 1. Prompt-shield patterns (capture-group aware)
    for p in PROMPT_SHIELD_PATTERNS:
        # Walk the text manually so we can reset the search position when
        # the credential-keyword gate rejects an assignment. If the gate
        # fails, the regex has already greedy-consumed the value (which
        # may contain an inner credential assignment like
        # `--from-literal=DB_PASSWORD=...`); rewinding to after the LHS
        # lets the inner assignment be re-tried.
        pos = 0
        while pos < len(text):
            m = p.regex.search(text, pos)
            if m is None:
                break
            if p.name == "Inline credential assignment":
                lhs = m.group(1) if (m.lastindex or 0) >= 1 else ""
                if not CREDENTIAL_KEYWORD_RE.search(lhs):
                    pos = m.start() + len(lhs)
                    continue
                env_base = lhs
            else:
                env_base = p.env_base_name
            raw_value = m.group(p.value_group) if p.value_group <= (m.lastindex or 0) else None
            # Trim trailing sentence-ending punctuation that the regex
            # value class does not reject.
            value = re.sub(r"[.?!)\]}]+$", "", raw_value) if raw_value else raw_value
            if not value or len(value) < 6 or _is_likely_placeholder(value):
                pos = max(m.end(), pos + 1)
                continue
            key = (p.name, value)
            if key in seen:
                pos = max(m.end(), pos + 1)
                continue
            seen.add(key)
            out.append(DetectedSecret(pattern_name=p.name, env_base_name=env_base, value=value))
            pos = max(m.end(), pos + 1)

    # 2. Default secret patterns (full match = value)
    scanner = RegexScanner()
    for match in scanner.scan_text(text):
        value = match.match
        if not value or _is_likely_placeholder(value):
            continue
        base_name = DEFAULT_PATTERN_ENV_NAMES.get(match.pattern.name, "RAFTER_SECRET")
        if any(prior.value == value for prior in out):
            continue
        key = (match.pattern.name, value)
        if key in seen:
            continue
        seen.add(key)
        out.append(DetectedSecret(pattern_name=match.pattern.name, env_base_name=base_name, value=value))

    return out


def replace_secrets_with_refs(
    text: str,
    detected: list[DetectedSecret],
    value_to_name: dict[str, str],
) -> str:
    """Replace each detected literal with $<name>. Longest values first to avoid
    substring overlaps clobbering shorter values mid-substitution."""
    if not text or not detected:
        return text
    ordered = sorted(detected, key=lambda d: -len(d.value))
    out = text
    for d in ordered:
        name = value_to_name.get(d.value)
        if not name:
            continue
        out = out.replace(d.value, f"${name}")
    return out


def _is_likely_placeholder(value: str) -> bool:
    lower = value.lower()
    if _PLACEHOLDER_XXX_RE.match(lower):
        return True
    if lower in _PLACEHOLDER_LITERALS:
        return True
    if _PLACEHOLDER_BRACKET_RE.match(value):
        return True
    if _PLACEHOLDER_VAR_RE.match(value):
        return True
    if _PLACEHOLDER_EXAMPLE_RE.match(lower):
        return True
    return False
