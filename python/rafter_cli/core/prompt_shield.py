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


_PLACEHOLDER_LITERALS = {"changeme", "change-me", "your-secret", "your_secret"}
_PLACEHOLDER_BRACKET_RE = re.compile(r"^<.+>$")
_PLACEHOLDER_VAR_RE = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$")


def detect_secrets(text: str) -> list[DetectedSecret]:
    if not text:
        return []
    seen: set[tuple[str, str]] = set()
    out: list[DetectedSecret] = []

    # 1. Prompt-shield patterns (capture-group aware)
    for p in PROMPT_SHIELD_PATTERNS:
        for m in p.regex.finditer(text):
            value = m.group(p.value_group) if p.value_group <= (m.lastindex or 0) else None
            if not value or _is_likely_placeholder(value):
                continue
            if p.name == "Inline credential assignment":
                lhs = m.group(1) if (m.lastindex or 0) >= 1 else ""
                if not CREDENTIAL_KEYWORD_RE.search(lhs):
                    continue
                env_base = lhs
            else:
                env_base = p.env_base_name
            key = (p.name, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(DetectedSecret(pattern_name=p.name, env_base_name=env_base, value=value))

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
    if "xxx" in lower and len(lower) < 16:
        return True
    if lower in _PLACEHOLDER_LITERALS:
        return True
    if _PLACEHOLDER_BRACKET_RE.match(value):
        return True
    if _PLACEHOLDER_VAR_RE.match(value):
        return True
    if lower.startswith("example"):
        return True
    return False
