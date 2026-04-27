"""PromptInjectionDetector — EXPERIMENTAL.

See docs/research/prompt-injection-detector.md for the full design,
threat model, and known limitations. Pattern-based, English-only,
trivially bypassable by paraphrase. Do not rely on this as a sole
line of defense.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Literal

from .prompt_injection_patterns import (
    ALL_TEXT_PATTERNS,
    HIDDEN_UNICODE_RANGES,
    InjectionCategory,
    InjectionPattern,
    InjectionSeverity,
)

InjectionVerdict = Literal["clean", "suspicious", "likely_injection"]


@dataclass
class InjectionFinding:
    category: InjectionCategory
    severity: InjectionSeverity
    pattern: str
    evidence: str
    offset: int
    description: str


@dataclass
class InjectionScanResult:
    findings: list[InjectionFinding] = field(default_factory=list)
    score: int = 0
    verdict: InjectionVerdict = "clean"


SEVERITY_WEIGHT: dict[InjectionSeverity, int] = {
    "low": 5,
    "medium": 15,
    "high": 35,
    "critical": 60,
}

SEVERITY_RANK: dict[InjectionSeverity, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

DEFAULT_MAX_LENGTH = 1_000_000
DEFAULT_BASE64_MIN = 40
DECODED_CHUNK_CAP = 4096
EVIDENCE_WINDOW = 60

_DATA_URI_RE = re.compile(r"data:[^;]+;base64,$", re.IGNORECASE)


class PromptInjectionDetector:
    def __init__(self, patterns: list[InjectionPattern] | None = None) -> None:
        self.patterns = patterns if patterns is not None else ALL_TEXT_PATTERNS

    def scan(
        self,
        text: str,
        *,
        max_length: int = DEFAULT_MAX_LENGTH,
        base64_min_length: int = DEFAULT_BASE64_MIN,
        min_severity: InjectionSeverity = "low",
    ) -> InjectionScanResult:
        if len(text) > max_length:
            text = text[:max_length]

        findings: list[InjectionFinding] = []
        self._scan_text_patterns(text, findings)
        self._scan_hidden_unicode(text, findings)
        if base64_min_length > 0:
            self._scan_encoded_payloads(text, base64_min_length, findings)

        min_rank = SEVERITY_RANK[min_severity]
        filtered = [f for f in findings if SEVERITY_RANK[f.severity] >= min_rank]
        deduped = _dedupe(filtered)
        score = _aggregate_score(deduped)
        verdict = _score_to_verdict(score)
        return InjectionScanResult(findings=deduped, score=score, verdict=verdict)

    def _scan_text_patterns(self, text: str, out: list[InjectionFinding]) -> None:
        for p in self.patterns:
            count = 0
            for m in p.regex.finditer(text):
                if count > 100:
                    break
                count += 1
                offset = m.start()
                out.append(
                    InjectionFinding(
                        category=p.category,
                        severity=p.severity,
                        pattern=p.name,
                        evidence=_snippet(text, offset, len(m.group(0))),
                        offset=offset,
                        description=p.description,
                    )
                )

    def _scan_hidden_unicode(self, text: str, out: list[InjectionFinding]) -> None:
        for i, ch in enumerate(text):
            cp = ord(ch)
            for rng in HIDDEN_UNICODE_RANGES:
                if not rng.test(cp):
                    continue
                if rng.name == "zero_width_in_word":
                    prev_cp = ord(text[i - 1]) if i > 0 else 0
                    next_cp = ord(text[i + 1]) if i + 1 < len(text) else 0
                    if not (_is_word_char(prev_cp) and _is_word_char(next_cp)):
                        continue
                out.append(
                    InjectionFinding(
                        category="hidden_unicode",
                        severity=rng.severity,
                        pattern=rng.name,
                        evidence=_snippet(text, i, 1),
                        offset=i,
                        description=f"Hidden Unicode codepoint U+{cp:04X}",
                    )
                )
                break

    def _scan_encoded_payloads(
        self, text: str, min_len: int, out: list[InjectionFinding]
    ) -> None:
        chunk_re = re.compile(rf"[A-Za-z0-9+/]{{{min_len},}}={{0,2}}")
        count = 0
        for m in chunk_re.finditer(text):
            if count > 50:
                break
            count += 1
            chunk = m.group(0)[:DECODED_CHUNK_CAP]
            before = text[max(0, m.start() - 24) : m.start()]
            if _DATA_URI_RE.search(before):
                continue
            try:
                decoded_bytes = base64.b64decode(chunk, validate=False)
                decoded = decoded_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue
            if not _is_mostly_printable(decoded):
                continue
            inner = PromptInjectionDetector(self.patterns)
            inner_result = inner.scan(decoded, base64_min_length=-1)
            for f in inner_result.findings:
                out.append(
                    InjectionFinding(
                        category="encoded_payload",
                        severity=_step_down(f.severity),
                        pattern=f"base64_{f.pattern}",
                        evidence=_snippet(text, m.start(), min(len(m.group(0)), 40)),
                        offset=m.start(),
                        description=f"Decoded base64 contains {f.pattern}: {f.description}",
                    )
                )


def _snippet(text: str, offset: int, match_len: int) -> str:
    pad = max(0, (EVIDENCE_WINDOW - match_len) // 2)
    start = max(0, offset - pad)
    end = min(len(text), start + EVIDENCE_WINDOW)
    return re.sub(r"\s+", " ", text[start:end]).strip()


def _is_word_char(cp: int) -> bool:
    if cp == 0x5F:
        return True
    if 0x30 <= cp <= 0x39:
        return True
    if 0x41 <= cp <= 0x5A:
        return True
    if 0x61 <= cp <= 0x7A:
        return True
    if 0xC0 <= cp <= 0x024F:
        return True
    return False


def _is_mostly_printable(s: str) -> bool:
    if not s:
        return False
    printable = sum(
        1
        for c in s
        if ord(c) in (9, 10, 13) or 32 <= ord(c) < 127
    )
    return printable / len(s) > 0.85


def _step_down(s: InjectionSeverity) -> InjectionSeverity:
    if s == "critical":
        return "high"
    if s == "high":
        return "medium"
    if s == "medium":
        return "low"
    return "low"


def _dedupe(findings: list[InjectionFinding]) -> list[InjectionFinding]:
    seen: set[tuple[str, str, int]] = set()
    out: list[InjectionFinding] = []
    for f in findings:
        key = (f.category, f.pattern, f.offset)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _aggregate_score(findings: list[InjectionFinding]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))


def _score_to_verdict(score: int) -> InjectionVerdict:
    if score >= 50:
        return "likely_injection"
    if score >= 15:
        return "suspicious"
    return "clean"
