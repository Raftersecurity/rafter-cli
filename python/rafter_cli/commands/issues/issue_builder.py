"""Build structured GitHub issues from scan findings."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .dedup import embed_fingerprint, fingerprint


@dataclass
class IssueDraft:
    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    fingerprint: str = ""


@dataclass
class BackendVulnerability:
    """Backend vulnerability from `GET /api/static/scan` (`rafter get <id> --format json`).

    The real API shape (`toRafterFindings()` on the backend) is
    `rule_id`/`severity`/`title`/`description`/`file_path`/`line_start`/
    `line_end` plus optional `cwe`/`confidence`. `level`/`message`/`file`/
    `line` are the pre-rename names, kept as a fallback for old cached
    payloads and existing tests, never the primary source.
    """

    rule_id: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    cwe: str | None = None
    confidence: str | None = None
    # Pre-rename names.
    level: str = ""
    message: str = ""
    file: str = ""
    line: int | None = None


@dataclass
class LocalMatch:
    pattern_name: str
    severity: str
    description: str = ""
    line: int | None = None
    column: int | None = None
    redacted: str = ""


_SEVERITY_MAP = {
    "error": "critical",
    "critical": "critical",
    "warning": "high",
    "high": "high",
    "note": "medium",
    "medium": "medium",
    "low": "low",
}

_SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
}


def _severity_label(level: str) -> str:
    return _SEVERITY_MAP.get(level.lower(), "medium")


def _severity_emoji(level: str) -> str:
    return _SEVERITY_EMOJI.get(_severity_label(level), "\U0001f7e1")


def _truncate(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def build_from_backend_vulnerability(vuln: BackendVulnerability) -> IssueDraft:
    rule_id = vuln.rule_id or "unknown-rule"
    level = vuln.severity or vuln.level or "note"
    summary = vuln.title or vuln.message or "Security finding"
    details = vuln.description or vuln.message or summary
    file = vuln.file_path or vuln.file or "unknown file"
    line = vuln.line_start if vuln.line_start is not None else vuln.line

    sev = _severity_label(level)
    emoji = _severity_emoji(level)
    fp = fingerprint(file, rule_id)

    title = f"{emoji} [{sev.upper()}] {rule_id}: {_truncate(summary, 80)}"

    body = f"## Security Finding\n\n"
    body += f"**Rule:** `{rule_id}`\n"
    body += f"**Severity:** {sev}\n"
    body += f"**File:** `{file}`"
    if line:
        body += f" (line {line})"
    body += "\n\n"
    body += f"### Description\n\n{details}\n\n"
    body += f"### Remediation\n\nReview and fix the finding in `{file}`.\n"
    body += "\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n"

    labels = ["security", f"severity:{sev}", f"rule:{rule_id}"]

    return IssueDraft(
        title=title,
        body=embed_fingerprint(body, fp),
        labels=labels,
        fingerprint=fp,
    )


def build_from_local_match(file: str, match: LocalMatch) -> IssueDraft:
    sev = _severity_label(match.severity)
    emoji = _severity_emoji(match.severity)
    fp = fingerprint(file, match.pattern_name)

    basename = os.path.basename(file)
    title = f"{emoji} [{sev.upper()}] Secret detected: {match.pattern_name} in {basename}"

    body = "## Secret Detection\n\n"
    body += f"**Pattern:** `{match.pattern_name}`\n"
    body += f"**Severity:** {sev}\n"
    body += f"**File:** `{file}`"
    if match.line:
        body += f" (line {match.line})"
    body += "\n"
    if match.redacted:
        body += f"**Match:** `{match.redacted}`\n"
    body += "\n"
    if match.description:
        body += f"### Description\n\n{match.description}\n\n"
    body += "### Remediation\n\n"
    body += "1. Rotate the exposed credential immediately\n"
    body += "2. Remove the secret from source code\n"
    body += "3. Use environment variables or a secrets manager instead\n"
    body += "\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n"

    labels = ["security", "secret-detected", f"severity:{sev}"]

    return IssueDraft(
        title=title,
        body=embed_fingerprint(body, fp),
        labels=labels,
        fingerprint=fp,
    )
