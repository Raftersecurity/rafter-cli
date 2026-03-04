"""Deduplication logic for GitHub issues created from scan findings."""
from __future__ import annotations

import hashlib

from .github_client import GitHubIssue

FINGERPRINT_PREFIX = "<!-- rafter-fingerprint:"
FINGERPRINT_SUFFIX = " -->"


def fingerprint(file: str, rule_id: str) -> str:
    h = hashlib.sha256(f"{file}:{rule_id}".encode()).hexdigest()[:12]
    return h


def embed_fingerprint(body: str, fp: str) -> str:
    return f"{body}\n\n{FINGERPRINT_PREFIX}{fp}{FINGERPRINT_SUFFIX}"


def extract_fingerprint(body: str) -> str | None:
    idx = body.find(FINGERPRINT_PREFIX)
    if idx == -1:
        return None
    start = idx + len(FINGERPRINT_PREFIX)
    end = body.find(FINGERPRINT_SUFFIX, start)
    if end == -1:
        return None
    return body[start:end]


def find_duplicates(
    existing_issues: list[GitHubIssue],
    new_fingerprints: list[str],
) -> set[str]:
    existing_fps: set[str] = set()
    for issue in existing_issues:
        fp = extract_fingerprint(issue.body)
        if fp:
            existing_fps.add(fp)
    return {fp for fp in new_fingerprints if fp in existing_fps}
