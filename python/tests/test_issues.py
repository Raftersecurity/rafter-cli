"""Tests for rafter issues create from-scan and from-text commands.

Covers: dedup/fingerprinting, issue builder, natural text parsing,
local scan loading, dry-run output, label handling, error conditions.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from rafter_cli.commands.issues.dedup import (
    embed_fingerprint,
    extract_fingerprint,
    find_duplicates,
    fingerprint,
)
from rafter_cli.commands.issues.github_client import GitHubIssue
from rafter_cli.commands.issues.issue_builder import (
    BackendVulnerability,
    IssueDraft,
    LocalMatch,
    build_from_backend_vulnerability,
    build_from_local_match,
    _severity_label,
    _severity_emoji,
)


# ── Fingerprinting ────────────────────────────────────────────────────


class TestFingerprint:
    def test_deterministic_12_char_hex(self):
        fp = fingerprint("src/config.ts", "AWS_KEY")
        assert len(fp) == 12
        assert all(c in "0123456789abcdef" for c in fp)
        assert fingerprint("src/config.ts", "AWS_KEY") == fp

    def test_differs_for_different_files(self):
        assert fingerprint("a.ts", "rule1") != fingerprint("b.ts", "rule1")

    def test_differs_for_different_rules(self):
        assert fingerprint("a.ts", "rule1") != fingerprint("a.ts", "rule2")

    def test_empty_inputs_produce_valid_fingerprint(self):
        fp = fingerprint("", "")
        assert len(fp) == 12
        assert all(c in "0123456789abcdef" for c in fp)

    def test_special_characters_in_path(self):
        fp = fingerprint("src/path with spaces/file.ts", "rule:special/chars")
        assert len(fp) == 12
        assert all(c in "0123456789abcdef" for c in fp)

    def test_consistent_across_calls(self):
        results = [fingerprint("src/auth.ts", "sql-injection") for _ in range(5)]
        assert len(set(results)) == 1


class TestEmbedExtractFingerprint:
    def test_round_trip(self):
        fp = fingerprint("file.ts", "rule")
        body = embed_fingerprint("Some issue body", fp)
        assert extract_fingerprint(body) == fp

    def test_returns_none_when_no_fingerprint(self):
        assert extract_fingerprint("plain body text") is None

    def test_returns_none_for_malformed(self):
        assert extract_fingerprint("<!-- rafter-fingerprint:abc") is None

    def test_preserves_original_body(self):
        original = "My original body\nWith multiple lines"
        fp = fingerprint("f.ts", "r")
        embedded = embed_fingerprint(original, fp)
        assert embedded.startswith(original)


class TestFindDuplicates:
    def _make_issue(self, fp: str | None) -> GitHubIssue:
        body = embed_fingerprint("body", fp) if fp else "body without fingerprint"
        return GitHubIssue(
            number=1, title="test", body=body, labels=[],
            html_url="https://github.com/test/test/issues/1", state="open",
        )

    def test_finds_duplicates(self):
        fp = fingerprint("file.ts", "rule")
        existing = [self._make_issue(fp)]
        dupes = find_duplicates(existing, [fp])
        assert fp in dupes

    def test_empty_when_no_match(self):
        existing = [self._make_issue(fingerprint("a.ts", "r1"))]
        dupes = find_duplicates(existing, [fingerprint("b.ts", "r2")])
        assert len(dupes) == 0

    def test_ignores_issues_without_fingerprints(self):
        existing = [self._make_issue(None)]
        dupes = find_duplicates(existing, [fingerprint("file.ts", "rule")])
        assert len(dupes) == 0

    def test_handles_empty_existing(self):
        dupes = find_duplicates([], [fingerprint("file.ts", "rule")])
        assert len(dupes) == 0


# ── Severity mapping ─────────────────────────────────────────────────


class TestSeverityLabel:
    def test_error_to_critical(self):
        assert _severity_label("error") == "critical"

    def test_warning_to_high(self):
        assert _severity_label("warning") == "high"

    def test_note_to_medium(self):
        assert _severity_label("note") == "medium"

    def test_low_to_low(self):
        assert _severity_label("low") == "low"

    def test_case_insensitive(self):
        assert _severity_label("HIGH") == "high"
        assert _severity_label("Error") == "critical"

    def test_unknown_defaults_to_medium(self):
        assert _severity_label("unknown") == "medium"


class TestSeverityEmoji:
    def test_critical_red(self):
        assert _severity_emoji("error") == "\U0001f534"

    def test_high_orange(self):
        assert _severity_emoji("warning") == "\U0001f7e0"

    def test_medium_yellow(self):
        assert _severity_emoji("note") == "\U0001f7e1"

    def test_low_green(self):
        assert _severity_emoji("low") == "\U0001f7e2"


# ── Issue builder: backend vulnerabilities ────────────────────────────


class TestBuildFromBackendVulnerability:
    def _vuln(self, **overrides) -> BackendVulnerability:
        defaults = dict(
            rule_id="sql-injection", level="error",
            message="SQL injection vulnerability detected",
            file="src/db.ts", line=42,
        )
        defaults.update(overrides)
        return BackendVulnerability(**defaults)

    def test_title_contains_severity_and_rule(self):
        draft = build_from_backend_vulnerability(self._vuln())
        assert "[CRITICAL]" in draft.title
        assert "sql-injection" in draft.title

    def test_body_contains_file_and_line(self):
        draft = build_from_backend_vulnerability(self._vuln())
        assert "`src/db.ts`" in draft.body
        assert "line 42" in draft.body

    def test_labels_include_security_severity_rule(self):
        draft = build_from_backend_vulnerability(self._vuln())
        assert "security" in draft.labels
        assert "severity:critical" in draft.labels
        assert "rule:sql-injection" in draft.labels

    def test_fingerprint_embedded_in_body(self):
        draft = build_from_backend_vulnerability(self._vuln())
        assert extract_fingerprint(draft.body) == draft.fingerprint

    def test_omits_line_when_none(self):
        draft = build_from_backend_vulnerability(self._vuln(line=None))
        assert "line " not in draft.body.split("## Security Finding")[1].split("### Description")[0]

    def test_truncates_long_message_in_title(self):
        draft = build_from_backend_vulnerability(self._vuln(message="A" * 100))
        assert "..." in draft.title

    def test_body_has_all_sections(self):
        draft = build_from_backend_vulnerability(self._vuln())
        assert "## Security Finding" in draft.body
        assert "### Description" in draft.body
        assert "### Remediation" in draft.body
        assert "Rafter CLI" in draft.body

    def test_different_severity_levels(self):
        for level, expected in [("error", "critical"), ("warning", "high"), ("note", "medium"), ("low", "low")]:
            draft = build_from_backend_vulnerability(self._vuln(level=level))
            assert f"severity:{expected}" in draft.labels


# ── Issue builder: local matches ──────────────────────────────────────


class TestBuildFromLocalMatch:
    def _match(self, **overrides) -> LocalMatch:
        defaults = dict(
            pattern_name="AWS Access Key", severity="high",
            description="AWS key found", line=10, redacted="AKIA****XXXX",
        )
        defaults.update(overrides)
        return LocalMatch(**defaults)

    def test_title_contains_pattern_and_basename(self):
        draft = build_from_local_match("src/config.ts", self._match())
        assert "AWS Access Key" in draft.title
        assert "config.ts" in draft.title
        assert "[HIGH]" in draft.title

    def test_body_contains_redacted_match(self):
        draft = build_from_local_match("src/config.ts", self._match())
        assert "AKIA****XXXX" in draft.body

    def test_remediation_steps(self):
        draft = build_from_local_match("f.ts", self._match())
        assert "Rotate the exposed credential" in draft.body
        assert "secrets manager" in draft.body

    def test_secret_detected_label(self):
        draft = build_from_local_match("f.ts", self._match())
        assert "secret-detected" in draft.labels

    def test_no_description_section_when_empty(self):
        draft = build_from_local_match("f.ts", self._match(description=""))
        assert "### Description" not in draft.body

    def test_no_match_line_when_empty(self):
        draft = build_from_local_match("f.ts", self._match(redacted=""))
        assert "**Match:**" not in draft.body

    def test_no_line_when_none(self):
        draft = build_from_local_match("f.ts", self._match(line=None))
        file_section = draft.body.split("## Secret Detection")[1].split("###")[0]
        assert "line " not in file_section

    def test_title_uses_basename_not_full_path(self):
        draft = build_from_local_match("src/deep/nested/config.env", self._match())
        assert "config.env" in draft.title
        assert "src/deep/nested/config.env" not in draft.title


# ── from-scan: local scan loading ─────────────────────────────────────


class TestDraftsFromLocalScan:
    """Test the local scan JSON parsing logic."""

    def _sample_scan(self):
        return [
            {
                "file": "src/config.ts",
                "matches": [
                    {
                        "pattern": {"name": "AWS Access Key", "severity": "critical", "description": "AWS key"},
                        "line": 15,
                        "redacted": "AKIA****XXXX",
                    },
                    {
                        "pattern": {"name": "Generic API Key", "severity": "medium"},
                        "line": 42,
                        "redacted": "api_****_key",
                    },
                ],
            },
            {
                "file": "src/db.ts",
                "matches": [
                    {
                        "pattern": {"name": "Database Password", "severity": "high", "description": "DB pass"},
                        "line": 7,
                        "redacted": "pass****word",
                    },
                ],
            },
        ]

    def _load_local(self, data):
        """Mirrors _drafts_from_local logic from issues_app.py."""
        drafts = []
        for result in data:
            for match in result.get("matches", []):
                pattern = match.get("pattern", {})
                drafts.append(
                    build_from_local_match(
                        result["file"],
                        LocalMatch(
                            pattern_name=pattern.get("name", "unknown"),
                            severity=pattern.get("severity", "medium"),
                            description=pattern.get("description", ""),
                            line=match.get("line"),
                            column=match.get("column"),
                            redacted=match.get("redacted", ""),
                        ),
                    )
                )
        return drafts

    def test_creates_one_draft_per_match(self):
        drafts = self._load_local(self._sample_scan())
        assert len(drafts) == 3

    def test_correct_file_associations(self):
        drafts = self._load_local(self._sample_scan())
        assert "src/config.ts" in drafts[0].body
        assert "src/config.ts" in drafts[1].body
        assert "src/db.ts" in drafts[2].body

    def test_unique_fingerprints(self):
        drafts = self._load_local(self._sample_scan())
        fps = [d.fingerprint for d in drafts]
        assert len(set(fps)) == 3

    def test_severity_labels_correct(self):
        drafts = self._load_local(self._sample_scan())
        assert "severity:critical" in drafts[0].labels
        assert "severity:medium" in drafts[1].labels
        assert "severity:high" in drafts[2].labels

    def test_empty_scan_results(self):
        drafts = self._load_local([])
        assert len(drafts) == 0

    def test_file_with_no_matches(self):
        drafts = self._load_local([{"file": "clean.ts", "matches": []}])
        assert len(drafts) == 0

    def test_from_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._sample_scan(), f)
            f.flush()
            data = json.loads(open(f.name).read())
            drafts = self._load_local(data)
            assert len(drafts) == 3
            os.unlink(f.name)

    def test_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{{")
            f.flush()
            with pytest.raises(json.JSONDecodeError):
                json.loads(open(f.name).read())
            os.unlink(f.name)


# ── from-scan: deduplication integration ──────────────────────────────


class TestDeduplicationFlow:
    def _make_draft(self, file: str, rule: str) -> IssueDraft:
        return build_from_local_match(
            file,
            LocalMatch(pattern_name=rule, severity="high", line=1, redacted="****"),
        )

    def _make_existing_issue(self, fp: str) -> GitHubIssue:
        return GitHubIssue(
            number=1, title="existing",
            body=embed_fingerprint("body", fp),
            labels=[], html_url="https://github.com/test/repo/issues/1",
            state="open",
        )

    def test_filters_duplicates(self):
        d1 = self._make_draft("a.ts", "AWS_KEY")
        d2 = self._make_draft("b.ts", "DB_PASS")
        existing = [self._make_existing_issue(d1.fingerprint)]
        dupes = find_duplicates(existing, [d1.fingerprint, d2.fingerprint])
        filtered = [d for d in [d1, d2] if d.fingerprint not in dupes]
        assert len(filtered) == 1
        assert filtered[0].fingerprint == d2.fingerprint

    def test_keeps_all_when_no_existing_fingerprints(self):
        d1 = self._make_draft("a.ts", "AWS_KEY")
        d2 = self._make_draft("b.ts", "DB_PASS")
        existing = [GitHubIssue(number=1, title="old", body="no fp", labels=[])]
        dupes = find_duplicates(existing, [d1.fingerprint, d2.fingerprint])
        filtered = [d for d in [d1, d2] if d.fingerprint not in dupes]
        assert len(filtered) == 2

    def test_deduplicates_all_when_all_exist(self):
        d1 = self._make_draft("a.ts", "AWS_KEY")
        d2 = self._make_draft("b.ts", "DB_PASS")
        existing = [
            self._make_existing_issue(d1.fingerprint),
            self._make_existing_issue(d2.fingerprint),
        ]
        dupes = find_duplicates(existing, [d1.fingerprint, d2.fingerprint])
        filtered = [d for d in [d1, d2] if d.fingerprint not in dupes]
        assert len(filtered) == 0

    def test_no_dedup_keeps_all(self):
        """Simulates --no-dedup: skip findDuplicates entirely."""
        d1 = self._make_draft("a.ts", "AWS_KEY")
        d2 = self._make_draft("b.ts", "DB_PASS")
        drafts = [d1, d2]  # No filtering applied
        assert len(drafts) == 2


# ── from-scan: dry-run output ─────────────────────────────────────────


class TestFromScanDryRun:
    def test_drafts_serialize_to_json(self):
        draft = build_from_backend_vulnerability(BackendVulnerability(
            rule_id="sql-injection", level="error",
            message="SQL injection", file="src/query.ts", line=99,
        ))
        data = json.loads(json.dumps({
            "title": draft.title, "body": draft.body,
            "labels": draft.labels, "fingerprint": draft.fingerprint,
        }))
        assert "title" in data
        assert "body" in data
        assert "labels" in data
        assert len(data["fingerprint"]) == 12

    def test_multiple_drafts_serialize(self):
        drafts = [
            build_from_backend_vulnerability(BackendVulnerability(
                rule_id="xss", level="warning",
                message="XSS", file="render.ts",
            )),
            build_from_local_match("env.ts", LocalMatch(
                pattern_name="ENV_SECRET", severity="critical",
                line=5, redacted="****",
            )),
        ]
        data = json.loads(json.dumps([
            {"title": d.title, "body": d.body, "labels": d.labels}
            for d in drafts
        ]))
        assert len(data) == 2
        assert "security" in data[0]["labels"]
        assert "secret-detected" in data[1]["labels"]


# ── from-text: natural text parsing ───────────────────────────────────


class TestParseNaturalText:
    """Mirrors _parse_natural_text from issues_app.py."""

    def _parse(self, text: str) -> dict:
        """Inline mirror of _parse_natural_text."""
        import re
        lines = text.strip().split("\n")
        issue_labels: list[str] = []
        title = ""
        body_start = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped:
                title = re.sub(r"^#+\s*", "", stripped).strip()
                body_start = i + 1
                break
        if not title:
            title = "Security issue reported via Rafter CLI"
        if len(title) > 120:
            title = title[:117] + "..."
        body_lines = lines[body_start:]
        body = "\n".join(body_lines).strip() or text.strip()
        text_lower = text.lower()
        if "critical" in text_lower or "p0" in text_lower:
            issue_labels.append("severity:critical")
        elif "high severity" in text_lower or "high risk" in text_lower or "p1" in text_lower:
            issue_labels.append("severity:high")
        elif "medium" in text_lower or "p2" in text_lower:
            issue_labels.append("severity:medium")
        elif "low" in text_lower or "p3" in text_lower:
            issue_labels.append("severity:low")
        security_keywords = [
            "security", "vulnerability", "cve", "cwe", "owasp",
            "secret", "credential", "token", "password", "injection",
            "xss", "csrf", "ssrf", "exploit",
        ]
        if any(kw in text_lower for kw in security_keywords):
            issue_labels.append("security")
        file_refs = re.findall(
            r"(?:^|\s)([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,10})(?::(\d+))?", text
        )
        if file_refs:
            files = [f[0].strip() for f in file_refs if "/" in f[0] or "." in f[0]]
            if files:
                body += "\n\n### Referenced Files\n\n"
                for f in files[:10]:
                    body += f"- `{f}`\n"
        body += "\n\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n"
        return {"title": title, "body": body, "labels": list(set(issue_labels))}

    def test_extracts_first_line_as_title(self):
        result = self._parse("SQL injection in login form\nDetails here")
        assert result["title"] == "SQL injection in login form"

    def test_strips_markdown_headers(self):
        result = self._parse("## Security Bug\nBody text")
        assert result["title"] == "Security Bug"

    def test_truncates_long_titles(self):
        result = self._parse("A" * 150)
        assert len(result["title"]) <= 120
        assert result["title"].endswith("...")

    def test_default_title_for_blank_input(self):
        result = self._parse("   \n   \n   ")
        assert result["title"] == "Security issue reported via Rafter CLI"

    def test_single_line_uses_as_both_title_and_body(self):
        result = self._parse("Single line issue")
        assert result["title"] == "Single line issue"
        assert "Single line issue" in result["body"]

    def test_adds_rafter_footer(self):
        result = self._parse("Some issue")
        assert "Rafter CLI" in result["body"]


class TestFromTextSeverityDetection:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    def test_critical(self):
        assert "severity:critical" in self._parse("Critical vulnerability")["labels"]

    def test_p0(self):
        assert "severity:critical" in self._parse("P0 outage")["labels"]

    def test_high_severity(self):
        assert "severity:high" in self._parse("High severity bug")["labels"]

    def test_high_risk(self):
        assert "severity:high" in self._parse("High risk issue")["labels"]

    def test_p1(self):
        assert "severity:high" in self._parse("P1 regression")["labels"]

    def test_medium(self):
        assert "severity:medium" in self._parse("Medium risk config issue")["labels"]

    def test_p2(self):
        assert "severity:medium" in self._parse("P2 improvement")["labels"]

    def test_low(self):
        assert "severity:low" in self._parse("Low priority cleanup")["labels"]

    def test_p3(self):
        assert "severity:low" in self._parse("P3 cosmetic")["labels"]

    def test_no_severity_keyword(self):
        result = self._parse("Something happened in the app")
        assert not any(l.startswith("severity:") for l in result["labels"])


class TestFromTextSecurityDetection:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    @pytest.mark.parametrize("keyword", [
        "security", "vulnerability", "cve", "cwe", "owasp",
        "secret", "credential", "token", "password", "injection",
        "xss", "csrf", "ssrf", "exploit",
    ])
    def test_detects_security_keyword(self, keyword):
        result = self._parse(f"Issue involving {keyword} concern")
        assert "security" in result["labels"]

    def test_no_security_label_for_non_security(self):
        result = self._parse("The button color is wrong")
        assert "security" not in result["labels"]


class TestFromTextFileExtraction:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    def test_extracts_file_with_line_number(self):
        result = self._parse("Bug in src/auth/login.ts:42 causes crash")
        assert "### Referenced Files" in result["body"]
        assert "src/auth/login.ts" in result["body"]

    def test_extracts_multiple_files(self):
        result = self._parse("Issues in src/a.ts and src/b.ts and lib/c.js")
        assert "src/a.ts" in result["body"]
        assert "src/b.ts" in result["body"]
        assert "lib/c.js" in result["body"]

    def test_no_files_section_when_none_found(self):
        result = self._parse("This has no file references at all")
        assert "### Referenced Files" not in result["body"]

    def test_limits_to_10_files(self):
        files = " ".join(f"src/file{i}.ts" for i in range(15))
        result = self._parse(f"Issues in {files}")
        count = result["body"].count("- `")
        assert count <= 10


class TestFromTextLabelsFlag:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    def test_appends_extra_labels(self):
        parsed = self._parse("Critical security bug")
        extra = [l.strip() for l in "team:backend,priority:urgent".split(",") if l.strip()]
        parsed["labels"].extend(extra)
        assert "team:backend" in parsed["labels"]
        assert "priority:urgent" in parsed["labels"]

    def test_empty_labels_string(self):
        parsed = self._parse("Some issue")
        extra = [l.strip() for l in "".split(",") if l.strip()]
        parsed["labels"].extend(extra)
        assert not any("team:" in l for l in parsed["labels"])

    def test_labels_with_whitespace(self):
        parsed = self._parse("Bug found")
        extra = [l.strip() for l in " bug , needs-review , ".split(",") if l.strip()]
        parsed["labels"].extend(extra)
        assert "bug" in parsed["labels"]
        assert "needs-review" in parsed["labels"]


class TestFromTextTitleOverride:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    def test_title_override(self):
        parsed = self._parse("Original title\nBody text")
        parsed["title"] = "My Custom Title"
        assert parsed["title"] == "My Custom Title"


class TestFromTextDryRun:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    def test_parsed_serializes_to_json(self):
        parsed = self._parse("XSS vulnerability in comments\nDetails")
        data = json.loads(json.dumps(parsed))
        assert data["title"] == "XSS vulnerability in comments"
        assert "security" in data["labels"]


class TestFromTextFileInput:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    def test_reads_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("## Critical Security Bug\nSQL injection in src/db.ts:15")
            f.flush()
            text = open(f.name).read()
            parsed = self._parse(text)
            assert parsed["title"] == "Critical Security Bug"
            assert "severity:critical" in parsed["labels"]
            assert "security" in parsed["labels"]
            os.unlink(f.name)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("   \n  \n  ")
            f.flush()
            text = open(f.name).read()
            parsed = self._parse(text)
            assert parsed["title"] == "Security issue reported via Rafter CLI"
            os.unlink(f.name)


class TestFromTextLabelDedup:
    def _parse(self, text):
        return TestParseNaturalText()._parse(text)

    def test_labels_are_unique(self):
        result = self._parse("Critical security vulnerability with credentials and tokens")
        assert len(result["labels"]) == len(set(result["labels"]))
