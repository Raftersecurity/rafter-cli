"""Tests for the rafter notify command."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from rafter_cli.commands.notify import (
    _detect_platform,
    _format_discord_payload,
    _format_generic_payload,
    _format_slack_payload,
)


SAMPLE_SCAN_CLEAN = {
    "status": "completed",
    "repository_name": "acme/web-app",
    "scan_id": "scan-abc123",
    "branch_name": "main",
    "findings": [],
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
}

SAMPLE_SCAN_WITH_FINDINGS = {
    "status": "completed",
    "repository_name": "acme/api-server",
    "scan_id": "scan-def456",
    "branch_name": "feature/auth",
    "findings": [
        {"severity": "critical", "title": "SQL Injection", "file": "src/db.py"},
        {"severity": "high", "title": "Hardcoded Secret", "location": "config/prod.yml:12"},
        {"severity": "medium", "title": "Missing CSRF Token", "file": "views/form.py"},
    ],
    "summary": {"critical": 1, "high": 1, "medium": 1, "low": 0},
}

SAMPLE_SCAN_FAILED = {
    "status": "failed",
    "repository_name": "acme/broken",
    "scan_id": "scan-fail1",
    "findings": [],
    "summary": {},
}


class TestDetectPlatform:
    def test_slack_hooks(self):
        assert _detect_platform("https://hooks.slack.com/services/T/B/x") == "slack"

    def test_slack_api(self):
        assert _detect_platform("https://slack.com/api/chat.postMessage") == "slack"

    def test_discord(self):
        assert _detect_platform("https://discord.com/api/webhooks/123/abc") == "discord"

    def test_discordapp(self):
        assert _detect_platform("https://discordapp.com/api/webhooks/123/abc") == "discord"

    def test_generic(self):
        assert _detect_platform("https://example.com/webhook") == "generic"


class TestSlackPayload:
    def test_clean_scan(self):
        payload = _format_slack_payload(SAMPLE_SCAN_CLEAN)
        assert "[rafter]" in payload["text"]
        assert "Clean" in payload["text"]
        assert "blocks" in payload
        # Header block
        assert payload["blocks"][0]["type"] == "header"
        assert "white_check_mark" in payload["blocks"][0]["text"]["text"]

    def test_findings_scan(self):
        payload = _format_slack_payload(SAMPLE_SCAN_WITH_FINDINGS)
        assert "3 issues found" in payload["text"]
        assert "blocks" in payload
        # Should have severity breakdown and findings
        block_types = [b["type"] for b in payload["blocks"]]
        assert "divider" in block_types
        # Find findings block
        finding_blocks = [b for b in payload["blocks"] if b.get("text", {}).get("text", "").startswith("*Top Findings")]
        assert len(finding_blocks) == 1
        assert "SQL Injection" in finding_blocks[0]["text"]["text"]

    def test_failed_scan(self):
        payload = _format_slack_payload(SAMPLE_SCAN_FAILED)
        assert "failed" in payload["text"].lower()

    def test_section_fields_include_repo_and_status(self):
        payload = _format_slack_payload(SAMPLE_SCAN_WITH_FINDINGS)
        section = payload["blocks"][1]
        assert section["type"] == "section"
        field_texts = [f["text"] for f in section["fields"]]
        assert any("acme/api-server" in t for t in field_texts)

    def test_context_footer(self):
        payload = _format_slack_payload(SAMPLE_SCAN_CLEAN)
        last_block = payload["blocks"][-1]
        assert last_block["type"] == "context"
        assert "rafter-bot" in last_block["elements"][0]["text"]


class TestDiscordPayload:
    def test_clean_scan(self):
        payload = _format_discord_payload(SAMPLE_SCAN_CLEAN)
        assert "[rafter]" in payload["content"]
        assert "Clean" in payload["content"]
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert embed["color"] == 0x2ECC71  # green

    def test_findings_scan(self):
        payload = _format_discord_payload(SAMPLE_SCAN_WITH_FINDINGS)
        assert "3 issues found" in payload["content"]
        embed = payload["embeds"][0]
        assert embed["color"] == 0xE74C3C  # red (has critical)
        field_names = [f["name"] for f in embed["fields"]]
        assert "Severity Breakdown" in field_names
        assert "Top Findings" in field_names

    def test_failed_scan(self):
        payload = _format_discord_payload(SAMPLE_SCAN_FAILED)
        embed = payload["embeds"][0]
        assert embed["color"] == 0x95A5A6  # gray

    def test_footer(self):
        payload = _format_discord_payload(SAMPLE_SCAN_CLEAN)
        embed = payload["embeds"][0]
        assert embed["footer"]["text"] == "rafter-bot | rafter.so"


class TestGenericPayload:
    def test_clean_scan(self):
        payload = _format_generic_payload(SAMPLE_SCAN_CLEAN)
        assert "[rafter]" in payload["text"]
        assert "[rafter]" in payload["content"]
        assert payload["text"] == payload["content"]

    def test_findings_scan(self):
        payload = _format_generic_payload(SAMPLE_SCAN_WITH_FINDINGS)
        assert "3 issues" in payload["text"]

    def test_includes_scan_data(self):
        payload = _format_generic_payload(SAMPLE_SCAN_WITH_FINDINGS)
        assert payload["scan_id"] == "scan-def456"


class TestFindingsTruncation:
    def test_max_five_findings_shown(self):
        scan = {
            **SAMPLE_SCAN_WITH_FINDINGS,
            "findings": [
                {"severity": "high", "title": f"Finding {i}", "file": f"file{i}.py"}
                for i in range(8)
            ],
            "summary": {"critical": 0, "high": 8, "medium": 0, "low": 0},
        }
        slack = _format_slack_payload(scan)
        # Find the findings block
        findings_text = ""
        for block in slack["blocks"]:
            text = block.get("text", {})
            if isinstance(text, dict) and "Top Findings" in text.get("text", ""):
                findings_text = text["text"]
                break
        assert "and 3 more" in findings_text

        discord = _format_discord_payload(scan)
        embed = discord["embeds"][0]
        findings_field = next(f for f in embed["fields"] if f["name"] == "Top Findings")
        assert "and 3 more" in findings_field["value"]
