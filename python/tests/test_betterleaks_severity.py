"""Tests for BetterleaksScanner._get_severity mapping."""
from __future__ import annotations

import pytest

from rafter_cli.scanners.betterleaks import BetterleaksScanner


class TestGetSeverity:
    """Test the severity classification logic."""

    @pytest.mark.parametrize("rule_id", [
        "private-key",
        "rsa-private-key",
        "password",
        "database-password",
        "database-url",
        "github-access-token",
        "slack-access-token",
        "aws-secret-key",
        "github-pat",
        "azure-devops-pat",
    ])
    def test_critical_rules(self, rule_id):
        assert BetterleaksScanner._get_severity(rule_id, []) == "critical"

    @pytest.mark.parametrize("rule_id", [
        "api-key",
        "slack-webhook-token",
        "oauth-token",
        "token-refresh",
    ])
    def test_high_rules(self, rule_id):
        assert BetterleaksScanner._get_severity(rule_id, []) == "high"

    @pytest.mark.parametrize("rule_id", [
        "generic-secret",
    ])
    def test_medium_rules(self, rule_id):
        assert BetterleaksScanner._get_severity(rule_id, []) == "medium"

    def test_unknown_rule_defaults_to_high(self):
        assert BetterleaksScanner._get_severity("some-unknown-rule", []) == "high"

    # ── No false positives ───────────────────────────────────────

    def test_spatial_data_not_critical(self):
        """'-pat' should only match at end of rule ID."""
        sev = BetterleaksScanner._get_severity("spatial-data", [])
        assert sev != "critical"

    def test_file_pattern_not_critical(self):
        sev = BetterleaksScanner._get_severity("file-pattern", [])
        assert sev != "critical"

    def test_tokenizer_not_matched_by_token_rule(self):
        """'tokenizer' doesn't contain '-token' or start with 'token-', falls to default."""
        sev = BetterleaksScanner._get_severity("tokenizer-config", [])
        assert sev == "high"  # default for unknown rules, not via token match

    # ── Tag-based classification (parity with Node) ──────────────

    def test_tag_key_plus_secret_is_critical(self):
        sev = BetterleaksScanner._get_severity("some-unknown-rule", ["key", "secret"])
        assert sev == "critical"

    def test_tag_api_is_high(self):
        sev = BetterleaksScanner._get_severity("some-unknown-rule", ["api"])
        assert sev == "high"

    def test_tag_generic_is_medium(self):
        sev = BetterleaksScanner._get_severity("some-unknown-rule", ["generic"])
        assert sev == "medium"
