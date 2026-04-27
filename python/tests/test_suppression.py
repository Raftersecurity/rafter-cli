"""Unit tests for the suppression engine — policy-driven and .rafterignore."""
from __future__ import annotations

from rafter_cli.core.custom_patterns import (
    Suppression,
    apply_suppressions,
    find_suppression,
    policy_ignore_to_suppressions,
)
from rafter_cli.core.config_schema import ScanIgnoreRule
from rafter_cli.core.pattern_engine import Pattern, PatternMatch
from rafter_cli.scanners.regex_scanner import ScanResult


def _mk_match(name: str, severity: str = "high", line: int = 1) -> PatternMatch:
    return PatternMatch(
        pattern=Pattern(name=name, regex=".*", severity=severity),
        match="secret",
        line=line,
        column=1,
        redacted="***",
    )


class TestPolicyIgnoreToSuppressions:
    def test_flattens_paths_x_rules(self):
        rules = [ScanIgnoreRule(
            paths=["tests/**", "fixtures/**"],
            rules=["AWS Access Key"],
            reason="fixtures",
        )]
        out = policy_ignore_to_suppressions(rules)
        assert len(out) == 2
        assert out[0].path_glob == "tests/**"
        assert out[0].pattern_name == "AWS Access Key"
        assert out[0].reason == "fixtures"
        assert out[0].source == ".rafter.yml"

    def test_no_rules_means_all_rules_suppressed(self):
        rules = [ScanIgnoreRule(paths=["docs/**"], rules=None, reason="docs")]
        out = policy_ignore_to_suppressions(rules)
        assert len(out) == 1
        assert out[0].pattern_name is None

    def test_empty_input(self):
        assert policy_ignore_to_suppressions(None) == []
        assert policy_ignore_to_suppressions([]) == []


class TestFindSuppression:
    def test_first_match_wins(self):
        sups = [
            Suppression(path_glob="tests/**", pattern_name="AWS Access Key", reason="first", source=".rafter.yml"),
            Suppression(path_glob="tests/**", pattern_name=None, reason="fallback", source=".rafter.yml"),
        ]
        hit = find_suppression("tests/foo.env", "AWS Access Key", sups)
        assert hit is not None
        assert hit.reason == "first"

    def test_case_insensitive_rule_match(self):
        sups = [Suppression(path_glob="*.env", pattern_name="aws access key", source=".rafter.yml")]
        assert find_suppression("foo.env", "AWS Access Key", sups) is not None

    def test_non_existent_rule_does_not_match(self):
        sups = [Suppression(path_glob="tests/**", pattern_name="Made-Up Rule", source=".rafter.yml")]
        assert find_suppression("tests/foo.env", "AWS Access Key", sups) is None


class TestApplySuppressions:
    def test_returns_input_when_no_suppressions(self):
        results = [ScanResult(file="a.ts", matches=[_mk_match("AWS Access Key")])]
        kept, suppressed = apply_suppressions(results, [])
        assert kept is results
        assert suppressed == []

    def test_splits_kept_and_suppressed(self):
        sups = [Suppression(path_glob="tests/**", pattern_name="AWS Access Key", reason="fixtures", source=".rafter.yml")]
        results = [
            ScanResult(file="tests/foo.env", matches=[
                _mk_match("AWS Access Key", "critical", 5),
                _mk_match("Generic API Key", "high", 7),
            ]),
            ScanResult(file="src/api.ts", matches=[_mk_match("AWS Access Key", "critical", 12)]),
        ]
        kept, suppressed = apply_suppressions(results, sups)
        # tests/foo.env keeps Generic API Key only; src/api.ts unchanged
        assert len(kept) == 2
        kept_names = {r.file: [m.pattern.name for m in r.matches] for r in kept}
        assert kept_names["tests/foo.env"] == ["Generic API Key"]
        assert kept_names["src/api.ts"] == ["AWS Access Key"]
        # Suppressed entry has structured detail
        assert len(suppressed) == 1
        assert suppressed[0].file == "tests/foo.env"
        assert suppressed[0].rule == "AWS Access Key"
        assert suppressed[0].severity == "critical"
        assert suppressed[0].reason == "fixtures"
        assert suppressed[0].source == ".rafter.yml"
        assert suppressed[0].line == 5

    def test_drops_files_with_all_matches_suppressed(self):
        sups = [Suppression(path_glob="fixtures/**", reason="all fixtures", source=".rafter.yml")]
        results = [
            ScanResult(file="fixtures/a.env", matches=[_mk_match("AWS Access Key")]),
            ScanResult(file="src/x.ts", matches=[_mk_match("Generic API Key")]),
        ]
        kept, suppressed = apply_suppressions(results, sups)
        assert [r.file for r in kept] == ["src/x.ts"]
        assert len(suppressed) == 1

    def test_rafterignore_source_has_no_reason(self):
        sups = [Suppression(path_glob="vendor/**", source=".rafterignore")]
        results = [ScanResult(file="vendor/lib.js", matches=[_mk_match("AWS Access Key")])]
        _, suppressed = apply_suppressions(results, sups)
        assert suppressed[0].reason is None
        assert suppressed[0].source == ".rafterignore"
