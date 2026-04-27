"""Tests for custom pattern loading, .rafterignore suppression, and their interaction."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from rafter_cli.core.custom_patterns import (
    load_custom_patterns,
    load_suppressions,
    is_suppressed,
    Suppression,
)
from rafter_cli.scanners.regex_scanner import RegexScanner


# ══════════════════════════════════════════════════════════════════════
# Custom pattern loading from ~/.rafter/patterns/
# ══════════════════════════════════════════════════════════════════════


class TestTxtPatterns:
    """Test .txt pattern file loading."""

    def test_loads_one_regex_per_line(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "internal.txt").write_text(
            "INTERNAL_[A-Z0-9]{32}\nCOMPANY_SECRET_[a-z]{16}\n"
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 2
        assert patterns[0].name == "Custom (internal)"
        assert patterns[0].regex == "INTERNAL_[A-Z0-9]{32}"
        assert patterns[0].severity == "high"
        assert patterns[1].regex == "COMPANY_SECRET_[a-z]{16}"

    def test_ignores_comments_and_blank_lines(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "sparse.txt").write_text(
            "# comment\n\nACTUAL_PATTERN_[0-9]+\n  \n# another comment\n"
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 1
        assert patterns[0].regex == "ACTUAL_PATTERN_[0-9]+"


class TestJsonPatterns:
    """Test .json pattern file loading."""

    def test_loads_array_of_pattern_objects(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "custom.json").write_text(
            json.dumps(
                [
                    {
                        "name": "Internal API Key",
                        "pattern": "INTERNAL_[A-Z0-9]{32}",
                        "severity": "critical",
                        "description": "Internal API key",
                    }
                ]
            )
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 1
        assert patterns[0].name == "Internal API Key"
        assert patterns[0].regex == "INTERNAL_[A-Z0-9]{32}"
        assert patterns[0].severity == "critical"
        assert patterns[0].description == "Internal API key"

    def test_defaults_name_from_filename(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "mypatterns.json").write_text(
            json.dumps([{"pattern": "FOO_[0-9]+"}])
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 1
        assert patterns[0].name == "Custom (mypatterns)"

    def test_defaults_severity_to_high(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "x.json").write_text(
            json.dumps([{"name": "Test", "pattern": "TEST_[0-9]+"}])
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert patterns[0].severity == "high"

    def test_skips_invalid_regex_with_warning(self, tmp_path, monkeypatch, capsys):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "bad.json").write_text(
            json.dumps(
                [
                    {"name": "Bad", "pattern": "[invalid("},
                    {"name": "Good", "pattern": "GOOD_[0-9]+"},
                ]
            )
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 1
        assert patterns[0].name == "Good"
        captured = capsys.readouterr()
        assert "invalid regex" in captured.err

    def test_skips_invalid_severity_with_warning(self, tmp_path, monkeypatch, capsys):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "sev.json").write_text(
            json.dumps(
                [
                    {"name": "Bad Sev", "pattern": "BAD_[0-9]+", "severity": "extreme"},
                    {"name": "Good Sev", "pattern": "GOOD_[0-9]+", "severity": "low"},
                ]
            )
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 1
        assert patterns[0].name == "Good Sev"
        captured = capsys.readouterr()
        assert "invalid severity" in captured.err

    def test_skips_missing_or_empty_pattern(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "missing.json").write_text(
            json.dumps(
                [
                    {"name": "No pattern"},
                    {"name": "Empty pattern", "pattern": ""},
                    {"name": "Valid", "pattern": "OK_[0-9]+"},
                ]
            )
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 1
        assert patterns[0].name == "Valid"

    def test_returns_empty_for_non_array_json(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "obj.json").write_text('{"not": "array"}')
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 0


class TestEdgeCases:
    """Edge cases for custom pattern loading."""

    def test_empty_when_no_patterns_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )
        patterns = load_custom_patterns()
        assert len(patterns) == 0

    def test_empty_when_patterns_dir_is_empty(self, tmp_path, monkeypatch):
        (tmp_path / "patterns").mkdir()
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )
        patterns = load_custom_patterns()
        assert len(patterns) == 0

    def test_ignores_non_txt_json_files(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "readme.md").write_text("PATTERN_[0-9]+")
        (pdir / "data.yaml").write_text("pattern: STUFF_[0-9]+")
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 0

    def test_ignores_subdirectories(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        (pdir / "subdir").mkdir(parents=True)
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 0

    def test_loads_from_both_txt_and_json(self, tmp_path, monkeypatch):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "a.txt").write_text("TXT_PAT_[0-9]+\n")
        (pdir / "b.json").write_text(
            json.dumps([{"name": "JSON Pat", "pattern": "JSON_PAT_[0-9]+"}])
        )
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )

        patterns = load_custom_patterns()
        assert len(patterns) == 2
        names = [p.name for p in patterns]
        assert "Custom (a)" in names
        assert "JSON Pat" in names


# ══════════════════════════════════════════════════════════════════════
# .rafterignore loading
# ══════════════════════════════════════════════════════════════════════


class TestLoadSuppressions:
    """Test .rafterignore parsing."""

    def test_parses_path_only_suppressions(self, tmp_path):
        (tmp_path / ".rafterignore").write_text("node_modules/\ntest/fixtures/\n")
        suppressions = load_suppressions(str(tmp_path))
        assert len(suppressions) == 2
        assert suppressions[0].path_glob == "node_modules/"
        assert suppressions[0].pattern_name is None
        assert suppressions[1].path_glob == "test/fixtures/"

    def test_parses_pattern_specific_suppressions(self, tmp_path):
        (tmp_path / ".rafterignore").write_text(
            ".env:AWS Access Key ID\nvendor/**:Generic API Key\n"
        )
        suppressions = load_suppressions(str(tmp_path))
        assert len(suppressions) == 2
        assert suppressions[0].path_glob == ".env"
        assert suppressions[0].pattern_name == "AWS Access Key ID"
        assert suppressions[1].path_glob == "vendor/**"
        assert suppressions[1].pattern_name == "Generic API Key"

    def test_ignores_comments_and_blank_lines(self, tmp_path):
        (tmp_path / ".rafterignore").write_text(
            "# Comment\n\ntest/\n  \n# Another comment\n"
        )
        suppressions = load_suppressions(str(tmp_path))
        assert len(suppressions) == 1
        assert suppressions[0].path_glob == "test/"

    def test_empty_when_no_rafterignore(self, tmp_path):
        suppressions = load_suppressions(str(tmp_path))
        assert len(suppressions) == 0

    def test_empty_for_empty_rafterignore(self, tmp_path):
        (tmp_path / ".rafterignore").write_text("")
        suppressions = load_suppressions(str(tmp_path))
        assert len(suppressions) == 0

    def test_wildcard_pattern(self, tmp_path):
        (tmp_path / ".rafterignore").write_text("vendor/**:*\n")
        suppressions = load_suppressions(str(tmp_path))
        assert len(suppressions) == 1
        assert suppressions[0].path_glob == "vendor/**"
        assert suppressions[0].pattern_name == "*"


# ══════════════════════════════════════════════════════════════════════
# is_suppressed logic
# ══════════════════════════════════════════════════════════════════════


class TestIsSuppressed:
    """Test suppression matching logic."""

    def test_suppresses_all_patterns_when_no_pattern_name(self):
        suppressions = [Suppression(path_glob="node_modules/*")]
        assert is_suppressed("node_modules/pkg/index.js", "AWS Access Key ID", suppressions)
        assert is_suppressed("node_modules/pkg/index.js", "Generic Secret", suppressions)

    def test_suppresses_only_matching_pattern_name(self):
        suppressions = [Suppression(path_glob="*.env", pattern_name="AWS Access Key ID")]
        assert is_suppressed(".env", "AWS Access Key ID", suppressions)
        assert not is_suppressed(".env", "Generic Secret", suppressions)

    def test_case_insensitive_pattern_name(self):
        suppressions = [Suppression(path_glob="*.env", pattern_name="aws access key id")]
        assert is_suppressed("config/.env", "AWS Access Key ID", suppressions)
        assert is_suppressed("config/.env", "aws access key id", suppressions)

    def test_no_suppress_for_non_matching_path(self):
        suppressions = [Suppression(path_glob="vendor/*")]
        assert not is_suppressed("src/main.py", "Generic Secret", suppressions)

    def test_basename_matching(self):
        """Bare patterns (no /) match against basename."""
        suppressions = [Suppression(path_glob="*.test.py")]
        assert is_suppressed("src/utils/auth.test.py", "Generic Secret", suppressions)
        assert is_suppressed("auth.test.py", "Generic Secret", suppressions)

    def test_empty_suppressions(self):
        assert not is_suppressed("anything.py", "Any Pattern", [])


# ══════════════════════════════════════════════════════════════════════
# Integration: custom patterns via RegexScanner constructor
# ══════════════════════════════════════════════════════════════════════


class TestCustomPatternsViaScanner:
    """Test custom patterns passed to RegexScanner constructor."""

    def test_custom_pattern_name_in_results(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )
        scanner = RegexScanner(
            custom_patterns=[
                {"name": "Internal Token", "regex": "INTERNAL_TK_[A-Z0-9]{20}", "severity": "critical"},
            ]
        )

        f = tmp_path / "config.txt"
        f.write_text("token = INTERNAL_TK_ABCDEFGHIJ0123456789\n")
        result = scanner.scan_file(str(f))
        assert any(m.pattern.name == "Internal Token" for m in result.matches)

    def test_custom_pattern_severity_respected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )
        scanner = RegexScanner(
            custom_patterns=[
                {"name": "Low Risk Token", "regex": "LOW_RISK_[A-Z]{10}", "severity": "low"},
            ]
        )

        f = tmp_path / "test.txt"
        f.write_text("LOW_RISK_ABCDEFGHIJ\n")
        result = scanner.scan_file(str(f))
        match = next((m for m in result.matches if m.pattern.name == "Low Risk Token"), None)
        assert match is not None
        assert match.pattern.severity == "low"

    def test_custom_pattern_missing_description(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "rafter_cli.core.custom_patterns.get_rafter_dir", lambda: tmp_path
        )
        scanner = RegexScanner(
            custom_patterns=[
                {"name": "No Desc", "regex": "NODESC_[0-9]{8}", "severity": "medium"},
            ]
        )

        f = tmp_path / "file.txt"
        f.write_text("NODESC_12345678\n")
        result = scanner.scan_file(str(f))
        assert any(m.pattern.name == "No Desc" for m in result.matches)


# ══════════════════════════════════════════════════════════════════════
# Interaction tests: custom patterns + .rafterignore
# ══════════════════════════════════════════════════════════════════════


class TestInteraction:
    """Test interactions between custom patterns and .rafterignore."""

    def test_custom_pattern_in_ignored_file_suppressed(self):
        suppressions = [Suppression(path_glob="test/fixtures/*")]
        assert is_suppressed("test/fixtures/secrets.txt", "Custom (internal)", suppressions)

    def test_custom_pattern_not_in_rafterignore_reported(self):
        suppressions = [Suppression(path_glob="test/fixtures/*")]
        assert not is_suppressed("src/config.py", "Custom (internal)", suppressions)

    def test_builtin_pattern_in_rafterignore_suppressed(self):
        suppressions = [Suppression(path_glob="*.env", pattern_name="AWS Access Key ID")]
        assert is_suppressed("config/.env", "AWS Access Key ID", suppressions)

    def test_builtin_pattern_not_in_rafterignore_reported(self):
        suppressions = [Suppression(path_glob="*.env", pattern_name="AWS Access Key ID")]
        # Different pattern, same file
        assert not is_suppressed("config/.env", "Generic Secret", suppressions)
        # Same pattern, different file
        assert not is_suppressed("src/main.py", "AWS Access Key ID", suppressions)
