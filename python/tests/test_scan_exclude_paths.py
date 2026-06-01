"""Regression tests for sable-yz0 (Python parity).

Three layers of coverage:

1. ``_path_matches_exclude_pattern`` — the pure matching function.
   Same semantics as Node ``pathMatchesExcludePattern``.
2. ``_apply_exclude_paths`` — the chokepoint that turns a list of
   ``ScanResult`` into a filtered list. This is what plugs into the
   betterleaks + patterns engines and the staged / diff modes.
3. ``_scan_directory`` end-to-end via the in-repo RegexScanner — proves
   the chokepoint catches what the walker-level filter missed.

We test the helpers directly (mirroring ``test_agent_init.py``) rather
than subprocessing the CLI, so the suite runs in any environment that
can import the package — CI installs the package via ``pip install -e``;
local dev may not.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from rafter_cli.commands.agent import (
    _apply_exclude_paths,
    _path_matches_exclude_pattern,
    _scan_directory,
)
from rafter_cli.core.pattern_engine import PatternMatch
from rafter_cli.scanners.regex_scanner import ScanResult

# Stripe-style key, split so this file doesn't trip its own scanner.
FAKE_STRIPE = "sk" + "_live_" + "1234567890abcdefghijklmn"


def _make_result(file_path: str) -> ScanResult:
    """Build a minimal ScanResult with one fake match for filtering tests."""
    from rafter_cli.core.pattern_engine import Pattern
    p = Pattern(name="Test", regex="x", severity="high", description="t")
    m = PatternMatch(pattern=p, match="x", line=1, column=1, redacted="x")
    return ScanResult(file=file_path, matches=[m])


class TestPathMatchesExcludePattern:
    def test_exact_match(self):
        assert _path_matches_exclude_pattern("components/common/Mermaid.tsx", "components/common/Mermaid.tsx")
        assert not _path_matches_exclude_pattern("components/common/Other.tsx", "components/common/Mermaid.tsx")

    def test_directory_prefix_no_slash(self):
        assert _path_matches_exclude_pattern("scripts/dev.ts", "scripts")
        assert _path_matches_exclude_pattern("scripts/sub/foo.ts", "scripts")
        assert not _path_matches_exclude_pattern("scripted/foo.ts", "scripts")

    def test_directory_prefix_trailing_slash(self):
        assert _path_matches_exclude_pattern("scripts/dev.ts", "scripts/")
        assert _path_matches_exclude_pattern("scripts/sub/foo.ts", "scripts/")

    def test_dirname_anywhere(self):
        """Bare name matches a dir at any depth — preserves the prior
        RegexScanner walker behavior so users with `node_modules` keep
        working for nested copies."""
        assert _path_matches_exclude_pattern("pkg/node_modules/foo.ts", "node_modules")
        assert not _path_matches_exclude_pattern("pkg/notnode_modules/foo.ts", "node_modules")

    def test_glob_with_recursion(self):
        assert _path_matches_exclude_pattern("supabase/migrations/foo.sql", "**/*.sql")
        assert not _path_matches_exclude_pattern("supabase/migrations/foo.json", "**/*.sql")

    def test_glob_extension_anywhere(self):
        assert _path_matches_exclude_pattern("a/b/c/foo.snap", "*.snap")
        assert _path_matches_exclude_pattern("foo.snap", "*.snap")

    def test_empty_pattern_never_matches(self):
        assert not _path_matches_exclude_pattern("anything", "")
        assert not _path_matches_exclude_pattern("anything", "/")


class TestApplyExcludePaths:
    """Chokepoint filter — what plugs into both scan engines."""

    def test_no_excludes_returns_unchanged(self):
        results = [_make_result("/repo/a.ts"), _make_result("/repo/b.ts")]
        assert _apply_exclude_paths(results, None, "/repo") == results
        assert _apply_exclude_paths(results, [], "/repo") == results

    def test_customer_repro(self, tmp_path):
        """User's exact .rafter.yml — three excludes, one safe path."""
        results = [
            _make_result(str(tmp_path / "scripts" / "dev.ts")),
            _make_result(str(tmp_path / "components" / "common" / "Mermaid.tsx")),
            _make_result(str(tmp_path / "supabase" / "migrations" / "20250215000000_resend_setup.sql")),
            _make_result(str(tmp_path / "safe" / "leaky.ts")),
        ]
        excludes = [
            "scripts/",
            "components/common/Mermaid.tsx",
            "supabase/migrations/20250215000000_resend_setup.sql",
        ]
        kept = _apply_exclude_paths(results, excludes, str(tmp_path))
        assert len(kept) == 1
        assert kept[0].file.endswith("safe/leaky.ts")

    def test_filter_resolves_relative_to_scan_root(self, tmp_path):
        """A multi-segment exclude must match against the path relative
        to scan_root, not the absolute path."""
        results = [_make_result(str(tmp_path / "components" / "common" / "Mermaid.tsx"))]
        assert _apply_exclude_paths(results, ["components/common/Mermaid.tsx"], str(tmp_path)) == []

    def test_glob(self, tmp_path):
        results = [
            _make_result(str(tmp_path / "supabase" / "migrations" / "x.sql")),
            _make_result(str(tmp_path / "safe.ts")),
        ]
        kept = _apply_exclude_paths(results, ["**/*.sql"], str(tmp_path))
        assert len(kept) == 1
        assert kept[0].file.endswith("safe.ts")


class TestScanDirectoryEndToEnd:
    """Plant real fake secrets, run _scan_directory, assert chokepoint filtered."""

    def test_full_repro(self, tmp_path):
        from rafter_cli.core.config_schema import ScanConfig

        for sub in ("scripts", "components/common", "supabase/migrations", "safe"):
            (tmp_path / sub).mkdir(parents=True)
        (tmp_path / "scripts" / "dev.ts").write_text(f"// {FAKE_STRIPE}\n")
        (tmp_path / "components" / "common" / "Mermaid.tsx").write_text(f"// {FAKE_STRIPE}\n")
        (tmp_path / "supabase" / "migrations" / "20250215000000_resend_setup.sql").write_text(f"-- {FAKE_STRIPE}\n")
        (tmp_path / "safe" / "leaky.ts").write_text(f"// {FAKE_STRIPE}\n")

        scan_cfg = ScanConfig(
            exclude_paths=[
                "scripts/",
                "components/common/Mermaid.tsx",
                "supabase/migrations/20250215000000_resend_setup.sql",
            ],
            custom_patterns=[],
            ignore=[],
        )

        results = _scan_directory(str(tmp_path), engine="patterns", scan_cfg=scan_cfg, respect_gitignore=False)
        files = sorted(r.file for r in results)
        assert len(files) == 1, f"expected only safe/leaky.ts, got: {files}"
        assert files[0].endswith("safe/leaky.ts")
