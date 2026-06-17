"""Unit tests for unified git diff parsing and added-line scanning."""

from rafter_cli.scanners.git_diff_scan import scan_added_diff_lines
from rafter_cli.scanners.regex_scanner import RegexScanner
from rafter_cli.utils.git_diff import AddedDiffLine, normalize_diff_path, parse_unified_diff_added_lines


class TestNormalizeDiffPath:
    def test_strips_b_prefix(self):
        assert normalize_diff_path("b/foo/bar.ts") == "foo/bar.ts"

    def test_strips_a_prefix(self):
        assert normalize_diff_path("a/foo/bar.ts") == "foo/bar.ts"

    def test_normalizes_backslashes(self):
        assert normalize_diff_path("b\\src\\app.py") == "src/app.py"


class TestParseUnifiedDiffAddedLines:
    def test_empty_patch(self):
        assert parse_unified_diff_added_lines("") == []
        assert parse_unified_diff_added_lines("  \n  ") == []

    def test_extracts_added_lines_with_paths_and_line_numbers(self):
        patch = "\n".join(
            [
                "diff --git a/src/config.py b/src/config.py",
                "--- a/src/config.py",
                "+++ b/src/config.py",
                "@@ -0,0 +1,2 @@",
                "+key = 'AKIAIOSFODNN7EXAMPLE'",
                "+new = 1",
            ]
        )
        lines = parse_unified_diff_added_lines(patch)
        assert lines == [
            AddedDiffLine(file="src/config.py", line=1, text="key = 'AKIAIOSFODNN7EXAMPLE'"),
            AddedDiffLine(file="src/config.py", line=2, text="new = 1"),
        ]

    def test_parses_multiple_files(self):
        patch = "\n".join(
            [
                "diff --git a/a.py b/a.py",
                "+++ b/a.py",
                "@@ -0,0 +1,1 @@",
                "+alpha = 1",
                "diff --git a/b.py b/b.py",
                "+++ b/b.py",
                "@@ -0,0 +1,1 @@",
                "+beta = 2",
            ]
        )
        lines = parse_unified_diff_added_lines(patch)
        assert len(lines) == 2
        assert lines[0].file == "a.py"
        assert lines[1].file == "b.py"

    def test_modifications_return_plus_side_only(self):
        patch = "\n".join(
            [
                "+++ b/app.py",
                "@@ -10 +10,2 @@",
                "-const x = 1;",
                "+const x = 2;",
                "+const y = 3;",
            ]
        )
        lines = parse_unified_diff_added_lines(patch)
        assert len(lines) == 2
        assert lines[0].line == 10
        assert lines[1].line == 11

    def test_ignores_deletions_without_advancing_new_line_counter(self):
        patch = "\n".join(
            [
                "+++ b/item.py",
                "@@ -5,3 +5,2 @@",
                "-removed only",
                "-also removed",
                "+kept replacement",
            ]
        )
        lines = parse_unified_diff_added_lines(patch)
        assert lines == [AddedDiffLine(file="item.py", line=5, text="kept replacement")]

    def test_ignores_context_but_advances_new_line_counter(self):
        patch = "\n".join(
            [
                "+++ b/with_context.py",
                "@@ -1,3 +1,4 @@",
                " context one",
                "+inserted",
                " context two",
            ]
        )
        lines = parse_unified_diff_added_lines(patch)
        assert lines == [AddedDiffLine(file="with_context.py", line=2, text="inserted")]

    def test_multiple_hunks_in_one_file(self):
        patch = "\n".join(
            [
                "+++ b/multi.py",
                "@@ -1 +1,2 @@",
                "+top",
                "+more top",
                "@@ -20 +21,1 @@",
                "+bottom",
            ]
        )
        lines = parse_unified_diff_added_lines(patch)
        assert [line.line for line in lines] == [1, 2, 21]

    def test_skips_binary_and_deletion_only(self):
        patch = "\n".join(
            [
                "diff --git a/x.bin b/x.bin",
                "Binary files a/x.bin and b/x.bin differ",
                "diff --git a/gone.txt b/gone.txt",
                "--- a/gone.txt",
                "+++ /dev/null",
                "@@ -1 +0,0 @@",
                "-bye",
            ]
        )
        assert parse_unified_diff_added_lines(patch) == []

    def test_skips_no_newline_marker(self):
        patch = "\n".join(
            [
                "+++ b/x.py",
                "@@ -0,0 +1,1 @@",
                "+line without newline",
                "\\ No newline at end of file",
            ]
        )
        assert parse_unified_diff_added_lines(patch) == [
            AddedDiffLine(file="x.py", line=1, text="line without newline")
        ]

    def test_does_not_treat_file_header_as_content(self):
        assert parse_unified_diff_added_lines("+++ b/only_header.py") == []


class TestScanAddedDiffLines:
    def test_finds_secret_at_line(self):
        added = parse_unified_diff_added_lines(
            "\n".join(
                [
                    "+++ b/secret.py",
                    "@@ -0,0 +1,1 @@",
                    "+API = 'AKIAIOSFODNN7EXAMPLE'",
                ]
            )
        )
        results = scan_added_diff_lines(added, "/repo")
        assert len(results) == 1
        assert results[0].file.endswith("secret.py")
        assert results[0].matches[0].line == 1

    def test_clean_lines_produce_no_results(self):
        added = [AddedDiffLine(file="clean.py", line=1, text="ok = True")]
        assert scan_added_diff_lines(added, "/repo") == []

    def test_groups_findings_per_file(self):
        ghp = "ghp_123456789012345678901234567890123456"
        added = [
            AddedDiffLine(file="a.py", line=1, text="k = 'AKIAIOSFODNN7EXAMPLE'"),
            AddedDiffLine(file="a.py", line=2, text=f"t = '{ghp}'"),
        ]
        results = scan_added_diff_lines(added, "/repo")
        assert len(results) == 1
        assert len(results[0].matches) == 2


class TestRegexScannerScanLine:
    def test_assigns_line_number(self):
        scanner = RegexScanner()
        ghp = "ghp_123456789012345678901234567890123456"
        matches = scanner.scan_line(f"token = '{ghp}'", 9)
        assert matches[0].line == 9
