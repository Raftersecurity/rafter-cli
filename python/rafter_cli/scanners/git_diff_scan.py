import os

from ..scanners.regex_scanner import RegexScanner, ScanResult
from ..utils.git_diff import AddedDiffLine


def scan_added_diff_lines(
    added_lines: list[AddedDiffLine],
    repo_root: str,
    custom_patterns=None,
) -> list[ScanResult]:
    """Scan parsed git diff added lines with the patterns engine."""
    if not added_lines:
        return []

    scanner = RegexScanner(custom_patterns)
    by_file: dict[str, list] = {}

    for entry in added_lines:
        abs_path = os.path.join(repo_root, entry.file)
        matches = scanner.scan_line(entry.text, entry.line)
        if matches:
            by_file.setdefault(abs_path, []).extend(matches)

    return [ScanResult(file=f, matches=m) for f, m in by_file.items() if m]
