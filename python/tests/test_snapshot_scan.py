"""Golden file / snapshot tests for scan output.

Compares scanner output against stored reference (golden) files.
To regenerate golden files after intentional changes:

    UPDATE_SNAPSHOTS=1 pytest tests/test_snapshot_scan.py
"""
import json
import os
from pathlib import Path

import pytest

from rafter_cli.scanners.regex_scanner import RegexScanner

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "snapshots" / "fixtures"
GOLDEN_DIR = TESTS_DIR / "snapshots" / "golden"
UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"


def _normalize(result) -> dict:
    """Normalize a ScanResult for snapshot comparison."""
    matches = []
    for m in result.matches:
        matches.append({
            "pattern": {
                "name": m.pattern.name,
                "severity": m.pattern.severity,
            },
            "line": m.line,
            "column": m.column,
            "redacted": m.redacted or None,
        })
    matches.sort(key=lambda m: (m["line"] or 0, m["column"] or 0, m["pattern"]["name"]))
    return {
        "file": Path(result.file).name,
        "matches": matches,
    }


def _normalize_results(results: list) -> list[dict]:
    normalized = [_normalize(r) for r in results]
    normalized.sort(key=lambda r: r["file"])
    return normalized


def _read_golden(name: str):
    return json.loads((GOLDEN_DIR / name).read_text())


def _write_golden(name: str, data):
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    (GOLDEN_DIR / name).write_text(json.dumps(data, indent=2) + "\n")


@pytest.fixture
def scanner():
    return RegexScanner()


class TestSingleFileScans:
    @pytest.mark.parametrize("fixture,golden", [
        ("aws-keys.txt", "aws-keys.json"),
        ("multi-pattern.py", "multi-pattern.json"),
        ("mixed-severity.js", "mixed-severity.json"),
        ("clean-file.txt", "clean-file.json"),
        ("database-urls.env", "database-urls.json"),
    ])
    def test_matches_golden(self, scanner, fixture, golden):
        result = scanner.scan_file(str(FIXTURES_DIR / fixture))
        normalized = _normalize(result)

        if UPDATE:
            _write_golden(golden, normalized)
            return

        expected = _read_golden(golden)
        assert normalized == expected, (
            f"Scan output for {fixture} does not match golden file {golden}. "
            f"Run UPDATE_SNAPSHOTS=1 pytest to regenerate."
        )


class TestDirectoryScan:
    def test_matches_golden(self, scanner):
        results = scanner.scan_directory(str(FIXTURES_DIR))
        normalized = _normalize_results(results)

        if UPDATE:
            _write_golden("directory-scan.json", normalized)
            return

        expected = _read_golden("directory-scan.json")
        assert normalized == expected, (
            "Directory scan output does not match golden file. "
            "Run UPDATE_SNAPSHOTS=1 pytest to regenerate."
        )


class TestRedactionAccuracy:
    def test_matches_golden(self, scanner):
        samples = [
            {"input": "AKIAIOSFODNN7EXAMPLE", "label": "aws-key-20char"},
            {"input": "ghp_FAKEEFGHIJKLMNOPQRSTUVWXYZ0123456789", "label": "github-pat-40char"},
            {"input": "sk_l1ve_abcdefghijklmnopqrstuvwx", "label": "stripe-30char"},
            {"input": "xoxb-12", "label": "short-token-7char"},
        ]

        normalized = [
            {
                "label": s["label"],
                "input_length": len(s["input"]),
                "redacted": scanner.redact(s["input"]),
            }
            for s in samples
        ]

        if UPDATE:
            _write_golden("redaction-samples.json", normalized)
            return

        expected = _read_golden("redaction-samples.json")
        assert normalized == expected, (
            "Redaction output does not match golden file. "
            "Run UPDATE_SNAPSHOTS=1 pytest to regenerate."
        )


class TestPositionAccuracy:
    def test_matches_golden(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "multi-pattern.py"))
        positions = [
            {
                "pattern": m.pattern.name,
                "line": m.line,
                "column": m.column,
            }
            for m in result.matches
        ]
        positions.sort(key=lambda p: (p["line"] or 0, p["pattern"]))

        if UPDATE:
            _write_golden("positions-multi-pattern.json", positions)
            return

        expected = _read_golden("positions-multi-pattern.json")
        assert positions == expected, (
            "Position data does not match golden file. "
            "Run UPDATE_SNAPSHOTS=1 pytest to regenerate."
        )
