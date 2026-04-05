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
GOLDEN_DIR = TESTS_DIR / "snapshots" / "golden"
UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"

# Fixture content — secrets are split across string operations so GitHub
# push protection doesn't flag them in source code.
_FIXTURES = {
    "aws-keys.txt": "\n".join([
        "# AWS Configuration",
        "# This file contains fake AWS credentials for testing",
        "",
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "",
    ]),
    "multi-pattern.py": "\n".join([
        "# Configuration with multiple secret types",
        "import os",
        "",
        'GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTU' + 'VWXYZabcdefghij"',
        'SLACK_TOKEN = "xoxb-123456789012-12345678' + '90123-ABCDEFGHIJKLMNOPQRSTUVwx"',
        'STRIPE_KEY = "sk_' + "live_abcdefghijklmnopqrstuvwx" + '"',
        "",
    ]),
    "mixed-severity.js": "\n".join([
        "// File with mixed severity patterns",
        "const config = {",
        "  // Critical: AWS key",
        '  awsKey: "AKIAIOSFODNN7EXAMPLE",',
        "  // High: generic API key",
        '  api_key: "sk_' + 'test_BQokikJOvBiI2HlWgH4olfQ2",',
        "  // High: bearer token",
        '  auth: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp'
        + 'XVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",',
        "};",
        "",
    ]),
    "clean-file.txt": "\n".join([
        "# This file contains no secrets",
        "# Just some regular configuration",
        "",
        "log_level = info",
        "max_retries = 3",
        "timeout = 30",
        "",
    ]),
    "database-urls.env": "\n".join([
        "# Database connection strings",
        "",
        "POSTGRES_URL=postgresql://admin:supersecretpass@db.example.com:5432/myapp",
        "MONGO_URL=mongodb://root:mongopass123@mongo.example.com:27017/production",
        "",
    ]),
}


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


@pytest.fixture
def fixtures_dir(tmp_path):
    """Create fixture files in a temp directory."""
    for name, content in _FIXTURES.items():
        (tmp_path / name).write_text(content)
    return tmp_path


class TestSingleFileScans:
    @pytest.mark.parametrize("fixture,golden", [
        ("aws-keys.txt", "aws-keys.json"),
        ("multi-pattern.py", "multi-pattern.json"),
        ("mixed-severity.js", "mixed-severity.json"),
        ("clean-file.txt", "clean-file.json"),
        ("database-urls.env", "database-urls.json"),
    ])
    def test_matches_golden(self, scanner, fixtures_dir, fixture, golden):
        result = scanner.scan_file(str(fixtures_dir / fixture))
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
    def test_matches_golden(self, scanner, fixtures_dir):
        results = scanner.scan_directory(str(fixtures_dir))
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
            {"input": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "label": "github-pat-40char"},
            {"input": "sk_" + "live_abcdefghijklmnopqrstuvwx", "label": "stripe-30char"},
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
    def test_matches_golden(self, scanner, fixtures_dir):
        result = scanner.scan_file(str(fixtures_dir / "multi-pattern.py"))
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
