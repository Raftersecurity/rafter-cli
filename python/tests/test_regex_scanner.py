"""Tests for regex scanner."""
import os
from pathlib import Path

import pytest

from rafter_cli.scanners.regex_scanner import RegexScanner


@pytest.fixture
def scanner():
    return RegexScanner()


def test_scan_file_with_secret(scanner, tmp_path):
    f = tmp_path / "secrets.txt"
    f.write_text("my aws key is AKIAIOSFODNN7EXAMPLE\n")
    result = scanner.scan_file(str(f))
    assert len(result.matches) > 0
    assert any(m.pattern.name == "AWS Access Key ID" for m in result.matches)


def test_scan_file_clean(scanner, tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("This file has no secrets.\n")
    result = scanner.scan_file(str(f))
    assert len(result.matches) == 0


def test_scan_directory(scanner, tmp_path):
    # Plant secrets in a nested structure
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "config.py").write_text("API_KEY = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'\n")
    (sub / "clean.py").write_text("x = 42\n")
    (tmp_path / "readme.md").write_text("No secrets here\n")

    results = scanner.scan_directory(str(tmp_path))
    assert len(results) == 1
    assert "config.py" in results[0].file


def test_scan_directory_excludes(scanner, tmp_path):
    # Secret in excluded dir
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "leaked.js").write_text("const key = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';\n")

    results = scanner.scan_directory(str(tmp_path))
    assert len(results) == 0


def test_scan_directory_custom_exclude(scanner, tmp_path):
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("secret=AKIAIOSFODNN7EXAMPLE\n")

    results = scanner.scan_directory(str(tmp_path), exclude_paths=["vendor"])
    assert len(results) == 0


def test_scan_text(scanner):
    matches = scanner.scan_text("sk_" + "live_abcdefghijklmnopqrstuvwx")
    assert len(matches) > 0


def test_has_secrets(scanner):
    assert scanner.has_secrets("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert not scanner.has_secrets("just a normal string")


def test_custom_patterns():
    scanner = RegexScanner(custom_patterns=[
        {"name": "Test Pattern", "regex": "CUSTOM_[A-Z]{10}", "severity": "high"},
    ])
    matches = scanner.scan_text("CUSTOM_ABCDEFGHIJ")
    assert any(m.pattern.name == "Test Pattern" for m in matches)


def test_binary_files_skipped(scanner, tmp_path):
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n" + b"AKIAIOSFODNN7EXAMPLE")
    results = scanner.scan_directory(str(tmp_path))
    assert len(results) == 0
