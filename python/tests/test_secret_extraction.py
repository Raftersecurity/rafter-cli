"""Tests for secret extraction: confidence/remediation/fingerprint/entropy."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from rafter_cli.core.pattern_engine import (
    PatternEngine,
    fingerprint_for,
    shannon_entropy,
)
from rafter_cli.scanners.regex_scanner import RegexScanner
from rafter_cli.scanners.secret_patterns import DEFAULT_SECRET_PATTERNS


# Build secret-shaped fixtures at runtime so this test file itself
# does not contain anything our pre-commit / hook scanner would flag.
_QUOTE = chr(34)  # "
_APIKEY = "api" + "key"
_PASSWORD = "pass" + "word"


def _line(key: str, value: str) -> str:
    return f"{key} = {_QUOTE}{value}{_QUOTE}"


_FAKE_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLEZZ"
_FAKE_GHP = "ghp_" + "abcdef0123456789ABCDEFghijklmnoPQRSTU"[:36]
_FAKE_LOW_ENTROPY = "a" * 12 + "1"
_FAKE_HIGH_ENT_API = "Xy" + "7Qz" + "9p2" + "Rt5" + "Wn8" + "Bm4" + "Jc6" + "Kd"


# -- Pattern annotations --------------------------------------------------


def test_every_pattern_has_confidence():
    for p in DEFAULT_SECRET_PATTERNS:
        assert p.confidence in {"low", "medium", "high"}, (
            f"pattern {p.name} has invalid confidence: {p.confidence!r}"
        )


def test_every_pattern_has_remediation():
    for p in DEFAULT_SECRET_PATTERNS:
        assert p.remediation, f"pattern {p.name} missing remediation"
        assert len(p.remediation) > 20


# -- Shannon entropy ------------------------------------------------------


def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_single_char():
    assert shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_two_chars():
    assert shannon_entropy("abab") == pytest.approx(1.0, abs=1e-6)


def test_shannon_entropy_higher_for_diverse():
    assert shannon_entropy("Xy7" + "&!Qz#9p") > shannon_entropy("aaaaaaa")


# -- Fingerprint ----------------------------------------------------------


def test_fingerprint_deterministic():
    a = fingerprint_for("a.txt", "rule", "redacted-x")
    b = fingerprint_for("a.txt", "rule", "redacted-x")
    assert a == b


def test_fingerprint_format():
    fp = fingerprint_for("a.txt", "rule", "x")
    assert re.match(r"^[0-9a-f]{16}$", fp)


def test_fingerprint_changes_per_input():
    base = fingerprint_for("a.txt", "rule", "x")
    assert base != fingerprint_for("b.txt", "rule", "x")
    assert base != fingerprint_for("a.txt", "rule2", "x")
    assert base != fingerprint_for("a.txt", "rule", "y")


def test_fingerprint_does_not_encode_raw_secret():
    raw = "super-leaky-1234"
    redacted = "supe****1234"
    fp = fingerprint_for("a.txt", "rule", redacted)
    assert raw not in fp


# -- Entropy filter on Generic patterns -----------------------------------


def test_entropy_filter_drops_low_entropy_secret(tmp_path: Path):
    text = _line(_PASSWORD, _FAKE_LOW_ENTROPY)
    fp = tmp_path / "config.txt"
    fp.write_text(text)
    scanner = RegexScanner()
    r = scanner.scan_file(str(fp))
    generic = [m for m in r.matches if m.pattern.name == "Generic Secret"]
    assert generic == []


def test_entropy_filter_keeps_high_entropy_apikey(tmp_path: Path):
    text = _line(_APIKEY, _FAKE_HIGH_ENT_API)
    fp = tmp_path / "config.txt"
    fp.write_text(text)
    scanner = RegexScanner()
    r = scanner.scan_file(str(fp))
    generic = [m for m in r.matches if m.pattern.name == "Generic API Key"]
    assert len(generic) > 0


# -- Adversarial fixture: shape-only fakes --------------------------------


def test_aws_shape_detected_and_redacted(tmp_path: Path):
    fp = tmp_path / "fake.txt"
    fp.write_text(_line("aws_key", _FAKE_AWS) + "\n")
    scanner = RegexScanner()
    r = scanner.scan_file(str(fp))
    aws = next((m for m in r.matches if m.pattern.name == "AWS Access Key ID"), None)
    assert aws is not None
    assert aws.redacted
    assert aws.redacted != aws.match
    assert aws.redacted.startswith(aws.match[:4])
    assert aws.redacted.endswith(aws.match[-4:])
    assert aws.pattern.confidence == "high"
    assert aws.pattern.remediation
    assert re.match(r"^[0-9a-f]{16}$", aws.fingerprint)


def test_ghp_high_entropy_detected(tmp_path: Path):
    fp = tmp_path / "fake.txt"
    fp.write_text(_line("token", _FAKE_GHP) + "\n")
    scanner = RegexScanner()
    r = scanner.scan_file(str(fp))
    ghp = next((m for m in r.matches if m.pattern.name == "GitHub Personal Access Token"), None)
    assert ghp is not None
    assert ghp.pattern.confidence == "high"


def test_placeholders_ignored(tmp_path: Path):
    """UPPER_SNAKE and lowercase_snake placeholders → dropped by FP heuristic."""
    fp = tmp_path / "fake.txt"
    fp.write_text(
        "\n".join([
            _line(_APIKEY, "EXAMPLE_API_KEY_PLACEHOLDER"),
            _line("secret", "REPLACE_ME_BEFORE_PROD"),
            _line(_PASSWORD, "your_password_here"),
        ])
    )
    scanner = RegexScanner()
    r = scanner.scan_file(str(fp))
    generic = [
        m for m in r.matches
        if m.pattern.name in {"Generic API Key", "Generic Secret"}
    ]
    assert generic == []


# -- Hard rule: no raw secrets in any output surface ----------------------


def _run_cli(args: list[str], cwd: str | None = None) -> tuple[str, str]:
    """Invoke `rafter secrets ...` and return (stdout, stderr)."""
    cmd = [sys.executable, "-m", "rafter_cli", "secrets", *args]
    env = {**os.environ, "NO_COLOR": "1"}
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, cwd=cwd, env=env
    )
    return proc.stdout, proc.stderr


@pytest.fixture
def leak_dir(tmp_path: Path) -> Path:
    fp = tmp_path / "leak.txt"
    fp.write_text(_line("aws_key", _FAKE_AWS) + "\n")
    return tmp_path


def test_text_output_no_raw_secret(leak_dir: Path):
    stdout, stderr = _run_cli([str(leak_dir)])
    assert _FAKE_AWS not in stdout + stderr


def test_json_output_no_raw_secret(leak_dir: Path):
    stdout, stderr = _run_cli([str(leak_dir), "--json"])
    assert _FAKE_AWS not in stdout + stderr


def test_sarif_output_no_raw_secret(leak_dir: Path):
    stdout, stderr = _run_cli([str(leak_dir), "--format", "sarif"])
    assert _FAKE_AWS not in stdout + stderr


def test_json_output_includes_extraction_fields(leak_dir: Path):
    stdout, _ = _run_cli([str(leak_dir), "--json"])
    parsed = json.loads(stdout)
    findings = parsed["results"]
    assert findings
    m = findings[0]["matches"][0]
    assert m["pattern"]["confidence"]
    assert m["remediation"]
    assert re.match(r"^[0-9a-f]{16}$", m["fingerprint"])
