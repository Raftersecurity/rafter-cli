"""Tests for regex scanner."""

import os

import pytest

from rafter_cli.scanners.regex_scanner import RegexScanner


@pytest.fixture
def scanner():
    return RegexScanner()


def test_scan_file_with_secret(scanner, tmp_path):
    f = tmp_path / "secrets.txt"
    f.write_text("my aws key is AKIAIOSFODNN7ABCDEFG\n")
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


def test_scan_text(scanner):
    matches = scanner.scan_text("sk_" + "live_abcdefghijklmnopqrstuvwx")
    assert len(matches) > 0


def test_scan_text_detects_hashicorp_vault_token(scanner):
    token = "hv" + "s." + ("A" * 90)
    matches = scanner.scan_text(token)
    assert any(m.pattern.name == "HashiCorp Vault Token" for m in matches)


def test_scan_text_ignores_short_hashicorp_vault_like_string(scanner):
    token = "hv" + "s." + ("A" * 32)
    matches = scanner.scan_text(token)
    assert not any(m.pattern.name == "HashiCorp Vault Token" for m in matches)

def test_scan_text_detects_digitalocean_token(scanner):
    token = "dop_v1_" + ("a" * 64)
    matches = scanner.scan_text(token)
    assert any(m.pattern.name == "DigitalOcean Personal Access Token" for m in matches)

def test_scan_text_detects_mailchimp_key(scanner):
    token = ("a" * 32) + "-us12"
    matches = scanner.scan_text(token)
    assert any(m.pattern.name == "Mailchimp API Key" for m in matches)

def test_scan_text_ignores_bare_hex_without_datacenter_suffix(scanner):
    token = "a" * 32
    matches = scanner.scan_text(token)
    assert not any(m.pattern.name == "Mailchimp API Key" for m in matches)

def test_scan_text_detects_sendgrid_key(scanner):
    token = "SG." + ("A" * 22) + "." + ("A" * 43)
    matches = scanner.scan_text(token)
    assert any(m.pattern.name == "SendGrid API Key" for m in matches)

def test_scan_text_ignores_short_sendgrid_like_string(scanner):
    token = "SG." + ("A" * 10) + "." + ("A" * 20)
    matches = scanner.scan_text(token)
    assert not any(m.pattern.name == "SendGrid API Key" for m in matches)

def test_has_secrets(scanner):
    assert scanner.has_secrets("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert not scanner.has_secrets("just a normal string")


def test_symlinks_not_followed(scanner, tmp_path):
    """Symlinks should be skipped to prevent traversal outside intended scope."""
    # Create an "outside" directory with a secret
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("AKIAIOSFODNN7ABCDEFG\n")

    # Create the scan target with a symlink pointing outside
    scan_dir = tmp_path / "project"
    scan_dir.mkdir()
    (scan_dir / "clean.txt").write_text("no secrets here\n")
    (scan_dir / "link_to_outside").symlink_to(outside)

    results = scanner.scan_directory(str(scan_dir))
    # The symlinked directory should not be followed
    assert len(results) == 0


def test_symlinked_file_not_followed(scanner, tmp_path):
    """Symlinked files should be skipped to prevent reading outside scope."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret_file = outside / "secret.txt"
    secret_file.write_text("AKIAIOSFODNN7ABCDEFG\n")

    scan_dir = tmp_path / "project"
    scan_dir.mkdir()
    (scan_dir / "link_to_secret.txt").symlink_to(secret_file)

    results = scanner.scan_directory(str(scan_dir))
    assert len(results) == 0


# The Node and Python CLIs must skip the same directories by default: Python
# once scanned vendor/ and reported 19,920 findings where Node reported 271.
def test_skips_the_same_default_directories_as_the_node_cli(scanner, tmp_path):
    skipped = ["node_modules", ".git", "dist", "build", ".next", "coverage", ".vscode", ".idea", "vendor", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "results", ".terraform", "bower_components"]
    for d in skipped:
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d / "creds.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n")
    (tmp_path / "creds.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n")
    results = scanner.scan_directory(str(tmp_path), respect_gitignore=False)
    assert [os.path.relpath(r.file, tmp_path) for r in results] == ["creds.env"]


# sable-ilbx — a file that cannot be read is not a clean scan. The scanner
# swallowed the read error and returned nothing, so a permission-denied file
# looked identical to one with no secrets.
def test_scan_file_surfaces_read_error(scanner, tmp_path):
    f = tmp_path / "secret.env"
    f.write_text("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef1234567890ABCDEFGHIJKL\n")
    f.chmod(0o000)
    try:
        result = scanner.scan_file(str(f))
        assert result.read_error
        assert len(result.matches) == 0
    finally:
        f.chmod(0o644)


def test_scan_directory_reports_unreadable_file(scanner, tmp_path):
    f = tmp_path / "secret.env"
    f.write_text("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef1234567890ABCDEFGHIJKL\n")
    f.chmod(0o000)
    try:
        results = scanner.scan_directory(str(tmp_path), respect_gitignore=False)
        unreadable = [r for r in results if r.read_error]
        assert len(unreadable) == 1
        assert unreadable[0].file == str(f)
    finally:
        f.chmod(0o644)
