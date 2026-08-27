"""The audit-log hint the scanner prints must be true.

``rafter secrets`` ends with "Run 'rafter agent audit' to see the security
log", and that log was always empty — only command interception ever wrote to
it. Three of seven beta users followed the hint and hit a dead end, one
immediately after a correct and useful scan result.

Mirrors node/tests/audit-records-scans.test.ts.
"""
from __future__ import annotations

import os
import site
import subprocess
import sys

import pytest

AWS_CANARY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
REPO_PYTHON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Overriding HOME moves PYTHONUSERBASE with it, which hides the user
# site-packages the CLI's dependencies live in. Pin it, as test_e2e_cli does.
_USER_BASE = site.getuserbase()


def rafter(args: list[str], home) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PYTHONPATH"] = REPO_PYTHON + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUSERBASE"] = _USER_BASE
    return subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args],
        capture_output=True, text=True, env=env, timeout=120,
    )


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "cfg.js").write_text(f'const k = "{AWS_CANARY}";\n')
    return root


def test_records_the_scan_that_pointed_the_user_at_the_audit_log(project, home):
    scan = rafter(["secrets", str(project)], home)
    assert "rafter agent audit" in scan.stdout

    audit = rafter(["agent", "audit"], home)
    assert "scan_executed" in audit.stdout
    assert "No audit log entries found" not in audit.stdout


def test_records_a_clean_scan_too(tmp_path, home):
    root = tmp_path / "clean"
    root.mkdir()
    (root / "ok.js").write_text("const x = 1;\n")

    rafter(["secrets", str(root), "--engine", "patterns"], home)

    assert "scan_executed" in rafter(["agent", "audit"], home).stdout


def test_never_writes_a_matched_secret_into_the_audit_log(project, home):
    # The log outlives the terminal. It must not become a second place secrets
    # live — pattern names and counts only.
    rafter(["secrets", str(project)], home)

    log = (home / ".rafter" / "audit.jsonl").read_text()
    assert "scan_executed" in log
    assert AWS_CANARY not in log
    assert "AWS Access Key" in log


def test_scan_survives_an_unwritable_audit_log(project, home):
    rafter_dir = home / ".rafter"
    rafter_dir.mkdir(parents=True, exist_ok=True)
    log = rafter_dir / "audit.jsonl"
    log.write_text("")
    os.chmod(log, 0o400)
    try:
        # The scan result is the product; logging is a side effect and must
        # never take the product down with it.
        r = rafter(["secrets", str(project)], home)
        assert r.returncode == 1  # findings, not a crash
        assert "secret(s) detected" in r.stdout
    finally:
        os.chmod(log, 0o600)
