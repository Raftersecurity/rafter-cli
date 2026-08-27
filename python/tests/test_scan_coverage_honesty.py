"""A scan that did not happen must never look like a scan that found nothing.

Two silent false negatives, both found by grey-box beta users driving the real
CLI and both confirmed by re-running their repro:

  - ``rafter secrets <unreadable>`` returned ``results: []`` and exit 0 — byte
    for byte what a genuinely clean directory returns. A CI job gating on the
    exit code cannot tell "nothing found" from "could not look", and the
    directory a scanner cannot enter is exactly where an unnoticed credential
    is most likely to be.
  - ``--engine betterleaks``, explicitly requested, returned zero findings and
    exit 0 on a file containing a canonical AWS key.

Mirrors node/tests/scan-coverage-honesty.test.ts.
"""
from __future__ import annotations

import json
import os
import site
import subprocess
import sys

import pytest

AWS_CANARY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
REPO_PYTHON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Overriding HOME moves PYTHONUSERBASE with it, which hides the user
# site-packages the CLI's own dependencies live in. Pin it, as test_e2e_cli does.
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
def locked_dir(tmp_path):
    d = tmp_path / "locked"
    d.mkdir()
    (d / "secret.js").write_text(f'const k = "{AWS_CANARY}";\n')
    os.chmod(d, 0o000)
    yield d
    os.chmod(d, 0o755)


def test_unreadable_target_exits_2_and_says_nothing_was_scanned(locked_dir, home):
    r = rafter(["secrets", str(locked_dir)], home)
    assert r.returncode == 2
    assert "Cannot read" in r.stderr
    assert "Nothing was scanned" in r.stderr


def test_unreadable_target_does_not_answer_like_an_empty_directory(locked_dir, home, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    unreadable = rafter(["secrets", str(locked_dir), "--json"], home)
    empty_scan = rafter(["secrets", str(empty), "--json"], home)

    assert empty_scan.returncode == 0
    assert json.loads(empty_scan.stdout)["results"] == []
    # The whole bug in one assertion: these two used to be identical.
    assert unreadable.returncode != empty_scan.returncode


def test_unreadable_subdirectory_is_reported_during_a_walk(tmp_path, home):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.js").write_text(f'const k = "{AWS_CANARY}";\n')
    vault = root / "vault"
    vault.mkdir()
    (vault / "keys.js").write_text(f'const k = "{AWS_CANARY}";\n')
    os.chmod(vault, 0o000)
    try:
        r = rafter(["secrets", str(root), "--json"], home)
        payload = json.loads(r.stdout)

        assert len(payload["results"]) > 0
        assert "skipped" in payload
        assert any("vault" in s["path"] for s in payload["skipped"])
    finally:
        os.chmod(vault, 0o755)


def test_complete_coverage_says_nothing_about_coverage(tmp_path, home):
    root = tmp_path / "clean"
    root.mkdir()
    (root / "ok.js").write_text("const x = 1;\n")

    # --engine patterns pins this to the one engine that cannot degrade. On
    # `auto` the result depends on whether the developer's betterleaks binary
    # happens to work, and a test whose meaning changes with the machine is
    # testing the machine.
    r = rafter(["secrets", str(root), "--json", "--engine", "patterns"], home)
    payload = json.loads(r.stdout)

    assert r.returncode == 0
    assert "skipped" not in payload
    assert "degraded" not in payload
