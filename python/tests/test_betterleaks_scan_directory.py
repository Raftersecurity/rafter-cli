"""#262 — `betterleaks dir` ignores .gitignore, so handed a directory it walked
node_modules / build output / .env: slow enough to hit the timeout, and it
reported gitignored local secret stores. A fake binary stands in for
betterleaks: it logs its argv and reports every scanned file containing AKIA.
Mirrors node/tests/betterleaks-scan-directory.test.ts.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from rafter_cli.scanners.betterleaks import BetterleaksScanner

FAKE_BL = r"""#!/bin/sh
printf '%s\n' "$@" >> "$FAKE_BL_ARGV"
[ -n "$FAKE_BL_SLEEP" ] && sleep "$FAKE_BL_SLEEP"
report=""
while [ $# -gt 0 ]; do
  case "$1" in -r|--report-path) report="$2"; shift 2;; --) shift; break;; *) shift;; esac
done
out=""; sep=""
for f in $(find "$@" -type f); do
  if grep -q AKIA "$f"; then
    out="$out$sep{\"File\":\"$f\",\"RuleID\":\"aws-access-token\",\"Description\":\"AWS\",\"Secret\":\"AKIAQYLPMN5HHHFPZAM2\",\"Match\":\"AKIAQYLPMN5HHHFPZAM2\",\"StartLine\":1,\"EndLine\":1,\"StartColumn\":1,\"EndColumn\":1,\"Tags\":[]}"
    sep=","
  fi
done
echo "[$out]" > "$report"
[ -n "$sep" ] && exit 1
exit 0
"""

SECRET = "aws_key = AKIAQYLPMN5HHHFPZAM2\n"

# The stub must be executable, and the system temp dir is often mounted noexec
# (sable-m8vv). Keep it beside the tests, which are on an executable
# filesystem wherever this suite can run; RAFTER_TEST_EXEC_DIR overrides.
EXEC_BASE = os.environ.get("RAFTER_TEST_EXEC_DIR") or os.path.join(os.path.dirname(__file__), ".exec-tmp")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "build").mkdir(parents=True)
    os.makedirs(EXEC_BASE, exist_ok=True)
    bin_dir = tempfile.mkdtemp(prefix="bl-", dir=EXEC_BASE)
    bin_path = Path(bin_dir) / "betterleaks"
    bin_path.write_text(FAKE_BL)
    bin_path.chmod(0o755)
    argv_log = tmp_path / "argv.log"
    monkeypatch.setenv("FAKE_BL_ARGV", str(argv_log))

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".gitignore").write_text(".env\nbuild/\n")
    (repo / ".env").write_text(SECRET)
    (repo / "build" / "out.js").write_text(SECRET)
    (repo / "tracked.js").write_text(SECRET)
    (repo / "untracked.js").write_text(SECRET)
    subprocess.run(["git", "add", ".gitignore", "tracked.js"], cwd=repo, check=True)

    scanner = BetterleaksScanner()
    scanner._path = str(bin_path)
    yield scanner, repo, argv_log
    shutil.rmtree(bin_dir, ignore_errors=True)


def _reported(results, repo):
    return sorted(os.path.relpath(r.file, repo) for r in results)


def test_skips_gitignored_files_by_default(setup):
    scanner, repo, _ = setup
    assert _reported(scanner.scan_directory(str(repo)), repo) == ["tracked.js", "untracked.js"]


def test_scans_gitignored_files_when_asked(setup):
    scanner, repo, _ = setup
    results = scanner.scan_directory(str(repo), respect_gitignore=False)
    assert _reported(results, repo) == sorted(
        [".env", os.path.join("build", "out.js"), "tracked.js", "untracked.js"]
    )


def test_still_applies_the_targets_own_config(setup):
    scanner, repo, argv_log = setup
    (repo / ".betterleaks.toml").write_text("[extend]\nuseDefault = true\n")
    scanner.scan_directory(str(repo))
    argv = argv_log.read_text().split("\n")
    assert argv[argv.index("-c") + 1] == str(repo / ".betterleaks.toml")


def test_timeout_is_an_error_not_a_clean_scan(setup, monkeypatch):
    # A timed-out scan used to return [] — read as "no secrets" by the
    # betterleaks-only engine instead of falling back to patterns.
    scanner, repo, _ = setup

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 60)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        scanner.scan_directory(str(repo), use_git=True)
