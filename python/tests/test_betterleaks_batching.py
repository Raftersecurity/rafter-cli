"""sable-jiqb — betterleaks' cost scales with the explicit file list it is handed
(~0.2s/file), so one `dir -- <all tracked files>` call on a few-hundred-file repo
exceeds the per-invocation timeout and the engine silently falls back to patterns.
The scanner must split the file list into batches small enough that no single
invocation approaches the timeout, while still finding every secret and honoring
.gitignore. Mirrors node/tests/betterleaks-batching.test.ts.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from rafter_cli.scanners.betterleaks import BetterleaksScanner, MAX_FILES_PER_CALL

# A fake betterleaks that records, per invocation, the count of file targets it
# was handed (the args after `--`), then reports every scanned file with AKIA.
FAKE_BL = r"""#!/bin/sh
count=0; after=0
for a in "$@"; do
  [ "$after" = 1 ] && count=$((count+1))
  [ "$a" = "--" ] && after=1
done
echo "$count" >> "$FAKE_BL_CALLS"
report=""
while [ $# -gt 0 ]; do
  case "$1" in --report-path) report="$2"; shift 2;; --) shift; break;; *) shift;; esac
done
out=""; sep=""
for f in $(find "$@" -type f 2>/dev/null); do
  if grep -q AKIA "$f" 2>/dev/null; then
    out="$out$sep{\"File\":\"$f\",\"RuleID\":\"aws-access-token\",\"Description\":\"AWS\",\"Secret\":\"AKIAQYLPMN5HHHFPZAM2\",\"Match\":\"AKIAQYLPMN5HHHFPZAM2\",\"StartLine\":1,\"EndLine\":1,\"StartColumn\":1,\"EndColumn\":1,\"Tags\":[]}"
    sep=","
  fi
done
echo "[$out]" > "$report"
[ -n "$sep" ] && exit 1
exit 0
"""

EXEC_BASE = os.environ.get("RAFTER_TEST_EXEC_DIR") or os.path.join(os.path.dirname(__file__), ".exec-tmp")

N = MAX_FILES_PER_CALL + 10  # guarantees more than one batch


@pytest.fixture
def setup(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    os.makedirs(EXEC_BASE, exist_ok=True)
    bin_dir = tempfile.mkdtemp(prefix="bl-batch-", dir=EXEC_BASE)
    bin_path = Path(bin_dir) / "betterleaks"
    bin_path.write_text(FAKE_BL)
    bin_path.chmod(0o755)
    calls_log = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_BL_CALLS", str(calls_log))

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    secret_idx = N // 2
    for i in range(N):
        body = "k = 'AKIAQYLPMN5HHHFPZAM2'\n" if i == secret_idx else f"x{i} = {i}\n"
        (repo / f"f{i}.py").write_text(body)
    # A gitignored file carrying a secret must never be scanned.
    (repo / ".gitignore").write_text("secret.local\n")
    (repo / "secret.local").write_text("s = 'AKIAQYLPMN5HHHFPZAM2'\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

    scanner = BetterleaksScanner()
    scanner._path = str(bin_path)
    yield scanner, repo, calls_log, secret_idx
    shutil.rmtree(bin_dir, ignore_errors=True)


def test_splits_large_file_list_into_bounded_batches(setup):
    scanner, repo, calls_log, _ = setup
    scanner.scan_directory(str(repo))
    calls = [int(x) for x in calls_log.read_text().split()]
    assert len(calls) > 1
    assert max(calls) <= MAX_FILES_PER_CALL


def test_still_finds_secret_and_skips_gitignored(setup):
    scanner, repo, _, secret_idx = setup
    results = scanner.scan_directory(str(repo))
    reported = sorted(os.path.basename(r.file) for r in results)
    assert f"f{secret_idx}.py" in reported
    assert "secret.local" not in reported
