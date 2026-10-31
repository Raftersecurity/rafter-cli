"""sable-28lv — `secrets --history` handed history to betterleaks alone.

The patterns engine scanned the working tree instead, so a secret in a deleted
file was found only if a betterleaks rule matched it, and without betterleaks
`--history` reported a clean scan of history it never read.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   cwd=cwd, check=True, capture_output=True)


def _secrets(cwd, *args):
    env = {**os.environ, "HOME": str(cwd)}
    r = subprocess.run([sys.executable, "-m", "rafter_cli", "secrets", *args],
                       cwd=cwd, env=env, capture_output=True, text=True, timeout=60)
    return r.stdout, r.stderr, r.returncode


def test_history_finds_secret_only_in_deleted_file(tmp_path):
    repo = (tmp_path / "repo").resolve()
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "README").write_text("hello\n")
    (repo / "aws.cfg").write_text(
        "[default]\nregion = us-east-1\naws_access_key_id = AKIAIOSFODNN7ABCDEFG\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add")
    _git(repo, "rm", "-q", "aws.cfg")
    _git(repo, "commit", "-q", "-m", "remove")

    out, err, rc = _secrets(repo, ".", "--history", "--engine", "patterns", "--json")
    assert rc == 1, err
    results = json.loads(out)["results"]
    assert len(results) == 1
    assert results[0]["file"] == str(repo / "aws.cfg")
    m = results[0]["matches"][0]
    assert m["pattern"]["name"] == "AWS Access Key ID"
    assert (m["line"], m["column"]) == (3, 21)


def test_history_outside_git_repo_is_an_error(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    _, err, rc = _secrets(plain, ".", "--history", "--engine", "patterns")
    assert rc == 2
    assert "not a git repository" in err.lower()
