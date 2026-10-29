"""#262 — `betterleaks dir` ignores .gitignore, so handed a directory it walked
node_modules / build output / .env: slow enough to hit the timeout, and it
reported gitignored local secret stores. A fake binary stands in for
betterleaks: it logs its argv, keeps a copy of its -c config, and reports
every file under its targets containing AKIA.
Mirrors node/tests/betterleaks-scan-directory.test.ts.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

import sys
import tomllib

from rafter_cli.scanners.betterleaks import BetterleaksScanner, git_skipped_paths, scan_config_toml

# The developer's own betterleaks config must not leak into these tests.
CONFIG_ENV_VARS = ("BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML")

FAKE_BL = r"""#!/bin/sh
printf '%s\n' "$@" >> "$FAKE_BL_ARGV"
prev=""; for a in "$@"; do [ "$prev" = "-c" ] && cp "$a" "$FAKE_BL_CFG"; prev="$a"; done
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
    monkeypatch.setenv("FAKE_BL_CFG", str(tmp_path / "scan.toml"))
    for v in CONFIG_ENV_VARS:
        monkeypatch.delenv(v, raising=False)

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".gitignore").write_text(".env\nbuild/\n")
    (repo / ".env").write_text(SECRET)
    (repo / "build" / "out.js").write_text(SECRET)
    (repo / "tracked.js").write_text(SECRET)
    (repo / "untracked.js").write_text(SECRET)
    subprocess.run(["git", "add", ".gitignore", "tracked.js"], cwd=repo, check=True)

    scanner = BetterleaksScanner()
    scanner._path = str(bin_path)
    yield scanner, repo, argv_log, tmp_path / "scan.toml"
    shutil.rmtree(bin_dir, ignore_errors=True)


def _reported(results, repo):
    return sorted(os.path.relpath(r.file, repo) for r in results)


def _skipped_by(toml, repo):
    # The fake ignores the config, so read off it what betterleaks would skip.
    pats = [re.compile(json.loads(m)) for m in re.findall(r"^  (\".*\"),$", toml, re.M)]
    return lambda rel: any(p.search(os.path.join(str(repo), rel)) for p in pats)


def test_walks_the_target_once_under_a_config_that_skips_what_git_ignores(setup):
    scanner, repo, argv_log, cfg = setup
    scanner.scan_directory(str(repo))
    argv = argv_log.read_text().strip().split("\n")
    assert argv[argv.index("--") + 1:] == [str(repo)]
    toml = cfg.read_text()
    assert re.search(r"^useDefault = true$", toml, re.M)
    files = [".env", os.path.join("build", "out.js"), "tracked.js", "untracked.js"]
    assert [f for f in files if _skipped_by(toml, repo)(f)] == [".env", os.path.join("build", "out.js")]


def test_scans_gitignored_files_when_asked(setup):
    scanner, repo, _, _ = setup
    results = scanner.scan_directory(str(repo), respect_gitignore=False)
    assert _reported(results, repo) == sorted(
        [".env", os.path.join("build", "out.js"), "tracked.js", "untracked.js"]
    )


def test_carries_the_targets_own_config(setup):
    scanner, repo, _, cfg = setup
    (repo / ".betterleaks.toml").write_text("[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['x']\n")
    scanner.scan_directory(str(repo))
    toml = cfg.read_text()
    assert "[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = ['x']\n" in toml
    assert not re.search(r"^\[allowlist\]", toml, re.M)


def test_carries_the_config_betterleaks_would_pick(setup, monkeypatch):
    scanner, repo, _, cfg = setup
    (repo / ".betterleaks.toml").write_text("# repo file\n")
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", "# env content\n")
    scanner.scan_directory(str(repo))
    assert "# env content\n" in cfg.read_text()

    env_file = repo / "env-path.toml"
    env_file.write_text("# env path\n")
    monkeypatch.setenv("BETTERLEAKS_CONFIG", str(env_file))
    scanner.scan_directory(str(repo))
    toml = cfg.read_text()
    assert "# env path\n" in toml
    assert "# env content" not in toml
    assert "# repo file" not in toml


# The skip list and the generated config decide what betterleaks never reads,
# so an error in either hides secrets. These need git but not betterleaks.
def _git(repo, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout


def _skips(toml, abs_path):
    return any(re.search(p, abs_path) for p in tomllib.loads(toml)["allowlists"][0]["paths"])


def test_skip_list_scans_tracked_file_now_dir_but_skips_submodules_and_nested_repos(tmp_path):
    repo = tmp_path
    _git(repo, "init", "-q")
    (repo / "vendor").write_text("x\n")
    _git(repo, "add", "vendor")
    _git(repo, "commit", "-qm", "c")
    (repo / "vendor").unlink()
    (repo / "vendor").mkdir()
    (repo / "vendor" / "s.js").write_text(SECRET)
    sha = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sha},sub")
    (repo / "sub").mkdir()
    (repo / "nested").mkdir()
    _git(repo / "nested", "init", "-q")
    (repo / "nested" / "n.js").write_text(SECRET)
    assert sorted(git_skipped_paths(str(repo))) == ["nested/", "sub"]


@pytest.mark.skipif(sys.platform == "win32", reason="a backslash is a separator on Windows")
def test_config_keeps_a_backslash_in_a_posix_filename_literal(tmp_path):
    toml = scan_config_toml(str(tmp_path), ["trigger\\x.txt"], None)
    assert _skips(toml, os.path.join(str(tmp_path), "trigger\\x.txt"))
    assert not _skips(toml, os.path.join(str(tmp_path), "trigger", "x.txt"))


def test_config_is_valid_toml_whatever_the_filenames(tmp_path):
    toml = scan_config_toml(str(tmp_path), ["d\x7fel.txt", "t\tab", "n\nl"], None)
    assert tomllib.loads(toml)["extend"]["useDefault"] is True
    assert _skips(toml, os.path.join(str(tmp_path), "d\x7fel.txt"))


@pytest.mark.skipif(shutil.which("betterleaks") is None, reason="needs the betterleaks binary")
def test_real_betterleaks_scans_what_the_skip_list_must_not_touch(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / ".gitignore").write_text("*.txt\n")
    (repo / "vendor").write_text("x\n")
    _git(repo, "add", "vendor", ".gitignore")
    _git(repo, "commit", "-qm", "c")
    (repo / "vendor").unlink()
    (repo / "vendor").mkdir()
    pat = lambda i: f'const t = "ghp_{str(i) * 4}Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXyZ0";\n'
    (repo / "vendor" / "v.js").write_text(pat(1))
    (repo / "trigger").mkdir()
    (repo / "trigger" / "x.txt").write_text(pat(2))
    _git(repo, "add", "-f", "trigger/x.txt")
    (repo / "trigger\\x.txt").write_text("ignored\n")
    (repo / "d\x7fel.txt").write_text(pat(3))
    scanner = BetterleaksScanner()
    scanner._path = shutil.which("betterleaks")
    files = sorted(os.path.relpath(r.file, repo) for r in scanner.scan_directory(str(repo)))
    assert files == [os.path.join("trigger", "x.txt"), os.path.join("vendor", "v.js")]


# #262 — betterleaks 1.1.x never resets its extend-depth counter, so handed many
# paths under a config that extends the default rules, it applied rules to the
# first two paths only. Needs the real binary on PATH; skipped without it.
@pytest.mark.skipif(shutil.which("betterleaks") is None, reason="needs the betterleaks binary")
def test_real_betterleaks_applies_extended_rules_to_every_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".betterleaks.toml").write_text("[extend]\nuseDefault = true\n")
    (repo / ".gitignore").write_text(".env\n")
    pat = lambda i: f'const t = "ghp_{str(i) * 4}Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXyZ0";\n'
    for i in range(1, 5):
        (repo / f"f{i}.js").write_text(pat(i))
    (repo / ".env").write_text(pat(9))
    scanner = BetterleaksScanner()
    scanner._path = shutil.which("betterleaks")
    files = sorted(os.path.basename(r.file) for r in scanner.scan_directory(str(repo)))
    assert files == ["f1.js", "f2.js", "f3.js", "f4.js"]


# A repo config that extends a shared config, which extends the default
# rules: a depth betterleaks follows itself, which a generated config that
# extended the repo's exceeded (sable-v6f0).
@pytest.mark.skipif(shutil.which("betterleaks") is None, reason="needs the betterleaks binary")
def test_real_betterleaks_keeps_default_rules_two_extends_away_and_the_repo_allowlist(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    org = repo / "org.toml"
    org.write_text("[extend]\nuseDefault = true\n")
    (repo / ".betterleaks.toml").write_text("\n".join([
        "[extend]", f"path = {json.dumps(str(org))}", "",
        "[[rules]]", 'id = "repo-custom"', "regex = 'REPOSECRET_[0-9]{6}'", "",
        "[allowlist]", "paths = ['allowed\\.js$']", "",
    ]))
    (repo / ".gitignore").write_text(".env\n")
    gh = 'const t = "ghp_1111Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXyZ0";\n'
    (repo / "a.js").write_text(gh + 'const r = "REPOSECRET_123456";\n')
    (repo / "allowed.js").write_text(gh)
    (repo / ".env").write_text(gh)
    scanner = BetterleaksScanner()
    scanner._path = shutil.which("betterleaks")
    found = sorted(
        f"{os.path.basename(r.file)}:{m.pattern.name}" for r in scanner.scan_directory(str(repo)) for m in r.matches
    )
    assert found == ["a.js:github-pat", "a.js:repo-custom"]


def test_timeout_is_an_error_not_a_clean_scan(setup, monkeypatch):
    # A timed-out scan used to return [] — read as "no secrets" by the
    # betterleaks-only engine instead of falling back to patterns.
    scanner, repo, _, _ = setup

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 60)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        scanner.scan_directory(str(repo), use_git=True)
