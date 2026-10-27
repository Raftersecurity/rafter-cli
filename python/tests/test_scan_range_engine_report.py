"""sable-jiqb — two surfaces, mirrored from
node/tests/scan-range-engine-report.test.ts:
  --range <a>..<b>  scope a scan to a commit range's changed files.
  engine reporting  the JSON must name the engine actually used and flag any
                    fall-back, so a betterleaks miss is never silent.
"""
from __future__ import annotations

import json
import os
import site
import subprocess
import sys

import pytest


def _git(args: str, cwd: str) -> str:
    return subprocess.run(
        ["git", *args.split()], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


# The source package dir (python/), so the subprocess imports THIS tree rather
# than any stale pip-installed rafter_cli. Captured with the real user-site
# (where deps like typer live) at import time, under the real HOME — a test that
# overrides HOME moves the user-site, so both must be pinned on PYTHONPATH to
# keep the source package and its dependencies importable.
_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_USER_SITE = site.getusersitepackages()


def _rafter(args, cwd, env=None):
    # sys.executable (absolute) so a test can blank PATH without losing python.
    full_env = {**os.environ, **(env or {})}
    parts = [_SRC, _USER_SITE]
    if full_env.get("PYTHONPATH"):
        parts.append(full_env["PYTHONPATH"])
    full_env["PYTHONPATH"] = os.pathsep.join(parts)
    return subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args],
        cwd=cwd, capture_output=True, text=True, timeout=120,
        env=full_env,
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git("init", str(r))
    _git("config user.email t@example.com", str(r))
    _git("config user.name t", str(r))
    (r / "README.md").write_text("# repo\n")
    _git("add README.md", str(r))
    _git("commit -m initial", str(r))
    return r


class TestRange:
    def test_finds_secret_within_range(self, repo, tmp_path):
        base = _git("rev-parse HEAD", str(repo))
        (repo / "cfg.py").write_text("k = 'AKIAIOSFODNN7ABCDEFG'\n")
        _git("add cfg.py", str(repo))
        _git("commit -m add-secret", str(repo))
        head = _git("rev-parse HEAD", str(repo))

        r = _rafter(
            ["secrets", str(repo), "--range", f"{base}..{head}", "--engine", "patterns", "--json"],
            str(repo), env={"HOME": str(tmp_path)},
        )
        assert r.returncode == 1, r.stderr
        parsed = json.loads(r.stdout)
        assert parsed["results"][0]["matches"][0]["pattern"]["name"] == "AWS Access Key ID"

    def test_ignores_secret_outside_range(self, repo, tmp_path):
        (repo / "old.py").write_text("k = 'AKIAIOSFODNN7ABCDEFG'\n")
        _git("add old.py", str(repo))
        _git("commit -m old-secret", str(repo))
        base = _git("rev-parse HEAD", str(repo))
        (repo / "clean.py").write_text("x = 1\n")
        _git("add clean.py", str(repo))
        _git("commit -m clean", str(repo))
        head = _git("rev-parse HEAD", str(repo))

        r = _rafter(
            ["secrets", str(repo), "--range", f"{base}..{head}", "--engine", "patterns", "--quiet"],
            str(repo), env={"HOME": str(tmp_path)},
        )
        assert r.returncode == 0, r.stderr

    def test_rejects_option_like_range(self, repo, tmp_path):
        r = _rafter(
            ["secrets", str(repo), "--range", "--output=/tmp/x", "--engine", "patterns", "--quiet"],
            str(repo), env={"HOME": str(tmp_path)},
        )
        assert r.returncode == 2


class TestEngineReportJson:
    def test_patterns_scan_reports_engine_fields(self, tmp_path):
        d = tmp_path / "proj"
        d.mkdir()
        (d / "cfg.py").write_text("k = 'AKIAIOSFODNN7ABCDEFG'\n")
        r = _rafter(["secrets", str(d), "--engine", "patterns", "--json"], str(d),
                    env={"HOME": str(tmp_path)})
        assert r.returncode == 1, r.stderr
        parsed = json.loads(r.stdout)
        assert parsed["engine_requested"] == "patterns"
        assert parsed["engine_used"] == "patterns"
        assert parsed["degraded"] is False

    def test_degraded_flagged_when_betterleaks_unavailable(self, tmp_path):
        # PATH holds no betterleaks and HOME holds no managed binary, so the
        # requested betterleaks engine resolves to patterns — a downgrade the
        # JSON must carry rather than swallow.
        d = tmp_path / "proj"
        d.mkdir()
        (d / "cfg.py").write_text("k = 'AKIAIOSFODNN7ABCDEFG'\n")
        empty_bin = tmp_path / "emptybin"
        empty_bin.mkdir()
        clean_home = tmp_path / "home"
        clean_home.mkdir()
        r = _rafter(
            ["secrets", str(d), "--engine", "betterleaks", "--json"], str(d),
            env={"HOME": str(clean_home), "PATH": str(empty_bin)},
        )
        assert r.returncode == 1, r.stderr
        parsed = json.loads(r.stdout)
        assert parsed["engine_requested"] == "betterleaks"
        assert parsed["engine_used"] == "patterns"
        assert parsed["degraded"] is True
        assert isinstance(parsed["degraded_reason"], str) and parsed["degraded_reason"]
        assert parsed["results"][0]["matches"][0]["pattern"]["name"] == "AWS Access Key ID"
