"""Local usage counters. Mirrors node/tests/usage-counters.test.ts."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from rafter_cli.core import usage_counters as uc

SHARED = Path(__file__).resolve().parents[2] / "shared-docs" / "usage-counters.json"

# Built at runtime so no key-shaped literal sits in the repo.
FAKE_KEY = "AKIA" + "Z" * 16
# Each input carries the repo name "secret-repo" inside a path, URL or slug. A
# bare lowercase token is the one documented exception: the unknown-command
# counter keeps it locally (shared-docs/CLI_SPEC.md), so it is not fed here.
LEAKS = ["/home/x/secret-repo", "https://github.com/acme/secret-repo.git", FAKE_KEY, "acme/secret-repo", f"secret-repo {FAKE_KEY}"]

BASH_LS = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls /home/x/secret-repo"}})


@pytest.fixture(autouse=True)
def _reset():
    uc.reset_pending()
    yield
    uc.reset_pending()


def _usage_files(home: Path) -> list[Path]:
    d = home / ".rafter" / "usage"
    return sorted(d.iterdir()) if d.exists() else []


def _rafter(home: Path, *args: str, stdin: str = "", cwd: Path | None = None, env: dict | None = None):
    e = {**os.environ, "HOME": str(home), "CI": "1"}
    e.pop("DO_NOT_TRACK", None)
    e.pop("RAFTER_TELEMETRY", None)
    e.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args],
        input=stdin, capture_output=True, text=True, cwd=str(cwd or home), env=e, timeout=60,
    )


def test_allowlist_matches_shared_file():
    """Fails if the Python allowlist drifts from the shared file Node also embeds."""
    shared = json.loads(SHARED.read_text(encoding="utf-8"))
    shared.pop("description")
    assert uc.USAGE_ALLOWLIST == shared


def test_never_stores_paths_urls_secrets_or_repo_names(tmp_path, monkeypatch):
    """Fails if any recorder lets a path, URL, secret or repo name reach the store."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("RAFTER_TELEMETRY", raising=False)

    class Report:
        def __init__(self, s):
            self.requested = self.used = self.reason = s
            self.degraded = True

    for s in LEAKS:
        uc.count_unknown_command(s)
        uc.count_unknown_option(f"--{s}")
        uc.count_unknown_option(f"--engine={s}")
        uc.set_command_path(["secrets", s])
        uc.count_hook(s, s, s)
        uc.count_scan(Report(s), 0.01)
        uc.count_error(type(s.replace("/", "_").replace(":", "_").replace(".", "_").replace(" ", "_"), (Exception,), {})(s))
        uc.count_error(TypeError(s))
        uc.write_counts({f"unknown_command:{s}": 1, f"command:{s}:exit:0": 1, s: 1})
    uc.flush(LEAKS[0])

    files = _usage_files(tmp_path)
    assert len(files) == 1
    stored = files[0].read_text(encoding="utf-8")
    # Positive control: the recorders ran and wrote their fall-back values.
    assert '"unknown_command:other"' in stored
    assert '"error_class:other:TypeError"' in stored
    for s in [*LEAKS, "secret-repo", FAKE_KEY]:
        assert s not in stored


def test_counts_a_real_cli_session(tmp_path):
    """Fails if `rafter` stops counting a real session: unknown command, hook decision, scan, command result."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("x = 1\n")
    _rafter(tmp_path, "acme-payroll")
    assert _rafter(tmp_path, "hook", "pretool", stdin=BASH_LS).returncode == 0
    _rafter(tmp_path, "secrets", "--json", "--engine", "patterns", str(proj))
    out = _rafter(tmp_path, "telemetry", "show", "--json")
    assert out.returncode == 0, out.stderr
    report = json.loads(out.stdout)
    assert report["store"] == "~/.rafter/usage"
    assert report["enabled"] is True
    assert report["counters"]["unknown_command"]["unknown_command:acme-payroll"] == 1
    assert report["counters"]["hook"]["hook:shell:allow:low"] == 1
    assert report["counters"]["command"]["command:hook.pretool:exit:0"] == 1
    assert report["counters"]["scan_engine"]["scan_engine:patterns:patterns"] == 1
    assert "secret-repo" not in _usage_files(tmp_path)[0].read_text()


def test_writes_nothing_when_disabled_whatever_rafter_yml_says(tmp_path):
    """Fails if a kill switch or the global setting stops working, or a project .rafter.yml can turn counting on."""
    _rafter(tmp_path, "hook", "pretool", stdin=BASH_LS, env={"DO_NOT_TRACK": "1"})
    _rafter(tmp_path, "hook", "pretool", stdin=BASH_LS, env={"RAFTER_TELEMETRY": "off"})
    assert _usage_files(tmp_path) == []

    (tmp_path / ".rafter").mkdir(exist_ok=True)
    (tmp_path / ".rafter" / "config.json").write_text(json.dumps({"agent": {"usage": {"enabled": False}}}))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".rafter.yml").write_text("usage:\n  enabled: true\nagent:\n  usage:\n    enabled: true\n")
    _rafter(tmp_path, "hook", "pretool", stdin=BASH_LS, cwd=proj)
    assert _usage_files(tmp_path) == []

    # Positive control: the same call with the setting removed does write.
    (tmp_path / ".rafter" / "config.json").write_text("{}")
    _rafter(tmp_path, "hook", "pretool", stdin=BASH_LS, cwd=proj)
    assert len(_usage_files(tmp_path)) == 1
