"""`rafter agent update` re-applies only the integrations already installed,
and `agent status` / `agent verify` say when what is installed is older than
this CLI. Runs against fixtures/install-0.11.2/home, the real state of a
published 0.11.2 `agent init --all`. Mirrors node/tests/agent-update.test.ts.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rafter_cli.__main__ import app

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "fixtures" / "install-0.11.2" / "home"
HOOK_FILES = (".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json")

_REAL = re.compile(r"(added|updated|kept|replaced) +(/\S+)")
_PLAN = re.compile(r"^\s+WRITE\s+(\S+)\s+\((added|updated|(\S+) kept: modified)\)", re.MULTILINE)
_UNCHANGED = re.compile(r"(\d+) files? unchanged")


def _unchanged(out: str) -> int:
    m = _UNCHANGED.search(out)
    return int(m.group(1)) if m else 0


def real_outcomes(out: str) -> dict:
    return {"files": [(m.group(2), m.group(1)) for m in _REAL.finditer(out)], "unchanged": _unchanged(out)}


def planned_outcomes(out: str) -> dict:
    files = [(m.group(3), "kept") if m.group(3) else (m.group(1), m.group(2)) for m in _PLAN.finditer(out)]
    return {"files": files, "unchanged": _unchanged(out)}


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    # No real `rafter` / `gemini` from the developer's PATH.
    monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: None)
    return tmp_path


def copy_fixture(home: Path) -> None:
    shutil.copytree(FIXTURE, home, dirs_exist_ok=True)
    for rel in HOOK_FILES:
        p = home / rel
        p.write_text(p.read_text().replace("__RAFTER_BIN__", "/usr/local/bin/rafter"))


def cli(*args: str):
    result = CliRunner().invoke(app, list(args))
    return result.output, result.exit_code


def test_update_reapplies_only_installed_platforms_matches_dry_run_and_is_idempotent(home):
    copy_fixture(home)
    # Leave Claude Code, Codex and Gemini installed. The other platforms'
    # directories stay (so they are "detected"), but rafter's files go.
    for rel in (
        ".cursor/rules", ".cursor/agents", ".cursor/hooks.json", ".cursor/mcp.json",
        ".windsurf", ".codeium/windsurf/mcp_config.json", ".continue/rules", ".continue/config.json",
        "RAFTER.md", ".aider.conf.yml", ".hermes/config.yaml", ".config/opencode/opencode.json", ".openclaw/workspace",
    ):
        p = home / rel
        shutil.rmtree(p) if p.is_dir() else p.unlink()

    plan = planned_outcomes(cli("agent", "update", "--dry-run")[0])
    out, code = cli("agent", "update")
    assert code == 0, out
    first = real_outcomes(out)
    assert plan == first
    assert any(o == "updated" for _, o in first["files"])
    assert {Path(p).relative_to(home).parts[0] for p, _ in first["files"]} == {".claude", ".agents"}

    for rel in (
        ".cursor/rules", ".cursor/mcp.json", ".windsurf", ".continue/rules", ".continue/config.json",
        "RAFTER.md", ".aider.conf.yml", ".hermes/config.yaml", ".config/opencode/opencode.json", ".openclaw/workspace",
    ):
        assert not (home / rel).exists(), rel
    assert "hook pretool" in (home / ".gemini" / "settings.json").read_text()

    second = real_outcomes(cli("agent", "update")[0])
    assert second["files"] == []
    assert second["unchanged"] == len(first["files"]) + first["unchanged"]


def test_update_with_nothing_installed_says_so_and_writes_nothing(home):
    (home / ".claude").mkdir()
    out, code = cli("agent", "update")
    assert code == 0, out
    assert "No rafter integrations found" in out
    assert [p.name for p in home.iterdir()] == [".claude"]
    assert list((home / ".claude").iterdir()) == []


def test_status_and_verify_flag_old_install_clear_after_update_and_keep_verify_exit_code(home):
    copy_fixture(home)
    before = json.loads(cli("agent", "status", "--json")[0])
    assert before["stale"] is True
    assert before["installed_version"] is None
    assert "rafter agent update" in cli("agent", "status")[0]

    assert cli("agent", "update", "--quiet")[1] == 0
    after = json.loads(cli("agent", "status", "--json")[0])
    assert after["stale"] is False
    assert after["installed_version"] == after["version"]
    fresh_out, fresh_code = cli("agent", "verify", "--json")
    assert json.loads(fresh_out.splitlines()[0])["stale"] is False
    assert "rafter agent update" not in cli("agent", "status")[0]

    # An older recorded version alone makes it stale, without failing verify.
    manifest = home / ".rafter" / "installed.json"
    doc = json.loads(manifest.read_text())
    manifest.write_text(json.dumps({**doc, "cliVersion": "0.0.1"}))
    old_out, old_code = cli("agent", "verify", "--json")
    old = json.loads(old_out.splitlines()[0])
    assert old["stale"] is True
    assert old["installed_version"] == "0.0.1"
    assert old_code == fresh_code
    assert "rafter agent update" in cli("agent", "verify")[0]
