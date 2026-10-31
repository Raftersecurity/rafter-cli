"""#231: `agent init --dry-run` must describe what the real run does, and the
instruction block a real run installs must not point at a skill it skipped.

Each test runs the dry run and the real run against the same fresh HOME and
compares the plan with what landed on disk. Mirrors
node/tests/agent-init-plan-parity.test.ts.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rafter_cli.__main__ import app

RESOURCES_SKILLS = Path(__file__).resolve().parent.parent / "rafter_cli" / "resources" / "skills"


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path
    proj = home / "proj"
    (home / ".claude").mkdir()
    proj.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(proj)
    return home, proj


def run(*args: str) -> str:
    result = CliRunner().invoke(app, list(args))
    assert result.exit_code == 0, result.output
    return result.stdout


def planned_writes(stdout: str) -> list[str]:
    out = []
    for line in stdout.splitlines():
        m = re.match(r"^\s+WRITE\s+(\S+)", line)
        if m and not m.group(1).endswith("/"):
            out.append(m.group(1))
    return out


def installed_claude_skills(home: Path) -> list[str]:
    d = home / ".claude" / "skills"
    if not d.exists():
        return []
    return [p.name for p in d.iterdir() if (p / "SKILL.md").exists()]


def test_user_scope_plan_matches_real_run(env):
    home, _ = env
    plan = planned_writes(run("agent", "init", "--with-claude-code", "--dry-run"))
    run("agent", "init", "--with-claude-code")

    assert [p for p in plan if not Path(p).exists()] == [], "planned but not written"
    unplanned = [
        str(home / ".claude" / "skills" / s / "SKILL.md")
        for s in installed_claude_skills(home)
        if str(home / ".claude" / "skills" / s / "SKILL.md") not in plan
    ]
    assert unplanned == [], "written but not planned"


def test_every_skill_named_in_claude_md_is_installed(env):
    home, _ = env
    run("agent", "init", "--with-claude-code")
    claude_md = (home / ".claude" / "CLAUDE.md").read_text()
    referenced = {
        n for n in re.findall(r"\brafter-[a-z-]+-[a-z]+\b", claude_md)
        if (RESOURCES_SKILLS / n).exists()
    }
    assert "rafter-skill-review" in referenced
    installed = installed_claude_skills(home)
    assert sorted(n for n in referenced if n not in installed) == []


def test_project_scope_plan_matches_real_run(env):
    _, proj = env
    plan = planned_writes(run("agent", "init", "--local", "--all", "--dry-run"))
    run("agent", "init", "--local", "--all")
    assert [p for p in plan if not Path(p).exists()] == [], "planned but not written"
    assert str(proj / ".mcp.json") in plan


def test_skipped_write_reported_as_skip(env):
    home, proj = env
    run("agent", "init")
    cfg_path = home / ".rafter" / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["agent"]["components"] = {"claude-code.mcp": {"enabled": False}}
    cfg_path.write_text(json.dumps(cfg, indent=2))

    out = run("agent", "init", "--local", "--with-claude-code", "--dry-run")
    mcp = proj / ".mcp.json"
    assert str(mcp) not in planned_writes(out)
    assert re.search(r"SKIP\s+\S*\.mcp\.json", out)

    run("agent", "init", "--local", "--with-claude-code")
    assert not mcp.exists()


def test_existing_betterleaks_not_planned_as_download(env, monkeypatch, tmp_path):
    home, _ = env
    binary = home / ".rafter" / "bin" / "betterleaks"
    binary.parent.mkdir(parents=True)
    binary.write_text("")
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    out = run("agent", "init", "--with-betterleaks", "--dry-run")
    assert not re.search(r"DOWNLOAD\s+\S*betterleaks", out)
    assert "0 downloads" in out
