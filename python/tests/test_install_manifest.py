"""`rafter agent init` must not destroy a user's edit to a file it installed.

The fixture, fixtures/install-0.11.2/home, is the real on-disk state of the
published 0.11.2 `agent init --all` (captured from the npm package; ~/.rafter
left out). Hook and config files carry __RAFTER_BIN__ / __HOME__ placeholders.
Each test copies it to a temp HOME, so these run against what users have.
Mirrors node/tests/install-manifest.test.ts.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from rafter_cli.commands.install_files import (
    FileArtifact,
    InstallSession,
    claude_agent_artifacts,
    cleanup_retired_rules,
    cleanup_retired_skills,
    cursor_agent_artifacts,
    manifest_path,
    rule_artifacts,
    sha256,
    skill_artifacts,
)

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "fixtures" / "install-0.11.2" / "home"
HOOK_FILES = (".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json")


def copy_fixture(dest: Path) -> None:
    shutil.copytree(FIXTURE, dest, dirs_exist_ok=True)
    for rel in HOOK_FILES:
        p = dest / rel
        p.write_text(p.read_text().replace("__RAFTER_BIN__", "/usr/local/bin/rafter"))


class _Out:
    def __init__(self) -> None:
        self.warnings: list[str] = []

    def info(self, message: str = "") -> None:
        pass

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def session(home: Path, **kw) -> tuple[InstallSession, _Out]:
    out = _Out()
    return InstallSession(root=home, out=out, version="test", **kw), out


def platforms(home: Path) -> dict[str, list[FileArtifact]]:
    return {
        "claude-code": skill_artifacts(home / ".claude" / "skills", "claude-code", "claude-code.skills")
        + claude_agent_artifacts(home),
        "codex": skill_artifacts(home / ".agents" / "skills", "codex", "codex.skills"),
        "gemini": skill_artifacts(home / ".agents" / "skills", "gemini", "gemini.skills"),
        "cursor": rule_artifacts("cursor", home) + cursor_agent_artifacts(home),
        "windsurf": rule_artifacts("windsurf", home),
        "continue": rule_artifacts("continue", home),
    }


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path


# ── upgrade over a real 0.11.2 install ───────────────────────────────


@pytest.mark.parametrize("platform", ["claude-code", "codex", "gemini", "cursor", "windsurf", "continue"])
def test_every_shipped_file_is_brought_to_the_current_version(home, platform):
    copy_fixture(home)
    artifacts = platforms(home)[platform]
    # A file added to a skill since 0.11.2 is not in the fixture: it is "added".
    before = {a.dest: a.dest.read_bytes() if a.dest.exists() else None for a in artifacts}
    s, _ = session(home)
    outcomes = s.apply_all(artifacts)
    s.save()

    for a, outcome in zip(artifacts, outcomes):
        assert sha256(a.dest.read_bytes()) == sha256(a.content), a.dest
        was = before[a.dest]
        assert outcome == ("added" if was is None else "unchanged" if was == a.content else "updated"), a.dest
        assert not Path(f"{a.dest}.rafter-new").exists(), a.dest
    assert "updated" in outcomes
    manifest = json.loads(manifest_path(home).read_text())
    assert artifacts[0].dest.relative_to(home).as_posix() in manifest["files"]


def test_cursor_subagent_as_python_wrote_it_through_0_11_is_recognized(home):
    copy_fixture(home)
    # The old strip left a blank line where `tools:` was; re-create it from the 0.11.2 source.
    raw = (FIXTURE / ".claude" / "agents" / "rafter.md").read_text()
    end = raw.find("\n---", 4)
    legacy = "---\n" + re.sub(r"^tools:\s.*$\n?", "", raw[4:end], flags=re.MULTILINE) + raw[end:]
    dest = home / ".cursor" / "agents" / "rafter.md"
    dest.write_text(legacy)
    assert legacy != (FIXTURE / ".cursor" / "agents" / "rafter.md").read_text()
    s, _ = session(home)
    assert s.apply_all(cursor_agent_artifacts(home)) == ["updated"]


def test_cursor_subagent_bytes_match_what_node_writes(home):
    # Fails if the two runtimes strip `tools:` differently, which makes each
    # one rewrite the other's install on every run. The fixture holds Node's
    # output for the 0.11.2 source, so compare only while that source is current.
    from rafter_cli.commands.install_files import _resources

    source = _resources().joinpath("agents", "rafter.md").read_bytes()
    if source != (FIXTURE / ".claude" / "agents" / "rafter.md").read_bytes():
        pytest.skip("agents/rafter.md changed since 0.11.2; no Node output to compare against")
    assert cursor_agent_artifacts(home)[0].content == (FIXTURE / ".cursor" / "agents" / "rafter.md").read_bytes()


def test_hand_edited_skill_and_rule_are_kept_with_new_version_beside(home):
    copy_fixture(home)
    skill = home / ".claude" / "skills" / "rafter" / "SKILL.md"
    rule = home / ".cursor" / "rules" / "rafter.mdc"
    for p in (skill, rule):
        p.write_text(p.read_text() + "\nmy local note\n")
    edited = {p: p.read_bytes() for p in (skill, rule)}

    s, out = session(home)
    arts = platforms(home)
    all_arts = arts["claude-code"] + arts["cursor"]
    outcomes = {a.dest: s.apply(a) for a in all_arts}

    for p, data in edited.items():
        assert outcomes[p] == "kept"
        assert p.read_bytes() == data
        fresh = next(a.content for a in all_arts if a.dest == p)
        assert Path(f"{p}.rafter-new").read_bytes() == fresh
    assert len([w for w in out.warnings if "kept" in w]) == 2
    assert all(o in ("added", "updated", "unchanged") for p, o in outcomes.items() if p not in edited)


def test_second_run_reports_every_file_unchanged(home):
    copy_fixture(home)
    first, _ = session(home)
    first.apply_all([a for arts in platforms(home).values() for a in arts])
    first.save()
    second, _ = session(home)
    assert set(second.apply_all([a for arts in platforms(home).values() for a in arts])) == {"unchanged"}


def test_force_replaces_modified_file_and_keeps_old_as_bak(home):
    copy_fixture(home)
    skill = home / ".claude" / "skills" / "rafter" / "SKILL.md"
    skill.write_text("my rewrite\n")
    s, _ = session(home, force=True)
    a = next(x for x in platforms(home)["claude-code"] if x.dest == skill)
    assert s.apply(a) == "replaced"
    assert skill.read_bytes() == a.content
    assert Path(f"{skill}.bak").read_text() == "my rewrite\n"


# ── write policy ─────────────────────────────────────────────────────


def _artifact(home: Path, content: str, name: str = "f.md") -> FileArtifact:
    return FileArtifact(dest=home / name, content=content.encode(), resource_key="not-shipped", component="c", platform="p")


def test_manifest_proves_ownership_and_its_absence_means_keep(home):
    first, _ = session(home)
    assert first.apply(_artifact(home, "v1")) == "added"
    first.save()
    assert session(home)[0].apply(_artifact(home, "v2")) == "updated"

    (home / "f.md").write_text("v1")
    manifest_path(home).unlink()
    assert session(home)[0].apply(_artifact(home, "v3")) == "kept"


def test_corrupt_manifest_is_treated_as_absent_and_warns_once(home):
    manifest_path(home).parent.mkdir(parents=True)
    manifest_path(home).write_text("{not json")
    (home / "f.md").write_text("theirs")
    s, out = session(home)
    assert s.apply(_artifact(home, "ours")) == "kept"
    assert s.apply(_artifact(home, "ours", "g.md")) == "added"
    assert len([w for w in out.warnings if "unreadable install manifest" in w]) == 1


def test_dry_run_predicts_without_writing_and_sees_its_own_predictions(home):
    copy_fixture(home)
    s, _ = session(home, dry_run=True)
    arts = platforms(home)
    assert "updated" in s.apply_all(arts["codex"])
    assert set(s.apply_all(arts["gemini"])) == {"unchanged"}
    assert not manifest_path(home).exists()
    rel = Path(".agents/skills/rafter/SKILL.md")
    assert (home / rel).read_bytes() == (FIXTURE / rel).read_bytes()


# ── retired-artifact cleanup uses hashes as proof of ownership ───────
# 0.11.2 skills carry no publisher tag, so only the hash table can prove these
# are rafter's. "rafter" stands in for a retired name.


def test_removes_untagged_retired_skill_dir_and_rule_that_hash_to_shipped_content(home):
    copy_fixture(home)
    s, _ = session(home)
    assert len(cleanup_retired_skills(s, home / ".claude" / "skills", ("rafter",)).removed) == 1
    assert len(cleanup_retired_rules(s, "windsurf", ("rafter",)).removed) == 1
    assert not (home / ".claude" / "skills" / "rafter").exists()
    assert not (home / ".windsurf" / "rules" / "rafter.md").exists()


def test_keeps_retired_skill_dir_and_rule_the_user_modified(home):
    copy_fixture(home)
    for rel in (".claude/skills/rafter/docs/backend.md", ".windsurf/rules/rafter.md"):
        p = home / rel
        p.write_text(p.read_text() + "\nmine\n")
    s, _ = session(home)
    assert len(cleanup_retired_skills(s, home / ".claude" / "skills", ("rafter",)).kept) == 1
    assert len(cleanup_retired_rules(s, "windsurf", ("rafter",)).kept) == 1
    assert (home / ".claude" / "skills" / "rafter" / "SKILL.md").exists()
    assert (home / ".windsurf" / "rules" / "rafter.md").exists()


def test_node_and_python_ship_identical_hash_tables():
    node = (REPO / "node" / "resources" / "shipped-hashes.json").read_bytes()
    py = (REPO / "python" / "rafter_cli" / "resources" / "shipped-hashes.json").read_bytes()
    assert node == py


# ── one pass through the CLI ─────────────────────────────────────────
# The per-file report, the dry-run plan agreeing with the real run, and the
# marker-block / merged-config files (which do not go through the write
# policy) surviving an upgrade intact.

_FLAGS = ["--with-claude-code", "--with-codex", "--with-gemini", "--with-cursor", "--with-windsurf", "--with-continue", "--with-aider"]
_REAL = re.compile(r"(added|updated|kept|replaced) +(/\S+)")
_PLAN = re.compile(r"^\s+WRITE\s+(\S+)\s+\((added|updated|(\S+) kept: modified)\)", re.MULTILINE)
_UNCHANGED = re.compile(r"(\d+) files? unchanged")


def _unchanged(output: str) -> int:
    m = _UNCHANGED.search(output)
    return int(m.group(1)) if m else 0


def _real_outcomes(output: str) -> dict:
    """[path, outcome] per reported file of a real run, plus the unchanged count."""
    return {"files": [(m.group(2), m.group(1)) for m in _REAL.finditer(output)], "unchanged": _unchanged(output)}


def _planned_outcomes(output: str) -> dict:
    files = [(m.group(3), "kept") if m.group(3) else (m.group(1), m.group(2)) for m in _PLAN.finditer(output)]
    return {"files": files, "unchanged": _unchanged(output)}


def test_init_reports_each_file_keeps_edits_preserves_user_text_and_dedupes_hooks(home, monkeypatch):
    from typer.testing import CliRunner
    from rafter_cli.__main__ import app

    copy_fixture(home)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home)
    monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: None)

    user_text = "\n\nMY OWN NOTES — keep me\n"
    marker_files = [home / p for p in (".claude/CLAUDE.md", "AGENTS.md", ".gemini/GEMINI.md", "RAFTER.md")]
    for p in marker_files:
        p.write_text(p.read_text() + user_text)
    edited = home / ".continue" / "rules" / "rafter.md"
    edited.write_text(edited.read_text() + "\nmine\n")

    def init(*extra: str) -> str:
        result = CliRunner().invoke(app, ["agent", "init", *_FLAGS, *extra])
        assert result.exit_code == 0, result.output
        return result.output

    plan = _planned_outcomes(init("--dry-run"))
    first = _real_outcomes(init())
    assert plan == first
    assert (str(edited), "kept") in first["files"]
    assert any(o == "updated" for _, o in first["files"])
    assert first["unchanged"] > 0

    for p in marker_files:
        text = p.read_text()
        assert "MY OWN NOTES — keep me" in text, p
        assert text.count("<!-- rafter:start -->") == 1, p

    def hook_count(rel: str) -> int:
        return (home / rel).read_text().count("hook pretool")

    hooks_before = [hook_count(r) for r in HOOK_FILES]
    assert (home / ".aider.conf.yml").read_text().count("RAFTER.md") == 1

    second = _real_outcomes(init())
    assert second["files"] == [(str(edited), "kept")]
    assert second["unchanged"] == len(first["files"]) + first["unchanged"] - 1
    assert [hook_count(r) for r in HOOK_FILES] == hooks_before
    assert "rafter" in json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]


def test_enable_keeps_edited_skill_and_rule_writing_new_version_beside(home, monkeypatch):
    from typer.testing import CliRunner
    from rafter_cli.__main__ import app
    from rafter_cli.commands.agent_components import reset_registry_cache
    from rafter_cli.commands.install_files import _resources

    copy_fixture(home)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home)
    reset_registry_cache()
    skill = home / ".claude" / "skills" / "rafter" / "SKILL.md"
    rule = home / ".windsurf" / "rules" / "rafter.md"
    for p in (skill, rule):
        p.write_text(p.read_text() + "\nmine\n")
    edited = [p.read_bytes() for p in (skill, rule)]

    result = CliRunner().invoke(app, ["agent", "enable", "claude-code.skills", "windsurf.rules"])
    reset_registry_cache()
    assert result.exit_code == 0, result.output

    fresh = [
        _resources().joinpath("skills", "rafter", "SKILL.md").read_bytes(),
        _resources().joinpath("windsurf-rules", "rafter.md").read_bytes(),
    ]
    for p, before, new in zip((skill, rule), edited, fresh):
        assert p.read_bytes() == before, p
        assert Path(f"{p}.rafter-new").read_bytes() == new, p
        assert re.search(rf"kept +{re.escape(str(p))}", result.output), result.output


# ── no write follows a symlink a repo planted ────────────────────────
# A cloned repo controls every path under it. Each test plants a link where
# `agent init --local` writes (the file, its .bak / .rafter-new, the
# manifest) aimed at a file outside the project, then checks that file is
# untouched (existing target) or never created (dangling target).


@pytest.fixture
def repo(tmp_path: Path):
    victim = tmp_path / "outside" / "victim"
    victim.parent.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    skill = skill_artifacts(root / ".claude" / "skills", "claude-code", "claude-code.skills")[0]
    skill.dest.parent.mkdir(parents=True)
    return root, victim, skill


def _both_targets(repo, act) -> None:
    root, victim, skill = repo
    victim.write_text("user data\n")
    act()
    assert victim.read_text() == "user data\n"
    victim.unlink()
    for p in (skill.dest, Path(f"{skill.dest}.bak"), Path(f"{skill.dest}.rafter-new"), manifest_path(root)):
        if p.is_symlink() or p.exists():
            p.unlink()
    act()
    assert not victim.exists()


def _edited(skill) -> None:
    skill.dest.write_text("edited by the repo\n")


def test_force_does_not_follow_a_link_at_bak(repo):
    root, victim, skill = repo

    def act():
        _edited(skill)
        Path(f"{skill.dest}.bak").symlink_to(victim)
        assert session(root, force=True)[0].apply(skill) == "replaced"
        assert Path(f"{skill.dest}.bak").read_text() == "edited by the repo\n"

    _both_targets(repo, act)


def test_kept_does_not_follow_a_link_at_rafter_new(repo):
    root, victim, skill = repo

    def act():
        _edited(skill)
        Path(f"{skill.dest}.rafter-new").symlink_to(victim)
        assert session(root)[0].apply(skill) == "kept"

    _both_targets(repo, act)


def test_save_does_not_follow_a_link_at_the_manifest(repo):
    root, victim, skill = repo

    def act():
        manifest_path(root).parent.mkdir(exist_ok=True)
        manifest_path(root).symlink_to(victim)
        s, _ = session(root)
        s.apply(skill)
        s.save()
        assert json.loads(manifest_path(root).read_text())["files"]

    _both_targets(repo, act)


def test_a_link_at_the_file_itself_is_never_written_through(repo):
    root, victim, skill = repo

    def act():
        skill.dest.symlink_to(victim)
        assert session(root)[0].apply(skill) == "kept"
        assert Path(f"{skill.dest}.rafter-new").read_bytes() == skill.content
        assert session(root, force=True)[0].apply(skill) == "replaced"
        assert skill.dest.read_bytes() == skill.content
        assert Path(f"{skill.dest}.bak").is_symlink()

    _both_targets(repo, act)


def test_a_linked_directory_leading_out_of_the_project_is_refused(repo):
    root, victim, skill = repo
    skills_dir = root / ".claude" / "skills"
    shutil.rmtree(skills_dir)
    skills_dir.symlink_to(victim.parent)
    with pytest.raises(OSError, match="outside"):
        session(root)[0].apply(skill)
    assert list(victim.parent.iterdir()) == []
