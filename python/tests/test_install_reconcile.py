"""A file the user modified is kept with the new version beside it as
<file>.rafter-new; rafter flags it until the user reconciles, then notices
that they did. The pretool hook applies updates to unmodified files on its
own, once a day. Fixture: fixtures/install-0.11.2/home, the real state of a
published 0.11.2 `agent init --all`. Mirrors node/tests/install-reconcile.test.ts.
"""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rafter_cli.__main__ import app
from rafter_cli.commands.auto_update import auto_update_line, auto_update_stamp_path, maybe_auto_update
from rafter_cli.commands.install_files import (
    FileArtifact,
    InstallSession,
    _resources,
    manifest_path,
    sha256,
)

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "fixtures" / "install-0.11.2" / "home"
HOOK_FILES = (".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json")
DAY = 24 * 60 * 60 * 1000


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("RAFTER_DISABLE_AUTO_UPDATE", raising=False)
    # No real `rafter` / `gemini` from the developer's PATH.
    monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: None)
    return tmp_path


def copy_fixture(home: Path) -> None:
    shutil.copytree(FIXTURE, home, dirs_exist_ok=True)
    for rel in HOOK_FILES:
        p = home / rel
        p.write_text(p.read_text().replace("__RAFTER_BIN__", "/usr/local/bin/rafter"))


class _Silent:
    def info(self, message: str = "") -> None:
        pass

    def warn(self, message: str) -> None:
        pass


class TestReconcile:
    def _run(self, home: Path, content: str) -> str:
        s = InstallSession(root=home, out=_Silent(), version="test")
        outcome = s.apply(FileArtifact(home / "f.md", content.encode(), "not-shipped", "c", "p"))
        s.save()
        return outcome

    def _entry(self, home: Path) -> dict:
        return json.loads(manifest_path(home).read_text())["files"]["f.md"]

    def test_kept_until_the_user_acts_reconciled_once_then_quiet(self, home):
        f, pending = home / "f.md", home / "f.md.rafter-new"
        assert self._run(home, "v1") == "added"
        f.write_text("v1 + mine")

        assert self._run(home, "v2") == "kept"
        assert pending.read_text() == "v2"
        assert self._run(home, "v2") == "kept"  # still flagged while .rafter-new waits

        pending.unlink()  # "keep mine"
        assert self._run(home, "v2") == "reconciled"
        assert self._entry(home)["reconciledWith"] == sha256(b"v2")
        assert self._run(home, "v2") == "unchanged"
        assert not pending.exists()
        assert f.read_text() == "v1 + mine"

        assert self._run(home, "v3") == "kept"  # a new release flags it again
        assert pending.read_text() == "v3"

    def test_merging_into_rafter_new_and_moving_it_over_reconciles(self, home):
        f, pending = home / "f.md", home / "f.md.rafter-new"
        self._run(home, "v1")
        f.write_text("v1 + mine")
        assert self._run(home, "v2") == "kept"
        pending.write_text("v2 + mine")
        assert self._run(home, "v2") == "kept"  # the merge in progress is not overwritten
        assert pending.read_text() == "v2 + mine"

        pending.replace(f)
        assert self._run(home, "v2") == "reconciled"
        assert self._run(home, "v2") == "unchanged"
        assert f.read_text() == "v2 + mine"

    def test_taking_rafters_version_as_is_clears_the_state(self, home):
        f, pending = home / "f.md", home / "f.md.rafter-new"
        self._run(home, "v1")
        f.write_text("v1 + mine")
        self._run(home, "v2")
        shutil.copyfile(pending, f)  # copied, not moved: the leftover goes too
        assert self._run(home, "v2") == "unchanged"
        assert not pending.exists()
        assert "pendingSha" not in self._entry(home)
        assert self._run(home, "v3") == "updated"


class TestHookAutoUpdate:
    def _shipped(self, rel: str) -> bytes:
        node = _resources()
        for part in rel.split("/"):
            node = node.joinpath(part)
        return node.read_bytes()

    def test_updates_unmodified_keeps_and_flags_edited_runs_once_per_day(self, home):
        copy_fixture(home)
        skill = home / ".claude" / "skills" / "rafter" / "SKILL.md"
        edited = home / ".cursor" / "rules" / "rafter.mdc"
        edited.write_bytes(edited.read_bytes() + b"\nmy local note\n")
        mine = edited.read_bytes()
        now = int(time.time() * 1000)

        r = maybe_auto_update(home, now, "99.0.0")
        assert r is not None and r.updated > 0
        assert r.needs_reconcile == [edited]
        assert skill.read_bytes() == self._shipped("skills/rafter/SKILL.md")
        assert edited.read_bytes() == mine
        assert Path(f"{edited}.rafter-new").read_bytes() == self._shipped("cursor-rules/rafter.mdc")
        assert f"{edited}.rafter-new" in auto_update_line(r)
        # Only files: the manifest does not claim the whole install is current.
        assert json.loads(manifest_path(home).read_text())["cliVersion"] is None

        assert maybe_auto_update(home, now + 60_000, "99.0.0") is None
        next_day = maybe_auto_update(home, now + DAY + 1, "99.0.0")
        assert next_day is not None and next_day.updated == 0
        assert next_day.needs_reconcile == [edited]

    def test_does_not_bring_back_a_removed_skill(self, home):
        copy_fixture(home)
        shutil.rmtree(home / ".claude" / "skills" / "rafter-code-review")
        maybe_auto_update(home, None, "99.0.0")
        assert not (home / ".claude" / "skills" / "rafter-code-review").exists()

    def test_leaves_a_symlink_at_a_file_or_its_rafter_new_alone(self, home):
        # Both links dangle: a link at an existing file is refused by the
        # .rafter-new merge guard anyway, so it would not show the skip working.
        copy_fixture(home)
        outside = home / "outside"
        outside.mkdir()
        skill = home / ".claude" / "skills" / "rafter" / "SKILL.md"
        skill.unlink()
        skill.symlink_to(outside / "dangling")
        rule = home / ".cursor" / "rules" / "rafter.mdc"
        rule.write_bytes(rule.read_bytes() + b"\nmine\n")
        pending = Path(f"{rule}.rafter-new")
        pending.symlink_to(outside / "victim")
        maybe_auto_update(home, None, "99.0.0")
        assert list(outside.iterdir()) == []
        assert skill.readlink() == outside / "dangling"
        assert pending.readlink() == outside / "victim"
        assert not Path(f"{skill}.rafter-new").exists()

    def test_nothing_when_current_empty_or_disabled(self, home, monkeypatch):
        assert maybe_auto_update(home, None, "99.0.0") is None  # empty home
        assert auto_update_stamp_path(home).exists()

        copy_fixture(home)
        auto_update_stamp_path(home).unlink()
        manifest_path(home).write_text(json.dumps({"schema": 1, "cliVersion": "99.0.0", "files": {}}))
        assert maybe_auto_update(home, None, "99.0.0") is None

        auto_update_stamp_path(home).unlink()
        manifest_path(home).unlink()
        monkeypatch.setenv("RAFTER_DISABLE_AUTO_UPDATE", "1")
        assert maybe_auto_update(home, None, "99.0.0") is None
        skill = Path(".claude/skills/rafter/SKILL.md")
        assert (home / skill).read_bytes() == (FIXTURE / skill).read_bytes()


def test_cli_hook_status_and_update_agree_on_reconcile_state(home):
    copy_fixture(home)
    skill = home / ".claude" / "skills" / "rafter" / "SKILL.md"
    skill.write_bytes(skill.read_bytes() + b"\nmy local note\n")

    hook = CliRunner().invoke(app, ["hook", "pretool"], input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}))
    assert hook.exit_code == 0
    assert hook.stdout == "{}\n"
    assert re.search(r"^rafter: updated \d+ skill/rule files to .*needs? reconciling with .*SKILL\.md\.rafter-new", hook.stderr, re.M)
    assert Path(f"{skill}.rafter-new").exists()

    status = json.loads(CliRunner().invoke(app, ["agent", "status", "--json"]).stdout)
    assert str(skill) in status["needs_reconcile"]
    assert status["stale"] is True  # hooks and instruction blocks still need `agent update`
    text = CliRunner().invoke(app, ["agent", "status"]).output
    assert f"{skill}.rafter-new" in text
    assert "To reconcile: merge your changes into <file>.rafter-new" in text

    Path(f"{skill}.rafter-new").unlink()
    update = CliRunner().invoke(app, ["agent", "update"]).output
    assert re.search(rf"reconciled +{re.escape(str(skill))}", update)
    again = CliRunner().invoke(app, ["agent", "update"]).output
    assert str(skill) not in again
    assert json.loads(CliRunner().invoke(app, ["agent", "status", "--json"]).stdout)["needs_reconcile"] == []
