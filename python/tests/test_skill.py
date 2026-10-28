"""Tests for `rafter skill list / install / uninstall`. Mirrors
node/tests/skill.test.ts. Each test uses a fake HOME so on-disk side effects
are observable and isolated.
"""
from __future__ import annotations

import json
import os
import site
import subprocess
import sys
from pathlib import Path

import pytest

# Captured under the real HOME so user-site packages (e.g. typer) remain
# importable in subprocesses launched with HOME overridden to tmp_path.
_USER_BASE = site.getuserbase()


def _run(args: str, home: Path) -> tuple[str, str, int]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["PYTHONUSERBASE"] = _USER_BASE
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args.split()],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path


class TestSkillList:
    def test_json_lists_bundled_skills(self, home: Path):
        stdout, _, code = _run("skill list --json", home)
        assert code == 0
        payload = json.loads(stdout)
        names = {s["name"] for s in payload["skills"]}
        assert {"rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"} <= names
        # Nothing installed yet in the pristine fake HOME.
        assert all(not row["installed"] for row in payload["installations"])

    def test_installed_filter(self, home: Path):
        (home / ".claude").mkdir()
        _run("skill install rafter-secure-design --platform claude-code", home)
        stdout, _, code = _run("skill list --json --installed", home)
        assert code == 0
        payload = json.loads(stdout)
        assert len(payload["installations"]) >= 1
        assert all(row["installed"] for row in payload["installations"])
        assert payload["installations"][0]["name"] == "rafter-secure-design"
        assert payload["installations"][0]["platform"] == "claude-code"

    def test_rejects_unknown_platform(self, home: Path):
        _, stderr, code = _run("skill list --platform bogus", home)
        assert code == 1
        assert "Unknown platform" in stderr


class TestSkillInstallUninstall:
    def test_round_trip_claude_code(self, home: Path):
        (home / ".claude").mkdir()
        skill_path = home / ".claude" / "skills" / "rafter-secure-design" / "SKILL.md"

        _, _, code = _run("skill install rafter-secure-design --platform claude-code", home)
        assert code == 0
        assert skill_path.exists()
        assert "rafter-secure-design" in skill_path.read_text(encoding="utf-8")

        _, _, code = _run("skill uninstall rafter-secure-design --platform claude-code", home)
        assert code == 0
        assert not skill_path.exists()

        _, _, code = _run("skill install rafter-secure-design --platform claude-code", home)
        assert code == 0
        assert skill_path.exists()

    def test_install_is_idempotent(self, home: Path):
        (home / ".claude").mkdir()
        skill_path = home / ".claude" / "skills" / "rafter" / "SKILL.md"
        _run("skill install rafter --platform claude-code", home)
        first = skill_path.read_text(encoding="utf-8")
        _run("skill install rafter --platform claude-code", home)
        assert skill_path.read_text(encoding="utf-8") == first

    def test_install_all_detected_platforms(self, home: Path):
        (home / ".claude").mkdir()
        (home / ".cursor").mkdir()
        _, _, code = _run("skill install rafter-code-review", home)
        assert code == 0
        assert (home / ".claude" / "skills" / "rafter-code-review" / "SKILL.md").exists()
        assert (home / ".cursor" / "rules" / "rafter-code-review.mdc").exists()
        # openclaw not detected, so no file there:
        assert not (home / ".openclaw" / "skills" / "rafter-code-review.md").exists()

    def test_install_exits_2_when_no_platform_detected(self, home: Path):
        _, stderr, code = _run("skill install rafter-secure-design", home)
        assert code == 2
        assert "No supported platform detected" in stderr

    def test_force_installs_everywhere(self, home: Path):
        _, _, code = _run("skill install rafter --force", home)
        assert code == 0
        assert (home / ".claude" / "skills" / "rafter" / "SKILL.md").exists()
        assert (home / ".cursor" / "rules" / "rafter.mdc").exists()
        assert (home / ".openclaw" / "skills" / "rafter.md").exists()

    def test_explicit_dir_destination(self, home: Path):
        dest = home / "custom-skills"
        _, _, code = _run(f"skill install rafter --to {dest}", home)
        assert code == 0
        assert (dest / "rafter" / "SKILL.md").exists()

    def test_explicit_file_destination(self, home: Path):
        dest = home / "custom" / "my-skill.md"
        _, _, code = _run(f"skill install rafter --to {dest}", home)
        assert code == 0
        assert dest.exists()
        assert "name: rafter" in dest.read_text(encoding="utf-8")

    def test_openclaw_flat_file_naming(self, home: Path):
        (home / ".openclaw").mkdir()
        _, _, code = _run("skill install rafter-secure-design --platform openclaw", home)
        assert code == 0
        assert (home / ".openclaw" / "skills" / "rafter-secure-design.md").exists()

    def test_cursor_uses_mdc_extension(self, home: Path):
        (home / ".cursor").mkdir()
        _, _, code = _run("skill install rafter --platform cursor", home)
        assert code == 0
        assert (home / ".cursor" / "rules" / "rafter.mdc").exists()

    def test_unknown_skill_exits_1(self, home: Path):
        _, stderr, code = _run("skill install bogus-skill", home)
        assert code == 1
        assert "Unknown skill: bogus-skill" in stderr

    def test_unknown_platform_exits_1(self, home: Path):
        (home / ".claude").mkdir()
        _, stderr, code = _run("skill install rafter --platform whatever", home)
        assert code == 1
        assert "Unknown platform" in stderr

    def test_uninstall_all_platforms_by_default(self, home: Path):
        (home / ".claude").mkdir()
        (home / ".cursor").mkdir()
        _run("skill install rafter", home)
        assert (home / ".claude" / "skills" / "rafter" / "SKILL.md").exists()
        assert (home / ".cursor" / "rules" / "rafter.mdc").exists()
        _, _, code = _run("skill uninstall rafter", home)
        assert code == 0
        assert not (home / ".claude" / "skills" / "rafter" / "SKILL.md").exists()
        assert not (home / ".cursor" / "rules" / "rafter.mdc").exists()

    def test_uninstall_noop_when_not_installed(self, home: Path):
        stdout, _, code = _run("skill uninstall rafter", home)
        assert code == 0
        assert "not installed on any known platform" in stdout

    def test_records_installations_state_in_config(self, home: Path):
        (home / ".claude").mkdir()
        _run("skill install rafter-secure-design --platform claude-code", home)
        cfg_path = home / ".rafter" / "config.json"
        assert cfg_path.exists()
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        entry = cfg.get("skillInstallations", {}).get("claude-code", {}).get("rafter-secure-design")
        assert entry is not None
        assert entry["enabled"] is True
        assert entry["version"] == "0.1.0"

        _run("skill uninstall rafter-secure-design --platform claude-code", home)
        cfg2 = json.loads(cfg_path.read_text(encoding="utf-8"))
        entry2 = cfg2.get("skillInstallations", {}).get("claude-code", {}).get("rafter-secure-design")
        assert entry2 is not None
        assert entry2["enabled"] is False


class TestRemoveRetiredSkills:
    """Tests for the generic retired-skill cleanup used by every skill
    install path (`_install_skills_to` in agent.py, `_skills_component` in
    agent_components.py). Before this, renaming or removing a bundled skill
    needed new hand-written unlink code at every install path, and the old
    directory would otherwise survive forever on a machine that installed it
    under the old name. This fails if a "retired" directory is left behind
    after a simulated rename, or if cleanup deletes a user's own skill that
    happens to reuse the retired name.
    """

    @staticmethod
    def _write_skill(base: Path, name: str, publisher: str | None) -> Path:
        skill_dir = base / name
        skill_dir.mkdir(parents=True, exist_ok=True)
        frontmatter = (
            f"---\nname: {name}\npublisher: {publisher}\n---\n"
            if publisher is not None
            else f"---\nname: {name}\n---\n"
        )
        (skill_dir / "SKILL.md").write_text(f"{frontmatter}\n# {name}\n", encoding="utf-8")
        return skill_dir

    def test_removes_rafter_authored_skill_once_retired(self, tmp_path: Path):
        from rafter_cli.commands.skill import remove_retired_skills

        # "install" under the old name, as a real install path would have.
        skill_dir = self._write_skill(tmp_path, "rafter-old-name", "rafter-security")
        assert skill_dir.exists()

        # Simulate the rename landing: the name is now retired.
        removed = remove_retired_skills(tmp_path, ("rafter-old-name",))

        assert removed == ["rafter-old-name"]
        assert not skill_dir.exists()

    def test_leaves_user_authored_skill_alone(self, tmp_path: Path):
        from rafter_cli.commands.skill import remove_retired_skills

        skill_dir = self._write_skill(tmp_path, "rafter-old-name", None)  # no publisher — not ours
        removed = remove_retired_skills(tmp_path, ("rafter-old-name",))

        assert removed == []
        assert skill_dir.exists()

    def test_leaves_different_publishers_same_named_skill_alone(self, tmp_path: Path):
        from rafter_cli.commands.skill import remove_retired_skills

        skill_dir = self._write_skill(tmp_path, "rafter-old-name", "someone-else")
        removed = remove_retired_skills(tmp_path, ("rafter-old-name",))

        assert removed == []
        assert skill_dir.exists()

    def test_noop_when_retired_name_never_installed(self, tmp_path: Path):
        from rafter_cli.commands.skill import remove_retired_skills

        removed = remove_retired_skills(tmp_path, ("never-installed",))
        assert removed == []

    def test_is_rafter_authored_skill_dir_distinguishes_lookalikes(self, tmp_path: Path):
        from rafter_cli.commands.skill import _is_rafter_authored_skill_dir

        rafter_dir = self._write_skill(tmp_path, "rafter-x", "rafter-security")
        user_dir = self._write_skill(tmp_path, "rafter-y", None)
        assert _is_rafter_authored_skill_dir(rafter_dir) is True
        assert _is_rafter_authored_skill_dir(user_dir) is False
