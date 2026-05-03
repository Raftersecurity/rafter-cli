"""Tests for agent init hook and MCP installation."""
from __future__ import annotations

import json
from pathlib import Path

from rafter_cli.commands.agent import (
    _install_claude_code_hooks,
    _install_claude_code_mcp,
    _install_gemini_mcp,
    _install_cursor_mcp,
    _install_windsurf_mcp,
    _install_windsurf_rules,
    _install_continue_dev_mcp,
    _install_continue_dev_rules,
    _install_aider_read,
)


class TestInstallClaudeCodeHooks:
    def test_creates_settings_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        _install_claude_code_hooks(tmp_path)

        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()

        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]
        assert len(settings["hooks"]["PreToolUse"]) == 2

        matchers = [e["matcher"] for e in settings["hooks"]["PreToolUse"]]
        assert "Bash" in matchers
        assert "Write|Edit" in matchers

    def test_preserves_existing_hooks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool check"}]}
                ]
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        _install_claude_code_hooks(tmp_path)

        settings = json.loads((claude_dir / "settings.json").read_text())
        # Should have 3 entries: existing other-tool + 2 Rafter hooks
        assert len(settings["hooks"]["PreToolUse"]) == 3

    def test_deduplicates_rafter_hooks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        # Pre-existing Rafter hooks
        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "rafter hook pretool"}]},
                    {"matcher": "Write|Edit", "hooks": [{"type": "command", "command": "rafter hook pretool"}]},
                ]
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        _install_claude_code_hooks(tmp_path)

        settings = json.loads((claude_dir / "settings.json").read_text())
        # Old ones removed, 2 new ones added = exactly 2
        assert len(settings["hooks"]["PreToolUse"]) == 2

    def test_preserves_non_hook_settings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        existing = {"theme": "dark", "hooks": {}}
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        _install_claude_code_hooks(tmp_path)

        settings = json.loads((claude_dir / "settings.json").read_text())
        assert settings["theme"] == "dark"
        assert len(settings["hooks"]["PreToolUse"]) == 2


class TestInstallGeminiMcp:
    def test_creates_settings_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_gemini_mcp(tmp_path)

        settings_path = tmp_path / ".gemini" / "settings.json"
        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert settings["mcpServers"]["rafter"]["command"] == "rafter"
        assert settings["mcpServers"]["rafter"]["args"] == ["mcp", "serve"]

    def test_preserves_existing_settings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        (gemini_dir / "settings.json").write_text(json.dumps({"model": "gemini-pro"}))

        _install_gemini_mcp(tmp_path)

        settings = json.loads((gemini_dir / "settings.json").read_text())
        assert settings["model"] == "gemini-pro"
        assert "rafter" in settings["mcpServers"]


class TestInstallCursorMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_cursor_mcp(tmp_path)

        mcp_path = tmp_path / ".cursor" / "mcp.json"
        assert mcp_path.exists()
        config = json.loads(mcp_path.read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"

    def test_preserves_existing_servers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}))

        _install_cursor_mcp(tmp_path)

        config = json.loads((cursor_dir / "mcp.json").read_text())
        assert "other" in config["mcpServers"]
        assert "rafter" in config["mcpServers"]


class TestInstallWindsurfMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_windsurf_mcp(tmp_path)

        mcp_path = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        assert mcp_path.exists()
        config = json.loads(mcp_path.read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"


class TestInstallWindsurfRules:
    """rf-0vr3 — per-skill rules at .windsurf/rules/<skill>.md replace
    the broken ~/.windsurf/hooks.json install (Windsurf has no hook surface)."""

    SKILL_NAMES = ("rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review")

    def test_writes_one_rule_per_skill(self, tmp_path):
        _install_windsurf_rules(tmp_path)
        rules_dir = tmp_path / ".windsurf" / "rules"
        for name in self.SKILL_NAMES:
            assert (rules_dir / f"{name}.md").exists(), f"missing rule: {name}"

    def test_rules_have_windsurf_frontmatter(self, tmp_path):
        _install_windsurf_rules(tmp_path)
        rules_dir = tmp_path / ".windsurf" / "rules"
        for name in self.SKILL_NAMES:
            body = (rules_dir / f"{name}.md").read_text()
            assert body.startswith("---\ntrigger: model_decision"), (
                f"{name}.md missing Windsurf trigger frontmatter"
            )
            assert "description:" in body.split("---")[1]

    def test_does_not_write_hooks_json(self, tmp_path):
        _install_windsurf_rules(tmp_path)
        # hooks.json explicitly not created — Windsurf has no hook surface (rf-0vr3).
        assert not (tmp_path / ".windsurf" / "hooks.json").exists()

    def test_idempotent_on_reinstall(self, tmp_path):
        _install_windsurf_rules(tmp_path)
        _install_windsurf_rules(tmp_path)
        rules_dir = tmp_path / ".windsurf" / "rules"
        # Still exactly the four files; no duplicates appended to filenames.
        files = sorted(p.name for p in rules_dir.iterdir())
        assert files == sorted(f"{n}.md" for n in self.SKILL_NAMES)


class TestInstallContinueDevRules:
    """rf-acz0 — per-skill rules at .continue/rules/<skill>.md (workspace-scope).
    Continue.dev's only persistent-rule surface; previously rafter shipped
    nothing here, only MCP."""

    SKILL_NAMES = ("rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review")

    def test_writes_one_rule_per_skill(self, tmp_path):
        _install_continue_dev_rules(tmp_path)
        rules_dir = tmp_path / ".continue" / "rules"
        for name in self.SKILL_NAMES:
            assert (rules_dir / f"{name}.md").exists(), f"missing rule: {name}"

    def test_rules_have_continue_frontmatter(self, tmp_path):
        _install_continue_dev_rules(tmp_path)
        rules_dir = tmp_path / ".continue" / "rules"
        for name in self.SKILL_NAMES:
            body = (rules_dir / f"{name}.md").read_text()
            assert body.startswith("---\nname: "), f"{name}.md missing Continue.dev `name:` field"
            assert "description:" in body.split("---")[1]
            assert "alwaysApply: false" in body.split("---")[1]

    def test_idempotent_on_reinstall(self, tmp_path):
        _install_continue_dev_rules(tmp_path)
        _install_continue_dev_rules(tmp_path)
        rules_dir = tmp_path / ".continue" / "rules"
        files = sorted(p.name for p in rules_dir.iterdir())
        assert files == sorted(f"{n}.md" for n in self.SKILL_NAMES)


class TestInstallContinueDevMcp:
    def test_creates_config_with_array_format(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_continue_dev_mcp(tmp_path)

        config_path = tmp_path / ".continue" / "config.json"
        assert config_path.exists()
        config = json.loads(config_path.read_text())
        assert isinstance(config["mcpServers"], list)
        assert any(s["name"] == "rafter" for s in config["mcpServers"])

    def test_deduplicates_on_reinstall(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()
        existing = {"mcpServers": [{"name": "rafter", "command": "old"}]}
        (continue_dir / "config.json").write_text(json.dumps(existing))

        _install_continue_dev_mcp(tmp_path)

        config = json.loads((continue_dir / "config.json").read_text())
        rafter_entries = [s for s in config["mcpServers"] if s["name"] == "rafter"]
        assert len(rafter_entries) == 1
        assert rafter_entries[0]["command"] == "rafter"

    def test_handles_object_format(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()
        existing = {"mcpServers": {"other": {"command": "other"}}}
        (continue_dir / "config.json").write_text(json.dumps(existing))

        _install_continue_dev_mcp(tmp_path)

        config = json.loads((continue_dir / "config.json").read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"
        assert config["mcpServers"]["other"]["command"] == "other"


class TestInstallAiderRead:
    """rf-du2o — replaces broken `mcp-server-command:` install. Aider has no
    native MCP support; its only persistent-context primitive is the `read:`
    flag in `.aider.conf.yml`."""

    def test_writes_rafter_md(self, tmp_path):
        assert _install_aider_read(tmp_path)
        rafter_md = tmp_path / "RAFTER.md"
        assert rafter_md.exists()
        body = rafter_md.read_text()
        assert "<!-- rafter:start -->" in body
        assert "<!-- rafter:end -->" in body

    def test_adds_rafter_md_to_read_list(self, tmp_path):
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("model: gpt-4\n")

        _install_aider_read(tmp_path)

        content = config_path.read_text()
        assert "model: gpt-4" in content
        assert "RAFTER.md" in content

    def test_does_not_write_legacy_mcp_line(self, tmp_path):
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("# fresh\n")

        _install_aider_read(tmp_path)

        content = config_path.read_text()
        assert "mcp-server-command" not in content
        assert "rafter mcp serve" not in content

    def test_strips_legacy_mcp_block_on_reinstall(self, tmp_path):
        """Migration path: pre-existing legacy line must be removed."""
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text(
            "model: gpt-5\n\n# Rafter security MCP server\nmcp-server-command: rafter mcp serve\n"
        )

        _install_aider_read(tmp_path)

        content = config_path.read_text()
        assert "mcp-server-command" not in content
        assert "Rafter security MCP server" not in content
        assert "model: gpt-5" in content
        assert "RAFTER.md" in content

    def test_preserves_existing_read_entries(self, tmp_path):
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("read:\n  - CONVENTIONS.md\n  - DESIGN.md\n")

        _install_aider_read(tmp_path)

        content = config_path.read_text()
        assert "CONVENTIONS.md" in content
        assert "DESIGN.md" in content
        assert "RAFTER.md" in content

    def test_idempotent_on_repeated_installs(self, tmp_path):
        config_path = tmp_path / ".aider.conf.yml"
        config_path.write_text("model: gpt-5\n")

        _install_aider_read(tmp_path)
        _install_aider_read(tmp_path)

        content = config_path.read_text()
        assert content.count("RAFTER.md") == 1


# ── Flag rejection tests ─────────────────────────────────────────────


class TestFlagRejection:
    """--skip-openclaw and --skip-claude-code are NOT valid flags for `agent init`."""

    def test_skip_openclaw_rejected(self):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--skip-openclaw"])
        assert result.exit_code != 0, f"Expected non-zero exit code, got {result.exit_code}"

    def test_skip_claude_code_rejected(self):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--skip-claude-code"])
        assert result.exit_code != 0, f"Expected non-zero exit code, got {result.exit_code}"


# ── Opt-in gating tests ──────────────────────────────────────────────


class TestOptInGating:
    """Running init without --with-* flags should NOT install any platform configs."""

    def test_no_flags_skips_all_installations(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Create directories so environments are "detected" but no --with-* flags
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".openclaw").mkdir()
        (tmp_path / ".codex").mkdir()
        (tmp_path / ".gemini").mkdir()
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
        (tmp_path / ".continue").mkdir()
        (tmp_path / ".aider.conf.yml").write_text("")

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init"])

        # Claude Code hooks should NOT be installed
        settings_path = tmp_path / ".claude" / "settings.json"
        assert not settings_path.exists(), "Claude Code settings.json should not be created without --with-claude-code"

        # OpenClaw skill should NOT be installed
        openclaw_skill = tmp_path / ".openclaw" / "skills" / "rafter-security.md"
        assert not openclaw_skill.exists(), "OpenClaw skill should not be installed without --with-openclaw"

        # Codex skills should NOT be installed
        codex_skill = tmp_path / ".agents" / "skills" / "rafter" / "SKILL.md"
        assert not codex_skill.exists(), "Codex skill should not be installed without --with-codex"

        # Gemini MCP should NOT be installed
        gemini_settings = tmp_path / ".gemini" / "settings.json"
        assert not gemini_settings.exists(), "Gemini settings.json should not be created without --with-gemini"

        # Cursor MCP should NOT be installed
        cursor_mcp = tmp_path / ".cursor" / "mcp.json"
        assert not cursor_mcp.exists(), "Cursor mcp.json should not be created without --with-cursor"

        # Windsurf MCP should NOT be installed
        windsurf_mcp = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        assert not windsurf_mcp.exists(), "Windsurf mcp_config.json should not be created without --with-windsurf"

        # Continue.dev MCP should NOT be installed
        continue_config = tmp_path / ".continue" / "config.json"
        assert not continue_config.exists(), "Continue config.json should not be created without --with-continue"

        # Aider read: should NOT be appended (rf-du2o); RAFTER.md not written.
        aider_content = (tmp_path / ".aider.conf.yml").read_text()
        assert "RAFTER.md" not in aider_content, "Aider config should not be modified without --with-aider"
        assert not (tmp_path / "RAFTER.md").exists()


# ── Codex skill installation tests ───────────────────────────────────

from rafter_cli.commands.agent import _install_codex_skills


class TestInstallCodexSkills:
    def test_creates_skills_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        ok, error = _install_codex_skills(tmp_path)
        assert ok, f"Expected success, got error: {error}"
        assert error == ""

        # Must mirror _AGENT_SKILLS in python/rafter_cli/commands/agent.py.
        for name in ("rafter", "rafter-secure-design", "rafter-code-review"):
            skill_path = tmp_path / ".agents" / "skills" / name / "SKILL.md"
            assert skill_path.exists(), f"{name} SKILL.md should be installed"
            assert skill_path.read_text().strip(), f"{name} SKILL.md should not be empty"

    def test_overwrites_existing_skills(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Pre-create with stale content
        backend_dir = tmp_path / ".agents" / "skills" / "rafter"
        backend_dir.mkdir(parents=True)
        (backend_dir / "SKILL.md").write_text("old content")

        ok, error = _install_codex_skills(tmp_path)
        assert ok

        content = (backend_dir / "SKILL.md").read_text()
        assert content != "old content", "Skill should be updated on reinstall"


# ── Gemini skill installation tests ──────────────────────────────────

from rafter_cli.commands.agent import _install_gemini_skills, _register_gemini_skills


class TestInstallGeminiSkills:
    def test_creates_skills_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        ok, error = _install_gemini_skills(tmp_path)
        assert ok, f"Expected success, got error: {error}"
        assert error == ""

        # Mirrors _AGENT_SKILLS — same list as codex.
        for name in ("rafter", "rafter-secure-design", "rafter-code-review"):
            skill_path = tmp_path / ".agents" / "skills" / name / "SKILL.md"
            assert skill_path.exists(), f"{name} SKILL.md should be installed"
            assert skill_path.read_text().strip(), f"{name} SKILL.md should not be empty"

    def test_shares_dir_with_codex(self, tmp_path, monkeypatch):
        """Gemini + Codex both write to <root>/.agents/skills/ — reinstall is idempotent."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        from rafter_cli.commands.agent import _install_codex_skills

        _install_codex_skills(tmp_path)
        first = (tmp_path / ".agents" / "skills" / "rafter" / "SKILL.md").read_text()
        _install_gemini_skills(tmp_path)
        second = (tmp_path / ".agents" / "skills" / "rafter" / "SKILL.md").read_text()
        assert first == second


class TestRegisterGeminiSkills:
    def test_skips_when_gemini_not_on_path(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: None)
        # Should not raise, should just warn
        _register_gemini_skills(tmp_path / ".agents" / "skills")

    def test_calls_gemini_skills_link_for_each_skill(self, tmp_path, monkeypatch):
        # Install skill dirs
        skills_dir = tmp_path / ".agents" / "skills"
        for name in ("rafter", "rafter-secure-design", "rafter-code-review"):
            (skills_dir / name).mkdir(parents=True)
            (skills_dir / name / "SKILL.md").write_text("---\nname: x\n---\n")

        monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: "/fake/gemini")

        calls: list[list[str]] = []

        def fake_run(cmd, check=True, capture_output=True, timeout=None, **kw):
            calls.append(list(cmd))
            import subprocess as _sp
            return _sp.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rafter_cli.commands.agent.subprocess.run", fake_run)

        _register_gemini_skills(skills_dir)

        # First call: `gemini skills --help` probe
        assert calls[0][1:] == ["skills", "--help"]
        # Following calls: one `skills link <abs>` per skill
        link_calls = [c for c in calls if c[1:3] == ["skills", "link"]]
        assert len(link_calls) == 3
        linked_paths = {c[3] for c in link_calls}
        for name in ("rafter", "rafter-secure-design", "rafter-code-review"):
            assert str((skills_dir / name).resolve()) in linked_paths

    def test_skips_when_skills_subcommand_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: "/fake/gemini")

        import subprocess as _sp

        def fake_run(cmd, check=True, capture_output=True, timeout=None, **kw):
            raise _sp.CalledProcessError(1, cmd)

        monkeypatch.setattr("rafter_cli.commands.agent.subprocess.run", fake_run)

        # Should not raise
        _register_gemini_skills(tmp_path / ".agents" / "skills")


# ── OpenClaw skill installation tests ────────────────────────────────

from rafter_cli.commands.agent import _install_openclaw_skill


class TestInstallOpenClawSkill:
    def test_installs_skill_when_openclaw_dir_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".openclaw").mkdir()

        ok, source, dest, error = _install_openclaw_skill()
        assert ok, f"Expected success, got error: {error}"
        assert error == ""

        dest_path = tmp_path / ".openclaw" / "skills" / "rafter-security.md"
        assert dest_path.exists(), "Skill file should be installed"
        assert dest_path.read_text().strip(), "Skill file should not be empty"
        assert str(dest_path) == dest

    def test_fails_when_openclaw_dir_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # Do NOT create .openclaw directory

        ok, source, dest, error = _install_openclaw_skill()
        assert not ok, "Should fail when .openclaw directory is missing"
        assert "not found" in error.lower()

    def test_overwrites_existing_skill(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir()
        skills_dir = openclaw_dir / "skills"
        skills_dir.mkdir()
        (skills_dir / "rafter-security.md").write_text("old content")

        ok, source, dest, error = _install_openclaw_skill()
        assert ok

        content = (skills_dir / "rafter-security.md").read_text()
        assert content != "old content", "Skill should be updated on reinstall"

    def test_creates_skills_subdirectory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".openclaw").mkdir()
        # skills/ subdirectory does NOT exist yet

        ok, source, dest, error = _install_openclaw_skill()
        assert ok

        assert (tmp_path / ".openclaw" / "skills").is_dir(), "Should create skills subdirectory"


# ── Codex AGENTS.md instruction file tests ──────────────────────────


class TestCodexAgentsInstructionFile:
    """`rafter agent init --with-codex` should write AGENTS.md with the rafter marker block."""

    def test_writes_user_scope_agents_md(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-codex"])
        assert result.exit_code == 0, result.output

        agents_path = tmp_path / ".codex" / "AGENTS.md"
        assert agents_path.exists(), "~/.codex/AGENTS.md should be created"

        content = agents_path.read_text()
        assert "<!-- rafter:start -->" in content
        assert "<!-- rafter:end -->" in content

    def test_idempotent_on_repeat_install(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-codex"])
        first = (tmp_path / ".codex" / "AGENTS.md").read_text()
        runner.invoke(app, ["agent", "init", "--with-codex"])
        second = (tmp_path / ".codex" / "AGENTS.md").read_text()

        assert first == second

    def test_preserves_existing_user_content(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()
        agents_path = tmp_path / ".codex" / "AGENTS.md"
        agents_path.write_text("# My personal instructions\n\nDo the thing.\n")

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-codex"])

        content = agents_path.read_text()
        assert "# My personal instructions" in content
        assert "Do the thing." in content
        assert "<!-- rafter:start -->" in content

    def test_skipped_without_with_codex(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".codex").mkdir()
        (tmp_path / ".claude").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-claude-code"])

        assert not (tmp_path / ".codex" / "AGENTS.md").exists()


# ── Gemini GEMINI.md instruction file tests ─────────────────────────


class TestGeminiInstructionFile:
    """`rafter agent init --with-gemini` should write GEMINI.md with the rafter marker block."""

    def test_writes_user_scope_gemini_md(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-gemini"])
        assert result.exit_code == 0, result.output

        gemini_path = tmp_path / ".gemini" / "GEMINI.md"
        assert gemini_path.exists(), "~/.gemini/GEMINI.md should be created"

        content = gemini_path.read_text()
        assert "<!-- rafter:start -->" in content
        assert "<!-- rafter:end -->" in content

    def test_idempotent_on_repeat_install(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-gemini"])
        first = (tmp_path / ".gemini" / "GEMINI.md").read_text()
        runner.invoke(app, ["agent", "init", "--with-gemini"])
        second = (tmp_path / ".gemini" / "GEMINI.md").read_text()

        assert first == second

    def test_preserves_existing_user_content(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()
        gemini_path = tmp_path / ".gemini" / "GEMINI.md"
        gemini_path.write_text("# My personal instructions\n\nDo the thing.\n")

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-gemini"])

        content = gemini_path.read_text()
        assert "# My personal instructions" in content
        assert "Do the thing." in content
        assert "<!-- rafter:start -->" in content

    def test_skipped_without_with_gemini(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()
        (tmp_path / ".claude").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-claude-code"])

        assert not (tmp_path / ".gemini" / "GEMINI.md").exists()


class TestGeminiWithSkillsEndToEnd:
    """`rafter agent init --with-gemini` must install skills to .agents/skills/
    AND attempt gemini CLI registration."""

    def test_installs_skills_to_agents_dir(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()
        # gemini not on PATH — registration is a warning, install still runs
        monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: None if name == "gemini" else "/usr/bin/" + name)

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-gemini"])
        assert result.exit_code == 0, result.output

        for name in ("rafter", "rafter-secure-design", "rafter-code-review"):
            skill = tmp_path / ".agents" / "skills" / name / "SKILL.md"
            assert skill.exists(), f"{name} SKILL.md should be installed via --with-gemini"

    def test_calls_gemini_skills_link_when_gemini_available(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()

        monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: "/fake/" + name if name == "gemini" else None)

        link_calls: list[list[str]] = []

        import subprocess as _sp

        def fake_run(cmd, check=True, capture_output=True, timeout=None, **kw):
            link_calls.append(list(cmd))
            return _sp.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rafter_cli.commands.agent.subprocess.run", fake_run)

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-gemini"])
        assert result.exit_code == 0, result.output

        # One probe + one link per skill (3 skills)
        link_only = [c for c in link_calls if c[1:3] == ["skills", "link"]]
        assert len(link_only) == 3


class TestInstallClaudeCodeMcp:
    def test_creates_mcp_json_from_scratch(self, tmp_path):
        _install_claude_code_mcp(tmp_path)

        mcp_path = tmp_path / ".mcp.json"
        assert mcp_path.exists()

        config = json.loads(mcp_path.read_text())
        assert "mcpServers" in config
        assert "rafter" in config["mcpServers"]
        assert config["mcpServers"]["rafter"]["command"] == "rafter"
        assert config["mcpServers"]["rafter"]["args"] == ["mcp", "serve"]

    def test_idempotent(self, tmp_path):
        _install_claude_code_mcp(tmp_path)
        _install_claude_code_mcp(tmp_path)

        config = json.loads((tmp_path / ".mcp.json").read_text())
        assert list(config["mcpServers"].keys()) == ["rafter"]

    def test_preserves_existing_non_rafter_servers(self, tmp_path):
        existing = {"mcpServers": {"other": {"command": "other", "args": []}}}
        (tmp_path / ".mcp.json").write_text(json.dumps(existing))

        _install_claude_code_mcp(tmp_path)

        config = json.loads((tmp_path / ".mcp.json").read_text())
        assert "other" in config["mcpServers"]
        assert "rafter" in config["mcpServers"]

    def test_recovers_from_unreadable_mcp_json(self, tmp_path):
        (tmp_path / ".mcp.json").write_text("{ not json")
        _install_claude_code_mcp(tmp_path)

        config = json.loads((tmp_path / ".mcp.json").read_text())
        assert config["mcpServers"]["rafter"]["command"] == "rafter"


# ── Continue.dev hooks pruned (rf-cia phase b) ─────────────────────────
#
# Continue.dev does not read ~/.continue/settings.json and has no
# hooks.PreToolUse / PostToolUse field in its config schema (config.yaml
# in current versions, config.json in legacy). The hook installer was a
# silent no-op at runtime. These tests pin the new behavior.


class TestContinueDevHooksPruned:
    def test_install_does_not_write_continue_settings_json(self, tmp_path):
        # MCP install is the only Continue.dev install path and must not
        # produce a settings.json file.
        _install_continue_dev_mcp(tmp_path)

        settings_path = tmp_path / ".continue" / "settings.json"
        assert not settings_path.exists(), \
            "Continue.dev does not read settings.json — rafter must not write it"

    def test_install_preserves_existing_continue_settings_json(self, tmp_path):
        # If the user has their own Continue.dev settings.json, rafter
        # must leave it alone (older rafter versions stomped it with a
        # hooks block Continue.dev couldn't parse).
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir(parents=True)
        settings_path = continue_dir / "settings.json"
        user_content = '{"theme":"dark"}'
        settings_path.write_text(user_content, encoding="utf-8")

        _install_continue_dev_mcp(tmp_path)

        assert settings_path.read_text(encoding="utf-8") == user_content

    def test_install_still_writes_mcp_config(self, tmp_path):
        # Pruning hooks must not regress MCP install.
        _install_continue_dev_mcp(tmp_path)

        config_path = tmp_path / ".continue" / "config.json"
        assert config_path.exists()
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        servers = cfg.get("mcpServers")
        if isinstance(servers, list):
            assert any(s.get("name") == "rafter" for s in servers)
        else:
            assert "rafter" in (servers or {})


# ── Cursor deep support (rf-svn3) ────────────────────────────────────

# Skills shipped as both Cursor rules and skills package — must mirror
# AGENT_SKILLS_CURSOR in rafter_cli/commands/agent.py.
_CURSOR_SHIPPED_SKILLS = (
    "rafter",
    "rafter-secure-design",
    "rafter-code-review",
    "rafter-skill-review",
)


class TestInstallCursorHooks:
    """Cursor hooks must cover preToolUse, postToolUse, and beforeShellExecution."""

    def test_writes_all_three_events_from_scratch(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_hooks
        _install_cursor_hooks(tmp_path)

        hooks_path = tmp_path / ".cursor" / "hooks.json"
        assert hooks_path.exists()
        cfg = json.loads(hooks_path.read_text())
        assert cfg["version"] == 1
        for event in ("preToolUse", "postToolUse", "beforeShellExecution"):
            entries = cfg["hooks"][event]
            assert isinstance(entries, list) and entries, f"missing {event}"

        pre = next(e for e in cfg["hooks"]["preToolUse"] if "rafter" in e.get("command", ""))
        assert pre["command"] == "rafter hook pretool --format cursor"
        post = next(e for e in cfg["hooks"]["postToolUse"] if "rafter" in e.get("command", ""))
        assert post["command"] == "rafter hook posttool --format cursor"

    def test_idempotent_no_duplicates(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_hooks
        _install_cursor_hooks(tmp_path)
        _install_cursor_hooks(tmp_path)
        _install_cursor_hooks(tmp_path)

        cfg = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())
        for event in ("preToolUse", "postToolUse", "beforeShellExecution"):
            rafter_hooks = [
                e for e in cfg["hooks"][event] if "rafter" in e.get("command", "")
            ]
            assert len(rafter_hooks) == 1, f"event {event} duplicated"

    def test_preserves_non_rafter_entries(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_hooks
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "hooks.json").write_text(json.dumps({
            "version": 1,
            "hooks": {
                "preToolUse": [{"command": "other pre", "type": "command"}],
                "postToolUse": [{"command": "other post", "type": "command"}],
                "beforeShellExecution": [{"command": "other shell", "type": "command"}],
                "afterFileEdit": [{"command": "other edit", "type": "command"}],
            },
        }))

        _install_cursor_hooks(tmp_path)

        cfg = json.loads((cursor_dir / "hooks.json").read_text())
        commands = lambda ev: [e.get("command") for e in cfg["hooks"][ev]]
        assert "other pre" in commands("preToolUse")
        assert "other post" in commands("postToolUse")
        assert "other shell" in commands("beforeShellExecution")
        # Unrelated event preserved untouched.
        assert commands("afterFileEdit") == ["other edit"]


class TestInstallCursorRules:
    """Per-skill .mdc rules — one file per shipped skill."""

    def test_writes_one_mdc_per_shipped_skill(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_rules
        _install_cursor_rules(tmp_path)

        rules_dir = tmp_path / ".cursor" / "rules"
        for name in _CURSOR_SHIPPED_SKILLS:
            assert (rules_dir / f"{name}.mdc").exists(), f"missing {name}.mdc"

    def test_each_rule_has_alwaysApply_false_and_description(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_rules
        _install_cursor_rules(tmp_path)

        rules_dir = tmp_path / ".cursor" / "rules"
        for name in _CURSOR_SHIPPED_SKILLS:
            content = (rules_dir / f"{name}.mdc").read_text()
            assert content.startswith("---\n"), f"{name}: missing frontmatter"
            fm_end = content.find("\n---", 4)
            assert fm_end > 0, f"{name}: missing closing frontmatter"
            frontmatter = content[4:fm_end]
            assert "alwaysApply: false" in frontmatter, f"{name}: alwaysApply must be false"
            assert "description:" in frontmatter, f"{name}: description must exist"

    def test_descriptions_are_action_forcing(self, tmp_path):
        import re
        from rafter_cli.commands.agent import _install_cursor_rules
        _install_cursor_rules(tmp_path)

        rules_dir = tmp_path / ".cursor" / "rules"
        for name in _CURSOR_SHIPPED_SKILLS:
            content = (rules_dir / f"{name}.mdc").read_text()
            m = re.search(r'description:\s*"([^"]+)"', content)
            assert m, f"{name}: cannot extract description"
            desc = m.group(1)
            assert len(desc) > 20, f"{name}: description too short"
            assert re.match(r"^(REQUIRED|Use|Invoke|Entry|Run|Read|Stop)", desc), (
                f"{name}: description must be action-forcing, got: {desc[:40]}"
            )

    def test_does_not_write_legacy_rafter_security_mdc(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_rules
        _install_cursor_rules(tmp_path)
        legacy = tmp_path / ".cursor" / "rules" / "rafter-security.mdc"
        assert not legacy.exists(), "legacy consolidated rule must not be written"

    def test_idempotent(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_rules
        _install_cursor_rules(tmp_path)
        rules_dir = tmp_path / ".cursor" / "rules"
        before = {n: (rules_dir / f"{n}.mdc").read_text() for n in _CURSOR_SHIPPED_SKILLS}
        _install_cursor_rules(tmp_path)
        after = {n: (rules_dir / f"{n}.mdc").read_text() for n in _CURSOR_SHIPPED_SKILLS}
        assert after == before


class TestInstallCursorSubAgent:
    """Cursor sub-agent — .cursor/agents/rafter.md."""

    def test_writes_subagent_file(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_subagents
        _install_cursor_subagents(tmp_path)
        agent_path = tmp_path / ".cursor" / "agents" / "rafter.md"
        assert agent_path.exists()

    def test_frontmatter_has_name_description_no_tools(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_subagents
        _install_cursor_subagents(tmp_path)

        content = (tmp_path / ".cursor" / "agents" / "rafter.md").read_text()
        assert content.startswith("---\n")
        fm_end = content.find("\n---", 4)
        frontmatter = content[4:fm_end]
        assert "name: rafter" in frontmatter
        assert "description:" in frontmatter
        # Cursor frontmatter has no tools: field.
        for line in frontmatter.splitlines():
            assert not line.startswith("tools:"), \
                "Cursor sub-agent frontmatter must not include tools:"

    def test_body_references_all_three_cli_tiers(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_subagents
        _install_cursor_subagents(tmp_path)
        content = (tmp_path / ".cursor" / "agents" / "rafter.md").read_text()
        assert "rafter run" in content
        assert "--mode plus" in content
        assert "rafter secrets" in content

    def test_idempotent(self, tmp_path):
        from rafter_cli.commands.agent import _install_cursor_subagents
        _install_cursor_subagents(tmp_path)
        agent_path = tmp_path / ".cursor" / "agents" / "rafter.md"
        before = agent_path.read_text()
        _install_cursor_subagents(tmp_path)
        assert agent_path.read_text() == before
