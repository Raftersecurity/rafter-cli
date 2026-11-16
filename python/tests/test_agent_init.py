"""Tests for agent init hook and MCP installation."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

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
    _install_hermes_mcp,
    _install_opencode_mcp,
)


class TestInstallHermesMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_hermes_mcp(tmp_path)

        config_path = tmp_path / ".hermes" / "config.yaml"
        assert config_path.exists()
        config = yaml.safe_load(config_path.read_text())
        assert config["mcp_servers"]["rafter"]["command"] == "rafter"
        assert config["mcp_servers"]["rafter"]["args"] == ["mcp", "serve"]

    def test_preserves_existing_servers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        (hermes_dir / "config.yaml").write_text(yaml.safe_dump({
            "mcp_servers": {
                "other": {"command": "other", "args": ["go"]},
            },
            "log_level": "debug",
        }))

        _install_hermes_mcp(tmp_path)

        config = yaml.safe_load((hermes_dir / "config.yaml").read_text())
        assert "other" in config["mcp_servers"]
        assert "rafter" in config["mcp_servers"]
        # Non-mcp_servers top-level keys must survive the merge.
        assert config["log_level"] == "debug"

    def test_idempotent_on_reinstall(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        _install_hermes_mcp(tmp_path)
        first = (tmp_path / ".hermes" / "config.yaml").read_text()

        _install_hermes_mcp(tmp_path)
        second = (tmp_path / ".hermes" / "config.yaml").read_text()

        assert first == second, "second install should be a no-op"

    def test_recovers_from_unreadable_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        # Deliberately broken YAML — installer must not raise; should
        # warn and write a fresh config containing the rafter entry.
        (hermes_dir / "config.yaml").write_text("mcp_servers: [this is not\n  a valid: mapping")

        assert _install_hermes_mcp(tmp_path)
        config = yaml.safe_load((hermes_dir / "config.yaml").read_text())
        assert "rafter" in config["mcp_servers"]

    def test_replaces_array_shape_mcp_servers(self, tmp_path, monkeypatch):
        """If a user wrote `mcp_servers:` as a list (wrong shape), the
        installer must coerce it to a dict rather than blow up."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        (hermes_dir / "config.yaml").write_text(yaml.safe_dump({"mcp_servers": ["junk"]}))

        assert _install_hermes_mcp(tmp_path)
        config = yaml.safe_load((hermes_dir / "config.yaml").read_text())
        assert isinstance(config["mcp_servers"], dict)
        assert config["mcp_servers"]["rafter"]["command"] == "rafter"


class TestHermesDetection:
    """sable-gyw item 6 — Hermes must surface in verify / status / list."""

    def test_check_hermes_not_detected(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _check_hermes
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        result = _check_hermes()
        assert not result.passed
        assert result.optional
        assert "not detected" in result.detail.lower()

    def test_check_hermes_pass_after_install(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _check_hermes, _install_hermes_mcp
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        _install_hermes_mcp(tmp_path)
        result = _check_hermes()
        assert result.passed
        assert "configured" in result.detail.lower()

    def test_check_hermes_warns_when_config_lacks_rafter(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _check_hermes
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        (hermes_dir / "config.yaml").write_text(yaml.safe_dump({"mcp_servers": {"other": {"command": "other"}}}))
        result = _check_hermes()
        assert not result.passed
        assert result.optional  # warn, not hard fail

    def test_detect_agent_platforms_includes_hermes(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _detect_agent_platforms
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".hermes").mkdir()
        assert "hermes" in _detect_agent_platforms()

    def test_hermes_mcp_component_install_uninstall(self, tmp_path, monkeypatch):
        from rafter_cli.commands import agent_components
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        agent_components.reset_registry_cache()
        try:
            spec = agent_components.resolve_component("hermes.mcp")
            assert spec is not None
            assert not spec.is_installed()
            spec.install()
            assert spec.is_installed()
            config = yaml.safe_load((tmp_path / ".hermes" / "config.yaml").read_text())
            assert config["mcp_servers"]["rafter"]["command"] == "rafter"
            spec.uninstall()
            assert not spec.is_installed()
        finally:
            agent_components.reset_registry_cache()


class TestInstallOpenCodeMcp:
    def test_creates_config_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _install_opencode_mcp(tmp_path)

        config_path = tmp_path / ".config" / "opencode" / "opencode.json"
        assert config_path.exists()
        config = json.loads(config_path.read_text())
        assert config["mcp"]["rafter"]["type"] == "local"
        assert config["mcp"]["rafter"]["command"] == ["rafter", "mcp", "serve"]
        assert config["mcp"]["rafter"]["enabled"] is True
        assert config["$schema"] == "https://opencode.ai/config.json"

    def test_preserves_existing_servers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        opencode_dir = tmp_path / ".config" / "opencode"
        opencode_dir.mkdir(parents=True)
        (opencode_dir / "opencode.json").write_text(json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "other": {"type": "local", "command": ["other", "go"], "enabled": True},
            },
            "theme": "system",
        }, indent=2))

        _install_opencode_mcp(tmp_path)

        config = json.loads((opencode_dir / "opencode.json").read_text())
        assert "other" in config["mcp"]
        assert "rafter" in config["mcp"]
        # Non-mcp top-level keys must survive the merge.
        assert config["theme"] == "system"

    def test_idempotent_on_reinstall(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        _install_opencode_mcp(tmp_path)
        first = (tmp_path / ".config" / "opencode" / "opencode.json").read_text()

        _install_opencode_mcp(tmp_path)
        second = (tmp_path / ".config" / "opencode" / "opencode.json").read_text()

        assert first == second, "second install should be a no-op"

    def test_recovers_from_unreadable_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        opencode_dir = tmp_path / ".config" / "opencode"
        opencode_dir.mkdir(parents=True)
        # Deliberately broken JSON — installer must not raise; should warn and
        # write a fresh config containing the rafter entry.
        (opencode_dir / "opencode.json").write_text("{ this is not valid json")

        assert _install_opencode_mcp(tmp_path)
        config = json.loads((opencode_dir / "opencode.json").read_text())
        assert config["mcp"]["rafter"]["type"] == "local"

    def test_replaces_array_shape_mcp(self, tmp_path, monkeypatch):
        """If a user wrote `mcp:` as a list (wrong shape), the installer must
        coerce it to a dict rather than blow up."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        opencode_dir = tmp_path / ".config" / "opencode"
        opencode_dir.mkdir(parents=True)
        (opencode_dir / "opencode.json").write_text(json.dumps({"mcp": ["junk"]}))

        assert _install_opencode_mcp(tmp_path)
        config = json.loads((opencode_dir / "opencode.json").read_text())
        assert isinstance(config["mcp"], dict)
        assert config["mcp"]["rafter"]["command"] == ["rafter", "mcp", "serve"]

    def test_recovers_from_non_object_toplevel(self, tmp_path, monkeypatch):
        """Valid JSON whose top level is a list/primitive must be replaced with a
        fresh object, not crash on .get() (rafter review parity fix)."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        opencode_dir = tmp_path / ".config" / "opencode"
        opencode_dir.mkdir(parents=True)
        (opencode_dir / "opencode.json").write_text(json.dumps([1, 2, 3]))

        assert _install_opencode_mcp(tmp_path)
        config = json.loads((opencode_dir / "opencode.json").read_text())
        assert isinstance(config, dict)
        assert config["mcp"]["rafter"]["type"] == "local"
        assert config["$schema"] == "https://opencode.ai/config.json"


class TestOpenCodeDetection:
    """sable-l8e5 — OpenCode must surface in verify / status / list."""

    def test_check_opencode_not_detected(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _check_opencode
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        result = _check_opencode()
        assert not result.passed
        assert result.optional
        assert "not detected" in result.detail.lower()

    def test_check_opencode_pass_after_install(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _check_opencode, _install_opencode_mcp
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        _install_opencode_mcp(tmp_path)
        result = _check_opencode()
        assert result.passed
        assert "configured" in result.detail.lower()

    def test_check_opencode_warns_when_config_lacks_rafter(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _check_opencode
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        opencode_dir = tmp_path / ".config" / "opencode"
        opencode_dir.mkdir(parents=True)
        (opencode_dir / "opencode.json").write_text(json.dumps({"mcp": {"other": {"type": "local", "command": ["other"]}}}))
        result = _check_opencode()
        assert not result.passed
        assert result.optional  # warn, not hard fail

    def test_detect_agent_platforms_includes_opencode(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _detect_agent_platforms
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".config" / "opencode").mkdir(parents=True)
        assert "opencode" in _detect_agent_platforms()

    def test_opencode_mcp_component_install_uninstall(self, tmp_path, monkeypatch):
        from rafter_cli.commands import agent_components
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        agent_components.reset_registry_cache()
        try:
            spec = agent_components.resolve_component("opencode.mcp")
            assert spec is not None
            assert not spec.is_installed()
            spec.install()
            assert spec.is_installed()
            config = json.loads((tmp_path / ".config" / "opencode" / "opencode.json").read_text())
            assert config["mcp"]["rafter"]["command"] == ["rafter", "mcp", "serve"]
            spec.uninstall()
            assert not spec.is_installed()
        finally:
            agent_components.reset_registry_cache()

    def test_opencode_mcp_component_handles_non_object_config(self, tmp_path, monkeypatch):
        """is_installed()/install() must not crash on a valid-but-non-object
        top-level config (rafter review parity fix)."""
        from rafter_cli.commands import agent_components
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        opencode_dir = tmp_path / ".config" / "opencode"
        opencode_dir.mkdir(parents=True)
        (opencode_dir / "opencode.json").write_text(json.dumps([1, 2, 3]))
        agent_components.reset_registry_cache()
        try:
            spec = agent_components.resolve_component("opencode.mcp")
            assert spec is not None
            assert not spec.is_installed()  # must not raise on a list top-level
            spec.install()
            assert spec.is_installed()
            config = json.loads((opencode_dir / "opencode.json").read_text())
            assert isinstance(config, dict)
            assert config["mcp"]["rafter"]["type"] == "local"
        finally:
            agent_components.reset_registry_cache()


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
        assert "Write|Edit|MultiEdit" in matchers

        # PostToolUse is scoped to tools that produce scannable output (shell
        # output + file writes), not every tool call — avoids firing posttool
        # on Read/MCP calls that never produce secrets to redact.
        post_matchers = [e["matcher"] for e in settings["hooks"]["PostToolUse"]]
        assert post_matchers == ["Bash|Write|Edit|MultiEdit"]

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

    @pytest.mark.parametrize("flag", ["--skip-openclaw", "--skip-claude-code"])
    def test_removed_skip_flag_rejected(self, flag):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", flag])
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


# ── --dry-run (rf-hrtd) ──────────────────────────────────────────────


class TestDryRun:
    """rf-hrtd — `rafter agent init --dry-run` prints a plan without writing."""

    def test_writes_no_files_under_local_all(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--local", "--all", "--dry-run"])
        assert result.exit_code == 0
        assert "DRY RUN" in result.stdout
        assert "Plan:" in result.stdout
        assert "Re-run without --dry-run to apply." in result.stdout

        for sub in (".claude", ".codex", ".cursor", ".gemini", ".windsurf", ".continue", ".agents", ".mcp.json", "AGENTS.md", "RAFTER.md", "GEMINI.md", "CLAUDE.md"):
            assert not (tmp_path / sub).exists(), f"{sub} should NOT exist after --dry-run"
        # Even ~/.rafter/config.json (always-write) must not land.
        assert not (tmp_path / ".rafter" / "config.json").exists()

    def test_lists_all_platform_sections_under_local_all(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--local", "--all", "--dry-run"])
        assert result.exit_code == 0
        for header in (
            "Claude Code (--with-claude-code):",
            "Codex CLI (--with-codex):",
            "Gemini CLI (--with-gemini):",
            "Cursor (--with-cursor):",
            "Windsurf (--with-windsurf):",
            "Continue.dev (--with-continue):",
            "Aider (--with-aider):",
        ):
            assert header in result.stdout, f"missing section: {header}"
        # OpenClaw is user-scope only and skipped under --local.
        assert "OpenClaw (--with-openclaw):" not in result.stdout

    def test_with_betterleaks_lists_binary_download(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.chdir(tmp_path)
        # Keep a betterleaks on the developer's PATH out of view: the plan only
        # lists a download when the real run would perform one (#231).
        monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-betterleaks", "--dry-run"])
        assert result.exit_code == 0
        assert "DOWNLOAD" in result.stdout
        assert "betterleaks" in result.stdout


# ── --all warnings (rafter-cli#231) ───────────────────────────────────


class TestAllFlagUndetectedWarnings:
    """`--all` means "install all DETECTED integrations" per its own
    --help text, so an undetected platform shouldn't get an individual
    "requested but not detected" warning just because --all was passed —
    that noise buries the warnings that matter. An explicit
    --with-<platform> on a platform that turns out to be missing should
    still warn (rafter-cli#231)."""

    def test_all_does_not_warn_about_undetected_platforms(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # No platform directories created — every platform is undetected.

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--all"])
        assert result.exit_code == 0, result.output
        for label in (
            "OpenClaw", "Claude Code", "Codex CLI", "Gemini CLI", "Cursor",
            "Windsurf", "Continue.dev", "Aider", "Hermes", "OpenCode",
        ):
            assert f"{label} requested but not detected" not in result.output

    def test_explicit_with_flag_still_warns_when_undetected(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", "--with-codex"])
        assert result.exit_code == 0, result.output
        assert "Codex CLI requested but not detected" in result.output


# ── Codex skill installation tests ───────────────────────────────────

from rafter_cli.commands.agent import _install_codex_skills


class TestInstallCodexSkills:
    def test_creates_skills_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        ok, error = _install_codex_skills(tmp_path)
        assert ok, f"Expected success, got error: {error}"
        assert error == ""

        # Must mirror KNOWN_SKILL_NAMES in python/rafter_cli/commands/skill.py.
        for name in ("rafter", "rafter-secure-design", "rafter-code-review"):
            skill_path = tmp_path / ".agents" / "skills" / name / "SKILL.md"
            assert skill_path.exists(), f"{name} SKILL.md should be installed"
            assert skill_path.read_text().strip(), f"{name} SKILL.md should not be empty"

    def test_keeps_skill_content_rafter_did_not_write(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Content no rafter release shipped: a user's edit, not a stale copy.
        backend_dir = tmp_path / ".agents" / "skills" / "rafter"
        backend_dir.mkdir(parents=True)
        (backend_dir / "SKILL.md").write_text("old content")

        ok, error = _install_codex_skills(tmp_path)
        assert ok

        assert (backend_dir / "SKILL.md").read_text() == "old content"
        assert "name: rafter" in (backend_dir / "SKILL.md.rafter-new").read_text()


# ── Gemini skill installation tests ──────────────────────────────────

from rafter_cli.commands.agent import _install_gemini_skills, _register_gemini_skills


class TestInstallGeminiSkills:
    def test_creates_skills_from_scratch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        ok, error = _install_gemini_skills(tmp_path)
        assert ok, f"Expected success, got error: {error}"
        assert error == ""

        # Mirrors KNOWN_SKILL_NAMES — same list as codex.
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


class TestInstallOpenClawSkill:
    """rf-zgwj — OpenClaw integration writes a ClawHub-shaped skill at the
    canonical workspace path, not the legacy single-file path, under the same
    keep-edited-files policy as every other platform."""

    REPO = Path(__file__).resolve().parents[2]

    def _canonical_path(self, root: Path) -> Path:
        return root / ".openclaw" / "workspace" / "skills" / "rafter-security" / "SKILL.md"

    def _legacy_path(self, root: Path) -> Path:
        return root / ".openclaw" / "skills" / "rafter-security.md"

    def _init(self, tmp_path, monkeypatch) -> str:
        from rafter_cli.__main__ import app
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["agent", "init", "--with-openclaw"])
        assert result.exit_code == 0, result.output
        return result.output

    def test_installs_skill_at_clawhub_workspace_path(self, tmp_path, monkeypatch):
        (tmp_path / ".openclaw").mkdir()
        output = self._init(tmp_path, monkeypatch)
        dest_path = self._canonical_path(tmp_path)
        assert dest_path.read_text().startswith("---\nname: rafter-security\n")
        assert re.search(r"added +\S+\.openclaw/workspace/skills/rafter-security/SKILL\.md", output)

    def test_does_not_install_when_openclaw_dir_missing(self, tmp_path, monkeypatch):
        output = self._init(tmp_path, monkeypatch)
        assert "OpenClaw requested but not detected" in output
        assert not self._canonical_path(tmp_path).exists()

    def test_keeps_edited_skill_and_edited_legacy_file(self, tmp_path, monkeypatch):
        legacy = self._legacy_path(tmp_path)
        legacy.parent.mkdir(parents=True)
        legacy.write_text("---\nname: rafter-security\nversion: 0.6.0\n---\n# my notes\n")
        self._init(tmp_path, monkeypatch)
        skill = self._canonical_path(tmp_path)
        skill.write_text(skill.read_text() + "\nmine\n")
        edited = skill.read_text()

        output = self._init(tmp_path, monkeypatch)
        assert skill.read_text() == edited
        assert Path(f"{skill}.rafter-new").exists()
        assert legacy.exists()
        assert re.search(r"kept +\S+rafter-security/SKILL\.md", output)
        assert "Kept legacy" in output

    def test_strips_legacy_skill_that_is_rafters_content(self, tmp_path, monkeypatch):
        """rf-zgwj migration: the rafter ≤ 0.7.7 install left a file at
        ~/.openclaw/skills/rafter-security.md. OpenClaw never read it.
        Reinstall removes it when its bytes are ones a release shipped."""
        legacy = self._legacy_path(tmp_path)
        legacy.parent.mkdir(parents=True)
        shutil.copyfile(self.REPO / "fixtures" / "install-0.11.2" / "home" / ".openclaw" / "workspace" / "skills" / "rafter-security" / "SKILL.md", legacy)

        output = self._init(tmp_path, monkeypatch)
        assert self._canonical_path(tmp_path).exists()
        assert not legacy.exists(), "Legacy file should be stripped on reinstall"
        assert f"Removed legacy {legacy}" in output


# ── Codex AGENTS.md / Gemini GEMINI.md instruction file tests ───────
#
# Both platforms write a marker-delimited instructions file at the same
# relative shape: <platform-dir>/<filename>. Parametrized over both.


class TestMarkerInstructionFile:
    """`rafter agent init --with-<platform>` should write the marker-delimited
    instructions file (AGENTS.md for Codex, GEMINI.md for Gemini)."""

    PLATFORMS = [
        ("--with-codex", ".codex", "AGENTS.md"),
        ("--with-gemini", ".gemini", "GEMINI.md"),
    ]

    @pytest.mark.parametrize("flag,platform_dir,filename", PLATFORMS)
    def test_writes_user_scope_marker_file(self, tmp_path, monkeypatch, flag, platform_dir, filename):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / platform_dir).mkdir()

        runner = CliRunner()
        result = runner.invoke(app, ["agent", "init", flag])
        assert result.exit_code == 0, result.output

        marker_path = tmp_path / platform_dir / filename
        assert marker_path.exists(), f"~/{platform_dir}/{filename} should be created"

        content = marker_path.read_text()
        assert "<!-- rafter:start -->" in content
        assert "<!-- rafter:end -->" in content

    @pytest.mark.parametrize("flag,platform_dir,filename", PLATFORMS)
    def test_idempotent_on_repeat_install(self, tmp_path, monkeypatch, flag, platform_dir, filename):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / platform_dir).mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", flag])
        marker_path = tmp_path / platform_dir / filename
        first = marker_path.read_text()
        runner.invoke(app, ["agent", "init", flag])
        second = marker_path.read_text()

        assert first == second

    @pytest.mark.parametrize("flag,platform_dir,filename", PLATFORMS)
    def test_preserves_existing_user_content(self, tmp_path, monkeypatch, flag, platform_dir, filename):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / platform_dir).mkdir()
        marker_path = tmp_path / platform_dir / filename
        marker_path.write_text("# My personal instructions\n\nDo the thing.\n")

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", flag])

        content = marker_path.read_text()
        assert "# My personal instructions" in content
        assert "Do the thing." in content
        assert "<!-- rafter:start -->" in content

    @pytest.mark.parametrize("flag,platform_dir,filename", PLATFORMS)
    def test_skipped_without_flag(self, tmp_path, monkeypatch, flag, platform_dir, filename):
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / platform_dir).mkdir()
        (tmp_path / ".claude").mkdir()

        runner = CliRunner()
        runner.invoke(app, ["agent", "init", "--with-claude-code"])

        assert not (tmp_path / platform_dir / filename).exists()


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

    def test_installs_gemini_hooks(self, tmp_path, monkeypatch):
        # Without BeforeTool hooks, Gemini's shell and write tools bypass the
        # command policy and the secret gate entirely; Node always installed them.
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".gemini").mkdir()
        (tmp_path / ".gemini" / "settings.json").write_text(json.dumps({"theme": "dark"}))
        monkeypatch.setattr("rafter_cli.commands.agent.shutil.which", lambda name: None if name == "gemini" else "/usr/bin/" + name)

        runner = CliRunner()
        for _ in range(2):  # a re-run must not duplicate entries
            result = runner.invoke(app, ["agent", "init", "--with-gemini"])
            assert result.exit_code == 0, result.output

        settings = json.loads((tmp_path / ".gemini" / "settings.json").read_text())
        assert settings["theme"] == "dark"
        assert "rafter" in settings["mcpServers"]
        before = settings["hooks"]["BeforeTool"]
        after = settings["hooks"]["AfterTool"]
        assert len(before) == 1 and len(after) == 1
        assert before[0]["matcher"] == "run_shell_command|write_file|replace"
        assert before[0]["hooks"][0]["command"].endswith("hook pretool --format gemini")
        assert after[0]["hooks"][0]["command"].endswith("hook posttool --format gemini")

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
        from rafter_cli.commands.skill import KNOWN_SKILL_NAMES
        assert len(link_only) == len(KNOWN_SKILL_NAMES)


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

    def test_writes_all_three_events_from_scratch(self, tmp_path, monkeypatch):
        from rafter_cli.commands.agent import _install_cursor_hooks
        monkeypatch.setattr("rafter_cli.commands.agent._resolve_rafter_path", lambda: "/opt/rafter/bin/rafter")
        _install_cursor_hooks(tmp_path)

        hooks_path = tmp_path / ".cursor" / "hooks.json"
        assert hooks_path.exists()
        cfg = json.loads(hooks_path.read_text())
        assert cfg["version"] == 1
        for event in ("preToolUse", "postToolUse", "beforeShellExecution"):
            entries = cfg["hooks"][event]
            assert isinstance(entries, list) and entries, f"missing {event}"

        pre = next(e for e in cfg["hooks"]["preToolUse"] if "rafter" in e.get("command", ""))
        assert pre["command"] == "/opt/rafter/bin/rafter hook pretool --format cursor"
        post = next(e for e in cfg["hooks"]["postToolUse"] if "rafter" in e.get("command", ""))
        assert post["command"] == "/opt/rafter/bin/rafter hook posttool --format cursor"

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


# ── Claude Code rafter sub-agent install ─────────────────────────────

from rafter_cli.commands.agent import _install_claude_code_subagents


class TestInstallClaudeCodeSubAgents:
    def test_creates_subagent_from_scratch(self, tmp_path):
        _install_claude_code_subagents(tmp_path)

        subagent_path = tmp_path / ".claude" / "agents" / "rafter.md"
        assert subagent_path.exists(), "rafter.md sub-agent should be installed"

    def test_subagent_has_required_frontmatter(self, tmp_path):
        _install_claude_code_subagents(tmp_path)
        content = (tmp_path / ".claude" / "agents" / "rafter.md").read_text()

        # Frontmatter delimited
        assert content.startswith("---\n"), "must start with YAML frontmatter"
        closing = content.find("\n---\n", 4)
        assert closing > 0, "must have closing frontmatter delimiter"

        frontmatter = content[4:closing]
        assert "name: rafter" in frontmatter
        assert "description:" in frontmatter
        assert "tools:" in frontmatter and "Bash" in frontmatter

    def test_subagent_body_references_tier_hierarchy(self, tmp_path):
        _install_claude_code_subagents(tmp_path)
        content = (tmp_path / ".claude" / "agents" / "rafter.md").read_text()

        # Trigger phrasing
        assert "safe / secure / production worthy" in content
        # Tier hierarchy
        assert "rafter run" in content
        assert "--mode plus" in content
        assert "rafter secrets" in content
        # Honest about scope of secrets
        assert "NOT a code security scan" in content

    def test_idempotent_on_reinstall(self, tmp_path):
        _install_claude_code_subagents(tmp_path)
        first = (tmp_path / ".claude" / "agents" / "rafter.md").read_text()

        _install_claude_code_subagents(tmp_path)
        second = (tmp_path / ".claude" / "agents" / "rafter.md").read_text()

        assert first == second

    def test_keeps_subagent_content_rafter_did_not_write(self, tmp_path):
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        (agents_dir / "rafter.md").write_text("stale content from previous version")

        _install_claude_code_subagents(tmp_path)

        assert (agents_dir / "rafter.md").read_text() == "stale content from previous version"
        assert "name: rafter" in (agents_dir / "rafter.md.rafter-new").read_text()


# ── Help text points at the current skill-review command ─────────────────


class TestSkillScannerHelpText:
    """issue #231 item 4b: `agent audit-skill` is deprecated in favour of
    `rafter skill review`; the install flags' help text still pointed at it."""

    @staticmethod
    def _flat_help(args: list[str]) -> str:
        from typer.testing import CliRunner
        from rafter_cli.__main__ import app

        # Typer forces Rich colour when GITHUB_ACTIONS/FORCE_COLOR is set, and
        # Rich styles "-" and "-deep" separately, so the raw text never holds
        # "--deep". Strip the escapes, then collapse whitespace, since Rich
        # also wraps to terminal width.
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, result.output
        plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
        return " ".join(plain.split())

    def test_init_help_describes_with_skill_scanner_via_skill_review(self):
        flat = self._flat_help(["agent", "init", "--help"])
        assert "skill review --deep" in flat
        assert "audit-skill --deep" not in flat

    def test_update_skill_scanner_help_describes_via_skill_review(self):
        flat = self._flat_help(["agent", "update-skill-scanner", "--help"])
        assert "skill review --deep" in flat
        assert "audit-skill --deep" not in flat
