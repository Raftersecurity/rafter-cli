"""Tests for the brief command — knowledge delivery."""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from rafter_cli.__main__ import app
from rafter_cli.commands.brief import (
    RAFTER_SUBDOCS,
    RESOURCES_DIR,
    _extract_sections,
    _load_skill,
    _load_skill_doc,
    _render_platform_setup,
    _render_setup_guide,
    _render_topic,
    _render_topic_list,
    PLATFORM_GUIDES,
    TOPIC_DESCRIPTIONS,
)

runner = CliRunner()


class TestTopicListing:
    def test_lists_topics_when_no_argument(self):
        result = runner.invoke(app, ["brief"])
        assert result.exit_code == 0
        assert "Available topics:" in result.stdout
        assert "security" in result.stdout
        assert "scanning" in result.stdout
        assert "commands" in result.stdout
        assert "setup" in result.stdout
        assert "all" in result.stdout
        assert "pricing" in result.stdout

    def test_lists_setup_subtopics(self):
        result = runner.invoke(app, ["brief"])
        assert "setup/claude-code" in result.stdout
        assert "setup/codex" in result.stdout
        assert "setup/gemini" in result.stdout
        assert "setup/cursor" in result.stdout
        assert "setup/windsurf" in result.stdout
        assert "setup/aider" in result.stdout
        assert "setup/openclaw" in result.stdout
        assert "setup/continue" in result.stdout
        assert "setup/generic" in result.stdout

    def test_shows_usage_examples(self):
        result = runner.invoke(app, ["brief"])
        assert "Usage: rafter brief <topic>" in result.stdout
        assert "rafter brief security" in result.stdout
        assert "rafter brief all" in result.stdout


class TestTopicRendering:
    def test_security_topic_loads_skill(self):
        result = runner.invoke(app, ["brief", "security"])
        assert result.exit_code == 0
        assert len(result.stdout) > 100

    def test_scanning_topic_loads_skill(self):
        result = runner.invoke(app, ["brief", "scanning"])
        assert result.exit_code == 0
        assert len(result.stdout) > 100

    def test_commands_topic_has_both_sections(self):
        result = runner.invoke(app, ["brief", "commands"])
        assert result.exit_code == 0
        assert "Rafter Command Reference" in result.stdout
        assert "Remote Code Analysis" in result.stdout
        assert "Agent (Local Security)" in result.stdout

    def test_pricing_topic(self):
        result = runner.invoke(app, ["brief", "pricing"])
        assert result.exit_code == 0
        assert "Rafter Pricing" in result.stdout
        assert "Free forever" in result.stdout
        assert "No API key" in result.stdout

    def test_all_topic_combines_content(self):
        result = runner.invoke(app, ["brief", "all"])
        assert result.exit_code == 0
        assert "---" in result.stdout
        assert len(result.stdout) > 500


class TestSetupGuides:
    def test_setup_overview(self):
        result = runner.invoke(app, ["brief", "setup"])
        assert result.exit_code == 0
        assert "Rafter Setup Guide" in result.stdout
        assert "Supported Platforms" in result.stdout
        assert "Skill-Based" in result.stdout
        assert "MCP-Based" in result.stdout

    @pytest.mark.parametrize("slug,name,contains", [
        ("claude-code", "Claude Code", "skills"),
        ("codex", "Codex CLI", "skills"),
        ("gemini", "Gemini CLI", "MCP"),
        ("cursor", "Cursor", "MCP"),
        ("windsurf", "Windsurf", "MCP"),
        ("aider", "Aider", "MCP"),
        ("openclaw", "OpenClaw", "skill"),
        ("continue", "Continue.dev", "MCP"),
        ("generic", "Generic", "rafter brief"),
    ])
    def test_platform_setup(self, slug, name, contains):
        result = runner.invoke(app, ["brief", f"setup/{slug}"])
        assert result.exit_code == 0
        assert name in result.stdout
        assert contains.lower() in result.stdout.lower()


class TestErrorHandling:
    def test_unknown_topic_exits_1(self):
        result = runner.invoke(app, ["brief", "nonexistent"])
        assert result.exit_code == 1
        # CliRunner mixes stderr into stdout
        assert "Unknown topic: nonexistent" in result.output

    def test_unknown_platform_returns_message(self):
        result = runner.invoke(app, ["brief", "setup/nosuchplatform"])
        assert "Unknown platform: nosuchplatform" in result.stdout


class TestInternalFunctions:
    def test_load_skill_strips_frontmatter(self):
        content = _load_skill("rafter")
        assert not content.startswith("---")
        assert len(content) > 50

    def test_extract_sections_captures_matching_heading(self):
        md = "# Intro\nSome text\n## Commands\nDo this\nDo that\n## Other\nBlah"
        result = _extract_sections(md, ["Commands"])
        assert "## Commands" in result
        assert "Do this" in result
        assert "Do that" in result
        assert "Other" not in result
        assert "Blah" not in result

    def test_extract_sections_handles_code_blocks(self):
        md = "## Commands\n```bash\necho hello\n```\nMore text\n## Next\nEnd"
        result = _extract_sections(md, ["Commands"])
        assert "echo hello" in result
        assert "More text" in result
        assert "Next" not in result

    def test_extract_sections_case_insensitive(self):
        md = "## MY COMMANDS\nStuff here\n## Other"
        result = _extract_sections(md, ["commands"])
        assert "Stuff here" in result

    def test_extract_sections_no_match_returns_empty(self):
        md = "## Intro\nHello\n## Other\nWorld"
        result = _extract_sections(md, ["Nonexistent"])
        assert result == ""

    def test_render_topic_returns_none_for_unknown(self):
        assert _render_topic("totally_unknown") is None

    def test_render_platform_setup_unknown(self):
        assert "Unknown platform" in _render_platform_setup("badplatform")

    def test_render_setup_guide_has_quick_start(self):
        guide = _render_setup_guide()
        assert "Quick Start" in guide
        assert "rafter agent init" in guide

    def test_topic_list_formatting(self):
        listing = _render_topic_list()
        assert "Available topics:" in listing
        # Each topic should have description
        for topic, desc in TOPIC_DESCRIPTIONS.items():
            assert topic in listing
            assert desc in listing

    def test_all_platform_guides_present(self):
        expected = [
            "claude-code", "codex", "gemini", "cursor",
            "windsurf", "aider", "openclaw", "continue", "generic",
        ]
        for platform in expected:
            assert platform in PLATFORM_GUIDES


class TestRafterSkillCYOA:
    """Top-level rafter skill is a CYOA router; sub-docs live in docs/."""

    def test_skill_md_parses_and_is_under_120_lines(self):
        skill_path = RESOURCES_DIR / "rafter" / "SKILL.md"
        raw = skill_path.read_text()
        assert raw.startswith("---"), "SKILL.md must start with YAML frontmatter"
        # frontmatter closes
        assert raw.count("---") >= 2
        # under the 120-line budget
        assert len(raw.splitlines()) < 120, \
            f"top-level SKILL.md grew to {len(raw.splitlines())} lines; keep <120"

    def test_skill_md_references_each_subdoc(self):
        body = _load_skill("rafter")
        for slug, _desc in RAFTER_SUBDOCS:
            assert f"docs/{slug}.md" in body, \
                f"SKILL.md should reference docs/{slug}.md as a Read pointer"

    def test_all_subdoc_paths_resolve(self):
        for slug, _desc in RAFTER_SUBDOCS:
            path = RESOURCES_DIR / "rafter" / "docs" / f"{slug}.md"
            assert path.exists(), f"missing sub-doc: {path}"
            assert path.read_text().strip(), f"sub-doc is empty: {path}"

    def test_load_skill_doc_returns_content(self):
        for slug, _desc in RAFTER_SUBDOCS:
            content = _load_skill_doc("rafter", slug)
            assert len(content) > 100

    def test_brief_exposes_each_subdoc_as_topic(self):
        for slug, _desc in RAFTER_SUBDOCS:
            result = runner.invoke(app, ["brief", slug])
            assert result.exit_code == 0, f"brief {slug} failed: {result.output}"
            assert len(result.stdout) > 100

    def test_brief_lists_subdoc_topics(self):
        result = runner.invoke(app, ["brief"])
        for slug, _desc in RAFTER_SUBDOCS:
            assert slug in result.stdout
