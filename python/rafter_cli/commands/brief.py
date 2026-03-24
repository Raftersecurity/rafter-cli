"""rafter brief — print rafter knowledge for any agent."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import typer

brief_app = typer.Typer(name="brief", invoke_without_command=True, add_completion=False)

RESOURCES_DIR = Path(__file__).resolve().parent.parent / "resources" / "skills"

PLATFORM_GUIDES: dict[str, str] = {
    "claude-code": """\
# Rafter Setup — Claude Code

Claude Code has native skill support and hook integration.

## Automated Setup

```bash
rafter agent init --with-claude-code
```

This installs:
- Skills to `~/.claude/skills/rafter/` and `~/.claude/skills/rafter-agent-security/`
- PreToolUse/PostToolUse hooks to `~/.claude/settings.json`

## What You Get

- **Native skill triggers**: Claude Code will automatically invoke rafter skills
  when security-related topics come up
- **Automatic command interception**: All Bash tool calls are routed through
  rafter's risk assessment via hooks — no manual invocation needed
- **Write/Edit scanning**: File writes are checked for secrets before completing

## Manual Setup (if automated init isn't available)

1. Run `rafter brief security` and save key concepts to your memory
2. Run `rafter brief scanning` and save the command reference
3. Before commits, run: `rafter scan local .`
4. For remote analysis: `rafter run`""",

    "codex": """\
# Rafter Setup — Codex CLI

Codex CLI supports skill files in `~/.agents/skills/`.

## Automated Setup

```bash
rafter agent init --with-codex
```

This installs skills to `~/.agents/skills/rafter/` and `~/.agents/skills/rafter-agent-security/`.

## Manual Setup

1. Copy skill files manually:
   ```bash
   mkdir -p ~/.agents/skills/rafter
   rafter brief scanning > ~/.agents/skills/rafter/SKILL.md
   rafter brief security > ~/.agents/skills/rafter-agent-security/SKILL.md
   ```
2. Or run `rafter brief all` and save to your agent's instructions""",

    "gemini": """\
# Rafter Setup — Gemini CLI

Gemini CLI uses MCP for tool integration.

## Automated Setup

```bash
rafter agent init --with-gemini
```

This registers `rafter mcp serve` as an MCP server in Gemini's config.

## Manual Setup

Add to your Gemini CLI MCP config:
```json
{
  "mcpServers": {
    "rafter": {
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  }
}
```

## Supplementing with Brief

MCP gives you tool access, but not the full context of when/why to scan.
Run these and save the output to your agent's context:
```bash
rafter brief security
rafter brief scanning
```""",

    "cursor": """\
# Rafter Setup — Cursor

Cursor uses MCP for tool integration.

## Automated Setup

```bash
rafter agent init --with-cursor
```

This registers `rafter mcp serve` in Cursor's MCP config.

## Manual Setup

Add to `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "rafter": {
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  }
}
```

## Supplementing with Brief

```bash
rafter brief security   # save to your rules/instructions
rafter brief commands    # command reference
```""",

    "windsurf": """\
# Rafter Setup — Windsurf

Windsurf uses MCP for tool integration.

## Automated Setup

```bash
rafter agent init --with-windsurf
```

## Manual Setup

Add to Windsurf's MCP config (`~/.codeium/windsurf/mcp_config.json`):
```json
{
  "mcpServers": {
    "rafter": {
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  }
}
```""",

    "aider": """\
# Rafter Setup — Aider

Aider uses MCP for tool integration.

## Automated Setup

```bash
rafter agent init --with-aider
```

## Manual Setup

Add to `~/.aider.conf.yml`:
```yaml
mcp-servers:
  - name: rafter
    command: rafter mcp serve
```

## Supplementing with Brief

Aider doesn't have persistent memory, so run before each session:
```bash
rafter brief commands    # quick command reference
```""",

    "openclaw": """\
# Rafter Setup — OpenClaw

OpenClaw has native skill support.

## Automated Setup

```bash
rafter agent init --with-openclaw
```

This installs the security skill to `~/.openclaw/skills/rafter-security.md`.

## Manual Setup

```bash
mkdir -p ~/.openclaw/skills
rafter brief security > ~/.openclaw/skills/rafter-security.md
```""",

    "continue": """\
# Rafter Setup — Continue.dev

Continue.dev uses MCP for tool integration.

## Automated Setup

```bash
rafter agent init --with-continue
```

## Manual Setup

Add to Continue.dev's MCP config (`~/.continue/config.json`):
```json
{
  "mcpServers": [{
    "name": "rafter",
    "command": "rafter",
    "args": ["mcp", "serve"]
  }]
}
```""",

    "generic": """\
# Rafter Setup — Generic / Unsupported Agents

For agents on platforms rafter doesn't have native integration with.

## If Your Agent Has a Memory / Instructions System

Save rafter knowledge to your agent's persistent memory or system prompt:

```bash
# Save security knowledge
rafter brief security
# -> Copy the output into your agent's memory/instructions

# Save command reference
rafter brief commands
# -> Copy the output into your agent's memory/instructions
```

## If Your Agent Supports MCP

Register rafter as an MCP server:
```json
{
  "command": "rafter",
  "args": ["mcp", "serve"]
}
```

## If Your Agent Has Neither

Run `rafter brief` at the start of each session to load context:
```bash
rafter brief security   # understand the security layer
rafter brief commands    # know what commands are available
```

## Key Commands to Know

- `rafter scan local .` — scan for secrets locally (no API key needed)
- `rafter run` — trigger remote SAST/SCA analysis (needs API key)
- `rafter get <id>` — retrieve scan results
- `rafter agent audit` — review security event log
- `rafter agent exec <cmd>` — run a command with risk assessment""",
}


def _load_skill(name: str) -> str:
    """Load a skill file and strip YAML frontmatter."""
    raw = (RESOURCES_DIR / name / "SKILL.md").read_text()
    return re.sub(r"^---[\s\S]*?---\n*", "", raw).strip()


def _extract_sections(content: str, headings: list[str]) -> str:
    """Extract sections whose heading contains any of the given strings."""
    lines = content.split("\n")
    sections: list[str] = []
    capturing = False
    capture_level = 0
    in_code_block = False

    for line in lines:
        if line.lstrip().startswith("```"):
            in_code_block = not in_code_block
            if capturing:
                sections.append(line)
            continue
        if in_code_block:
            if capturing:
                sections.append(line)
            continue
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()
            if any(h.lower() in title.lower() for h in headings):
                capturing = True
                capture_level = level
                sections.append(line)
                continue
            if capturing and level <= capture_level:
                capturing = False
        if capturing:
            sections.append(line)

    return "\n".join(sections).strip()


def _render_setup_guide() -> str:
    return "\n".join([
        "# Rafter Setup Guide",
        "",
        "Platform-specific setup instructions. Use `rafter brief setup/<platform>`",
        "for details on a specific platform.",
        "",
        "## Supported Platforms",
        "",
        "### Skill-Based (native skill file support)",
        "- **Claude Code**: `rafter agent init --with-claude-code` — skills + hooks",
        "- **Codex CLI**: `rafter agent init --with-codex` — skills",
        "- **OpenClaw**: `rafter agent init --with-openclaw` — skills",
        "",
        "### MCP-Based (tool server integration)",
        "- **Gemini CLI**: `rafter agent init --with-gemini`",
        "- **Cursor**: `rafter agent init --with-cursor`",
        "- **Windsurf**: `rafter agent init --with-windsurf`",
        "- **Aider**: `rafter agent init --with-aider`",
        "- **Continue.dev**: `rafter agent init --with-continue`",
        "",
        "### Generic / Unsupported",
        "For any other agent, use `rafter brief` to load context manually.",
        "See `rafter brief setup/generic` for details.",
        "",
        "## Quick Start (Any Platform)",
        "",
        "```bash",
        "# 1. Initialize with your platform",
        "rafter agent init --with-<platform>",
        "",
        "# 2. If your platform doesn't have native integration,",
        "#    load knowledge manually:",
        "rafter brief security    # understand the security layer",
        "rafter brief scanning    # understand remote code analysis",
        "rafter brief commands    # full command reference",
        "```",
    ])


def _render_platform_setup(platform: str) -> str:
    return PLATFORM_GUIDES.get(platform, f"Unknown platform: {platform}")


# --- Topic registry ---

TOPIC_DESCRIPTIONS: dict[str, str] = {
    "security": "Local agent security — scanning, auditing, risk assessment",
    "scanning": "Remote SAST/SCA code analysis via backend API",
    "commands": "Condensed command reference for all rafter commands",
    "setup": "Setup instructions for all supported agent platforms",
    "setup/claude-code": "Setup instructions for Claude Code",
    "setup/codex": "Setup instructions for Codex CLI",
    "setup/gemini": "Setup instructions for Gemini CLI",
    "setup/cursor": "Setup instructions for Cursor",
    "setup/windsurf": "Setup instructions for Windsurf",
    "setup/aider": "Setup instructions for Aider",
    "setup/openclaw": "Setup instructions for OpenClaw",
    "setup/continue": "Setup instructions for Continue.dev",
    "setup/generic": "Setup instructions for unsupported / generic agents",
    "pricing": "What's free, what's paid, and the philosophy behind it",
    "all": "Everything — full security + scanning + setup briefing",
}


def _render_topic(topic: str) -> str | None:
    """Render a topic. Returns None if unknown."""
    if topic == "security":
        return _load_skill("rafter-agent-security")
    if topic == "scanning":
        return _load_skill("rafter")
    if topic == "commands":
        security = _load_skill("rafter-agent-security")
        backend = _load_skill("rafter")
        sec_cmds = _extract_sections(security, [
            "Commands", "/rafter-scan", "/rafter-bash",
            "/rafter-audit-skill", "/rafter-audit",
        ])
        back_cmds = _extract_sections(backend, [
            "Core Commands", "Trigger", "Get Scan", "Check API",
        ])
        return "\n".join([
            "# Rafter Command Reference",
            "",
            "## Backend (Remote Code Analysis)",
            "",
            back_cmds,
            "",
            "## Agent (Local Security)",
            "",
            sec_cmds,
        ])
    if topic == "setup":
        return _render_setup_guide()
    if topic.startswith("setup/"):
        platform = topic.split("/", 1)[1]
        return _render_platform_setup(platform)
    if topic == "pricing":
        return "\n".join([
            "# Rafter Pricing",
            "",
            "**Free forever for individuals and open source. No account required. No telemetry.**",
            "",
            "## What's Free",
            "",
            "All local agent security features are free with no limits:",
            "",
            "- Secret scanning (21+ patterns, Gitleaks integration)",
            "- Pre-commit hooks (local and global)",
            "- Command interception with risk-tiered approval",
            "- Skill/extension auditing",
            "- Audit logging",
            "- MCP server for tool integration",
            "- CI/CD pipeline generation",
            "- All supported agent integrations (Claude Code, Codex, Gemini, Cursor, Windsurf, Aider, OpenClaw, Continue.dev)",
            "",
            "No API key. No sign-up. No telemetry. No data collection. No network access required.",
            "Everything runs locally on your machine. MIT licensed.",
            "",
            "## Remote Code Analysis (API)",
            "",
            "Remote SAST/SCA scanning via the Rafter API has a free tier.",
            "Sign up at rafter.so for an API key. Enterprise plans offer higher",
            "limits, dashboards, policy management, and compliance reporting.",
            "",
            "## Philosophy",
            "",
            "Security tooling should be free for the people writing code.",
            "Generous free tiers drive bottom-up adoption. Enterprise value",
            "comes from dashboards, policy, and compliance — not from gating",
            "the tools developers use every day.",
        ])
    if topic == "all":
        parts = [
            _render_topic("scanning"),
            "---",
            _render_topic("security"),
            "---",
            _render_topic("setup"),
        ]
        return "\n\n".join(p for p in parts if p)
    return None


def _render_topic_list() -> str:
    lines = ["Available topics:", ""]
    for name, desc in TOPIC_DESCRIPTIONS.items():
        lines.append(f"  {name:<22} {desc}")
    lines.extend([
        "",
        "Usage: rafter brief <topic>",
        "",
        "Examples:",
        "  rafter brief security          # local security briefing",
        "  rafter brief scanning          # remote code analysis briefing",
        "  rafter brief commands          # full command reference",
        "  rafter brief setup/claude-code # Claude Code setup guide",
        "  rafter brief setup/generic     # setup for any agent",
        "  rafter brief all               # everything",
    ])
    return "\n".join(lines)


@brief_app.callback(invoke_without_command=True)
def brief(
    topic: str = typer.Argument(None, help="Topic to brief on (omit to list topics)"),
):
    """Print rafter knowledge for any agent — skills, commands, setup guides."""
    if topic is None:
        sys.stdout.write(_render_topic_list() + "\n")
        return

    result = _render_topic(topic)
    if result is None:
        sys.stderr.write(f"Unknown topic: {topic}\n\n{_render_topic_list()}\n")
        raise typer.Exit(code=1)
    sys.stdout.write(result + "\n")
