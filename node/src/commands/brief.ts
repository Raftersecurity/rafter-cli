import { Command } from "commander";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { isAgentMode } from "../utils/formatter.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RESOURCES_DIR = join(__dirname, "..", "..", "resources", "skills");

interface TopicEntry {
  description: string;
  render: () => string;
}

function loadSkill(name: string): string {
  const raw = readFileSync(join(RESOURCES_DIR, name, "SKILL.md"), "utf-8");
  // Strip YAML frontmatter
  return raw.replace(/^---[\s\S]*?---\n*/, "").trim();
}

function extractSections(content: string, headings: string[]): string {
  const lines = content.split("\n");
  const sections: string[] = [];
  let capturing = false;
  let captureLevel = 0;
  let inCodeBlock = false;

  for (const line of lines) {
    if (line.trimStart().startsWith("```")) {
      inCodeBlock = !inCodeBlock;
      if (capturing) sections.push(line);
      continue;
    }
    if (inCodeBlock) {
      if (capturing) sections.push(line);
      continue;
    }
    const headingMatch = line.match(/^(#{1,4})\s+(.*)/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      const title = headingMatch[2].trim();
      if (headings.some((h) => title.toLowerCase().includes(h.toLowerCase()))) {
        capturing = true;
        captureLevel = level;
        sections.push(line);
        continue;
      }
      if (capturing && level <= captureLevel) {
        capturing = false;
      }
    }
    if (capturing) {
      sections.push(line);
    }
  }
  return sections.join("\n").trim();
}

function buildTopics(): Record<string, TopicEntry> {
  return {
    security: {
      description: "Local agent security — scanning, auditing, risk assessment",
      render: () => loadSkill("rafter-agent-security"),
    },
    scanning: {
      description: "Remote SAST/SCA code analysis via backend API",
      render: () => loadSkill("rafter"),
    },
    commands: {
      description: "Condensed command reference for all rafter commands",
      render: () => {
        const security = loadSkill("rafter-agent-security");
        const backend = loadSkill("rafter");
        const secCmds = extractSections(security, [
          "Commands",
          "/rafter-scan",
          "/rafter-bash",
          "/rafter-audit-skill",
          "/rafter-audit",
        ]);
        const backCmds = extractSections(backend, [
          "Core Commands",
          "Trigger",
          "Get Scan",
          "Check API",
        ]);
        return [
          "# Rafter Command Reference",
          "",
          "## Backend (Remote Code Analysis)",
          "",
          backCmds,
          "",
          "## Agent (Local Security)",
          "",
          secCmds,
        ].join("\n");
      },
    },
    setup: {
      description: "Setup instructions for all supported agent platforms",
      render: () => renderSetupGuide(),
    },
    "setup/claude-code": {
      description: "Setup instructions for Claude Code",
      render: () => renderPlatformSetup("claude-code"),
    },
    "setup/codex": {
      description: "Setup instructions for Codex CLI",
      render: () => renderPlatformSetup("codex"),
    },
    "setup/gemini": {
      description: "Setup instructions for Gemini CLI",
      render: () => renderPlatformSetup("gemini"),
    },
    "setup/cursor": {
      description: "Setup instructions for Cursor",
      render: () => renderPlatformSetup("cursor"),
    },
    "setup/windsurf": {
      description: "Setup instructions for Windsurf",
      render: () => renderPlatformSetup("windsurf"),
    },
    "setup/aider": {
      description: "Setup instructions for Aider",
      render: () => renderPlatformSetup("aider"),
    },
    "setup/openclaw": {
      description: "Setup instructions for OpenClaw",
      render: () => renderPlatformSetup("openclaw"),
    },
    "setup/continue": {
      description: "Setup instructions for Continue.dev",
      render: () => renderPlatformSetup("continue"),
    },
    "setup/generic": {
      description: "Setup instructions for unsupported / generic agents",
      render: () => renderPlatformSetup("generic"),
    },
    all: {
      description: "Everything — full security + scanning + setup briefing",
      render: () => {
        const topics = buildTopics();
        return [
          topics.scanning.render(),
          "",
          "---",
          "",
          topics.security.render(),
          "",
          "---",
          "",
          topics.setup.render(),
        ].join("\n");
      },
    },
  };
}

const PLATFORM_GUIDES: Record<string, string> = {
  "claude-code": `# Rafter Setup — Claude Code

Claude Code has native skill support and hook integration.

## Automated Setup

\`\`\`bash
rafter agent init --with-claude-code
\`\`\`

This installs:
- Skills to \`~/.claude/skills/rafter/\` and \`~/.claude/skills/rafter-agent-security/\`
- PreToolUse/PostToolUse hooks to \`~/.claude/settings.json\`

## What You Get

- **Native skill triggers**: Claude Code will automatically invoke rafter skills
  when security-related topics come up
- **Automatic command interception**: All Bash tool calls are routed through
  rafter's risk assessment via hooks — no manual invocation needed
- **Write/Edit scanning**: File writes are checked for secrets before completing

## Manual Setup (if automated init isn't available)

1. Run \`rafter brief security\` and save key concepts to your memory
2. Run \`rafter brief scanning\` and save the command reference
3. Before commits, run: \`rafter scan local .\`
4. For remote analysis: \`rafter run\``,

  codex: `# Rafter Setup — Codex CLI

Codex CLI supports skill files in \`~/.agents/skills/\`.

## Automated Setup

\`\`\`bash
rafter agent init --with-codex
\`\`\`

This installs skills to \`~/.agents/skills/rafter/\` and \`~/.agents/skills/rafter-agent-security/\`.

## Manual Setup

1. Copy skill files manually:
   \`\`\`bash
   mkdir -p ~/.agents/skills/rafter
   rafter brief scanning > ~/.agents/skills/rafter/SKILL.md
   rafter brief security > ~/.agents/skills/rafter-agent-security/SKILL.md
   \`\`\`
2. Or run \`rafter brief all\` and save to your agent's instructions`,

  gemini: `# Rafter Setup — Gemini CLI

Gemini CLI uses MCP for tool integration.

## Automated Setup

\`\`\`bash
rafter agent init --with-gemini
\`\`\`

This registers \`rafter mcp serve\` as an MCP server in Gemini's config.

## Manual Setup

Add to your Gemini CLI MCP config:
\`\`\`json
{
  "mcpServers": {
    "rafter": {
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  }
}
\`\`\`

## Supplementing with Brief

MCP gives you tool access, but not the full context of when/why to scan.
Run these and save the output to your agent's context:
\`\`\`bash
rafter brief security
rafter brief scanning
\`\`\``,

  cursor: `# Rafter Setup — Cursor

Cursor uses MCP for tool integration.

## Automated Setup

\`\`\`bash
rafter agent init --with-cursor
\`\`\`

This registers \`rafter mcp serve\` in Cursor's MCP config.

## Manual Setup

Add to \`~/.cursor/mcp.json\`:
\`\`\`json
{
  "mcpServers": {
    "rafter": {
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  }
}
\`\`\`

## Supplementing with Brief

\`\`\`bash
rafter brief security   # save to your rules/instructions
rafter brief commands    # command reference
\`\`\``,

  windsurf: `# Rafter Setup — Windsurf

Windsurf uses MCP for tool integration.

## Automated Setup

\`\`\`bash
rafter agent init --with-windsurf
\`\`\`

## Manual Setup

Add to Windsurf's MCP config (\`~/.codeium/windsurf/mcp_config.json\`):
\`\`\`json
{
  "mcpServers": {
    "rafter": {
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  }
}
\`\`\``,

  aider: `# Rafter Setup — Aider

Aider uses MCP for tool integration.

## Automated Setup

\`\`\`bash
rafter agent init --with-aider
\`\`\`

## Manual Setup

Add to \`~/.aider.conf.yml\`:
\`\`\`yaml
mcp-servers:
  - name: rafter
    command: rafter mcp serve
\`\`\`

## Supplementing with Brief

Aider doesn't have persistent memory, so run before each session:
\`\`\`bash
rafter brief commands    # quick command reference
\`\`\``,

  openclaw: `# Rafter Setup — OpenClaw

OpenClaw has native skill support.

## Automated Setup

\`\`\`bash
rafter agent init --with-openclaw
\`\`\`

This installs the security skill to \`~/.openclaw/skills/rafter-security.md\`.

## Manual Setup

\`\`\`bash
mkdir -p ~/.openclaw/skills
rafter brief security > ~/.openclaw/skills/rafter-security.md
\`\`\``,

  continue: `# Rafter Setup — Continue.dev

Continue.dev uses MCP for tool integration.

## Automated Setup

\`\`\`bash
rafter agent init --with-continue
\`\`\`

## Manual Setup

Add to Continue.dev's MCP config (\`~/.continue/config.json\`):
\`\`\`json
{
  "mcpServers": [{
    "name": "rafter",
    "command": "rafter",
    "args": ["mcp", "serve"]
  }]
}
\`\`\``,

  generic: `# Rafter Setup — Generic / Unsupported Agents

For agents on platforms rafter doesn't have native integration with.

## If Your Agent Has a Memory / Instructions System

Save rafter knowledge to your agent's persistent memory or system prompt:

\`\`\`bash
# Save security knowledge
rafter brief security
# -> Copy the output into your agent's memory/instructions

# Save command reference
rafter brief commands
# -> Copy the output into your agent's memory/instructions
\`\`\`

## If Your Agent Supports MCP

Register rafter as an MCP server:
\`\`\`json
{
  "command": "rafter",
  "args": ["mcp", "serve"]
}
\`\`\`

## If Your Agent Has Neither

Run \`rafter brief\` at the start of each session to load context:
\`\`\`bash
rafter brief security   # understand the security layer
rafter brief commands    # know what commands are available
\`\`\`

## Key Commands to Know

- \`rafter scan local .\` — scan for secrets locally (no API key needed)
- \`rafter run\` — trigger remote SAST/SCA analysis (needs API key)
- \`rafter get <id>\` — retrieve scan results
- \`rafter agent audit\` — review security event log
- \`rafter agent exec <cmd>\` — run a command with risk assessment`,
};

function renderSetupGuide(): string {
  const platforms = [
    "claude-code",
    "codex",
    "openclaw",
    "gemini",
    "cursor",
    "windsurf",
    "aider",
    "continue",
    "generic",
  ];
  const parts = [
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
  ];
  return parts.join("\n");
}

function renderPlatformSetup(platform: string): string {
  return PLATFORM_GUIDES[platform] || `Unknown platform: ${platform}`;
}

function renderTopicList(topics: Record<string, TopicEntry>): string {
  const lines = [
    "Available topics:",
    "",
  ];
  for (const [name, entry] of Object.entries(topics)) {
    lines.push(`  ${name.padEnd(22)} ${entry.description}`);
  }
  lines.push("");
  lines.push("Usage: rafter brief <topic>");
  lines.push("");
  lines.push("Examples:");
  lines.push("  rafter brief security          # local security briefing");
  lines.push("  rafter brief scanning          # remote code analysis briefing");
  lines.push("  rafter brief commands          # full command reference");
  lines.push("  rafter brief setup/claude-code # Claude Code setup guide");
  lines.push("  rafter brief setup/generic     # setup for any agent");
  lines.push("  rafter brief all               # everything");
  return lines.join("\n");
}

export function createBriefCommand(): Command {
  return new Command("brief")
    .description(
      "Print rafter knowledge for any agent — skills, commands, setup guides",
    )
    .argument("[topic]", "Topic to brief on (omit to list topics)")
    .action((topic?: string) => {
      const topics = buildTopics();
      if (!topic) {
        process.stdout.write(renderTopicList(topics) + "\n");
        return;
      }
      const entry = topics[topic];
      if (!entry) {
        process.stderr.write(
          `Unknown topic: ${topic}\n\n${renderTopicList(topics)}\n`,
        );
        process.exit(1);
      }
      process.stdout.write(entry.render() + "\n");
    });
}
