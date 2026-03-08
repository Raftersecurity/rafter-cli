# Research: Agent Discoverability — How Agents Learn rafter-cli Is Installed

**Date**: 2026-03-05
**Bead**: rc-427

## Executive Summary

Each AI agent platform has its own initialization flow and discovery mechanisms.
Rafter-cli needs platform-specific integration for each. The Node implementation
(`node/src/commands/agent/init.ts`) already supports 8 platforms. This document
maps the discovery mechanisms per platform and identifies gaps.

---

## Platform Discovery Matrix

| Platform | Primary Discovery | Secondary Discovery | What rafter-cli Does Today | Gaps |
|----------|------------------|--------------------|-----------------------------|------|
| **Claude Code** | Skills (`~/.claude/skills/`) | PreToolUse hooks, CLAUDE.md, MCP | Skills + hooks installed | No project CLAUDE.md, no MCP auto-config |
| **Cursor** | MCP servers (`~/.cursor/mcp.json`) | `.cursorrules`, `.cursor/rules/` | MCP server configured | No .cursorrules generation |
| **Windsurf** | MCP servers (`~/.codeium/windsurf/mcp_config.json`) | `.windsurfrules` | MCP server configured | No .windsurfrules generation |
| **Continue.dev** | MCP servers (`~/.continue/config.json`) | Context providers, slash commands | MCP server configured | No custom context provider |
| **Aider** | MCP servers (`~/.aider.conf.yml`) | Conventions files (`.aider/conventions.md`) | MCP server configured | No conventions file generation |
| **Codex CLI** | Skills (`~/.agents/skills/`) | AGENTS.md | Skills installed | No AGENTS.md generation |
| **Gemini CLI** | MCP servers (`~/.gemini/settings.json`) | GEMINI.md | MCP server configured | No GEMINI.md generation |
| **OpenClaw** | Skills (`~/.openclaw/skills/`) | N/A | Skill installed | — |

---

## Per-Platform Deep Dive

### 1. Claude Code

**How agents discover tools:**

Claude Code has the richest discovery surface of any platform, with five
independent mechanisms:

1. **CLAUDE.md files** (highest priority for instructions)
   - `~/.claude/CLAUDE.md` — global instructions, loaded every session
   - `.claude/CLAUDE.md` or `CLAUDE.md` in project root — project-specific
   - These are read automatically at session start
   - Agents treat content as authoritative instructions
   - **Format**: Plain markdown with natural-language instructions

2. **Skills** (`~/.claude/skills/<name>/SKILL.md`)
   - Auto-discovered on session start from `~/.claude/skills/`
   - Also discoverable from project-level `.claude/skills/`
   - Matched to user intent by skill `description` in YAML frontmatter
   - `disable-model-invocation: true` = user must explicitly invoke (`/skill-name`)
   - `allowed-tools` restricts what tools the skill can use
   - Skills are the primary way to teach Claude Code about new CLI tools
   - **Rafter today**: Installs 2 skills — `rafter` (backend scanning) and
     `rafter-agent-security` (local security tools)

3. **PreToolUse / PostToolUse hooks** (`~/.claude/settings.json`)
   - Intercept tool calls before/after execution
   - Can block, modify, or audit commands
   - Matcher patterns select which tools to intercept (e.g., `"Bash"`, `"Write|Edit"`)
   - Hook command receives tool call details on stdin as JSON
   - Returns JSON with `{"decision": "allow"}` or `{"decision": "block", "reason": "..."}`
   - **Rafter today**: Installs PreToolUse hooks for Bash and Write|Edit,
     PostToolUse hook for all tools (`.*`)

4. **MCP servers** (`.mcp.json` in project root or `~/.claude/` global)
   - Model Context Protocol servers expose tools and resources
   - Claude Code auto-starts configured MCP servers
   - Servers expose typed tools with input schemas
   - Also expose resources (read-only data) like `rafter://config`, `rafter://policy`
   - **Rafter today**: Has MCP server (`rafter mcp serve`) but doesn't auto-configure
     it for Claude Code during init

5. **PATH-based CLI discovery**
   - Claude Code's Bash tool can invoke any command on PATH
   - No special registration needed — if `rafter` is on PATH, it's available
   - But the agent won't know to use it without instructions (CLAUDE.md or skills)

**What rafter-cli needs for Claude Code:**

| Already Done | Gap |
|-------------|-----|
| 2 skills installed to `~/.claude/skills/` | No project-level `.claude/CLAUDE.md` with security context |
| PreToolUse hooks for command interception | No MCP server auto-configuration in `.mcp.json` |
| PostToolUse hooks for audit logging | Skill trigger descriptions could be broader (see discoverability-improvements.md proposal #6) |
| Skills use `--agent` flag for machine-readable output | No `rafter agent status --json` for session orientation |

---

### 2. Cursor

**How agents discover tools:**

Cursor uses a combination of MCP servers and instruction files:

1. **MCP servers** (`~/.cursor/mcp.json`)
   - Global MCP configuration, JSON format with `mcpServers` key
   - Also supports project-level `.cursor/mcp.json`
   - Format: `{ "mcpServers": { "name": { "command": "...", "args": [...] } } }`
   - MCP tools appear as available actions in Cursor's agent mode
   - **Rafter today**: Configures `~/.cursor/mcp.json` during init

2. **Rules files**
   - `.cursorrules` in project root — loaded at session start (legacy, still works)
   - `.cursor/rules/*.mdc` — newer rules format, supports multiple rule files
   - Rules can have frontmatter with `globs` for file-pattern scoping
   - Plain markdown with natural-language instructions
   - Agents treat these as authoritative project context

3. **Settings** (`~/.cursor/settings.json`)
   - IDE settings, not primary tool discovery mechanism
   - Extensions can expose commands that the agent can invoke

**What rafter-cli needs for Cursor:**

| Already Done | Gap |
|-------------|-----|
| MCP server configured in `~/.cursor/mcp.json` | No `.cursorrules` generation with security context |
| MCP exposes `scan_secrets`, `evaluate_command`, `audit_events` tools | No `.cursor/rules/rafter-security.mdc` generation |

---

### 3. Windsurf

**How agents discover tools:**

1. **MCP servers** (`~/.codeium/windsurf/mcp_config.json`)
   - Same MCP protocol as Cursor, different config location
   - Format: `{ "mcpServers": { "name": { "command": "...", "args": [...] } } }`
   - **Rafter today**: Configured during init

2. **Rules files**
   - `.windsurfrules` in project root — loaded at session start
   - Global rules in Windsurf settings
   - Plain markdown instructions, similar to `.cursorrules`

3. **Cascade agent mode**
   - Windsurf's agent can use MCP tools and shell commands
   - Tools discovered through MCP configuration
   - Instructions from `.windsurfrules`

**What rafter-cli needs for Windsurf:**

| Already Done | Gap |
|-------------|-----|
| MCP server configured | No `.windsurfrules` generation with security instructions |

---

### 4. Aider

**How agents discover tools:**

1. **MCP servers** (`~/.aider.conf.yml`)
   - YAML configuration file
   - `mcp-server-command` key for MCP server registration
   - Aider supports MCP for tool integration
   - **Rafter today**: Appends MCP config line to `~/.aider.conf.yml`

2. **Conventions files**
   - `.aider/conventions.md` — project-level instructions
   - `CONVENTIONS.md` in project root (also recognized)
   - Loaded at session start as context
   - Natural-language instructions for coding style, tools, etc.

3. **Repository map**
   - Aider builds a map of the repository structure
   - CLI tools on PATH can be invoked via shell commands
   - But Aider needs instruction (conventions) to know about them

4. **In-chat commands**
   - `/run <command>` — execute shell commands
   - Aider can suggest running CLI tools during conversation

**What rafter-cli needs for Aider:**

| Already Done | Gap |
|-------------|-----|
| MCP server configured | No `.aider/conventions.md` security section |

---

### 5. Continue.dev

**How agents discover tools:**

1. **MCP servers** (`~/.continue/config.json`)
   - JSON config with `mcpServers` key (array or object format)
   - Continue.dev supports both array format (older) and object format (newer)
   - **Rafter today**: Handles both formats during init

2. **Context providers**
   - Custom context providers can inject information into conversations
   - Configured in `config.json` under `contextProviders` key
   - Can provide files, URLs, or custom data as context

3. **Slash commands**
   - Custom slash commands defined in config
   - Can invoke CLI tools or provide templated prompts

4. **System message / rules**
   - `rules` array in config — persistent instructions
   - `.continuerules` file in project root (newer versions)

**What rafter-cli needs for Continue.dev:**

| Already Done | Gap |
|-------------|-----|
| MCP server configured | No context provider for security status |
| | No `.continuerules` generation |

---

### 6. OpenAI Codex CLI

**How agents discover tools:**

1. **Skills** (`~/.agents/skills/<name>/SKILL.md`)
   - Same skill format as Claude Code (Codex adopted it)
   - Discovered from `~/.agents/skills/` directory
   - SKILL.md format with YAML frontmatter
   - **Rafter today**: Copies Claude Code skills to `~/.agents/skills/`

2. **AGENTS.md**
   - `AGENTS.md` in project root — loaded at session start
   - Equivalent to CLAUDE.md but for Codex
   - Natural-language instructions

3. **Shell access**
   - Codex can execute shell commands
   - Tools on PATH are available
   - Needs instruction to know about specific tools

**What rafter-cli needs for Codex:**

| Already Done | Gap |
|-------------|-----|
| Skills installed to `~/.agents/skills/` | No AGENTS.md security context generation |

---

### 7. Google Gemini CLI

**How agents discover tools:**

1. **MCP servers** (`~/.gemini/settings.json`)
   - JSON config with `mcpServers` key
   - Same MCP protocol as other platforms
   - **Rafter today**: Configured during init

2. **GEMINI.md**
   - `GEMINI.md` in project root — loaded at session start
   - Equivalent to CLAUDE.md but for Gemini CLI
   - Natural-language instructions for the agent

3. **Shell access**
   - Gemini CLI can execute shell commands
   - Tools on PATH are available

**What rafter-cli needs for Gemini:**

| Already Done | Gap |
|-------------|-----|
| MCP server configured | No GEMINI.md security context generation |

---

## Cross-Platform Analysis

### Two Discovery Paradigms

The platforms split into two groups:

**1. Skill-based platforms** (explicit tool registration):
- Claude Code → `~/.claude/skills/`
- Codex CLI → `~/.agents/skills/`
- OpenClaw → `~/.openclaw/skills/`

These platforms have structured skill files with metadata (name, description,
version, allowed-tools). The agent can discover capabilities without executing
anything. Rafter already handles these well.

**2. MCP-based platforms** (protocol-based tool exposure):
- Cursor → `~/.cursor/mcp.json`
- Windsurf → `~/.codeium/windsurf/mcp_config.json`
- Gemini CLI → `~/.gemini/settings.json`
- Continue.dev → `~/.continue/config.json`
- Aider → `~/.aider.conf.yml`

These platforms use MCP for tool discovery. The MCP server (`rafter mcp serve`)
exposes tools (`scan_secrets`, `evaluate_command`, `audit_events`) and resources
(`rafter://config`, `rafter://policy`). Rafter configures MCP for all of these.

### The Instruction File Gap

Nearly every platform has a project-level instruction file that agents read at
session start:

| Platform | Instruction File |
|----------|-----------------|
| Claude Code | `CLAUDE.md` or `.claude/CLAUDE.md` |
| Codex CLI | `AGENTS.md` |
| Gemini CLI | `GEMINI.md` |
| Cursor | `.cursorrules` or `.cursor/rules/*.mdc` |
| Windsurf | `.windsurfrules` |
| Continue.dev | `.continuerules` |
| Aider | `.aider/conventions.md` or `CONVENTIONS.md` |

**Rafter does not generate any of these today.** This is the biggest
discoverability gap. Even though MCP servers and skills are configured, agents
starting a session in a project with `.rafter.yml` have no context about
rafter's presence unless they happen to check the global MCP tools.

### Recommended: `rafter agent init-project`

A new command that generates project-level instruction files:

```bash
rafter agent init-project
```

This would:
1. Detect which platforms are configured (from `~/.rafter/config.json`)
2. Generate appropriate instruction files for each detected platform
3. Append security context to existing files (not overwrite)
4. Content generated from actual project configuration (`.rafter.yml`)

Generated content example (for CLAUDE.md):
```markdown
## Security: Rafter

This project uses Rafter for security scanning.
- Pre-commit hook installed — commits with secrets are blocked
- Run `rafter scan local --staged` before committing
- Run `rafter scan local .` for full project scan
- Security policy: see .rafter.yml
- View security events: `rafter agent audit`
```

Equivalent content adapted for each platform's instruction file format.

---

## Rafter's Current Agent Init Flow

### Detection Phase (in `rafter agent init`)

The init command auto-detects platforms by checking for their config directories:

| Platform | Detection Signal |
|----------|-----------------|
| Claude Code | `~/.claude` exists |
| Codex CLI | `~/.codex` exists |
| OpenClaw | `~/.openclaw` exists |
| Gemini CLI | `~/.gemini` exists |
| Cursor | `~/.cursor` exists |
| Windsurf | `~/.codeium/windsurf` exists |
| Continue.dev | `~/.continue` exists |
| Aider | `~/.aider.conf.yml` exists |

### Installation Phase

For each detected platform, init installs the appropriate integration:

| Platform | What Gets Installed |
|----------|-------------------|
| Claude Code | 2 skills (`~/.claude/skills/rafter/`, `~/.claude/skills/rafter-agent-security/`) + PreToolUse/PostToolUse hooks in `~/.claude/settings.json` |
| Codex CLI | 2 skills (`~/.agents/skills/rafter/`, `~/.agents/skills/rafter-agent-security/`) |
| OpenClaw | 1 skill (`~/.openclaw/skills/rafter-security.md`) |
| Gemini CLI | MCP entry in `~/.gemini/settings.json` |
| Cursor | MCP entry in `~/.cursor/mcp.json` |
| Windsurf | MCP entry in `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | MCP entry in `~/.continue/config.json` |
| Aider | MCP line in `~/.aider.conf.yml` |

### What MCP Exposes (for MCP-based platforms)

The MCP server (`rafter mcp serve`) exposes:

**Tools:**
- `scan_secrets` — Scan files/directories for hardcoded secrets
- `evaluate_command` — Check if a command is allowed by policy
- `audit_events` — Retrieve security audit log entries

**Resources:**
- `rafter://config` — Current configuration
- `rafter://policy` — Effective security policy

---

## Gap Analysis Summary

### High Priority Gaps

1. **No project-level instruction files** — Biggest gap. Agents in a
   rafter-configured project don't know rafter exists unless they check global
   tools. Need `rafter agent init-project` to generate CLAUDE.md, AGENTS.md,
   GEMINI.md, .cursorrules, .windsurfrules, .continuerules, and .aider/conventions.md
   sections.

2. **Claude Code MCP not auto-configured** — Claude Code supports `.mcp.json`
   in project root for project-level MCP servers. The init command doesn't
   create this. For Claude Code specifically, skills + hooks are sufficient,
   but MCP would provide an additional discovery path.

3. **Python CLI lacks parity with Node** — The Python implementation
   (`python/rafter_cli/commands/agent.py`) only supports Claude Code, OpenClaw,
   and Codex. Missing: Gemini, Cursor, Windsurf, Continue.dev, Aider.

### Medium Priority Gaps

4. **Skill trigger descriptions are narrow** — Current triggers match "security
   audit", "vulnerability scan" but miss common developer intents like "is this
   safe to merge?" or "check for leaked secrets" (see discoverability-improvements.md
   proposal #6).

5. **No `rafter agent status --json` for session orientation** — Agents can't
   quickly learn about rafter's state at session start.

6. **Post-init output doesn't teach** — `rafter agent init` prints what it did
   but doesn't output a structured summary of what's now available (see
   discoverability-improvements.md proposal #1).

### Low Priority Gaps

7. **No `rafter doctor`** — No unified health check command.

8. **`rafter scan auto`** — No intelligent "do the right thing" scan command.

---

## Recommendations for rafter-cli

### Immediate (addresses the bead directly)

1. **Document** this research as the canonical reference for platform discovery
   mechanisms (this document).

2. **Prioritize** `rafter agent init-project` as the key missing feature —
   generating project-level instruction files is the single highest-impact
   improvement for discoverability.

3. **Reach Python parity** for the 5 platforms the Node CLI supports but
   Python doesn't (Gemini, Cursor, Windsurf, Continue.dev, Aider).

### Near-term

4. Expand skill trigger descriptions for better intent matching.
5. Add `rafter agent status --json` for agent session orientation.
6. Enhance post-init output with structured "What's Active" summary.

### Longer-term

7. Add `.mcp.json` generation for Claude Code project-level MCP.
8. Add context providers for Continue.dev.
9. Implement `rafter doctor` and `rafter scan auto`.
