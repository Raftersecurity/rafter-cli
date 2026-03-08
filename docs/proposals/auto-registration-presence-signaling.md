# Design: Rafter CLI Auto-Registration and Presence Signaling

**Date**: 2026-03-05
**Status**: Draft
**Bead**: rc-crg

## Problem Statement

When `rafter agent init` runs, it installs skills, hooks, and MCP configs across
detected AI agent platforms. But the installed integrations are **passive** — they
wait for the agent or user to discover them. There is no active announcement, no
project-level context injection, and no mechanism for agents to learn what rafter
can do at session start.

This design specifies what rafter-cli should inject per platform, how it signals
its presence, and how agents discover its capabilities — drawing on patterns from
established CLI tools (gh, npm, docker, gitleaks).

---

## Prior Art: How Existing Tools Make Themselves Known

### GitHub CLI (`gh`)

- **Shell completions**: `gh completion -s {bash,zsh,fish}` — registered in shell
  startup files so `gh <tab>` works immediately
- **Environment detection**: `GH_TOKEN`, `GITHUB_TOKEN` env vars; auto-detects
  `.git` context for repo commands
- **Contextual help**: `gh` with no args prints grouped command overview; `gh status`
  surfaces actionable items (PRs, issues, notifications)
- **Extensions**: `gh extension list` — discoverability of installed extensions
- **PATH-based**: installs to PATH; no config-file registration needed
- **Key pattern**: zero-config when in a git repo; progressive disclosure via
  `--help` at every level

### npm

- **`postinstall` scripts**: after `npm install`, packages can run setup scripts
  that announce next steps
- **`.npmrc`**: per-project config detected automatically
- **`npx`**: discoverable run-without-install pattern
- **Lifecycle hooks**: `precommit`, `prepublish` — tools like husky and lint-staged
  hook into npm's lifecycle to inject themselves
- **Key pattern**: project-level config (package.json) is the discovery surface

### Docker

- **Shell completions**: `docker completion {bash,zsh,fish}`
- **Context system**: `docker context` — multiple configs, auto-switching
- **`.dockerignore`, `Dockerfile`, `docker-compose.yml`**: file presence signals
  Docker involvement to any tool scanning the project
- **Desktop notifications**: Docker Desktop pops up on state changes
- **Key pattern**: sentinel files (Dockerfile, compose.yml) signal presence

### Gitleaks

- **Pre-commit hook**: `.pre-commit-config.yaml` entry — the hook framework
  handles discovery
- **GitHub Action**: `gitleaks/gitleaks-action` — CI discovers it via workflow file
- **`.gitleaksignore`**: project-level config signals Gitleaks is active
- **Key pattern**: integrates into existing hook/CI frameworks rather than
  inventing new discovery

### Synthesis

The common patterns are:

1. **Sentinel files** signal presence (Dockerfile, .gitleaksignore, .rafter.yml)
2. **Shell completions** make the tool discoverable via tab
3. **Project config files** carry per-project context (package.json, .rafter.yml)
4. **Lifecycle hooks** inject at natural decision points (pre-commit, post-install)
5. **Progressive disclosure** — minimal output by default, detailed on request

For AI agents specifically, the discovery surfaces are:

| Surface | Who reads it | How to inject |
|---------|-------------|---------------|
| CLAUDE.md / .cursorrules | Agent at session start | Generate project-level file |
| MCP server config | Agent's MCP client | Write to platform config file |
| Skills/SKILL.md | Agent's skill loader | Copy to platform skill dir |
| PreToolUse hooks | Claude Code hook system | Write to settings.json |
| Shell PATH + completions | User's shell | Shell completion scripts |
| Env vars (RAFTER_*) | Any process | Set in shell profile |

---

## Per-Platform Integration Spec

### 1. Claude Code

**Current state** (already implemented):
- 2 SKILL.md files installed to `~/.claude/skills/`
- PreToolUse + PostToolUse hooks in `~/.claude/settings.json`

**Proposed additions**:

#### a. Project-Level CLAUDE.md Injection

When `rafter agent init` (or new `rafter agent init-project`) runs inside a git
repo, append a security context block to `.claude/CLAUDE.md`:

```markdown
## Security: Rafter

This project uses Rafter for security scanning and command interception.

**Active protections:**
- Pre-commit hook blocks commits containing secrets
- PreToolUse hook validates shell commands before execution
- Audit log: ~/.rafter/audit.jsonl

**Quick commands:**
- `rafter scan local .` — scan for leaked credentials
- `rafter scan local --staged` — scan staged files before commit
- `rafter agent audit --last 5` — recent security events
- `rafter agent status` — full security dashboard

**Policy:** {risk_level} risk level, {command_policy} command policy
```

The content is **generated from actual config**, not static boilerplate. If
`.rafter.yml` exists, policy details reflect the merged effective config.

**Implementation**: New function `generateProjectClaudeMd()` in
`node/src/commands/agent/init.ts` that:
1. Reads effective config (global + `.rafter.yml`)
2. Generates markdown block with actual policy values
3. Appends to `.claude/CLAUDE.md` (creates if missing, preserves existing content)
4. Uses `<!-- rafter:start -->` / `<!-- rafter:end -->` markers for idempotent updates

#### b. MCP Server Registration

Claude Code supports MCP servers in `.claude/settings.json`:

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

**Status**: Not currently installed by `rafter agent init` for Claude Code.
Should be added alongside the existing hook installation.

#### c. First-Run Session Detection

Add `--json` flag to `rafter agent status` that emits structured output for
agent consumption. The agent security skill can instruct Claude to call this
at session start:

```json
{
  "initialized": true,
  "risk_level": "moderate",
  "command_policy": "approve-dangerous",
  "gitleaks_available": true,
  "hooks_installed": { "pre_tool_use": true, "post_tool_use": true },
  "project_policy": ".rafter.yml found",
  "last_scan": "2026-03-05T10:00:00Z",
  "audit_summary": { "total": 42, "secrets": 3, "blocked": 1 },
  "suggestions": [
    "Run 'rafter scan local .' to scan the project",
    "Run 'rafter agent audit --last 5' to see recent events"
  ]
}
```

### 2. Cursor

**Current state**: MCP server registered in `~/.cursor/mcp.json`.

**Proposed additions**:

#### a. .cursorrules Generation

When `rafter agent init-project` runs in a git repo, generate or append to
`.cursorrules`:

```
# Security: Rafter
# This project uses Rafter CLI for security scanning.
# Before committing, run: rafter scan local --staged
# Pre-commit hook is active — commits with secrets will be blocked.
# View security events: rafter agent audit --last 5
# Full dashboard: rafter agent status
```

**Implementation**: Same generation logic as CLAUDE.md but formatted for
Cursor's `.cursorrules` format (plain text, no markdown headers).

#### b. MCP Tool Descriptions

The MCP server already exposes tools (`scan_secrets`, `evaluate_command`,
`read_audit_log`, `get_config`). Ensure tool descriptions include trigger
phrases that match natural developer intent:

- `scan_secrets`: "Scan files for leaked credentials, API keys, tokens, or
  passwords. Use before commits, when handling config files, or when the user
  asks 'is this safe to commit?'"
- `evaluate_command`: "Check if a shell command is allowed by security policy.
  Use when asked 'is this command safe?' or before running risky operations."

### 3. Codex CLI (OpenAI)

**Current state**: 2 SKILL.md files installed to `~/.agents/skills/`.

**Proposed additions**:

#### a. Codex Policy Export

`rafter policy export --format codex` already generates TOML policy. Should be
called automatically during `rafter agent init` when Codex is detected, writing
to `~/.codex/policy.toml` or wherever Codex reads policy.

#### b. Codex Instructions File

Generate `.codex/AGENTS.md` (or equivalent) with the same security context as
CLAUDE.md, adapted for Codex's instruction format.

### 4. Gemini CLI

**Current state**: MCP server registered in `~/.gemini/settings.json`.

**Proposed additions**:

#### a. Gemini Instructions

Gemini CLI reads `GEMINI.md` or `.gemini/instructions.md` for project context.
Generate security instructions using the same template as CLAUDE.md.

### 5. Aider

**Current state**: MCP server command in `~/.aider.conf.yml`.

**Proposed additions**:

#### a. .aider.conf.yml Enhancement

Aider supports `read` directives for context files. Add:

```yaml
# Rafter security context
read: .rafter-context.md
```

Generate `.rafter-context.md` with capability summary that Aider loads into
context on every session.

### 6. Windsurf / Continue.dev

**Current state**: MCP server registered in platform-specific config files.

**Proposed additions**: These platforms primarily consume MCP tools. Ensure MCP
tool descriptions are rich enough for discoverability. No additional file
injection needed beyond MCP registration.

---

## Capability Manifest

A machine-readable manifest that any tool can query to understand what
rafter-cli can do. Exposed via:

1. **CLI**: `rafter capabilities --json`
2. **MCP resource**: `rafter://capabilities`
3. **File**: `~/.rafter/capabilities.json` (generated on init, updated on config change)

```json
{
  "version": "0.5.8",
  "capabilities": {
    "secret_scanning": {
      "available": true,
      "engine": "gitleaks",
      "patterns": 150,
      "commands": ["rafter scan local <path>", "rafter scan local --staged"]
    },
    "command_interception": {
      "available": true,
      "mode": "approve-dangerous",
      "risk_levels": ["critical", "high", "medium", "low"]
    },
    "audit_logging": {
      "available": true,
      "log_path": "~/.rafter/audit.jsonl",
      "event_types": ["command_intercepted", "secret_detected", "policy_override", "config_changed"]
    },
    "skill_auditing": {
      "available": true,
      "command": "rafter agent audit-skill <path>"
    },
    "backend_scanning": {
      "available": false,
      "reason": "RAFTER_API_KEY not set",
      "setup": "export RAFTER_API_KEY=<key>"
    },
    "mcp_server": {
      "available": true,
      "command": "rafter mcp serve",
      "tools": ["scan_secrets", "evaluate_command", "read_audit_log", "get_config"]
    },
    "ci_integration": {
      "available": true,
      "platforms": ["github", "gitlab", "circleci"],
      "command": "rafter ci init"
    }
  },
  "integrations": {
    "claude_code": { "installed": true, "skills": 2, "hooks": true, "mcp": false },
    "cursor": { "installed": true, "mcp": true },
    "codex": { "installed": false },
    "gemini": { "installed": true, "mcp": true },
    "windsurf": { "installed": false },
    "continue_dev": { "installed": false },
    "aider": { "installed": false }
  }
}
```

This manifest enables any agent to introspect rafter's capabilities
programmatically without parsing help text.

---

## Agent Session Detection

### Can rafter-cli detect it's running inside an agent session?

Yes, via environment variable inspection:

| Agent | Detection Signal |
|-------|-----------------|
| Claude Code | `CLAUDE_CODE=1` or parent process is `claude` |
| Cursor | Running inside Cursor terminal (`TERM_PROGRAM=cursor`) |
| Codex CLI | `CODEX_CLI=1` or parent process detection |
| Aider | `AIDER=1` env var |
| Generic | `CI=true` (CI environment), `RAFTER_AGENT_MODE=1` (explicit) |

When agent session is detected, rafter can:

1. **Auto-format output for machines**: Emit JSON instead of human-readable text
   (equivalent to `--agent` flag being implicit)
2. **Suppress interactive prompts**: Never prompt for approval in agent mode;
   instead block and log
3. **Emit capability announcement on first invocation**:

```
[rafter] Security active. Capabilities: secret scanning, command interception, audit logging.
[rafter] Run 'rafter agent status --json' for full details.
```

This announcement goes to stderr (preserving stdout for data) and only fires
once per session (tracked via `RAFTER_SESSION_ANNOUNCED` env var or a temp file).

### Implementation

Add to `node/src/core/agent-detection.ts`:

```typescript
export function isAgentSession(): boolean {
  return !!(
    process.env.CLAUDE_CODE ||
    process.env.CODEX_CLI ||
    process.env.AIDER ||
    process.env.RAFTER_AGENT_MODE ||
    process.env.TERM_PROGRAM === "cursor"
  );
}
```

Wire into the CLI entry point: if `isAgentSession()` and first run in session,
emit the capability announcement to stderr.

---

## Shell Integration

### Completions

Already implemented for bash, zsh, and fish via `rafter completion <shell>`.

**Gap**: `rafter agent init` doesn't install completions. Proposed addition:

```bash
# During rafter agent init, detect shell and suggest completion setup
echo "Shell completions available:"
echo "  bash: eval \"\$(rafter completion bash)\""
echo "  zsh:  eval \"\$(rafter completion zsh)\""
echo "  fish: rafter completion fish | source"
echo ""
echo "Add to your shell profile for persistent completions."
```

### PATH Verification

During `rafter agent init`, verify `rafter` is on PATH and warn if it's only
accessible via `npx rafter` or `python -m rafter_cli`:

```
[warn] 'rafter' not found on PATH.
       Add to PATH or use: npx rafter <command>
       For permanent access: npm install -g @rafter-security/cli
```

---

## `rafter agent init-project` — Project-Level Setup

New command (or `--project` flag on existing `rafter agent init`) that:

1. Detects which AI agent config files exist in the project (`.claude/`,
   `.cursorrules`, `.codex/`, `GEMINI.md`)
2. Generates platform-specific security context files
3. Creates/updates `.rafter.yml` if missing (interactive or with defaults)
4. Installs pre-commit hook for this specific repo
5. Runs initial scan and creates baseline

**Output**:

```
Rafter Project Setup: /home/user/myproject

  [created]  .claude/CLAUDE.md — security context for Claude Code
  [created]  .cursorrules — security context for Cursor (appended)
  [skipped]  .codex/ — Codex CLI not detected
  [created]  .rafter.yml — project security policy (defaults)
  [installed] .git/hooks/pre-commit — secret scanning hook
  [scanned]  42 files, 0 secrets found

Project is now rafter-protected. Agents starting sessions in this
directory will see security context in their instructions.
```

### Idempotency

All file writes use marker comments for idempotent updates:

- **CLAUDE.md**: `<!-- rafter:start -->` / `<!-- rafter:end -->`
- **.cursorrules**: `# rafter:start` / `# rafter:end`
- **.rafter.yml**: Only created if missing; never overwritten
- **Pre-commit hook**: Checks for existing rafter hook before installing

Re-running `rafter agent init-project` updates the generated sections
without touching user-written content.

---

## Summary: What Gets Injected Per Platform

| Platform | Global (init) | Project (init-project) |
|----------|--------------|----------------------|
| **Claude Code** | Skills (2), Hooks (Pre/Post), MCP server | `.claude/CLAUDE.md` security context |
| **Cursor** | MCP server (`~/.cursor/mcp.json`) | `.cursorrules` security context |
| **Codex CLI** | Skills (2), Policy TOML | `.codex/AGENTS.md` security context |
| **Gemini CLI** | MCP server (`~/.gemini/settings.json`) | `GEMINI.md` security context |
| **Windsurf** | MCP server | (MCP tools sufficient) |
| **Continue.dev** | MCP server | (MCP tools sufficient) |
| **Aider** | MCP server, `read` directive | `.rafter-context.md` |
| **All** | Shell completions hint, PATH check | `.rafter.yml`, pre-commit hook, capability manifest |

---

## Implementation Priority

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| **P0** | Project-level CLAUDE.md generation | Medium | High — makes rafter visible to Claude Code agents in every session |
| **P0** | `rafter agent status --json` | Low | High — machine-readable status for agent consumption |
| **P0** | Claude Code MCP server registration in init | Low | High — enables tool discovery for MCP-aware sessions |
| **P1** | `rafter agent init-project` command | Medium | High — one-command project setup |
| **P1** | `.cursorrules` generation | Low | Medium — Cursor agent discoverability |
| **P1** | Capability manifest (`rafter capabilities --json`) | Medium | Medium — universal machine-readable discovery |
| **P1** | Agent session detection | Low | Medium — auto-format and announce |
| **P2** | Shell completion installation hint in init | Low | Low — user convenience |
| **P2** | PATH verification in init | Low | Low — prevents confusion |
| **P2** | Codex policy auto-export on init | Low | Low — Codex-specific |
| **P2** | Gemini/Aider project-level context | Low | Low — smaller user base |

---

## Design Principles

1. **Inject at the seams** — Use each platform's native config format (CLAUDE.md,
   .cursorrules, MCP config, settings.json). Don't invent new discovery mechanisms.

2. **Generate, don't template** — Content reflects actual config state, not static
   boilerplate. If the policy changes, re-running init-project updates the context.

3. **Idempotent updates** — Marker-delimited sections enable re-generation without
   destroying user content. Safe to run repeatedly.

4. **Progressive disclosure** — `rafter agent init` handles global setup.
   `rafter agent init-project` handles per-project. Each level adds context
   without requiring the previous level to have been run.

5. **Machine-first, human-readable** — All generated content serves agents first
   (structured, parseable) but remains readable by humans (markdown, comments).
