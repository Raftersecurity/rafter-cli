# Claude Code Setup

Rafter integrates with Claude Code two ways: a **PreToolUse hook** that intercepts every Bash command, and **skills** that expose scanning and auditing as slash commands.

## Automatic setup

```sh
rafter agent init
```

This auto-detects `~/.claude` and installs both the hook and skills. Done.

## Manual setup

### 1. PreToolUse hook

Add to your project's `.claude/settings.json` (or global `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "rafter hook pretool"
          }
        ]
      }
    ]
  }
}
```

This intercepts every Bash tool call, evaluates risk, and blocks dangerous commands before execution. No slash command needed—it's transparent.

### 2. Generate hook config from policy

If you have a `.rafter.yml` policy file, generate the matching Claude Code config:

```sh
rafter policy export --format claude
```

Outputs the JSON above, with matchers derived from your policy's blocked/approval patterns.

### 3. Skills (installed by `rafter agent init`)

Two skills are installed to `~/.claude/skills/`:

| Skill | Trigger | Purpose |
|-------|---------|---------|
| `rafter/` | Auto-invoked | Remote security audits (read-only API calls) |
| `rafter-agent-security/` | `/rafter-scan`, `/rafter-bash`, `/rafter-audit-skill`, `/rafter-audit` | Local secret scanning, command validation, skill auditing |

### 4. MCP server

`rafter agent init --local --with-claude-code` writes this to `<project>/.mcp.json` automatically:

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

Claude Code auto-loads project-scope `.mcp.json` and prompts you to approve the server on first interactive run. Exposes `scan_secrets`, `evaluate_command`, `read_audit_log`, `get_config`, `get_doc`, and `list_docs` tools as `mcp__rafter__*`.

**Headless (`claude -p`) note:** project-scope `.mcp.json` is gated behind per-project approval stored in `~/.claude.json` under `projects[<path>].enabledMcpjsonServers`. Fresh workdirs have no approval entry, so `-p` — even with `--dangerously-skip-permissions` — skips the server. Pass `--mcp-config .mcp.json` explicitly to load it:

```sh
claude --dangerously-skip-permissions --mcp-config .mcp.json -p "..."
```

## Verify

```sh
rafter agent verify
```

Confirms skills are installed and hook is configured.
