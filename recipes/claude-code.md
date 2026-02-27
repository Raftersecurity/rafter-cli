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
| `rafter/` | Auto-invoked | Backend security audits (read-only API calls) |
| `rafter-agent-security/` | `/rafter-scan`, `/rafter-bash`, `/rafter-audit-skill`, `/rafter-audit` | Local secret scanning, command validation, skill auditing |

### 4. MCP server (alternative)

Expose Rafter tools to Claude Code via MCP instead of skills:

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

Add to `.claude/settings.json`. Provides `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools.

## Verify

```sh
rafter agent verify
```

Confirms skills are installed and hook is configured.
