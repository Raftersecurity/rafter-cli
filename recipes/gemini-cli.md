# Gemini CLI Setup

Rafter integrates with Google Gemini CLI through an **MCP server** that exposes scanning and auditing tools.

## Automatic setup

```sh
rafter agent init --with-gemini
```

This auto-detects `~/.gemini` and installs the MCP server config. Done.

## Manual setup

### 1. MCP server

Add to your `~/.gemini/settings.json`:

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

### 2. Generate policy from `.rafter.yml`

If you have a `.rafter.yml` policy file, export it:

```sh
rafter policy export --format gemini
```

## Available MCP tools

Once the MCP server is configured, Gemini CLI can call the following tools:

| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan files or directories for hardcoded secrets and credentials. Supports `gitleaks` and `patterns` engines. |
| `evaluate_command` | Check if a shell command is allowed by Rafter security policy. Returns risk level and approval requirement. |
| `read_audit_log` | Query the Rafter audit log with optional filtering by event type, count, or timestamp. |
| `get_config` | Read Rafter configuration — full config or a specific key via dot-path (e.g. `agent.commandPolicy`). |

Two MCP resources are also exposed:

| Resource | Description |
|----------|-------------|
| `rafter://config` | Current Rafter configuration as JSON |
| `rafter://policy` | Active security policy (merged `.rafter.yml` + config) |

## Verify

```sh
rafter agent verify
```

Confirms MCP server is configured and Gemini CLI is detected.

## Troubleshooting

- **MCP server not loading**: Restart Gemini CLI after installing. The MCP server is spawned when Gemini starts.
- **`rafter` not found**: Ensure `rafter` is on your `PATH`. Check with `which rafter`.
- **Existing settings preserved**: `rafter agent init --with-gemini` merges into your existing `settings.json` — it won't overwrite other settings or MCP servers.
- **Re-install**: Running `rafter agent init --with-gemini` again is safe and idempotent.
