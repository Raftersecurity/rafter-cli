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

Provides `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools.

### 2. Generate policy from `.rafter.yml`

If you have a `.rafter.yml` policy file, export it:

```sh
rafter policy export --format gemini
```

## Verify

```sh
rafter agent verify
```

Confirms MCP server is configured and Gemini CLI is detected.
