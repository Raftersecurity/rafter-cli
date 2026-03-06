# Windsurf Setup

Rafter integrates with Windsurf (Codeium) through an **MCP server** that exposes scanning and auditing tools.

## Automatic setup

```sh
rafter agent init --with-windsurf
```

This auto-detects `~/.codeium/windsurf` and installs the MCP server config. Done.

## Manual setup

### 1. MCP server

Add to your `~/.codeium/windsurf/mcp_config.json`:

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

## Verify

```sh
rafter agent verify
```

Confirms MCP server is configured and Windsurf is detected.
