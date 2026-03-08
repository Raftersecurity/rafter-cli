# Continue.dev Setup

Rafter integrates with Continue.dev through an **MCP server** that exposes scanning and auditing tools.

## Automatic setup

```sh
rafter agent init --with-continue
```

This auto-detects `~/.continue` and installs the MCP server config. Done.

## Manual setup

### 1. MCP server

Add to your `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "rafter",
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  ]
}
```

Newer versions of Continue.dev may use object format instead of array:

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

Confirms MCP server is configured and Continue.dev is detected.
