# MCP Server

Expose Rafter security tools to **any MCP-compatible client** (Cursor, Windsurf, Claude Desktop,
Cline, etc.) over stdio.

## Start the server

```sh
rafter mcp serve
```

## Add to MCP client config

```json
{
  "rafter": {
    "command": "rafter",
    "args": ["mcp", "serve"]
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan files/directories for hardcoded secrets |
| `evaluate_command` | Check if a shell command is allowed by policy |
| `read_audit_log` | Read audit log entries with filtering |
| `get_config` | Read Rafter configuration |

## Resources

| Resource | Description |
|----------|-------------|
| `rafter://config` | Current configuration |
| `rafter://policy` | Active security policy (merged `.rafter.yml` + config) |

## Platform-specific setup

See individual setup recipes in [`recipes/`](../recipes/) for Cursor, Windsurf,
Continue.dev, Gemini CLI, and Aider.
