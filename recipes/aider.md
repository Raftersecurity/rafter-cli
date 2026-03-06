# Aider Setup

Rafter integrates with Aider through an **MCP server** that exposes scanning and auditing tools.

## Automatic setup

```sh
rafter agent init --with-aider
```

This auto-detects `~/.aider.conf.yml` and appends the MCP server config. Done.

## Manual setup

### 1. MCP server

Add to your `~/.aider.conf.yml`:

```yaml
# Rafter security MCP server
mcp-server-command: rafter mcp serve
```

Provides `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools.

## Verify

```sh
rafter agent verify
```

Confirms MCP server is configured and Aider is detected.
