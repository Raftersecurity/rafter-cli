# Cursor Setup

Rafter's Cursor integration covers an MCP server + Cursor-native hooks (`preToolUse` / `postToolUse` / `beforeShellExecution`) + per-skill rules + a Cursor sub-agent. See [`shared-docs/PLATFORM_PARITY_AUDIT.md`](../shared-docs/PLATFORM_PARITY_AUDIT.md) for the full surface matrix.

## Install the CLI first

```sh
npm install -g @rafter-security/cli   # Node
# or:
pip install rafter-cli                 # Python
```

> Using `npx`? The canonical form is `npx @rafter-security/cli` — the bare `npx rafter-cli` resolves to an **unrelated** package on npm.

## Automatic setup

### Driven by the Cursor agent itself (recommended for first-run)

```sh
rafter agent init --local --with-cursor
```

Writes to `./.rafter/` and `./.cursor/` instead of `$HOME` — sidesteps Cursor's sandbox prompt for writing under your home directory and scopes the install to this project. Run it from inside the repo you're working in.

### Global install (one-time, applies to every project)

```sh
rafter agent init --with-cursor
```

Auto-detects `~/.cursor` and installs at user scope. Requires elevated permissions if Cursor's sandbox is locked down — the agent will prompt for them.

## Manual setup

### 1. MCP server

Add to `~/.cursor/mcp.json` (or `./.cursor/mcp.json` for per-project):

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

Confirms MCP server is configured and Cursor is detected.
