# OpenCode Setup

Rafter integrates with [OpenCode](https://opencode.ai) — the terminal AI coding
agent — through its native MCP support:

**MCP server** registered in `~/.config/opencode/opencode.json` — exposes the
`scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools
over stdio via `rafter mcp serve`.

OpenCode also reads `AGENTS.md` natively as persistent project context, so a
project-root `AGENTS.md` (shared with Codex and Windsurf) is picked up
automatically when present.

> OpenCode's MCP schema differs from Cursor/Windsurf. The config block is
> `mcp` (not `mcpServers`), each local server carries `type: "local"`, and the
> command + arguments are a single `command` array (not split into
> `command`/`args`). See the
> [OpenCode MCP docs](https://opencode.ai/docs/mcp-servers/).

## Automatic setup

```sh
# User scope — registers the MCP server in ~/.config/opencode/opencode.json:
rafter agent init --with-opencode
```

The install auto-detects `~/.config/opencode`. Restart OpenCode afterward so it
loads the new MCP server.

## What gets installed

| Path | Scope | Purpose |
|---|---|---|
| `~/.config/opencode/opencode.json` | user | `mcp.rafter` local/stdio server entry |

Existing keys and any other MCP servers in the file are preserved. A `$schema`
pointer is seeded on first write so editors get completion.

## Manual setup

Add to `~/.config/opencode/opencode.json` (global) or a project-root
`opencode.json` (project config takes precedence):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "rafter": {
      "type": "local",
      "command": ["rafter", "mcp", "serve"],
      "enabled": true
    }
  }
}
```

## Verify

```sh
rafter agent verify
```

Confirms the MCP server entry is in place. Restart OpenCode after install so it
picks up the new server.
