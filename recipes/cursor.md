# Cursor Setup

Rafter's Cursor integration covers an MCP server + Cursor-native hooks
(`preToolUse` / `postToolUse` / `beforeShellExecution`) + per-skill rules + a
Cursor sub-agent. See
[`shared-docs/PLATFORM_PARITY_AUDIT.md`](../shared-docs/PLATFORM_PARITY_AUDIT.md)
for the full surface matrix.

## Prerequisites

- [Cursor](https://cursor.com) installed (creates `~/.cursor` on first launch)
- Rafter CLI on your `PATH`:

```sh
npm install -g @rafter-security/cli   # Node
# or:
pip install rafter-cli                 # Python
```

> Using `npx`? The canonical form is `npx @rafter-security/cli` — the bare
> `npx rafter-cli` resolves to an **unrelated** package on npm.

## Setup

### Driven by the Cursor agent itself (recommended for first-run)

```sh
rafter agent init --local --with-cursor
```

Writes to `./.rafter/` and `./.cursor/` instead of `$HOME` — sidesteps Cursor's
sandbox prompt for writing under your home directory and scopes the install to
this project. Run it from inside the repo you're working in.

### Global install (one-time, applies to every project)

```sh
rafter agent init --with-cursor
```

Auto-detects `~/.cursor` and installs at user scope. Requires elevated
permissions if Cursor's sandbox is locked down — the agent will prompt for them.

### Manual setup

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

Restart Cursor afterward so it loads the MCP server. Hooks, rules, and the
sub-agent are installed by `rafter agent init --with-cursor` (local or global);
prefer that over assembling them by hand.

## Verify

```sh
rafter agent verify
```

Confirms MCP server is configured and Cursor is detected. In Cursor, open
**Settings → MCP** and check that the `rafter` server is connected.

## Available MCP tools

Once the MCP server is configured, Cursor can call the following tools:

| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan files or directories for hardcoded secrets and credentials. Supports `auto` (default), `betterleaks`, and `patterns` engines — `auto` runs both engines and unions the results. |
| `evaluate_command` | Check if a shell command is allowed by Rafter security policy. Returns risk level and approval requirement. |
| `read_audit_log` | Query the Rafter audit log with optional filtering by event type, count, or timestamp. |
| `get_config` | Read Rafter configuration — full config or a specific key via dot-path (e.g. `agent.commandPolicy`). |

Three MCP resources are also exposed:

| Resource | Description |
|----------|-------------|
| `rafter://config` | Current Rafter configuration as JSON |
| `rafter://policy` | Active security policy (merged `.rafter.yml` + config) |
| `rafter://docs` | Repo-specific security docs declared in `.rafter.yml` (metadata only, no content) |

### Tool usage examples

Ask the Cursor agent in natural language — it calls the matching tool:

- "Scan `src/` for leaked secrets" → `scan_secrets`
- "Is `curl | bash` allowed by our policy?" → `evaluate_command`
- "Show recent blocked commands from the audit log" → `read_audit_log`
- "What's our current command policy?" → `get_config`

Hooks run automatically on tool/shell use; you do not need to invoke them
manually.

## Troubleshooting

- **MCP server not loading**: Restart Cursor after installing. Open
  **Settings → MCP** and confirm `rafter` is connected. Check `which rafter`.
- **`rafter` not found**: Ensure `rafter` is on your `PATH`. The MCP entry uses
  `"command": "rafter"` — a bare name, not a full path.
- **Sandbox / home-directory write blocked**: Use
  `rafter agent init --local --with-cursor` so files land under `./.cursor/`.
- **Cursor not detected**: Launch Cursor once so `~/.cursor` exists, or use
  `--local` from inside a project.
- **Existing config preserved**: `rafter agent init --with-cursor` merges into
  existing `mcp.json` / `hooks.json` — it won't overwrite other settings.
  Re-running is safe and idempotent.

## Uninstall

```sh
rafter agent disable cursor.mcp cursor.hooks cursor.instructions
```

Removes the Rafter MCP entry, hooks, rules, and sub-agent at user scope while
leaving the rest of your Cursor config intact.

For a local (`--local`) install, delete the corresponding files under
`./.cursor/` (or remove only the `rafter` key from `mcp.json` if you share that
file with other servers). Restart Cursor afterward.
