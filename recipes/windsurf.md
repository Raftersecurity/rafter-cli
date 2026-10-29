# Windsurf Setup

Rafter integrates with Windsurf (Codeium) through three surfaces:

1. **Per-skill workspace rules** at `.windsurf/rules/<skill>.md` — Windsurf's
   agent fetches the matching rule when its description matches the task.
2. **`AGENTS.md`** at the workspace root — Windsurf reads it natively as
   persistent project context (and so does Codex; one file covers both).
3. **MCP server** under `~/.codeium/windsurf/mcp_config.json` — exposes
   `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools.

> Windsurf has **no documented hook surface** in current versions. Earlier
> versions of `rafter agent init --with-windsurf` wrote `~/.windsurf/hooks.json`
> with `pre_run_command` / `pre_write_code` entries — the file existed but was
> never consumed by the IDE. That install was pruned in `rf-0vr3`.

## Prerequisites

- Rafter installed as either `@rafter-security/cli` (Node.js 22+) or
  `rafter-cli` (Python 3.11+).
- A project directory where Rafter can write `.windsurf/rules/` and
  `AGENTS.md`.
- For project-scope setup (`--local`), Windsurf does not need to be
  installed beforehand.
- For user-scope MCP registration, install and launch Windsurf so
  `~/.codeium/windsurf` exists.
- Ensure the `rafter` command is available on your `PATH`, particularly
  if you plan to use the optional MCP integration.

## Automatic setup

```sh
# At a project root (rules + AGENTS.md, no Windsurf install required):
rafter agent init --local --with-windsurf

# At user scope (additionally registers the MCP server):
rafter agent init --with-windsurf
```

The user-scope install auto-detects `~/.codeium/windsurf`. The project-scope
install (`--local`) writes only to the current workspace, so it works even on
a machine without Windsurf installed.

## What gets installed

| Path | Scope | Purpose |
|---|---|---|
| `<cwd>/.windsurf/rules/rafter.md` | workspace | Tier router rule (delegates to the `rafter` skill) |
| `<cwd>/.windsurf/rules/rafter-secure-design.md` | workspace | Shift-left design review rule |
| `<cwd>/.windsurf/rules/rafter-code-review.md` | workspace | Pre-merge code-review rule |
| `<cwd>/.windsurf/rules/rafter-skill-review.md` | workspace | Vet third-party agent assets before install |
| `<cwd>/AGENTS.md` | workspace | Persistent project context (also read by Codex) |
| `~/.codeium/windsurf/mcp_config.json` | user (only with user-scope install) | MCP server entry |

Each rule uses Windsurf's YAML frontmatter:

```yaml
---
trigger: model_decision
description: "REQUIRED before declaring a task done when the diff touches ..."
---
```

The `trigger: model_decision` mode lets Windsurf's agent decide when to fetch
the rule based on the description.

## Manual setup

### 1. Workspace rules

Create `.windsurf/rules/rafter.md` (and similar files for the other three
skills) with the frontmatter shape above. Cap each file at 12,000 characters
per Windsurf's per-file limit.

### 2. AGENTS.md

Create or extend `AGENTS.md` at the workspace root with a rafter content block
between `<!-- rafter:start -->` and `<!-- rafter:end -->` markers. Re-running
`rafter agent init --with-windsurf` will preserve content outside that block.

### 3. MCP server

Add to `~/.codeium/windsurf/mcp_config.json`:

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

## Verify

```sh
rafter agent verify
```
Confirms the rules, AGENTS.md, and (where applicable) the MCP server entry
are in place. Restart Windsurf after install so the agent picks up the new
rules and MCP server.

## MCP tools reference

The Rafter CLI is the primary way Windsurf agents use Rafter. MCP integration
is optional and provides additional security tools through the Rafter MCP
server (`rafter mcp serve`).

When MCP is configured, Windsurf can access these tools:

| Tool | Description |
|---|---|
| `scan_secrets` | Scan files or directories for hardcoded secrets and credentials. Supports `auto` (default), `betterleaks`, and `patterns` scanning engines. |
| `evaluate_command` | Check whether a shell command is allowed by Rafter's security policy. Returns the risk level and approval requirement. |
| `read_audit_log` | Query Rafter's audit log, optionally filtering by event type, count, or timestamp. |
| `get_config` | Read Rafter's configuration, either the full configuration or a specific key using a dot-path such as `agent.commandPolicy`. |

### Example MCP requests

With MCP configured, you can ask Windsurf to:

- "Scan `src/` for exposed secrets."
- "Check whether this shell command is allowed by our security policy."
- "Show recent blocked commands from the audit log."
- "What is our current command policy?"

These requests can use the MCP tools when available. Without MCP,
you can still use Rafter through its CLI.

## Troubleshooting

- **Windsurf rules are not loading:** Confirm that the Rafter rule files
  exist under `.windsurf/rules/` in your project directory. Restart
  Windsurf after installation so it can load the new rules.

- **Windsurf is not detected:** Launch Windsurf once to create its
  configuration directory at `~/.codeium/windsurf`. Alternatively,
  use `rafter agent init --local --with-windsurf` to install
  workspace rules without requiring Windsurf to be installed.

- **MCP server is not connecting:** MCP integration is optional.
  If enabled, check that `~/.codeium/windsurf/mcp_config.json`
  contains the `rafter` server entry with command `rafter`
  and arguments `["mcp", "serve"]`. Restart Windsurf afterward.

- **`rafter` command not found:** Ensure the Rafter CLI is installed
  and available on your `PATH`. Confirm with `rafter --version`.

- **`AGENTS.md` instructions are missing:** Confirm that `AGENTS.md`
  exists at the workspace root and contains Rafter's managed block
  between `<!-- rafter:start -->` and `<!-- rafter:end -->`.
  Re-run the appropriate setup command if necessary.

- **Old Windsurf hooks are present:** Earlier Rafter versions
  created `~/.windsurf/hooks.json`, but Windsurf did not consume
  those hooks. Current Rafter versions use workspace rules instead.
  Do not rely on the legacy hook configuration for security checks.

## Uninstall

On Rafter 0.11.2 and later, disable the Windsurf integration using:

```sh
rafter agent disable windsurf.rules windsurf.mcp
```

Run this command from the project directory containing the Windsurf rules.

- `windsurf.rules` removes Rafter's four managed rule files from
  `.windsurf/rules/` in the current workspace.
- `windsurf.mcp` removes only the `rafter` server entry from
  `~/.codeium/windsurf/mcp_config.json`, preserving other MCP servers.

The disable command does not remove the shared `AGENTS.md` file.
If you no longer need Rafter's project instructions, manually remove
only the content between `<!-- rafter:start -->` and
`<!-- rafter:end -->`, preserving any unrelated instructions.

Restart Windsurf after uninstalling.