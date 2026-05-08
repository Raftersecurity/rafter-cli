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
