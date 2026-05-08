# Continue.dev Setup

Rafter integrates with Continue.dev through two surfaces:

1. **Per-skill workspace rules** at `.continue/rules/<skill>.md` — Continue's
   agent reads these per-rule files (lexicographic load order) and surfaces
   the matching rule when its description matches the task.
2. **MCP server** under `~/.continue/config.json` — exposes `scan_secrets`,
   `evaluate_command`, `read_audit_log`, and `get_config` tools.

> Continue.dev has **no documented hook surface** — the `~/.continue/settings.json`
> hook install that earlier versions of rafter wrote was a silent no-op (pruned
> in `rf-cia` phase b).

## Automatic setup

```sh
# At a project root (rules only, no Continue.dev install required):
rafter agent init --local --with-continue

# At user scope (additionally registers the MCP server):
rafter agent init --with-continue
```

## What gets installed

| Path | Scope | Purpose |
|---|---|---|
| `<cwd>/.continue/rules/rafter.md` | workspace | Tier router rule (delegates to the `rafter` skill) |
| `<cwd>/.continue/rules/rafter-secure-design.md` | workspace | Shift-left design review rule |
| `<cwd>/.continue/rules/rafter-code-review.md` | workspace | Pre-merge code-review rule |
| `<cwd>/.continue/rules/rafter-skill-review.md` | workspace | Vet third-party agent assets before install |
| `~/.continue/config.json` | user (only with user-scope install) | MCP server entry under `mcpServers` |

Each rule uses Continue.dev's YAML frontmatter:

```yaml
---
name: rafter
description: "Entry point for rafter. Invoke when ..."
alwaysApply: false
---
```

`alwaysApply: false` lets Continue.dev's agent decide when to fetch the rule
based on the description.

## Manual setup

### 1. Workspace rules

Create `.continue/rules/rafter.md` (and similar files for the other three
skills) with the frontmatter shape above. Use a numeric prefix
(`01-rafter.md`, `02-rafter-code-review.md`) if you need to control load
order against your other rules.

### 2. MCP server

Continue.dev accepts both array and object formats for `mcpServers`. Newer
versions:

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

Older versions:

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

## Verify

```sh
rafter agent verify
```

Restart Continue.dev after install so the agent picks up the new rules and
MCP server.
