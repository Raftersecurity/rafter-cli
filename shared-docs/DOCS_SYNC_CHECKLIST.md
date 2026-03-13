# Documentation Sync Checklist

Checklist for keeping [Rome-1/docs](https://github.com/Rome-1/docs) in sync with the rafter-cli codebase.

## Source of Truth (this repo)

| File | What it covers |
|------|----------------|
| `shared-docs/CLI_SPEC.md` | Complete CLI command spec (commands, flags, exit codes, schemas) |
| `README.md` | Feature overview, quickstart, installation |
| `CHANGELOG.md` | Version history with all additions/changes/fixes |
| `node/.claude/skills/rafter/SKILL.md` | Backend scanning skill definition |
| `node/.claude/skills/rafter-agent-security/SKILL.md` | Agent security skill definition |

## Docs Repo Files to Update

When making CLI changes, update these files in Rome-1/docs:

### After adding/changing commands or flags

- [ ] `guides/agent-security/reference.mdx` — Full command reference (flags, exit codes, examples)
- [ ] `guides/quick-reference.mdx` — Quick reference card (abbreviated command list)
- [ ] `guides/agent-security/getting-started.mdx` — Agent init flags, directory structure

### After adding/changing scan features

- [ ] `guides/agent-security/secret-scanning.mdx` — Scan flags, output formats, engines
- [ ] `guides/ci-cd.mdx` — CI workflows using scan commands

### After adding/changing agent security features

- [ ] `guides/agent-security/command-execution.mdx` — Risk levels, policy modes
- [ ] `guides/agent-security/audit-log.mdx` — Event types, schema, webhook config
- [ ] `guides/agent-security/policy-file.mdx` — Policy file format

### After adding/changing integrations

- [ ] `guides/agent-security/claude-code-integration.mdx` — Claude Code hooks/skills
- [ ] `guides/agent-security/codex-integration.mdx` — Codex CLI skills
- [ ] `guides/agent-security/openclaw-integration.mdx` — OpenClaw skills
- [ ] `guides/agent-security/gemini-integration.mdx` — Gemini CLI MCP setup
- [ ] `guides/agent-security/cursor-integration.mdx` — Cursor MCP setup
- [ ] `guides/agent-security/windsurf-integration.mdx` — Windsurf MCP setup
- [ ] `guides/agent-security/continue-integration.mdx` — Continue.dev MCP setup
- [ ] `guides/agent-security/aider-integration.mdx` — Aider MCP setup
- [ ] `guides/agent-security/mcp-integration.mdx` — MCP server tools/resources

### After version bumps

- [ ] Check all version-specific qualifiers (e.g., "supported in v0.5.6") are still accurate
- [ ] Remove any "coming soon" notices for features that shipped
- [ ] Update exit code tables if new codes were added

## Common Pitfalls

1. **Deprecated commands**: When deprecating a command, update ALL docs files that reference it (not just the primary one). Use grep to find all occurrences.
2. **Flag names**: Verify exact flag names against CLI_SPEC.md. Common mistakes: `--limit` vs `--last`, `--skip-*` vs `--with-*`, flags that don't exist.
3. **File paths**: `audit.jsonl` not `audit.log`. Always check CLI_SPEC.md for canonical paths.
4. **Exit codes**: Local scan has 3 exit codes (0/1/2), backend has 5 (0/1/2/3/4). Keep them separate.
5. **Config keys**: Only document keys listed in CLI_SPEC.md. Don't invent config paths.
6. **Skills per agent**: Each agent gets TWO skills (`rafter/` and `rafter-agent-security/`), not one.

## Known Doc Errors (pending fix in Rome-1/docs)

### `--skip-*` flags on init don't exist (rc-lya)

**File:** `guides/agent-security/getting-started.mdx` (auto-detection table)

The table lists `--skip-claude-code`, `--skip-codex`, and `--skip-openclaw` as
flags for `rafter agent init`. These flags do not exist. The `init` command uses
opt-in `--with-*` flags (e.g., `--with-claude-code`, `--with-codex`,
`--with-openclaw`). Remove the `--skip-*` column/rows from the auto-detection
table entirely.

Note: `--skip-openclaw` does exist, but only on `rafter agent audit-skill`, not
on `init`.

## Sync Process

1. `git clone https://github.com/Rome-1/docs /tmp/rome1-docs`
2. Diff `shared-docs/CLI_SPEC.md` against docs repo files
3. Update stale content, add missing features
4. Push branch and create PR in Rome-1/docs
5. Reference this checklist in the PR description
