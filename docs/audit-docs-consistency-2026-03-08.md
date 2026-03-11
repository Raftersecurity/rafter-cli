# Documentation Consistency Audit: CLI v0.5.9 vs Rome-1/docs

**Date:** 2026-03-08
**Auditor:** polecat/jasper (automated)
**CLI Version:** 0.5.9 (Node.js + Python)
**Docs Source:** Rome-1/docs (main branch, Mintlify)

## Summary

14 inconsistencies found across the Rome-1/docs repository when compared against
the raftercli v0.5.9 source code. 3 are high-priority (broken flags/missing
features), 5 are medium, and 6 are low. **1 resolved** (see strikethrough items).

---

## HIGH Priority (documented flags/features that don't work)

### 1. ~~`rafter ci init` documented as "coming soon" but is implemented~~ ✅ RESOLVED

- **Doc file:** `guides/ci-cd.mdx`
- **Issue:** Note said "rafter ci init is coming soon" — but the command is fully
  implemented in `node/src/commands/ci/init.ts` with `--platform`, `--output`,
  and `--with-backend` flags.
- **Fix:** "Coming soon" note removed. `ci-cd.mdx` now documents the command with
  a tip block pointing to the command reference.
- **Bead:** rc-0ud

### 2. `rafter agent audit` flag names wrong

- **Doc files:** `guides/quick-reference.mdx`, `guides/agent-security/codex-integration.mdx`
- **Issue:** Docs show `--limit 50` and `--risk high`. Actual flags are
  `--last <n>` (no `--limit`). There is no `--risk` flag at all.
- **Fix:** Replace `--limit` with `--last` and remove `--risk` references.
- **Bead:** rc-bbz

### 3. `rafter agent init` flag naming mismatch

- **Doc files:** `guides/agent-security/getting-started.mdx`, `quick-reference.mdx`,
  `codex-integration.mdx`
- **Issue:** Docs show `--codex` and `--claude-code`. Actual flags are
  `--with-codex` and `--with-claude-code`.
- **Fix:** Add `--with-` prefix in all doc references.
- **Bead:** rc-1ap

## MEDIUM Priority

### 4. `audit.log` vs `audit.jsonl` filename

- **Doc file:** `guides/agent-security/getting-started.mdx` (directory tree diagram)
- **Issue:** Shows `audit.log` in the `~/.rafter/` tree. Actual filename is
  `audit.jsonl`. The `audit-log.mdx` page correctly says `audit.jsonl`.
- **Bead:** rc-2bf

### 5. `--skip-*` flags don't exist

- **Doc file:** `guides/agent-security/getting-started.mdx` (auto-detection table)
- **Issue:** Table lists `--skip-claude-code`, `--skip-codex`, `--skip-openclaw`
  as skip flags. These are not defined in `init.ts`.
- **Bead:** rc-lya

### 6. Vulnerability level values contradict themselves

- **Doc files:** `api-reference/endpoint/static/get.mdx` vs `guides/advanced.mdx`,
  `guides/ci-cd.mdx`
- **Issue:** API reference says levels are `critical`, `high`, `medium`, `low`.
  But jq examples throughout the guides filter on `error`, `warning`, `note`.
  These are incompatible schemas.
- **Bead:** rc-kce

### 7. Five agent integrations undocumented

- **Doc file:** `guides/agent-security/getting-started.mdx`
- **Issue:** Only documents Claude Code, Codex, OpenClaw. The CLI also supports
  `--with-gemini`, `--with-aider`, `--with-cursor`, `--with-windsurf`,
  `--with-continue` (confirmed in completion.ts and init.ts).
- **Bead:** rc-nfs

### 8. Exit code table conflates backend and local scans

- **Doc file:** `guides/quick-reference.mdx`
- **Issue:** Single exit code table covers both backend (0/1/2/3) and local scans
  (0/1/2) without distinguishing them. Code 2 means "scan not found" for backend
  but "runtime error" for local scans.

## LOW Priority

### 9. `rafter scan` described as "alias for run"

- **Doc files:** `quickstart.mdx`, `basics.mdx`, `quick-reference.mdx`
- **Issue:** `rafter scan` is its own command group with subcommands (`local`,
  `remote`). Calling it an "alias" is misleading even though bare `rafter scan`
  does behave like `rafter run`.

### 10. `--all` and `--update` flags undocumented

- **Issue:** `rafter agent init --all` (install all integrations + gitleaks) and
  `--update` (re-download without resetting config) are not documented.

### 11. `rafter agent init --force` may not exist

- **Doc file:** `guides/agent-security/openclaw-integration.mdx`
- **Issue:** Troubleshooting section suggests `rafter agent init --force` but
  this flag is not visible in init.ts option definitions.

### 12. GitHub Issues URL may be wrong

- **Doc files:** Multiple pages
- **Issue:** Links point to `github.com/raftersecurity/rafter-cli/issues` but
  the actual repo appears to be `Rome-1/rafter-cli`.

### 13. Python CLI parity gaps not documented

- **Doc file:** `guides/agent-security/audit-log.mdx`
- **Issue:** Only mentions Python CLI emits limited event types. No other page
  documents what's missing in the Python CLI vs Node.

### 14. Command execution page says "Claude Code: Coming soon: MCP server"

- **Doc file:** `guides/agent-security/command-execution.mdx`
- **Issue:** Says MCP integration is "coming soon" under Claude Code section.
  MCP server is fully implemented and documented on its own page.

---

## Method

1. Fetched all documentation files from Rome-1/docs via GitHub API
2. Catalogued all CLI commands, flags, and options from Node.js source code
3. Compared each documented command/flag against source definitions
4. Cross-referenced internal doc consistency (flag names, schemas, file paths)
5. Filed beads for each actionable inconsistency

## Not Tested

- Actual CLI execution (source-code-only audit)
- Python CLI source comparison (focused on Node.js as reference implementation)
- Backend API response format verification
