# Rafter Consistency Audit Report

**Date**: 2026-04-03
**Source of truth**: rafter-cli (this repo)
**Repos audited**: Rome-1/docs (docs.rafter.so), Rome-1/securable-bolt (rafter.so)

---

## CRITICAL — Incorrect information visible to users

### C1. PyPI package name wrong in docs

**Where**: docs `quickstart.mdx:31`, `guides/agent-security/getting-started.mdx:55`, `guides/agent-security/mcp-integration.mdx:28`
**Docs say**: `pip install rafter-cli`
**Actual (pyproject.toml)**: Package is published as `rafter-cli` on PyPI — but the README says `pip install rafter-security`. Need to verify which is canonical.
**Action**: Verify `pip install rafter-cli` vs `pip install rafter-security`. README line 106 says `rafter-security`, pyproject.toml `name = "rafter-cli"`. One of them is wrong.

### C2. `--github-token` flag missing from all docs

**Where**: ALL docs pages — reference.mdx, quickstart.mdx, quick-reference.mdx, api-reference/endpoint/static/scan.mdx
**Docs say**: `rafter run` / `rafter scan` only document `--repo`, `--branch`, `--api-key`, `--format`, `--mode`, `--skip-interactive`, `--quiet`
**Actual CLI**: Now has `--github-token <token>` (or `RAFTER_GITHUB_TOKEN` env var) for private repo scanning
**Fix**: Add `--github-token` to:
- `guides/agent-security/reference.mdx` — not present since remote commands aren't documented there
- `guides/quick-reference.mdx` — add to Remote Code Analysis section
- `api-reference/endpoint/static/scan.mdx` — add `github_token` field to request body table
- `guides/agent-security/reference.mdx` — add `RAFTER_GITHUB_TOKEN` to Environment Variables table

### C3. API docs show `remaining` field, CLI parses `used`

**Where**: `api-reference/endpoint/static/scan.mdx:72-77`
**Docs say**: 403 response includes `"remaining": 0`
**CLI actually parses**: Both Node (`api.ts`) and Python (`api.py`) look for `used` and `limit` fields, displaying `({used}/{limit} used this billing period)`
**Fix**: Change `"remaining": 0` to `"used": 1` in the 403 response example (or confirm with backend which is correct)

### C4. 429 response undocumented on POST /api/static/scan

**Where**: `api-reference/endpoint/static/scan.mdx`
**Docs say**: Error responses: 400, 401, 403, 404, 500. No 429.
**CLI handles**: Both implementations explicitly handle 429 → exit code 3
**Fix**: Add 429 Too Many Requests response example

---

## HIGH — Stale or incomplete platform listings

### H1. securable-bolt CLIFeaturetteSection only shows 3 agents

**Where**: `components/home/CLIFeaturetteSection.tsx:30-46`
**Site says**: Supported agents are Claude Code, Codex CLI, Open Claw (only 3 shown)
**Actual CLI**: Supports 8 init platforms — Claude Code, Codex, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider
**Fix**: Add Gemini CLI, Cursor, Windsurf, Continue.dev, Aider to the `agentLogos` array

### H2. securable-bolt CLIFeaturetteSection header text outdated

**Where**: `components/home/CLIFeaturetteSection.tsx:70`
**Site says**: "First-class integrations with Claude Code, Codex CLI, and Open Claw"
**Actual**: CLI supports 8+ platforms, not just 3
**Fix**: Change to "First-class integrations with Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, and more"

### H3. securable-bolt terminal mockup incomplete

**Where**: `components/home/CLIFeaturetteSection.tsx:104-108`
**Site shows**: Terminal detecting only Claude Code, Codex CLI, Open Claw
**Actual**: `rafter agent init` detects 8 platforms
**Fix**: Add Gemini CLI and Cursor to the detection output (showing all 8 would be noisy)

### H4. securable-bolt getting-started agent list includes non-supported platforms

**Where**: `app/getting-started/page.tsx:88-98`
**Site lists AI Coding Agents**: Claude Code, Cursor, GitHub Copilot, Windsurf, Cody, Aider, OpenClaw, Continue, Amazon Q Developer
**Actual CLI integrations**: Claude Code, Codex CLI, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider
**Issues**:
- Lists "GitHub Copilot", "Cody", "Amazon Q Developer" — no Rafter integrations for these
- Missing "Codex CLI" and "Gemini CLI" — actual supported platforms
- This is a "works with" list (scan results work with any agent), but it's misleading alongside the agent security section
**Fix**: Either (a) separate "Rafter integration" from "works with any agent" more clearly, or (b) add Codex CLI and Gemini CLI to the list

### H5. docs index.mdx missing OpenCode from platform list

**Where**: `index.mdx:29`
**Docs say**: "Supports Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider, and OpenClaw"
**README says**: Also lists OpenCode in badges
**Note**: OpenCode has a badge in README but NO `--with-opencode` flag in the CLI. The badge is aspirational. Docs are correct to omit it.
**Action**: No docs change needed, but the README badge for OpenCode is misleading since there's no actual init support.

### H6. securable-bolt IntegrationsCloud missing platforms

**Where**: `components/home/IntegrationsCloud.tsx`
**Site lists**: Lovable, Bolt, v0, Replit, Firebase Studio, Windsurf, Base44, Claude Code, Cursor, GitHub Copilot, Gemini, Cline, Devin, Aider, Codex, OpenClaw, VS Code
**Missing**: Continue.dev (has CLI integration)
**Extra/fine**: GitHub Copilot, Cline, Devin, VS Code etc. are "works with" not "has integration" — acceptable for this component since it's about scanning projects built with these tools

### H7. securable-bolt audit log path wrong

**Where**: `components/home/CLIFeaturetteSection.tsx:119`
**Site says**: `~/.rafter/audit.log`
**Actual**: `~/.rafter/audit.jsonl`
**Fix**: Change to `audit.jsonl`

---

## MEDIUM — Missing features or incomplete docs

### M1. docs reference.mdx init-project says "7 supported agent platforms"

**Where**: `guides/agent-security/reference.mdx:84`
**Docs say**: "Creates instruction files in the current project for all 7 supported agent platforms"
**Actual**: Lists 7 platforms in the table but CLI supports 8 init platforms. The init-project table is missing OpenClaw.
**Fix**: Either add OpenClaw to the init-project table or verify if init-project generates OpenClaw files

### M2. docs reference.mdx Environment Variables missing RAFTER_GITHUB_TOKEN

**Where**: `guides/agent-security/reference.mdx:889-892`
**Docs list**: `RAFTER_API_KEY`, `RAFTER_CONFIG_PATH`
**Actual**: CLI also supports `RAFTER_GITHUB_TOKEN`
**Fix**: Add `RAFTER_GITHUB_TOKEN` — "GitHub PAT for private repo scanning (Contents:Read scope)"

### M3. docs `rafter agent verify` doesn't mention Cursor/Windsurf/Continue/Aider

**Where**: `guides/agent-security/reference.mdx:476-483`
**Docs say**: Verify checks config, gitleaks, Claude Code, OpenClaw, Codex, Gemini
**Actual**: Need to verify if `rafter agent verify` also checks Cursor/Windsurf/Continue/Aider
**Action**: Check CLI source, then update docs if needed

### M4. docs quickstart doesn't mention local scanning at all

**Where**: `quickstart.mdx`
**Docs show**: Only remote scanning flow (API key required)
**Actual**: Most users start with local features (no API key). The quickstart should at least mention `rafter scan local` and `rafter agent init --all`.
**Fix**: Add a "Local Security (No Account Required)" section before or after the remote scanning steps

### M5. securable-bolt roadmap still says "Max" scan mode

**Where**: `app/roadmap/page.tsx:29`
**Site says**: "Code Security Scans (Fast + Max)"
**Actual CLI**: Scan modes are `fast` and `plus`, not "Max"
**Fix**: Change to "Fast + Plus"

---

## LOW — Cosmetic / minor

### L1. "Open Claw" vs "OpenClaw" inconsistency on site

**Where**: `components/home/CLIFeaturetteSection.tsx` uses "Open Claw" (with space) everywhere
**CLI uses**: "OpenClaw" (no space) — `--with-openclaw`
**Docs use**: "OpenClaw" (no space)
**Fix**: Change "Open Claw" to "OpenClaw" in CLIFeaturetteSection.tsx

### L2. docs API base URL double-slash

**Where**: CLI code `utils/api.ts`
**Code**: `API = "https://rafter.so/api/"` then appends `/static/scan` → double slash
**Impact**: Works fine (servers normalize), but technically incorrect
**Fix**: Remove trailing slash from API constant or leading slash from paths

### L3. `rafter agent scan` deprecation notices in docs

**Where**: `guides/agent-security/getting-started.mdx:155`, `guides/agent-security/secret-scanning.mdx:18`, `guides/agent-security/reference.mdx:121`
**Docs say**: "`rafter agent scan` still works but is deprecated"
**Status**: Good — these notices are correct and consistent
**Action**: No change needed

---

## Summary by repo

### Rome-1/docs (docs.rafter.so)
- 2 critical issues (C2, C3)
- 1 high issue (H5 is fine actually)
- 4 medium issues (M1-M4)
- Mostly well-maintained, main gap is the new `--github-token` flag

### Rome-1/securable-bolt (rafter.so)
- 4 high issues (H1, H2, H3, H7)
- 1 high issue on getting-started (H4)
- 1 medium issue (M5)
- 1 low issue (L1)
- Main problem: CLIFeaturetteSection stuck at 3 platforms when CLI supports 8

### rafter-cli (this repo)
- OpenCode badge in README has no matching `--with-opencode` init flag (aspirational badge)
- Otherwise source of truth is self-consistent between Node and Python

---

## Recommended priority

1. **Immediate**: Fix securable-bolt CLIFeaturetteSection (H1, H2, H3, H7, L1) — this is the landing page
2. **This week**: Add `--github-token` to docs (C2, M2) and fix API docs (C3, C4)
3. **Soon**: Fix getting-started platform list (H4), roadmap scan mode name (M5)
4. **Backlog**: Quickstart local scanning section (M4), init-project platform count (M1)
