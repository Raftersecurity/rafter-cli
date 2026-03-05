# Proposal: Rafter CLI Discoverability Improvements

**Date**: 2026-03-05
**Status**: Draft
**Bead**: rc-oox

## Problem Statement

Rafter CLI packs significant security value (secret scanning, command interception,
skill auditing, audit logging, MCP server, CI integration) but users and AI agents
don't naturally discover these capabilities at the moments they matter most. The
current discoverability model relies on users reading documentation upfront rather
than surfacing features contextually.

### Current State Assessment

**What works well:**
- `rafter agent init` auto-detects agents and installs skills/hooks — excellent zero-config UX
- Two-skill split (backend scanning vs agent security) correctly separates auto-invocable from user-invoked
- `--agent` flag for machine-readable output is well-designed
- PreToolUse hook integration makes command interception transparent
- CLI_SPEC.md provides a canonical reference

**What needs improvement:**
1. **Agent initialization output is opaque** — `rafter agent init` prints what it did but doesn't teach the agent (or user) what's now available
2. **No project-level CLAUDE.md generation** — agents working in a rafter-initialized repo have no local context about rafter's presence unless global skills are installed
3. **Security scanning not surfaced at natural moments** — no prompts to scan before PR creation, after dependency changes, or when touching sensitive files
4. **Command hierarchy confusion** — `rafter scan local` vs `rafter agent scan` (deprecated) vs `rafter run` vs `rafter scan` creates uncertainty
5. **Skills are installed globally but context is local** — a `.rafter.yml` in a project implies rafter is configured, but nothing tells the agent about project-specific policies
6. **MCP server capabilities are invisible** — agents using MCP don't see rafter's tools unless someone manually configures the client

---

## Proposed Improvements

### 1. Post-Init Summary with Actionable Next Steps

**Problem**: After `rafter agent init`, the user sees a list of what was installed but
not what to do next or what's now protecting them.

**Proposal**: Emit a structured "What's Active" summary after init:

```
Rafter Security Active

  Secret scanning:  Pre-commit hook installed (.git/hooks/pre-commit)
  Command policy:   moderate (approve-dangerous)
  Audit log:        ~/.rafter/audit.jsonl

  Agent integrations:
    Claude Code:    2 skills installed, PreToolUse hook active
    Cursor:         MCP server configured

  Quick commands:
    rafter scan local .              Scan for secrets now
    rafter agent audit               View security events
    rafter agent config show         Review your policy
    rafter ci init                   Add CI pipeline scanning

  Project setup (optional):
    rafter agent install-hook        Pre-commit hook for this repo
    Create .rafter.yml               Per-project security policy
```

For `--agent` mode, emit a machine-parseable JSON summary that agents can reference.

### 2. Generate Project-Level `.claude/CLAUDE.md` Security Context

**Problem**: An AI agent starting work in a repo with `.rafter.yml` has no idea rafter
is configured. Global skills help, but project-specific context is missing.

**Proposal**: Add `rafter agent init-project` (or integrate into `rafter agent init`
when run inside a git repo) that appends security context to the project's CLAUDE.md:

```markdown
## Security: Rafter

This project uses Rafter for security scanning. Before committing:

- Run `rafter scan local --staged` to check for leaked secrets
- Pre-commit hook is installed — commits with secrets will be blocked
- Security policy: see .rafter.yml for project-specific rules
- View security events: `rafter agent audit`

When reviewing PRs or external code:
- Run `rafter scan local <path>` on changed files
- Use `rafter agent audit-skill <path>` before installing any skills/extensions
```

This makes rafter discoverable to any agent (Claude Code, Cursor, Copilot) that reads
CLAUDE.md or .cursorrules. The content should be generated from the actual project
configuration, not static boilerplate.

### 3. Contextual Prompts at Natural Decision Points

**Problem**: Security scanning is most valuable at specific moments (pre-commit,
pre-PR, post-dependency-update) but rafter only activates when explicitly invoked
(except the pre-commit hook).

**Proposal A — Enhance PreToolUse hook with contextual suggestions:**

When the hook intercepts a `git push` or PR-related command, and a scan hasn't been
run recently, emit a suggestion to stderr:

```
hint: No rafter scan in this session. Consider: rafter scan local --diff origin/main
```

This is non-blocking (suggestion only) and respects the `--quiet` flag.

**Proposal B — Add `rafter scan auto` mode:**

A single command that intelligently picks what to scan:
- If staged files exist: scan staged files
- If on a feature branch: scan diff against base branch
- If neither: scan working directory

```sh
rafter scan auto    # "do the right thing"
```

This reduces cognitive load — instead of choosing between `--staged`, `--diff`, and
bare path scanning, users (and agents) run one command.

### 4. Simplify Command Hierarchy

**Problem**: The current command tree has historical layers that create confusion:
- `rafter scan` (no subcommand) = remote backend scan
- `rafter scan local` = local secret scan
- `rafter agent scan` = deprecated alias for `rafter scan local`
- `rafter run` = remote backend scan
- `rafter scan remote` = explicit remote backend scan

**Proposal**: Deprecation timeline and messaging:

Phase 1 (now): Add deprecation warnings to `rafter agent scan` pointing to
`rafter scan local`. Already done — verify the warning is clear and actionable.

Phase 2 (v0.6): Update all documentation, skills, and examples to use the
canonical forms exclusively:
- `rafter scan local` for local scanning
- `rafter scan` or `rafter run` for remote scanning
- Remove `rafter scan remote` alias (redundant)

Phase 3 (v1.0): Remove deprecated commands entirely.

Update the skills to use only canonical command forms. Currently the agent security
skill correctly uses `rafter scan local`, but the README still shows
`rafter agent scan` in examples (lines 149-155).

### 5. Project-Aware Policy Surfacing

**Problem**: When `.rafter.yml` exists, agents don't know what policies are active
without running `rafter agent config show` and understanding the merge semantics.

**Proposal**: Add `rafter policy summary` command that outputs a human/agent-readable
summary of the effective policy for the current directory:

```
Effective policy for /home/user/myproject:

  Sources:
    1. ~/.rafter/config.json (global)
    2. /home/user/myproject/.rafter.yml (project override)

  Risk level: moderate
  Command policy: approve-dangerous
  Blocked patterns: rm -rf /, <custom patterns from .rafter.yml>
  Excluded scan paths: vendor/, third_party/
  Custom patterns: 1 defined (Internal API Key)
  Audit retention: 90 days
```

The MCP server already exposes `rafter://policy` as a resource — this proposal
surfaces the same information as a CLI command for non-MCP contexts.

### 6. Improve Agent Skill Discoverability Triggers

**Problem**: The backend scanning skill triggers on phrases like "security audit" and
"vulnerability scan" — good. But common developer intents that should trigger rafter
are not covered.

**Proposal**: Expand skill trigger descriptions to include:

**Backend scanning skill** — add triggers for:
- "Is this code safe to merge?"
- "Check this PR for issues"
- "Run security checks before deploy"
- "Are there any vulnerabilities in this repo?"

**Agent security skill** — add triggers for:
- "Check for leaked secrets/credentials/keys"
- "Is it safe to commit this?"
- "Audit this extension/plugin/skill"
- "What security events happened?"
- "Show me the security policy"

These expanded descriptions help the agent's skill-matching logic activate rafter
at more natural moments.

### 7. First-Run Experience for Agents

**Problem**: When an agent encounters rafter for the first time (skill installed but
never used), it has no context about the project's security posture.

**Proposal**: Add a `rafter agent status` enhancement that returns a structured
onboarding message when invoked for the first time in a session:

```json
{
  "initialized": true,
  "risk_level": "moderate",
  "last_scan": "2026-03-04T15:30:00Z",
  "hooks_installed": true,
  "project_policy": ".rafter.yml found",
  "suggestions": [
    "Run 'rafter scan local .' to scan the project",
    "Run 'rafter agent audit --last 5' to see recent events"
  ]
}
```

The skill can instruct agents to call `rafter agent status --json` at session start
to orient themselves.

### 8. `rafter doctor` — Unified Health Check

**Problem**: `rafter agent verify` checks setup but doesn't provide actionable
improvement suggestions. Users don't know what they're missing.

**Proposal**: Add `rafter doctor` (or enhance `rafter agent verify`) to check
completeness and suggest improvements:

```
Rafter Health Check

  [pass]  Configuration: ~/.rafter/config.json exists
  [pass]  Gitleaks: v8.x installed at ~/.rafter/bin/gitleaks
  [pass]  Pre-commit hook: installed in current repo
  [pass]  Claude Code skills: 2 skills installed
  [warn]  No .rafter.yml in this project — consider adding one
  [warn]  No CI pipeline configured — run 'rafter ci init'
  [info]  Audit log: 47 entries, last event 2 hours ago
  [info]  Baseline: 3 suppressed findings

  Score: 7/9 checks passed
```

This gives users (and agents) a single command to understand their security coverage
and what actions would improve it.

---

## Implementation Priority

| Priority | Improvement | Effort | Impact |
|----------|------------|--------|--------|
| P0 | 2. Project-level CLAUDE.md generation | Medium | High — makes rafter visible to all agents |
| P0 | 4. Simplify command hierarchy (README cleanup) | Low | High — reduces confusion |
| P1 | 1. Post-init summary | Low | Medium — better onboarding |
| P1 | 6. Expand skill trigger descriptions | Low | Medium — more natural activation |
| P1 | 8. `rafter doctor` health check | Medium | Medium — actionable diagnostics |
| P2 | 3. Contextual prompts + `scan auto` | Medium | Medium — reduces friction |
| P2 | 5. Policy summary command | Low | Medium — transparency |
| P2 | 7. Enhanced agent status | Low | Low-Medium — better session start |

## Design Principles

These proposals follow three principles:

1. **Surface at the moment of need** — don't require upfront reading; show capabilities
   when they're relevant (pre-commit, pre-PR, post-init).

2. **Work with the grain of existing tools** — use CLAUDE.md, .cursorrules, MCP
   resources, and skill descriptions rather than inventing new discovery mechanisms.

3. **Progressive disclosure** — basic protection works with zero configuration
   (`rafter agent init`), advanced features are discoverable when needed
   (`rafter doctor`, `.rafter.yml`, `rafter ci init`).

## Appendix: Current Discoverability Surface Area

| Surface | What It Shows | Gap |
|---------|--------------|-----|
| `rafter --help` | Top-level commands | No "getting started" flow |
| `rafter agent --help` | Agent subcommands | No context about what's active |
| Skills (SKILL.md) | Command reference + triggers | Limited trigger phrases |
| PreToolUse hook | Transparent command interception | No visibility into what was blocked |
| README.md | Full feature reference | Discovery requires reading docs upfront |
| CLI_SPEC.md | Canonical spec for implementers | Not user-facing |
| `.rafter.yml` | Project policy | No agent-readable summary |
| MCP resources | `rafter://config`, `rafter://policy` | Only available to MCP clients |
