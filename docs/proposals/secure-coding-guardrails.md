# Proposal: Secure-Coding Guardrails for Agent Initialization

**Bead**: rc-1qt
**Date**: 2026-03-05
**Status**: Draft

## Problem

Rafter's `agent init` currently provides **reactive** security: hooks intercept
dangerous commands and secret scanning catches leaked credentials. But it does
not inject **proactive** secure-coding guidance into agent system prompts. Agents
write insecure code not because they intend to, but because they lack context
about what counts as a real vulnerability vs. a false positive in the codebase
they're working on.

The `claude-code-security-review` research (rc-q8c) identified 17 filtering
precedents that represent battle-tested secure coding knowledge. Embedding a
curated subset of these as agent prompt guidance would shift security left —
agents write secure code by default rather than having insecure code caught
after the fact.

## Analysis: Which Filtering Precedents Should Become Agent Guidance?

The 17 precedents from `claude-code-security-review` fall into three categories
for our purposes:

### Category A: Strong candidates for agent prompt injection (10)

These are practical, actionable rules that directly improve code generation:

| # | Precedent | Why inject |
|---|-----------|-----------|
| 1 | **Env vars and CLI flags are trusted input** | Agents over-validate env vars, adding unnecessary sanitization code |
| 3 | **React/Angular auto-escape XSS** | Agents flag/avoid framework-safe patterns; should only worry about `dangerouslySetInnerHTML` etc. |
| 5 | **Shell command injection requires specific untrusted input path** | Agents over-escape shell commands even when inputs are controlled |
| 6 | **SSRF only valid if attacker controls host/protocol** | Agents add unnecessary URL validation for path-only HTTP calls |
| 8 | **Logging non-PII data is safe** | Agents avoid helpful logging out of false caution |
| 9 | **Test files are not production attack surface** | Agents waste effort hardening test code |
| 11 | **Log spoofing is not a vulnerability** | Agents add unnecessary log sanitization |
| 12 | **Internal/private dependency references are fine** | Agents flag private registry deps as supply chain risks |
| 13 | **Crashes without security impact are not vulnerabilities** | Agents conflate stability with security |
| 2 | **UUIDs are unguessable** | Agents add unnecessary authorization layers on UUID-addressed resources |

### Category B: Context-dependent, better as configuration (4)

These depend on the project's tech stack and should be customizable:

| # | Precedent | Why configure, not hardcode |
|---|-----------|---------------------------|
| 4 | **Client-side auth checks not needed (backend validates)** | Only true if backend auth exists |
| 7 | **AI prompt injection is not a vulnerability** | Depends on the application's threat model |
| 10 | **GitHub Action workflow vulns need very specific attack path** | Only relevant to repos with Actions |
| - | **Memory safety findings excluded for non-C/C++** | Language-dependent; auto-detectable |

### Category C: Better handled by existing mechanisms (3)

These are already covered by Rafter's hook-based scanning or are too nuanced
for static prompt guidance:

| # | Precedent | Why skip |
|---|-----------|---------|
| - | **DOS/resource exhaustion excluded** | Already handled by risk-rules.ts command blocking |
| - | **Rate limiting not flagged** | Architectural concern, not code-level guidance |
| - | **Regex injection excluded** | Too rare to warrant prompt space |

## Where to Inject in Rafter's Init Flow

### Recommended: New CLAUDE.md section (primary) + skill enhancement (secondary)

The init flow currently has two injection points for Claude Code:

1. **Skills** (`~/.claude/skills/rafter-agent-security/SKILL.md`) — on-demand,
   `disable-model-invocation: true`, only loaded when explicitly invoked
2. **Hooks** (`~/.claude/settings.json` PreToolUse/PostToolUse) — reactive,
   intercepts tool calls at runtime

Neither is ideal for **proactive coding guidance** because:
- Skills are on-demand (not always-on)
- Hooks are reactive (post-hoc, not during generation)

**Proposed new injection point:**

3. **Project/user CLAUDE.md** — always loaded into context, influences all code
   generation. This is where coding standards belong.

### Injection mechanism

During `rafter agent init`, after installing skills and hooks, add a new step:

```
installClaudeCodeSkills()     // existing
installClaudeCodeHooks()      // existing
installSecureCodingGuidance() // NEW — writes to ~/.claude/CLAUDE.md
```

The new function should:

1. Read existing `~/.claude/CLAUDE.md` (if present)
2. Check for existing Rafter section (idempotent — don't duplicate)
3. Append (or replace) the Rafter secure-coding section
4. Preserve all non-Rafter content

For **project-level** injection (per-repo), add an optional `rafter agent init --project`
flag that writes to `.claude/CLAUDE.md` in the current repo instead. This allows
teams to customize per-project.

### Other agent environments

| Environment | Equivalent injection point |
|-------------|---------------------------|
| Claude Code | `~/.claude/CLAUDE.md` (user) or `.claude/CLAUDE.md` (project) |
| Cursor | `.cursorrules` file in project root |
| Windsurf | `.windsurfrules` file in project root |
| Continue.dev | `.continuerc` system prompt |
| Codex CLI | `~/.agents/AGENTS.md` or equivalent |
| OpenClaw | `.openclaw/SYSTEM.md` or equivalent |
| Gemini CLI | System instruction in settings |
| Aider | `.aider.conf.yml` conventions section |

## Format: What Gets Injected

### Draft content for `~/.claude/CLAUDE.md` injection

```markdown
<!-- BEGIN RAFTER SECURE CODING GUARDRAILS -->
# Secure Coding Guidelines (Rafter)

When writing or reviewing code, apply these principles:

## Trust Boundaries

- **Environment variables and CLI flags are trusted input.** Do not add
  sanitization or validation for values read from env vars or command-line
  arguments — these are set by the operator, not by attackers.
- **UUIDs are unguessable.** Do not add extra authorization checks solely
  because a resource is addressed by UUID. UUID entropy (122 bits) makes
  enumeration infeasible.
- **Internal/private package registry references are not supply chain risks.**
  Do not flag dependencies from private registries or internal package sources.

## Framework-Aware Security

- **Modern frontend frameworks auto-escape output.** In React, Angular, Vue,
  and similar frameworks, do not add manual HTML escaping. Only flag XSS when
  using escape hatches like `dangerouslySetInnerHTML`, `[innerHTML]`, or `v-html`.
- **SSRF requires attacker control of host/protocol.** If only the path portion
  of a URL comes from user input (and host is hardcoded), this is not SSRF.
  Only flag when attackers can control the full URL or at minimum the hostname.

## Pragmatic Security

- **Shell command injection requires an untrusted input path.** Do not flag
  shell commands as injection risks unless the specific input flowing into the
  command comes from an untrusted source (user input, external API, file content).
  Hardcoded commands and operator-controlled inputs are safe.
- **Logging non-sensitive data is safe and encouraged.** Only flag logging
  statements if they log passwords, API keys, tokens, PII, or other secrets.
  Logging request IDs, status codes, timestamps, and business events is good
  practice.
- **Log format injection is not a security vulnerability.** Do not flag the
  possibility of newline injection or format string issues in log output.
- **Crashes without security impact are bugs, not vulnerabilities.** A null
  pointer exception or unhandled error that crashes the process is a reliability
  issue, not a security finding. Only flag crashes that lead to data exposure,
  auth bypass, or similar security consequences.

## Scope

- **Test code is not production attack surface.** Do not apply production
  security hardening to unit tests, integration tests, or test fixtures.
  Hardcoded credentials in test files (for test databases, mock services) are
  acceptable.
- **Do not add security features the task doesn't call for.** If asked to
  implement a feature, implement it correctly. Do not speculatively add rate
  limiting, CSRF protection, input validation, or auth checks unless the
  task explicitly requires them or the code handles direct user input at a
  system boundary.
<!-- END RAFTER SECURE CODING GUARDRAILS -->
```

### Draft content for `.cursorrules` / `.windsurfrules` injection

Same content, adapted to the rules file format (no HTML comments, use heading
markers instead):

```
# --- RAFTER SECURE CODING GUARDRAILS ---
[same content as above, without HTML comment markers]
# --- END RAFTER SECURE CODING GUARDRAILS ---
```

## Implementation Plan

### Phase 1: Core injection (Claude Code)

1. Add `installSecureCodingGuidance()` function to `node/src/commands/agent/init.ts`
2. Create template content in `node/resources/secure-coding-guardrails.md`
3. Function reads existing `~/.claude/CLAUDE.md`, finds/replaces the Rafter
   section (between `BEGIN/END RAFTER` markers), preserves other content
4. Add `--skip-guardrails` flag to `rafter agent init`
5. Add `--project` flag for per-repo injection (writes to `.claude/CLAUDE.md`)
6. Mirror in Python implementation (`python/rafter_cli/commands/agent.py`)

### Phase 2: Multi-environment support

7. Add `.cursorrules` injection for Cursor
8. Add `.windsurfrules` injection for Windsurf
9. Add equivalent for other environments as their system prompt mechanisms
   stabilize

### Phase 3: Customization

10. Add `rafter agent config set guardrails.custom` for user-defined additions
    (additive model, matching `claude-code-security-review`'s approach)
11. Add `rafter agent guardrails show` to display active guardrails
12. Add `rafter agent guardrails reset` to restore defaults

## Design Decisions

### Why CLAUDE.md over skills?

Skills require explicit invocation or `disable-model-invocation: false` (which
loads them into every context). CLAUDE.md is the canonical location for coding
standards that should always be active. This matches how organizations already
use CLAUDE.md for style guides, conventions, and project-specific instructions.

### Why not a PostToolUse hook that reviews generated code?

Post-hoc review is more expensive (extra LLM pass), slower (blocks tool
completion), and less effective (the code is already written). Prompt guidance
changes what gets generated in the first place. Both approaches have value, but
guidance is the higher-leverage intervention.

### Why marker-delimited sections?

The `<!-- BEGIN/END RAFTER -->` markers enable:
- Idempotent updates (re-running `rafter agent init` replaces, not duplicates)
- Clean removal (`rafter agent uninstall` can strip exactly its content)
- Coexistence with user-authored CLAUDE.md content
- Version tracking (content can be updated across Rafter versions)

### Why not all 17 precedents?

Prompt space is finite and costly. Each guideline added to CLAUDE.md consumes
context tokens on every agent interaction. The 10 selected precedents are:
- Universally applicable (not stack-dependent)
- Directly actionable during code generation
- Address the most common false-positive patterns in agent-written code
- Not already covered by Rafter's hook-based enforcement

### Additive customization model

Following `claude-code-security-review`'s design, custom guardrails should
append to (not replace) the defaults. This prevents users from accidentally
removing baseline protections while adding domain-specific rules.

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Agents ignore CLAUDE.md guidance | Empirically, agents follow CLAUDE.md instructions well; this is the recommended injection point by Anthropic |
| Guidance conflicts with project security requirements | Per-project override via `--project` flag; custom additions via config |
| CLAUDE.md grows too large | Guardrails section is ~40 lines; well within budget |
| Updates clobber user edits | Marker-delimited sections ensure only Rafter content is replaced |
| False sense of security | Guardrails complement (not replace) hook-based enforcement and scanning |

## Success Metrics

1. Agents with Rafter guardrails produce fewer false-positive security warnings
   during code review (measured via `claude-code-security-review` findings count)
2. Reduction in unnecessary sanitization/validation code in agent-generated output
3. No increase in actual security vulnerabilities (validated by Rafter's existing
   scanning pipeline)
