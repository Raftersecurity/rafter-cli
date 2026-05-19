# Platform Parity Audit (rf-cia)

> Authored 2026-04-28 by raftercli/crew/lucy as the kickoff deliverable for the
> rf-cia P0 epic ("Cross-platform agent parity"). Establishes ground truth for
> what each supported platform currently gets vs. what gold-standard parity
> requires. Drives the per-platform work items that follow.
>
> Re-audited 2026-04-30 by raftercli/polecats/obsidian against `origin/main`
> (commit `e366778`, v0.7.7). See "Re-audit (2026-04-30)" section below.
>
> Re-audited 2026-05-19 by sable polecat (sable-2vz / B10 follow-up) against
> `origin/maylist` HEAD `d2d9f6a`, v0.8.1. See "Re-audit (2026-05-19) at v0.8.1"
> section below. The earlier sections are preserved as history.

## Re-audit (2026-05-19) at v0.8.1

Re-run after the v0.7.7 → v0.8.1 window. Pinned at `origin/maylist` `d2d9f6a`
(node/package.json v0.8.1, python/pyproject.toml v0.8.1). Host overloaded — no
test run; audit is code-walk only against `node/src/commands/agent/init.ts`,
`verify.ts`, `components.ts`, and Python mirrors at `python/rafter_cli/commands/agent.py`.

### Updated state matrix (v0.8.1)

Columns: `Skills` (count of SKILL.md files installed by the init path, of 4
shipped templates) / `MCP` / `Hooks` / `Instruction file` / `Per-skill rules`
/ `Sub-agent` / `Verify` (`agent verify` covers it) / `Uninstall` (`agent
disable`/`uninstall` cleanly tears down).

| Platform     | Skills (init) | MCP                                      | Hooks                                                    | Instruction file               | Per-skill rules                  | Sub-agent                                  | Verify                  | Uninstall (components.ts)       |
|--------------|---------------|------------------------------------------|----------------------------------------------------------|--------------------------------|----------------------------------|--------------------------------------------|-------------------------|---------------------------------|
| Claude Code  | **3 of 4**    | yes (`.mcp.json` project / settings user) | yes (`PreToolUse` + `PostToolUse`)                        | CLAUDE.md                      | n/a (uses skills)                | yes (`.claude/agents/rafter.md`)            | yes (file + `--probe`)  | hooks, instructions, skills, mcp |
| Codex        | **3 of 4**    | n/a (no MCP in Codex)                    | yes (`PreToolUse: Bash\|apply_patch` + `PostToolUse`)     | AGENTS.md                      | n/a                              | n/a (no first-class primitive)              | yes (skills only)        | hooks, skills (no instructions)  |
| Gemini       | **3 of 4**    | yes (`.gemini/settings.json`)            | yes (`BeforeTool` regex + `AfterTool`)                    | GEMINI.md                      | n/a                              | n/a                                        | yes (MCP only)          | hooks, mcp (no skills, no instructions) |
| Cursor       | n/a (rules)   | yes (`.cursor/mcp.json`)                 | yes (`preToolUse` + `postToolUse` + `beforeShellExecution`) | per-skill rules (see col)     | **4 of 4** in `.cursor/rules/`   | yes (`.cursor/agents/rafter.md`)            | yes (MCP only)          | hooks, instructions (rules+sub-agent), mcp |
| Windsurf     | n/a (rules)   | yes (`~/.codeium/windsurf/mcp_config.json`) | none (no hook surface; intentionally not installed)     | inherits root `AGENTS.md`      | **4 of 4** in `.windsurf/rules/` | n/a                                        | yes (MCP only)          | rules, mcp (no AGENTS.md teardown) |
| Continue.dev | n/a (rules)   | yes (`.continue/config.json`)            | none (no hook surface; pruned in rf-cia phase b)         | none                           | **4 of 4** in `.continue/rules/` | n/a                                        | yes (MCP only)          | rules, mcp                       |
| Aider        | n/a (read)    | n/a (no native MCP; legacy YAML stripped) | n/a (no hook surface)                                   | RAFTER.md via `read:`          | n/a                              | n/a                                        | yes (read-entry + file) | aider.read                       |
| OpenClaw     | 1 (ClawHub)   | n/a                                      | n/a                                                     | none                           | n/a                              | n/a                                        | yes (file + legacy hint) | openclaw.skills (**wrong path**) |

Notes:

- "Skills (init) = 3 of 4" for Claude Code / Codex / Gemini reflects the
  current `AGENT_SKILLS` registry in `node/src/commands/agent/init.ts:27-31`
  (and Python `_AGENT_SKILLS` at `python/rafter_cli/commands/agent.py:118-122`),
  which omits `rafter-skill-review`. The dry-run plan, the Cursor /
  Windsurf / Continue rule lists, and the `components.ts` registry's
  `COMPONENT_SKILL_NAMES` all enumerate 4. The init path therefore disagrees
  with `rafter agent enable claude-code.skills` (which installs 4). New gap.
- "Verify (MCP only)" for Gemini / Cursor / Windsurf / Continue means the
  platform check confirms the MCP server entry but does NOT confirm hooks
  fired or rules were copied. `--probe` covers Claude Code only.
- Components registry IDs (Node + Python): `claude-code.hooks`, `.instructions`,
  `.skills`, `.mcp`; `codex.hooks`, `.skills`; `cursor.hooks`, `.instructions`
  (rules + sub-agent), `.mcp`; `gemini.hooks`, `.mcp`; `windsurf.rules`, `.mcp`;
  `continue.rules`, `.mcp`; `aider.read`; `openclaw.skills`. No `gemini.skills`,
  no `gemini.instructions`, no `codex.instructions`, no `windsurf.instructions`
  for AGENTS.md.

### What's improved since v0.7.7

- **Cursor deep support shipped** (rf-svn3, PR #81) — full hook coverage
  (`preToolUse` + `postToolUse` + `beforeShellExecution`), 4 per-skill rules at
  `.cursor/rules/<skill>.mdc`, and `.cursor/agents/rafter.md` sub-agent.
- **Windsurf deep support shipped** (rf-0vr3, PR #84) — pruned silent-no-op
  hooks install; 4 per-skill rules at `.windsurf/rules/<skill>.md`; root
  `AGENTS.md` written via `installGlobalInstructions` (Windsurf reads it
  natively). Windsurf also installs at `--local` scope now.
- **Aider read-only context shipped** (rf-du2o, PR #85) — `RAFTER.md` write +
  `read: [..., RAFTER.md]` in `.aider.conf.yml`. Legacy
  `mcp-server-command: rafter mcp serve` line is stripped on reinstall.
- **Continue.dev per-skill rules shipped** (rf-acz0, PR #86) — 4 rules at
  `.continue/rules/<skill>.md` with Continue.dev YAML frontmatter. Continue.dev
  installs at `--local` scope now.
- **Codex hook matcher widened** (rf-ovql) — `PreToolUse.matcher` now
  `"Bash|apply_patch"` so file edits via `apply_patch` actually trigger pretool.
- **Gemini hook matcher tightened** (rf-044o, PR #87) — `BeforeTool.matcher`
  now `"run_shell_command|write_file|replace|edit"` matching current Gemini
  docs verbatim.
- **`rafter agent verify` overhauled** (rf-65zg, PR #88) — Python now covers
  all 8 platforms (parity with Node). Both add Continue.dev + Aider checks.
  New `--json` flag and `--probe` flag (runtime probe for Claude Code).
- **Onboarding contract published** (rf-o329, PR #89) —
  `docs/adding-a-platform.md` is the contract any new agent platform
  integration follows.
- **OpenClaw rebuilt as a ClawHub skill** (rf-zgwj) — install moved to
  `~/.openclaw/workspace/skills/rafter-security/SKILL.md` (the canonical
  ClawHub-discovered path). Returned to `--all`. Legacy `~/.openclaw/skills/
  rafter-security.md` stripped on reinstall.
- **Betterleaks migration shipped** (v0.8.0) — gitleaks → betterleaks. Legacy
  `~/.rafter/bin/gitleaks` is detected by `agent verify` / `status` with an
  upgrade hint; the `--with-gitleaks` / `--engine gitleaks` / `update-gitleaks`
  CLI flags have been removed.
- **Dry-run plan shipped** (rf-hrtd) — `rafter agent init --dry-run` enumerates
  every file path the install would touch without writing anything.
- **Component-granular install** — `rafter agent enable/disable <id>` for 17
  components across all 8 platforms.

### Gaps remaining (file as new beads, `discovered-from:sable-2vz`)

1. **Init path installs 3 skills instead of 4 for Claude Code / Codex / Gemini.**
   `AGENT_SKILLS` in `node/src/commands/agent/init.ts:27-31` omits
   `rafter-skill-review`; Python `_AGENT_SKILLS` at `agent.py:118-122` same
   miss. The dry-run printout, the Cursor / Windsurf / Continue rule lists,
   and `components.ts:COMPONENT_SKILL_NAMES` all list 4. Result: `rafter
   agent init --with-claude-code` ships 3 skills but `rafter agent enable
   claude-code.skills` ships 4. Same divergence for `codex.skills`. Add
   `rafter-skill-review` to `AGENT_SKILLS` / `_AGENT_SKILLS`.

2. **`openclaw.skills` component points at the legacy path.** `components.ts:976-998`
   manages `~/.openclaw/skills/rafter-security.md` while the init path
   (rf-zgwj) ships at `~/.openclaw/workspace/skills/rafter-security/SKILL.md`.
   `rafter agent disable openclaw.skills` and `agent enable openclaw.skills`
   operate on the wrong file — disable is a no-op against current installs.
   Update the component spec to the ClawHub path; mirror in Python.

3. **No component spec for AGENTS.md / GEMINI.md instruction files.** Codex
   and Gemini write AGENTS.md / GEMINI.md respectively in
   `installGlobalInstructions`, but `components.ts` has no
   `codex.instructions` or `gemini.instructions`. `agent disable
   codex.instructions` is not callable; AGENTS.md is orphaned after Codex
   teardown. Same for Windsurf which inherits root `AGENTS.md`.

4. **No component spec for Gemini skills.** Gemini install writes 3 skills to
   `.agents/skills/<name>/SKILL.md` and runs `gemini skills link`, but
   `components.ts` has no `gemini.skills` entry — user can't `agent disable
   gemini.skills` to roll back the `gemini skills link` registration.

5. **`agent verify` is shallow for the MCP-only platforms.** Cursor /
   Windsurf / Continue / Gemini checks confirm only the MCP server entry —
   they don't confirm hooks are present, rules are copied, or sub-agents
   exist. Cursor in particular ships hooks + rules + sub-agent + MCP and we
   verify only MCP. Bring each `checkX` to confirm every surface the install
   writes for that platform.

6. **`agent verify --probe` covers only Claude Code.** Cursor / Codex /
   Gemini hooks all invoke `rafter hook pretool` with different `--format`
   flags. The rf-65zg `--probe` synthesizes a Claude-format payload and asserts
   `audit.jsonl`. Extend `--probe` to fire one synthetic payload per supported
   hook format (`--format cursor`, `--format codex`, `--format gemini`) so we
   catch the rf-luk-style "wrote file but never fires" failure for non-Claude
   platforms.

7. **`docs/supported-platforms.md` is stale.** Still says "MCP server" for
   Cursor / Windsurf / Continue / Aider and reports skills installed at
   `~/.claude/skills/rafter/` and `rafter-agent-security/` (the latter name
   doesn't exist anywhere in the install path). Doesn't mention per-skill
   rules, sub-agents, AGENTS.md, RAFTER.md, or the ClawHub OpenClaw path.
   Lists OpenClaw skill install at `~/.openclaw/skills/rafter-security.md`
   (legacy). Patched in this commit but the underlying skill set listed in
   the body should be re-checked against the init path after gap #1 lands.

Beads to file (parent agent — do NOT file these from this sub-task):

- Gap 1 → P1 bug, "init path installs 3 of 4 skills for Claude Code / Codex /
  Gemini; add rafter-skill-review to AGENT_SKILLS"
- Gap 2 → P1 bug, "openclaw.skills component points at legacy path"
- Gap 3 → P2 task, "add codex.instructions / gemini.instructions / windsurf.instructions component specs"
- Gap 4 → P2 task, "add gemini.skills component spec"
- Gap 5 → P2 task, "broaden agent verify checks for Cursor / Windsurf / Continue / Gemini beyond MCP entry"
- Gap 6 → P2 task, "extend agent verify --probe to Cursor / Codex / Gemini hook formats"
- Gap 7 → P3 docs, "docs/supported-platforms.md content re-check after gap 1 fix"

### Findings unchanged since 2026-04-30

- AGENTS.md as cross-platform context standard (Codex + Windsurf): unchanged
  and realized at workspace root.
- `.claude/agents/` is multi-platform (Cursor reads it too): unchanged.
- Onboarding contract: now shipped at `docs/adding-a-platform.md` (gap closed).
- All 8 platforms covered by `agent verify` in both Node and Python (gap closed).



## Summary

| Platform     | Skills install | Skills runtime-surfaced | Hooks installed       | Hooks runtime-fire | MCP   | Sub-agent | Instruction file | `agent verify` |
|--------------|----------------|-------------------------|-----------------------|--------------------|-------|-----------|------------------|----------------|
| Claude Code  | yes            | yes                     | yes (PreToolUse+Post) | yes                | yes   | **yes (rf-q7j)** | CLAUDE.md   | yes (hook)     |
| Codex        | yes            | yes                     | yes (claude fmt)      | yes                | —     | n/a       | AGENTS.md        | partial (skills only) |
| Gemini       | yes (rf-yit)   | partial                 | yes (BeforeTool)      | unverified         | yes   | n/a       | GEMINI.md        | partial (MCP only) |
| Cursor       | **NO**         | n/a                     | yes (preToolUse+postToolUse+beforeShell, rf-svn3) | unverified         | yes   | **yes (rf-svn3)** | per-skill `.cursor/rules/<skill>.mdc` (rf-svn3) | partial (MCP only) |
| Windsurf     | **NO**         | n/a                     | yes (pre_run_command) | unverified         | yes   | n/a       | **none**         | partial (MCP only) |
| Continue.dev | **NO**         | n/a                     | **none (pruned)**     | n/a                | yes   | n/a       | **none**         | **NOT CHECKED** |
| Aider        | **NO**         | n/a                     | **none**              | n/a                | yes   | n/a       | **none**         | **NOT CHECKED** |
| OpenClaw     | yes            | unverified              | none                  | n/a                | —     | n/a       | none             | yes            |

The `agent verify` column is misleading on its own — even where verify runs a
check, it only verifies file presence, not runtime behavior. The Gemini lesson
(rf-yit: file written, runtime didn't see it) applies everywhere we haven't
proven the agent end-to-end.

## Code references

All findings reference current `main` (commit `9e485d9`, v0.7.7).

- `installClaudeCodeHooks` — `node/src/commands/agent/init.ts:108`
- `installCodexHooks` — `node/src/commands/agent/init.ts:173`
- `installCursorHooks` — `node/src/commands/agent/init.ts:215`
- `installGeminiHooks` — `node/src/commands/agent/init.ts:255`
- `installWindsurfHooks` — `node/src/commands/agent/init.ts:298`
- `installContinueDevHooks` — `node/src/commands/agent/init.ts:341`
- `installClaudeCodeMcp` / `installGeminiMcp` / `installCursorMcp` / `installWindsurfMcp` / `installContinueDevMcp` / `installAiderMcp` — same file, lines 396–566
- `AGENT_SKILLS` registry — `node/src/commands/agent/init.ts:26`
- Verify checks — `node/src/commands/agent/verify.ts` (no `checkContinueDev`, no `checkAider`, hook check only for Claude Code)

Python mirrors live at the same callsites in `python/rafter_cli/commands/agent.py`.

## Per-platform findings

### Claude Code — gold standard

What we ship: skills (`.claude/skills/<name>/SKILL.md`), sub-agent (`.claude/agents/rafter.md`, rf-q7j), hooks (PreToolUse Bash + Write|Edit, PostToolUse `.*`), MCP server, CLAUDE.md instruction block.

Verify check: presence of `rafter hook pretool` in `~/.claude/settings.json` PreToolUse array. Real test of whether hooks fire is implicit — they do, because Claude Code is what we built against.

Gaps: none structural. The sub-agent (rf-q7j) is currently in flight on PR #57 and not yet merged.

### Codex — close to parity

What we ship: skills (`.agents/skills/<name>/SKILL.md`), hooks (PreToolUse + PostToolUse using the same Claude-format protocol Codex adopted), AGENTS.md instruction block. No MCP — Codex doesn't speak MCP.

Verify check: skill file presence only. Doesn't verify hooks.

Gaps: no first-class sub-agent primitive in Codex itself, so we can't ship the rf-q7j equivalent. Watch quarterly.

### Gemini — partial; rf-yit was the closest call

What we ship: skills with explicit `gemini skills link` registration (rf-yit, shipped 82b86e3 on 2026-04-21), hooks in `.gemini/settings.json` under `BeforeTool`/`AfterTool`, MCP server in the same file under `mcpServers`, GEMINI.md instruction block.

Verify check: MCP server presence only. Does NOT verify hooks fire and does NOT verify the registered skills actually surface in Gemini's session.

Open questions for the rf-cia work:

1. Does Gemini's `BeforeTool` / `AfterTool` hook schema match what we write? Gemini's hook surface is undergoing changes; we should pin the version we're targeting and re-read its docs.
2. Does `gemini skills link` survive across Gemini upgrades? Or do we need to re-register on each upgrade?
3. Is the GEMINI.md instruction block actually picked up at session start?

### Cursor — MCP only is shipped + claimed; hooks ship silently

What we ship per code: hooks (`.cursor/hooks.json` with `beforeShellExecution`), MCP (`.cursor/mcp.json`), `.cursor/rules/rafter-security.mdc` instruction file.

What the recipe documents (`recipes/cursor.md`): MCP only. The recipe does NOT mention that hooks are also installed.

Verify check: MCP server presence only.

Gaps:
- **No skills install.** Cursor doesn't have a SKILL.md primitive, but its rules system is the closest analog — we could ship one rule per "skill" in `.cursor/rules/`, or fold all skill content into a single `rafter-security.mdc` and document that as the analog.
- **Recipe is out of date** — silently installs hooks but doesn't mention them. Either drop hook install (if Cursor's `beforeShellExecution` is unreliable) or document it.
- **No runtime verification** that `beforeShellExecution` actually fires for `rafter hook pretool`. Need an end-to-end probe.

### Windsurf — MCP only is shipped + claimed; hooks ship silently; no instructions

What we ship per code: hooks (`.windsurf/hooks.json` with `pre_run_command` + `pre_write_code`), MCP (`.codeium/windsurf/mcp_config.json`).

What the recipe documents: MCP only.

Verify check: MCP server presence only.

Gaps:
- No skills install.
- No instruction file. Windsurf has its own rules system (`.windsurfrules` for project, `~/.codeium/windsurf/memories/global_rules.md` for global) — we should adopt the closest one.
- Hook schema (`pre_run_command`, `pre_write_code`) needs verification against current Windsurf docs.
- Recipe out of date.

### Continue.dev — hooks pruned (rf-cia phase b)

**Status (2026-04-28):** Hook install removed. Continue.dev integration is now MCP-only — matches what the recipe always claimed.

What we previously shipped: hooks written to `.continue/settings.json` using Claude Code's `PreToolUse` / `PostToolUse` protocol. Continue.dev does NOT natively use that protocol; current versions use `~/.continue/config.yaml` (legacy `config.json`), with no `hooks.PreToolUse` field. Confirmed against `docs.continue.dev/customize/deep-dives/configuration` 2026-04-28: settings.json is not a Continue.dev config file. The install was a silent no-op at runtime.

What we ship now: MCP server entry in `.continue/config.json` only. The hook install function (`installContinueDevHooks` in Node, `_continue_hooks` ComponentSpec in Node + Python) was removed. The components registry no longer exposes `continue.hooks` for `rafter agent enable/disable`.

Verify check: still not implemented (`checkContinueDev` does not exist in verify.ts) — that comes in the next phase.

Remaining gaps:
- No skills install (Continue.dev's analog is its assistant config — not adopted yet).
- No instruction file.
- No `checkContinueDev` in `rafter agent verify`.

### Aider — only MCP via YAML append

What we ship: append `mcp-server-command: rafter mcp serve` to `.aider.conf.yml`. No hooks, no skills, no instruction file.

Verify check: not implemented.

Gaps:
- Aider doesn't have a hook surface in the Claude/Cursor/Windsurf sense. The realistic interjection point is Aider's `--read` files, where rafter context can be injected.
- No instruction file. We should add a `RAFTER.md` (or similar) that gets injected into Aider sessions via `read` config entries.
- No skills, no verify check.

### OpenClaw — verify before investing

OpenClaw skill is installed, no other surface. Verify whether OpenClaw is still actively maintained / has users before investing more here.

## Cross-cutting findings (2026-04-28 — deep dive into each platform's docs)

Two surprises that change the plan substantially:

### 1. `.claude/agents/` is multi-platform

Cursor reads `.cursor/agents/` AND `.claude/agents/` for sub-agent definitions. The rf-q7j sub-agent we just shipped (`<root>/.claude/agents/rafter.md`) is already half-supported on Cursor for free — any user who has both Claude Code and Cursor on the same project gets the rafter sub-agent in Cursor too. We should ship a Cursor-targeted equivalent so users with Cursor only also get it, and document the cross-platform nature.

Format (Cursor): same as Claude Code — markdown with `name`, `description`, `model: inherit`, optional `readonly: true`, optional `is_background: true`. Cursor's frontmatter doesn't have a granular `tools:` field; tools are inherited from parent agent (no per-subagent restriction). The toolset constraint we put on the rf-q7j sub-agent body still applies — Cursor doesn't enforce tool restrictions structurally.

### 2. `AGENTS.md` is multi-platform

Windsurf reads `AGENTS.md` natively (any directory in workspace). Our rf-djw Codex install already writes `AGENTS.md` and is therefore quietly helping Windsurf users too — we just never documented it. We should:
- Recognize AGENTS.md as the rafter cross-platform context standard
- Write it for any platform that reads it (currently Codex AND Windsurf)
- Update recipes to surface this

### Per-platform reality check

**Cursor** has full hook + rule + sub-agent + MCP support:
- Hooks at `~/.cursor/hooks.json` or `<project>/.cursor/hooks.json`. Events: `preToolUse`, `postToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `afterFileEdit`, `subagentStart`/`subagentStop`, etc. Schema: `{ version: 1, hooks: { event: [{ command, timeout, matcher, loop_limit }] } }`. Stdin JSON includes `hook_event_name`. Exit code `2` blocks. **Stable.** Our `beforeShellExecution` install is correct schema, but we only cover one event when we could cover the full PreToolUse/PostToolUse pair.
- Rules at `.cursor/rules/*.mdc` (or .md). Four types: `alwaysApply: true`, agent-decides via `description`, `globs`-matched, manual `@rule`. Per-rule files supported. **Maps perfectly to our 4 skills.**
- Sub-agents at `.cursor/agents/<name>.md` (or `.claude/agents/`). Frontmatter: `name`, `description`, `model`, `readonly`, `is_background`. Auto-delegation by description, explicit `/name` syntax, or natural language.

**Windsurf** has rich rules + MCP, but NO hooks:
- Confirmed NO pre-tool-use hook surface in current Windsurf. Our `.windsurf/hooks.json` install with `pre_run_command`/`pre_write_code` is silently a no-op (same shape as the Continue.dev problem).
- Rules at `.windsurf/rules/*.md` (workspace, 12KB/file cap) + `~/.codeium/windsurf/memories/global_rules.md` (global, 6KB cap total). YAML frontmatter with `trigger: [always_on|model_decision|glob|manual]`. Per-rule files.
- Reads `AGENTS.md` natively — files in any workspace directory.
- MCP at `~/.codeium/windsurf/mcp_config.json` (current path; we have this right).

**Aider** has neither hooks nor a skill primitive, but does have persistent context:
- NO hook surface. Aider doesn't intercept tool calls.
- `--read FILE` flag, settable in `.aider.conf.yml` as `read: [PATH, ...]`. CONVENTIONS.md is the community pattern — we should adopt the same for `RAFTER.md`.
- **MCP support unconfirmed by docs.** Our `.aider.conf.yml` append of `mcp-server-command: rafter mcp serve` is suspect — Aider docs don't list this as a real config field. Likely another silent no-op. Needs verification.

**Continue.dev** (phase b done) — confirmed NO hooks, has per-rule files:
- Rules at `.continue/rules/*.md` (workspace) + `~/.continue/rules/*.md` (global). YAML frontmatter with `name`, `globs`, `regex`, `description`, `alwaysApply`. Per-rule files in lexicographic load order.
- MCP at `.continue/config.json`.

**OpenClaw** — investigate whether actively maintained before investing.

## Revised per-platform deep-support plan (replaces earlier plan)

### Cursor — DONE (rf-svn3): full parity with Claude Code

| Surface | Pre-rf-svn3 | Now |
|---|---|---|
| Hooks | `beforeShellExecution` only | `preToolUse` + `postToolUse` + `beforeShellExecution` (all three idempotent, non-rafter entries preserved) |
| Rules | one consolidated `.cursor/rules/rafter-security.mdc` | 4 per-skill `.cursor/rules/<skill>.mdc` files with trigger-first descriptions reused verbatim from each SKILL.md (description-based activation) |
| Sub-agent | none | `.cursor/agents/rafter.md` (reuses rf-q7j body; Cursor frontmatter has no `tools:` field) |
| MCP | yes | yes (unchanged) |

### Windsurf — currently MCP + broken hooks; can be rules + AGENTS.md

| Surface | Today | Goal |
|---|---|---|
| Hooks | broken silent install (no Windsurf hook surface) | DROP — same prune pattern as Continue.dev |
| Rules | none | One per-skill rule in `.windsurf/rules/*.md` + a global rule pointer at `~/.codeium/windsurf/memories/global_rules.md` |
| AGENTS.md | none for Windsurf-only users | Write at root project level (Windsurf reads it natively) |
| MCP | yes | yes (no change) |

### Aider — currently broken MCP append; can be RAFTER.md context

| Surface | Today | Goal |
|---|---|---|
| Hooks | n/a (no surface) | n/a |
| Rules | none | n/a (no skill primitive) |
| Persistent context | none usable | Write `RAFTER.md` + add `read: [RAFTER.md]` to `.aider.conf.yml` |
| MCP | suspect YAML append | VERIFY first; drop if Aider doesn't actually read it |

### Continue.dev — phase b done; rules next

| Surface | Today | Goal |
|---|---|---|
| Hooks | none (pruned in phase b) | n/a |
| Rules | none | 4 per-skill rules in `.continue/rules/*.md` |
| MCP | yes | yes (no change) |

### Codex — already at parity (skills + hooks + AGENTS.md)
No further work.

### Gemini — re-verify rf-yit end-to-end
1. Hooks: schema match against current Gemini docs (last unverified).
2. Skills surface: confirm `gemini skills link` registration shows in session.
3. GEMINI.md: confirm picked up at session start.

### OpenClaw — investigate before investing
Verify activity / user count before more work.

## Cross-cutting gaps

1. **`rafter agent verify` is structurally weak.** It checks file presence, never runtime behavior. It doesn't check Continue.dev or Aider. It doesn't cross-check hook fire. Bring it to: (a) cover all 8 platforms, (b) check hook + skill + MCP per-platform where applicable, (c) optionally probe by invoking a known-dangerous test command and asserting `~/.rafter/audit.jsonl` got the expected `command_intercepted` entry.

2. **Recipes are stale relative to install code.** The hook installs are silent — three platforms (Cursor, Windsurf, Continue.dev) get hooks written by the CLI but the recipes only mention MCP. Either align recipes to reflect what gets installed or drop the silent hook installs.

3. **Skill primitive coverage is binary.** Today only Claude Code, Codex, and Gemini get SKILL.md. Cursor/Windsurf/Continue/Aider have analogous primitives (Cursor rules, Windsurf rules, Continue assistant config, Aider read files) we haven't adopted yet.

4. **No end-to-end runtime test for any non-Claude platform.** Tests assert file writes; no test runs the platform with a known prompt and asserts hook invocation. The Gemini-failure pattern can recur silently for any platform.

5. **`adding-a-platform` onboarding doc does not exist.** Each new platform requires touching init.ts (Node + Python), AGENT_SKILLS, hooks helper, MCP helper, recipes/, verify.ts. No single document explains the contract.

## Recommended sequencing (refines rf-cia plan)

Reorder of the plan in the bead based on these findings:

1. **Verify what's actually broken before fixing it.** Drop the hook installer for Continue.dev (almost certainly silent no-op), update the recipe to "MCP only." Same drill for Cursor and Windsurf if their hook schemas don't match what we write. (~1 day; net REDUCES surface area.)
2. **Bring `rafter agent verify` to full coverage** — all 8 platforms, hook+skill+MCP per-platform where applicable, plus an optional `--probe` flag that tests-fire a known-dangerous command and inspects audit.jsonl. (~2 days.)
3. **Re-verify Gemini end-to-end** — hooks fire, skills surface, GEMINI.md picked up. Includes upgrading `gemini skills link` to handle re-registration on Gemini upgrade. (~1 day.)
4. **Cursor + Windsurf instruction-file + skills-analog** — adopt `.cursor/rules/` and Windsurf's rules format for the skill content we already ship to Claude/Codex. (~2 days.)
5. **Aider read-file integration** — write a `RAFTER.md` and add `read: [RAFTER.md]` to `.aider.conf.yml`. Document workflow. (~1 day.)
6. **`docs/adding-a-platform.md` onboarding doc** — written so step-by-step adding a new agent CLI is mechanical, with verify hooks to confirm behavior. (~0.5 days.)

Total: roughly 7-8 days of focused work for full parity. CI integration tests per-platform are a follow-on once `verify --probe` is the contract.

## Out of scope for rf-cia

- New platform support (Hermes / future Continue extensions / etc.) — track separately under rf-01b and similar.
- Sub-agent equivalents on Codex/Cursor/etc. — none of those platforms have a first-class sub-agent primitive today. Watch quarterly.
- The `rafter review` standalone command — separate bead rf-0z9, on hold for user review.

## Re-audit (2026-04-30)

Re-run after phase a+b merged (rf-cia-audit branch, PR #61). Pinned at `origin/main` `e366778` / v0.7.7.

### What shipped since 2026-04-28

| Change | Commit / PR | Effect |
|---|---|---|
| Continue.dev hooks pruned in both Node + Python | `3378bcf` (rf-cia phase b) | `installContinueDevHooks` removed from `node/src/commands/agent/init.ts`; no `_continue_hooks` in `python/rafter_cli/commands/agent_components.py`. Components registry now exposes only `continue.mcp`. ✅ |
| Audit doc landed | `3e84859` + `1846256` (PR #61) | This file. |
| README OpenCode badge removed | `78caffe` (rc-dn0, PR #62) | We no longer claim OpenCode support in user-facing docs. |
| Repo-root `AGENTS.md` added | `2c395f7` (rf-pkn, PR #72) | Side benefit: Windsurf reads `AGENTS.md` natively, so Windsurf-only users get rafter context for free. Not yet documented as such in the recipe. |

Nothing else in the matrix has structurally changed. The four 2026-04-29 PRs shipped between 4/28 and 4/30 (#62, #71, #72) plus the rf-cia merge (#61) are the entire window. PR #71 was a test/binary-manager fix (gt-pvx), unrelated to platform parity.

### Updated state matrix (v0.7.7)

| Platform     | Skills install | Skills runtime-surfaced | Hooks installed             | Hooks runtime-fire | MCP   | Sub-agent | Instruction file       | `agent verify` |
|--------------|----------------|-------------------------|-----------------------------|--------------------|-------|-----------|-------------------------|----------------|
| Claude Code  | yes            | yes                     | yes (PreToolUse + PostToolUse) | yes              | yes   | **NOT YET (rf-q7j in flight)** | CLAUDE.md   | yes (hook)     |
| Codex        | yes            | yes                     | yes (claude fmt)            | yes                | —     | n/a       | AGENTS.md               | partial (skills only) |
| Gemini       | yes (rf-yit)   | partial                 | yes (BeforeTool / AfterTool) | unverified        | yes   | n/a       | GEMINI.md               | partial (Node only — MCP only; **Python missing**) |
| Cursor       | **NO**         | n/a                     | yes (`beforeShellExecution` only) | unverified   | yes   | n/a (gets `.claude/agents/` once rf-q7j ships) | `.cursor/rules/rafter-security.mdc` (single file) | partial (Node only — MCP only; **Python missing**) |
| Windsurf     | **NO**         | n/a                     | yes (`pre_run_command` + `pre_write_code`) — **silent no-op (no Windsurf hook surface exists)** | n/a | yes | n/a | none directly; **inherits root `AGENTS.md`** | partial (Node only — MCP only; **Python missing**) |
| Continue.dev | **NO**         | n/a                     | **none (pruned in phase b)** | n/a               | yes   | n/a       | none                    | **NOT CHECKED (Node + Python)** |
| Aider        | **NO**         | n/a                     | **none (no hook surface)**   | n/a               | yes (suspect — `mcp-server-command:` YAML append unverified against Aider docs) | n/a | none | **NOT CHECKED (Node + Python)** |
| OpenClaw     | yes            | unverified              | none                        | n/a                | —     | n/a       | none                    | yes            |

### Gaps (still open after phase a+b)

Each gap below is filed as a followup bead (see "Followup beads filed" section). All of these were named in the original audit's "Revised per-platform deep-support plan" but had not been beaded.

1. **Cursor — full hook coverage.** We install only `beforeShellExecution`; Cursor's hook surface supports `preToolUse` + `postToolUse` (matrix-equivalent to Claude Code). Add the missing events.
2. **Cursor — per-skill rules files.** Today: one consolidated `.cursor/rules/rafter-security.mdc`. Goal: 4 per-skill rule files mirroring `node/resources/skills/<skill>/SKILL.md` content under `.cursor/rules/<skill>.mdc`.
3. **Windsurf — drop hooks installer.** Per current Windsurf docs there is no `pre_run_command` / `pre_write_code` hook surface. Our installer writes `.windsurf/hooks.json` and Windsurf ignores it. Same fate as Continue.dev hooks: prune.
4. **Windsurf — rules + AGENTS.md surface.** Windsurf reads `.windsurf/rules/*.md` (workspace, 12KB cap) and `~/.codeium/windsurf/memories/global_rules.md` (global, 6KB cap). Recipe should also surface that root `AGENTS.md` is read natively. Today neither is mentioned.
5. **Continue.dev — rules.** Continue.dev reads `.continue/rules/*.md` (workspace) and `~/.continue/rules/*.md` (global). Today: zero skills/rules surface for Continue users.
6. **Aider — RAFTER.md + read config.** Aider doesn't intercept tool calls but persistent context via `--read` / `.aider.conf.yml read: [...]` is the realistic surface. Today: nothing.
7. **Aider MCP — verify or drop.** `installAiderMcp` appends `mcp-server-command: rafter mcp serve` to `.aider.conf.yml`. Aider's documented config schema does not list this field. Either confirm Aider reads it (recipe + test) or drop it like Continue.dev hooks. Treat with the rf-luk lesson: file presence isn't behavior.
8. **`rafter agent verify` — Python parity.** Node has `checkClaudeCode`, `checkOpenClaw`, `checkCodex`, `checkGemini`, `checkCursor`, `checkWindsurf`. Python (`python/rafter_cli/commands/agent.py`) has only `_check_gitleaks`, `_check_config`, `_check_claude_code`, `_check_openclaw`, `_check_codex`. Three missing.
9. **`rafter agent verify` — Continue.dev + Aider.** Neither implementation has `checkContinueDev` or `checkAider`. With phase b's prune, `continue.mcp` is the only surface — verify it.
10. **`rafter agent verify --probe`.** A flag that triggers a known-dangerous command and asserts `~/.rafter/audit.jsonl` recorded the interception. Required to detect the Gemini-style "wrote file, runtime ignored it" failure mode for Cursor / Windsurf / Gemini hooks.
11. **Re-verify Gemini end-to-end.** rf-yit shipped `gemini skills link` registration but no test confirms (a) hook schema still matches current Gemini, (b) `gemini skills link` survives Gemini upgrades, (c) GEMINI.md is read at session start.
12. **`docs/adding-a-platform.md`.** Onboarding doc named in the original audit. Not yet written.
13. **OpenClaw activity check.** Decide whether OpenClaw is still actively maintained / has users before any further investment. Our installer ships it as part of `--all` and `--with-openclaw`.
14. **Recipes still claim "MCP only" for Cursor + Windsurf.** They install hooks (item 1) and an instruction file (Cursor), and Windsurf-specific work in items 3+4. Recipes need a rewrite once the installers settle.

### Findings unchanged since 4/28

- AGENTS.md as cross-platform context standard (read by Codex, Windsurf, our tools/AGENTS.md root): unchanged. Now realized at root via rf-pkn — no install path needed for Windsurf.
- `.claude/agents/` is multi-platform (Cursor reads it too): unchanged. Materializes as a free win once rf-q7j ships.
- All cross-cutting findings (verify weakness, recipes drift, skills binary coverage, no end-to-end runtime test, no onboarding doc): unchanged.

### Followup beads filed (2026-04-30)

All linked via `discovered-from:rf-guvb,rf-cia`. See each bead for scope and acceptance.

- **rf-p1fs** (P1) — Cursor: full hook coverage + per-skill rules
- **rf-jrs0** (P1) — Windsurf: prune hooks installer + add per-skill rules + recipe rewrite
- **rf-acz0** (P1) — Continue.dev: per-skill rules under `.continue/rules/`
- **rf-du2o** (P1) — Aider: verify or drop MCP YAML append; add RAFTER.md read-config
- **rf-65zg** (P1) — `rafter agent verify`: Python parity + Continue/Aider coverage + `--probe` runtime mode
- **rf-044o** (P2) — Gemini: end-to-end re-verification (rf-yit follow-up)
- **rf-o329** (P2) — `docs/adding-a-platform.md`: onboarding contract for new agent CLIs
- **rf-0lig** (P3) — OpenClaw: confirm activity / users before further investment

The recipes-stale gap is folded into each per-platform bead's acceptance. Sub-agent for Claude Code is tracked under the existing rf-q7j (in flight).

## Update (2026-05-03 — phase c progress)

- **Cursor deep support shipped** — PR #81 (rf-svn3, merged). `preToolUse` + `postToolUse` + `beforeShellExecution` hooks, 4 per-skill `.cursor/rules/<skill>.mdc` files, and `.cursor/agents/rafter.md` sub-agent. Closes the Cursor matrix-row gaps (skills, hooks, sub-agent). rf-p1fs closed as duplicate of rf-svn3.
- **Windsurf deep support shipped** — PR #84 (rf-0vr3, merged). Pruned the silent-no-op `~/.windsurf/hooks.json` install (Windsurf has no hook surface), added 4 per-skill rules under `.windsurf/rules/<skill>.md`, extended `installGlobalInstructions` so `--with-windsurf` writes `AGENTS.md` at workspace root (Windsurf reads it natively). Windsurf now installs at `--local` scope as well. rf-jrs0 closed as duplicate of rf-0vr3.
- **Aider read-only context shipped** — PR #85 (rf-du2o, merged). Pruned the silent-no-op `mcp-server-command:` YAML append (Aider has no native MCP support), added a `RAFTER.md` write at workspace root + a `read: [..., RAFTER.md]` entry in `.aider.conf.yml`. Reinstalling strips the legacy line as a migration step. Aider also now installs at `--local` scope.
- **Continue.dev per-skill rules shipped** — PR #86 (rf-acz0, merged). Adds 4 per-skill rule files at `.continue/rules/<skill>.md` with Continue.dev YAML frontmatter (`name:` + `description:` + `alwaysApply: false`). Continue.dev now also installs at `--local` scope. MCP entry is unchanged.
- **Codex hook schema verified + matcher widened** — this PR (rf-ovql). Schema confirmed against `developers.openai.com/codex/hooks`: `~/.codex/hooks.json` with `PreToolUse`/`PostToolUse`/`PermissionRequest`/`SessionStart`/`UserPromptSubmit`/`Stop`. Updated `PreToolUse.matcher` from `"Bash"` to `"Bash|apply_patch"` so file edits via apply_patch actually trigger the rafter pretool hook (per the docs, PreToolUse intercepts Bash + apply_patch + MCP tool calls). The Bash-only-fires-reliably caveat from Codex issues #16732 / #20204 remains an upstream limitation.
- **Gemini hook schema verified + matcher tightened** — PR #87 (rf-044o, merged). Schema confirmed against `geminicli.com/docs/hooks/reference`: `~/.gemini/settings.json` with `BeforeTool`/`AfterTool` events, regex matcher against built-in tool names. Updated `BeforeTool.matcher` from the implicit-substring `"shell|write_file"` to the explicit `"run_shell_command|write_file|replace|edit"` so the install matches current Gemini docs verbatim. Schema was unverified at the time of the rf-cia research bead — Gemini's hook docs have since been published / consolidated.
- **`rafter agent verify` overhauled** — PR #88 (rf-65zg, merged). Python now covers all 8 platforms (parity with Node). Both impls gain `Continue.dev` + `Aider` checks. New `--json` flag for CI consumption (schema in `shared-docs/CLI_SPEC.md`). New `--probe` flag runs the Claude Code hook end-to-end (synthetic stdin payload → `rafter hook pretool` → audit-log assertion) so we catch the rf-luk-style "wrote file but never fires" failure mode without needing to drive Claude Code itself. The `agent verify` row in the matrix flips to "yes" across the board.
- **Onboarding contract published** — PR #89 (rf-o329, merged). `docs/adding-a-platform.md` is the contract any new agent platform integration follows: 5-question pre-flight, file-by-file checklist, decision tree for hooks/skills/AGENTS.md/MCP/sub-agent shapes, dual-impl rule, verification gate (file-presence + `--probe`), and a worked example. Cross-cutting gap #5 ("no onboarding doc") is now resolved. README links to it under "Documentation".
- **OpenClaw demoted from `--all`** — PR #90 (rf-0lig, merged). Activity check confirmed OpenClaw is highly active in 2026 (top GitHub repository, 4000+ ClawHub skills, regular releases). At the time, the rafter integration shape didn't match ClawHub's skill format, so the install was demoted to explicit opt-in.
- **OpenClaw rebuilt as a ClawHub skill** — this PR (rf-zgwj). Install moved to the canonical `~/.openclaw/workspace/skills/rafter-security/SKILL.md` path so OpenClaw auto-discovers it. ClawHub-required `name` / `description` top-level frontmatter added to the SKILL.md. Reinstalls on top of the rafter ≤ 0.7.7 layout strip the legacy file. **OpenClaw returned to `--all`** — the new shape is what the platform actually consumes.

rf-cia is now closed. All matrix entries are "yes" or upstream-limited.
