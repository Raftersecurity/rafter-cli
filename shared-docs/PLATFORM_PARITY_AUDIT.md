# Platform Parity Audit (rf-cia)

> Authored 2026-04-28 by raftercli/crew/lucy as the kickoff deliverable for the
> rf-cia P0 epic ("Cross-platform agent parity"). Establishes ground truth for
> what each supported platform currently gets vs. what gold-standard parity
> requires. Drives the per-platform work items that follow.

## Summary

| Platform     | Skills install | Skills runtime-surfaced | Hooks installed       | Hooks runtime-fire | MCP   | Sub-agent | Instruction file | `agent verify` |
|--------------|----------------|-------------------------|-----------------------|--------------------|-------|-----------|------------------|----------------|
| Claude Code  | yes            | yes                     | yes (PreToolUse+Post) | yes                | yes   | **yes (rf-q7j)** | CLAUDE.md   | yes (hook)     |
| Codex        | yes            | yes                     | yes (claude fmt)      | yes                | —     | n/a       | AGENTS.md        | partial (skills only) |
| Gemini       | yes (rf-yit)   | partial                 | yes (BeforeTool)      | unverified         | yes   | n/a       | GEMINI.md        | partial (MCP only) |
| Cursor       | **NO**         | n/a                     | yes (beforeShell)     | unverified         | yes   | n/a       | .cursor/rules/*.mdc | partial (MCP only) |
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
