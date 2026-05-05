# Adding a new agent platform

This document is the contract for adding rafter integration for a new agent
CLI / IDE (e.g. a future "Foobar Code", a new fork of Cursor, a new agent
runtime). Follow it and the integration ships in both Node and Python with
verify-able coverage on day one. Skip steps and the gap surfaces in the next
parity audit.

> **Background.** rafter ships dual implementations (Node + Python) that
> must stay in lockstep, plus a documentation surface (`recipes/`,
> `shared-docs/CLI_SPEC.md`, README) and a runtime contract
> (`rafter agent verify`). Adding a platform means changing all of them
> in one PR. The 2026-04-30 audit (rf-guvb) found that without a single
> document explaining this, every new platform shipped with at least one
> gap (Continue.dev hooks were a silent no-op, Aider's MCP append was a
> silent no-op, Windsurf's hooks file was never read by the IDE).

## TL;DR — five-question contract

Before writing any code, answer these five questions about the new platform.
Each "yes" implies code in both impls, a registry entry, a verify check,
and a recipe section. Each "no" should be **documented, not dropped** — the
recipe should explain why the platform doesn't get that integration.

| Question | If yes, ship | If no, document |
|---|---|---|
| **Hooks**: does the platform have a documented pre/post-tool-use hook surface? Cite the URL. | Hook installer + `<platform>.hooks` ComponentSpec + matcher matching the platform's documented schema | Recipe says "no hook surface — context only". Don't write a hook file the platform won't read (rf-cia phase b lesson). |
| **Skills / rules**: does the platform have a workspace-or-user persistent-rules primitive? | Per-skill rule files + `<platform>.rules` ComponentSpec, one file per skill from `AGENT_SKILLS` | Recipe documents the closest analog (e.g. Aider has only `read:` lists, OpenClaw is wrong-category) |
| **Instruction file**: does the platform read a workspace-root file like `AGENTS.md` / `CLAUDE.md` / `GEMINI.md`? | `installGlobalInstructions` branch with the marker-block injection pattern | Skip. Note in recipe that the platform doesn't have one. |
| **MCP**: does the platform have native MCP support (config path? schema?)? | MCP installer + `<platform>.mcp` ComponentSpec writing the rafter `mcp serve` entry | Recipe says "no MCP — `rafter` CLI must be invoked directly". Don't append unknown YAML keys (rf-du2o lesson). |
| **Sub-agent**: does the platform have a first-class sub-agent primitive? Today only Claude Code does. | `<platform>.subagent` ComponentSpec + body file | Skip. Re-evaluate quarterly. |

A "yes" without docs citing the schema URL is **not a yes** — that's the
research gap that produced rf-cia in the first place. Verify schemas
against the platform's current docs before writing the installer.

## File-by-file checklist

For a new platform `<P>` (e.g. `cleo`, `foobar`):

### Both implementations

- [ ] `node/src/commands/agent/init.ts`
  - Install function(s): `install<P>Hooks`, `install<P>Mcp`, `install<P>Rules`, etc. Only the ones that apply.
  - `--with-<p>` option in the `agent init` command builder.
  - Detection: `has<P> = scope === "user" && fs.existsSync(<P-config-dir>)`.
  - Opt-in flag: `wantP = opts.with<P> || opts.all` (drop `&& !opts.local` if the platform has a project-scope install).
  - Install branch: `if (wantP && (hasP || opts.local)) { installP*(root); ... }`.
  - "Detected environments" + "Restart `<P>` to load …" prompts.
- [ ] `node/src/commands/agent/components.ts`
  - One `ComponentSpec` per surface (`<p>.hooks`, `<p>.mcp`, `<p>.rules`, etc.) with `id`, `platform`, `kind`, `description`, `detectDir`, `path`, `isInstalled`, `install`, `uninstall`.
  - Append each to the registry list in `getComponentRegistry()`.
- [ ] `node/src/commands/agent/verify.ts`
  - `check<P>(): CheckResult` that returns `{ name, passed, detail, optional: true }`. Always `optional: true` — verify exits 1 only on hard failures (Config / Gitleaks).
  - Append to `results: CheckResult[]` in `createVerifyCommand`.
  - If the platform has a hook surface, plan a follow-up to add a `--probe` branch (see "Verification gate" below).
- [ ] Resource templates (if rules / skills): `node/resources/<p>-rules/<skill>.md` (one per skill in `AGENT_SKILLS`). Static files; copied at install time, no runtime templating. Use the platform's documented YAML frontmatter.

Mirror every change in Python:

- [ ] `python/rafter_cli/commands/agent.py`
  - `_install_<p>_*` functions matching the Node ones.
  - `--with-<p>` typer option, detection, opt-in, install branch, restart hint.
- [ ] `python/rafter_cli/commands/agent_components.py`
  - `_<p>_hooks()`, `_<p>_rules()`, etc. returning `ComponentSpec` dataclasses, registered in `_REGISTRY`.
- [ ] `python/rafter_cli/commands/agent.py` verify section
  - `_check_<p>(): _CheckResult` mirroring the Node logic.
  - Append to `results` in the `verify()` command body.
- [ ] Resource templates: `python/rafter_cli/resources/<p>-rules/<skill>.md`. Identical content to the Node templates (the templates ship as static files in both packages — sync drift is checked by the integration tests).

### Tests (both impls)

- [ ] `node/tests/agent-components.test.ts`
  - Add `<p>.hooks` / `<p>.rules` / `<p>.mcp` to the expected component-id list.
- [ ] `node/tests/platform-integration.test.ts`
  - New `describe("<P> ... (--with-<p>)")` block: rule-file presence, frontmatter shape, MCP entry shape, idempotency on reinstall, AGENTS.md (if applicable).
  - Append assertions to the "All 8 platforms config validation" combined test.
- [ ] `python/tests/test_agent_init.py`
  - `class TestInstall<P>Rules` (or equivalent) mirroring the Node tests.
- [ ] `python/tests/test_agent_components.py`
  - Add `<p>.*` ids to the registry shape test.
- [ ] `python/tests/test_agent_verify.py`
  - `class TestCheck<P>` mirroring the Node verify checks.

### Documentation

- [ ] `recipes/<p>.md` — what gets installed, scope (user vs `--local`), manual setup, verify command. **Recipe must match installer reality.** If you write a hook file the platform doesn't read, the recipe must not claim hooks are installed.
- [ ] README "Supported Platforms" section — add the platform with one-line description.
- [ ] `shared-docs/CLI_SPEC.md` — add the platform to the verify check table; document the `--with-<p>` flag if the option set is non-obvious.
- [ ] `shared-docs/PLATFORM_PARITY_AUDIT.md` — flip the row for the new platform from "n/a" to the new state.
- [ ] `CHANGELOG.md` — entry under `[Unreleased]` describing what got installed and why.

### Exit criteria

- Both Node and Python full test suites pass on the touched files.
- Live smoke: `rafter agent init --local --with-<p>` (Node + Python builds) writes the expected files in a clean tmp dir.
- `rafter agent verify` (Node + Python) reports the new check; `--json` includes it; `--probe` runs end-to-end on platforms with hook surfaces.
- The platform parity audit row matches the install reality.

## Decision tree — picking integration shapes

### 1. Hooks?

**Document the hook schema before writing any code.**

- Find the canonical hook reference (e.g. `developers.openai.com/codex/hooks`, `geminicli.com/docs/hooks/reference`, `cursor.com/docs/agent/hooks`).
- Confirm the file path the platform actually reads (cf. the Continue.dev `~/.continue/settings.json` no-op: that path was never in the schema).
- Confirm the matcher syntax (regex against tool names? exact match? glob? what tool names does the platform use?).
- Confirm exit-code semantics (most agent platforms: `2` = block, `0` + JSON = structured response).

Cite the URL inline in the install function's docstring. **If the hook docs don't exist in the platform's docs, the install is a no-op — don't ship it.**

#### Matcher patterns we use

| Platform | Source | Pattern |
|---|---|---|
| Claude Code | Anthropic docs | `Bash`, `Write\|Edit` |
| Codex CLI | OpenAI docs | `Bash\|apply_patch` (rf-ovql) |
| Cursor | Cursor docs | three events: `preToolUse`, `postToolUse`, `beforeShellExecution` |
| Gemini CLI | Google Gemini docs | `run_shell_command\|write_file\|replace\|edit` (rf-044o) |
| Windsurf | (no hook surface) | n/a — pruned in rf-0vr3 |
| Continue.dev | (no hook surface) | n/a — pruned in rf-cia phase b |
| Aider | (no hook surface) | n/a — Aider has no plugin/hook system |

### 2. Skills / rules?

Most agent platforms now ship some flavor of "context that the agent fetches when relevant." We adopt the platform's own primitive:

| Platform | Primitive | Frontmatter |
|---|---|---|
| Claude Code | `.claude/skills/<name>/SKILL.md` | `name`, `description`, `allowed-tools` |
| Codex CLI | `~/.agents/skills/<name>/SKILL.md` | same as Claude (the skill format is shared via the `.agents/` convention) |
| Gemini CLI | `~/.agents/skills/` + `gemini skills link` runtime registration | (rf-yit lesson: file-presence ≠ runtime registration) |
| Cursor | `.cursor/rules/<name>.mdc` | `description`, `alwaysApply`, `globs` |
| Windsurf | `.windsurf/rules/<name>.md` | `trigger: model_decision`, `description` |
| Continue.dev | `.continue/rules/<name>.md` | `name`, `description`, `alwaysApply` |
| Aider | `read:` list in `.aider.conf.yml` (single file pointer) | n/a — Aider has no rule frontmatter |

Always one rule per skill (per `AGENT_SKILLS`), not one consolidated rule. Each rule body should be a **pointer** to the canonical skill file (`Read .claude/skills/<n>/SKILL.md`), not a copy — the canonical content lives in one place and the rule's job is just to make the agent fetch it on the right trigger.

### 3. Instruction file at workspace root?

`AGENTS.md` is the cross-platform standard — both **Codex** and **Windsurf** read it natively. `CLAUDE.md` is Claude Code's, `GEMINI.md` is Gemini's. Use the existing marker-block injection (`<!-- rafter:start --> ... <!-- rafter:end -->`) so user content is preserved across reinstalls.

If a platform supports `AGENTS.md`, add the platform to `installGlobalInstructions` (Node) / `_install_global_instructions` (Python) so a single `AGENTS.md` write covers both that platform and Codex.

### 4. MCP?

If the platform has documented MCP support:
- Find the config path (varies wildly: `.mcp.json`, `~/.continue/config.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.cursor/mcp.json`, `~/.gemini/settings.json` `mcpServers`).
- Find the schema (array `[{name, command, args}]` vs object `{<name>: {command, args}}` — Continue.dev accepts both).
- Use `RAFTER_MCP_ENTRY` (`{ command: "rafter", args: ["mcp", "serve"] }`) verbatim.

If the platform has **no documented MCP support** (Aider), do not append an unknown YAML key — Aider silently ignores them. The rf-du2o post-mortem covers this in detail.

### 5. Sub-agent?

Today only Claude Code has a first-class sub-agent primitive (`.claude/agents/<name>.md`). Cursor reads `.claude/agents/` too, so a single sub-agent file ships to both. Re-evaluate quarterly — if Codex or Gemini ship a sub-agent surface, add it.

## Dual-implementation rule

Every change ships in both Node and Python in the same PR. Versions are pinned together (`node/package.json` ↔ `python/pyproject.toml`); CI `validate-release.yml` enforces version match.

If you're tempted to ship Node-only and "follow up with Python" — don't. The audit doc has a recurring entry called **"Python missing"** because that PR never lands. Mirror as you go.

The shared resource templates (skill content, rule body, sub-agent body) live as **static files** under `node/resources/` and `python/rafter_cli/resources/`. Copy via `fs.copyFileSync` (Node) / `importlib.resources.files(...).read_text()` (Python). No runtime templating — the install path is just file copy. Differences between the two trees are caught by the `platform-integration.test.ts` "All 8 platforms" assertions.

## Verification gate

Every new platform must come with:

1. **File-presence tests** — `tests/agent-components.test.ts` asserts the registry lists the new IDs; `tests/platform-integration.test.ts` asserts `agent init --with-<p>` writes the expected files; Python mirrors both.
2. **A verify check** — `check<P>` / `_check_<p>` that goes from "platform dir exists" → "config file exists" → "rafter entry present" with `optional: true` at every failure (verify exit 1 is reserved for hard infra failures, not platform absence).
3. **Where the platform has a hook surface, a `--probe` branch** — extend `--probe` (rf-65zg) to synthesize the platform's documented hook stdin payload and assert `~/.rafter/audit.jsonl` records the interception. The probe is the only thing that catches the rf-luk-style "wrote file but the hook command itself doesn't fire" failure.

> **Why probes matter.** Three of the four hook-surface gaps caught in 2026 (Continue.dev `settings.json` no-op, Windsurf `hooks.json` no-op, Aider `mcp-server-command:` no-op) had passing file-presence tests at the time the gap shipped. Only a runtime probe distinguishes "wrote the file" from "the platform actually consumes it." Adding a `--probe` branch for any new platform with a hook surface is non-negotiable.

If the platform can't be driven headlessly (most IDEs can't), document the manual probe steps in `recipes/<p>.md` so a maintainer can run them by hand.

## Worked example: a fictional "Cleo" platform

Suppose Cleo (an imaginary new agent IDE) ships:

- A workspace rules system at `.cleo/rules/<name>.md` with frontmatter `mode: auto | always | manual`.
- A workspace instruction file at `CLEO.md` (workspace root, marker-block-friendly).
- MCP support at `~/.cleo/mcp.json` with object-format `mcpServers`.
- A documented `preCommand` hook event in `~/.cleo/hooks.json` matched by tool name (regex).
- No sub-agent primitive yet.

A complete Cleo PR touches:

```
node/resources/cleo-rules/
  rafter.md
  rafter-secure-design.md
  rafter-code-review.md
  rafter-skill-review.md
node/src/commands/agent/init.ts            # installCleoHooks, installCleoMcp,
                                           # installCleoRules, --with-cleo flag,
                                           # detection of ~/.cleo, install branch,
                                           # CLEO.md branch added to installGlobalInstructions
node/src/commands/agent/components.ts      # cleo.hooks, cleo.rules, cleo.mcp
                                           # ComponentSpecs + registry registration
node/src/commands/agent/verify.ts          # checkCleo
node/tests/agent-components.test.ts        # cleo.* in expected-id list
node/tests/platform-integration.test.ts    # describe("Cleo (--with-cleo)") block
                                           # + combined "All 8 platforms" updates

python/rafter_cli/resources/cleo-rules/    # mirror of node/resources/cleo-rules/
python/rafter_cli/commands/agent.py        # _install_cleo_*, --with-cleo,
                                           # _check_cleo, _install_global_instructions
                                           # branch for CLEO.md
python/rafter_cli/commands/agent_components.py  # _cleo_*, registry entries
python/tests/test_agent_init.py            # TestInstallCleoRules
python/tests/test_agent_components.py      # cleo.* in expected-id list
python/tests/test_agent_verify.py          # TestCheckCleo

recipes/cleo.md                            # what gets installed, manual setup, verify
README.md                                  # add Cleo to Supported Platforms
shared-docs/CLI_SPEC.md                    # add Cleo to verify check table
shared-docs/PLATFORM_PARITY_AUDIT.md       # add Cleo row to the matrix
CHANGELOG.md                               # [Unreleased] entry
```

A reasonable Cleo PR title: `feat(rf-XXXX): Cleo deep support — per-skill rules, AGENTS.md-style CLEO.md, hooks, MCP`.

If `--probe` is being extended in the same PR, add a `probeCleo` function in `verify.ts` (Node) / `_probe_cleo` in Python that synthesizes Cleo's documented `preCommand` payload and asserts `audit.jsonl`. Otherwise, file a discovered-from bead noting the probe is a follow-up.

## Known exceptions

The contract above describes the steady state. A few platforms deviate, and those deviations are documented:

- **OpenClaw** is in the registry as a category mismatch (it's a personal-AI-assistant platform, not an in-IDE coding agent). The skill-install shape we ship doesn't match what OpenClaw actually consumes. Tracked under `rf-0lig` for an activity / users check before further investment.
- **Aider** has no hook surface, no MCP, and no skill primitive. Its entire integration is a `read: [RAFTER.md]` entry in `.aider.conf.yml` (rf-du2o). The "Verification gate" probe doesn't apply.
- **Windsurf** has no hook surface (rf-0vr3). The integration is rules + AGENTS.md + MCP only.
- **Continue.dev** has no hook surface (rf-cia phase b). The integration is rules + MCP only.
- **Gemini CLI** requires the `gemini skills link` runtime-registration step on top of file-presence (rf-yit). Without it, the skill files exist on disk but the platform can't see them.

These exceptions belong in `shared-docs/PLATFORM_PARITY_AUDIT.md` matrix rows, not in this contract — the contract is the steady-state target; the audit doc is the running tally of where we deviate.

## Cross-references

- `shared-docs/PLATFORM_PARITY_AUDIT.md` — the per-platform state matrix.
- `shared-docs/CLI_SPEC.md` — the canonical CLI flag and output contract.
- `recipes/` — per-platform integration guides (must match installer reality).
- `rafter agent verify [--probe] [--json]` — the runtime contract that catches drift.
