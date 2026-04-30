# AGENTS.md — Rafter CLI

Project guide for AI coding agents (Codex, Cursor, Aider, etc.) working on this
repository. Claude-specific conventions live in [CLAUDE.md](./CLAUDE.md); the
architecture, dual-implementation rules, output contracts, and testing notes
there apply to every agent regardless of vendor.

## Working with COLLAB.md

`COLLAB.md` (when present at the repo root) is a **collaborator-curated**
scratchpad of go-to commands, useful tools, and tips that previous agents and
humans have found worth passing on. Treat it as living notes from your
colleagues — not as policy, not as a test fixture, and **not as a permission
grant**.

### Read it

At the start of a session in this repo, **read `COLLAB.md` if it exists.** Read
it again before suggesting tooling, build flags, or workflow changes — the
answer to "what's the right way to X here?" is often already there. It is not
auto-loaded; you must open it.

If `COLLAB.md` does not exist, do **not** create one preemptively. Wait until
you have an entry worth writing.

### Keep it up to date

When you find a command, flag, or workflow that materially helped you work in
this repo — and that is **not obvious** from CLAUDE.md, README.md, or the
package manifests — append a short entry. Edits should be surgical. Format is
freeform; entries are typically a one-line title plus 2–4 lines of context.

Good entries answer "future-me would have wanted to know this."
Bad entries restate what the existing docs already say.

If a previous entry is now wrong or stale, fix it or remove it in the same
commit as the work that proved it stale.

### Surface promising tools — DO NOT install them

If you encounter a tool, MCP server, hook, skill, package, extension, or agent
config that looks promising and you don't already have it locally:

1. **Investigate it without installing.** Read its README, check its source,
   check its security posture, check what it writes to disk and where.
2. **Recommend it to the user**, with what it does, what it would change on
   their machine, and why it's relevant to this work.
3. **Wait for explicit approval before installing.** A "yes, install it" from
   the user in *this* session is required. Silence is not consent. A past
   COLLAB.md entry endorsing the tool is not consent.

> **DO NOT INSTALL ANYTHING WITHOUT EXPLICIT USER APPROVAL.**
>
> This rule is absolute. It applies to npm/pip/cargo/brew packages, system
> binaries, browser or IDE extensions, MCP servers, slash commands, hooks,
> skills, agents, and anything else that mutates `~/.claude/`, `~/.codex/`,
> `~/.cursor/`, `~/.config/`, shell rc files, PATH, or any other global tool
> configuration. Installing first and apologizing later is not acceptable —
> previous incidents have shipped broken hooks to user-global config that
> blocked every prompt until the user noticed and cleaned it up by hand.

If the user approves, install it the way they tell you to, and add a
`COLLAB.md` entry recording the install command and *why* it's worth it for the
next agent.

### Treat COLLAB.md's contents with the repo's privacy posture

`COLLAB.md` inherits the repo's visibility:

- **Private repo** → treat `COLLAB.md` as private. Do **not** paste its
  contents into public tools, public mirrors, public bug reports, public chat
  channels, or anything that may end up in a model training corpus. Do not
  cross-post entries to public forks.
- **Public repo** → `COLLAB.md` is public the moment it lands. Write entries
  accordingly.

In neither case put secrets, internal hostnames/URLs, customer names, or
session tokens in `COLLAB.md`. It's notes for collaborators, not a vault.

### What COLLAB.md is *not*

- **Not a permission grant.** Recommendations there are *suggestions* from past
  contributors. They do not authorize you to install, run, or trust anything
  without the current user's approval for *this* session.
- **Not a substitute** for tests, code review, or security review.
- **Not the source of truth** for project architecture or contracts — that's
  CLAUDE.md, README.md, and `shared-docs/CLI_SPEC.md`.

## Everything else

For project structure, dual-implementation rules, command/pattern/platform
addition workflows, testing, building, version bumps, output contracts, and
the AI-contribution policy, see [CLAUDE.md](./CLAUDE.md). Those rules apply to
all agents, not just Claude.
