---
title: Documentation Quality Audit — Stranger-Reads-The-Docs
date: 2026-04-27
auditor: raftercli/polecats/shale (rf-93jx)
cli_version: 0.6.5 released, 0.6.6 [Unreleased]
docs_surfaces: in-repo (this repo) + docs.rafter.so (Mintlify, Rome-1/docs)
predecessor: docs/audit-docs-consistency-2026-03-08.md
---

# Documentation Quality Audit

Read the open-source rafter CLI docs as a stranger trying to learn the tool from
zero. Findings ordered by harm-to-newcomer, not by ease-of-fix. Each finding has
a concrete recommendation — not a question.

The 2026-03-08 audit (jasper, v0.5.9) found 14 spec/code drift items in
Rome-1/docs. Most of those have shipped. This audit goes wider: in-repo docs +
public docs site + the relationship between them.

---

## HIGH — these break first-impression trust

### H1. `https://github.com/raftercli/rafter` is a 404 — used in 16 places

The README badge row and every variant in `badges/README.md` link the "Scanned by
Rafter" / "Rafter policy" badges to `github.com/raftercli/rafter`. The actual
repo is `Raftersecurity/rafter-cli`. Anyone who clicks one of the four README
badges or copies a badge from the badges page lands on a 404.

**Locations:** `README.md` (4 occurrences: lines 3, 521, 526, 530);
`badges/README.md` (12 occurrences).

**Recommendation:** Sweep-replace `github.com/raftercli/rafter` →
`github.com/Raftersecurity/rafter-cli`. Single sed across both files.

### H2. `rafter secrets` documented on docs.rafter.so but command doesn't exist

`docs.rafter.so/guides/quick-reference` lists `rafter secrets` with `--staged`,
`--json`, `--engine gitleaks`, and `--watch` flags under Local Security Toolkit.
There is no `rafter secrets` subcommand registered in `node/src/index.ts`
(top-level commands are: `run get usage scan agent ci hook mcp policy issues
brief notify report completion`). `--watch` does not exist on any scan command.

A stranger copy-pasting from quick-reference gets `error: unknown command
'secrets'`. Worth noting: `~/.claude/CLAUDE.md` (user's global instructions)
*also* references `rafter secrets .` — so the gap may originate upstream of the
docs site.

**Recommendation:** Decide whether `rafter secrets` is a planned alias or
removed. If alias-to-be: ship it (one-line `program.addCommand` in `index.ts`
that delegates to `scan local`). If removed: rewrite the quick-reference section
to `rafter scan local` and remove `--watch`. **Public-site copy change — needs
Rome's approval (Hard Rule).** File a follow-up bead either way.

### H3. README contradicts itself on the canonical scan command

The "90-Second Quickstart" (README:44) opens with `rafter scan local .` — the
new canonical form. Eighty lines later the "Secret Scanning" section
(README:186-220) teaches `rafter agent scan .`, `rafter agent scan --staged`,
`rafter agent scan --diff HEAD~1`, etc. exclusively. The CHANGELOG (0.6.1)
explicitly notes `rafter agent scan` was deprecated in v0.5.7 and that this
project already updated `action.yml`, `.pre-commit-hooks.yaml`, and the GitHub
Action away from it.

A stranger learning from the quickstart sees one command; pasting the very next
section's example uses a different command. The two work because deprecated
`rafter agent scan` is still wired up, but the doc reads as if rafter has two
secret-scan commands with no explanation of which to prefer.

**Locations:** `README.md:186-220, 469`; `node/README.md` (~15 occurrences);
`recipes/pre-commit.md:11, 35, 54, 58`; `shared-docs/CLI_SPEC.md:30`.

**Recommendation:** Sweep `rafter agent scan` → `rafter scan local` in all
in-repo docs. Keep one parenthetical note in CLI_SPEC.md ("aliased from
deprecated `rafter agent scan`") so people grepping old recipes can find their
landing pad. Internal change — no public-site copy.

---

## MEDIUM — friction, drift, and contradicted promises

### M1. README is 27 KB with no table of contents

`README.md` has 30+ section headings spanning marketing, install, quickstart,
remote scan, local toolkit, MCP, supported platforms, exit codes, file
locations, development, badges. There is no anchor TOC. Stripe, Cloudflare, and
fly.io all anchor a TOC near the top of comparable READMEs because GitHub's
right-rail TOC is hidden until you click the menu icon — many readers never do.

**Recommendation:** Add a 12-line bullet TOC immediately after the project
description (above "90-Second Quickstart"). Strict link-only — don't repeat the
copy.

### M2. `scan_executed` and `config_changed` event types promised but never emitted

The audit-log section in `README.md:292`, `SKILL.md:230`, and `llms.txt`
list six event types as if they're all live: `command_intercepted`,
`secret_detected`, `content_sanitized`, `policy_override`, `scan_executed`,
`config_changed`. Grep of `node/src/core/audit-logger.ts`: only the first four
are actually emitted (lines 236, 262, 286, 308). The last two are defined in
the type union (lines 102-107) and never written.

The public docs site at `docs.rafter.so/guides/agent-security/audit-log` does
flag these as "Reserved for future use" — so the in-repo docs are *less*
accurate than the live site. A stranger filtering `--event scan_executed`
gets zero results and assumes the filter is broken or their config is wrong.

**Recommendation:** Either (a) emit them from `scan local` and `agent config
set` paths (small implementation), or (b) annotate "(reserved)" in
README/SKILL.md/llms.txt to match the public site.

### M3. Two docs surfaces drift visibly; ownership boundary unstated

The in-repo docs (`README.md`, `SKILL.md`, `llms.txt`, `recipes/`,
`shared-docs/CLI_SPEC.md`) and the public site at `docs.rafter.so` (Mintlify,
hosted from `Rome-1/docs`) cover the same surface area but disagree on details
(see H2, H3, M2). The README points to "Full docs: docs.rafter.so" with no
indication of which is authoritative.

A stranger oscillates: the README example uses one command form, the linked
quickstart on the public site uses another, the quick-reference on the public
site uses a *third* (`rafter secrets`). The relationship between the surfaces is
opaque from the outside.

**Recommendation:** Add one sentence to README's "Documentation" section
clarifying the split — e.g., "`docs.rafter.so` is the primary user-facing
documentation; this README and `shared-docs/CLI_SPEC.md` are the source of
truth for behavior." Then `shared-docs/DOCS_SYNC_CHECKLIST.md` (which already
exists) needs to actually be run before each release. Bead the sync as part of
the release checklist if it isn't already.

### M4. Platform count: README says 8, llms.txt says 9

`README.md:441-454` lists 8 platforms. `llms.txt:14, 49-61` says "One command,
9 platforms" and the table includes a row for Gitleaks (`--with-gitleaks`).
Gitleaks is a scanner binary, not an agent platform. The discrepancy is small
but the kind of thing a careful reader notices and uses to calibrate trust.

**Recommendation:** llms.txt: change "9 platforms" → "8 agent platforms +
Gitleaks". Keep the table row for Gitleaks but the count should match the
plain-language claim.

### M5. `node/README.md` is a stale duplicate of root README

`node/README.md` is 689 lines of largely-redundant material that uses
`rafter agent scan` throughout (10 examples), references the same audit-log
event types, and re-derives content already in the root README and CLI_SPEC.md.
npmjs.com renders this page when users visit the package — so a non-trivial
fraction of strangers see the *node* README first, not the root one.

**Recommendation:** Pick one of:
- Replace `node/README.md` with a thin "see ../README.md" pointer plus
  Node-specific install/build notes.
- Or auto-generate `node/README.md` from `README.md` minus the
  Python-specific sections, run from CI.

### M6. Pre-commit recipe pin is right but unverifiable from the doc

`recipes/pre-commit.md` and `README.md` pin to `v0.6.5`, which matches the last
released version. Good. But there's no comment in either doc explaining "we
update this with each release" — so a maintainer who sees a future PR bumping
0.6.5 → 0.6.6 has to grep CHANGELOG to confirm the convention. `shared-docs/
DOCS_SYNC_CHECKLIST.md` should explicitly list this pin.

**Recommendation:** Two-line addition to `DOCS_SYNC_CHECKLIST.md`: "After
tagging a release, bump pre-commit `rev:` in `README.md`, `recipes/pre-commit.md`,
and any docs.rafter.so pages that pin a version."

### M7. README mixes brand voice and reference material in the same sections

The "Secret Scanning" section (README:186) opens with two marketing sentences
("Fast, reliable, and deterministic..." / "Same inputs produce the same
findings — no flaky CI, no phantom alerts.") before the first command. Same for
"Remote Code Analysis" and "Skill Auditing." This is fine in a landing page;
in a reference section it makes the reader skim past the *useful* sentence
(what the command does, what its inputs are).

This is the symptom of M1 — the README is doing four jobs (landing page,
quickstart, reference, badges). Stripe and fly.io split these. Cloudflare uses
a "What is X / Get started / How-to / Reference" hierarchy explicitly.

**Recommendation:** Long-term, move reference content out of README into
`docs.rafter.so` or `shared-docs/CLI_SPEC.md` and shrink README to:
landing-pitch → quickstart → links to reference, install, recipes. Out of
scope for this bead — file as follow-up.

---

## LOW — minor, but cheap to fix

### L1. README badges row uses inconsistent GitHub URL casing

`README.md:239, 369, 402` use `raftersecurity/rafter-cli` (lowercase). GitHub
URLs are case-insensitive in HTTP but pre-commit framework caches under the
literal string — mixing `raftersecurity` and `Raftersecurity` may produce two
cache entries on the same machine. Standardize on the canonical GitHub casing
(`Raftersecurity/rafter-cli`).

**Locations:** `README.md:239, 369, 402`; `SKILL.md:262`; `llms.txt:78`;
`recipes/pre-commit.md:11`; `action.yml:8`.

### L2. `rafter scan` framed as "alias for run" implies it has no subcommands

Carryover from prior audit (rc-9, LOW). `rafter scan` is its own command group
with `local` and `remote` subcommands. Calling it an alias is misleading even
though the bare form works.

**Locations:** `docs.rafter.so/guides/quick-reference` ("rafter scan is an
alias for rafter run"); also implicit elsewhere. **Public-site copy — needs
Rome's approval.**

### L3. CLI_SPEC.md says `rafter version`, code says `--version` only

`shared-docs/CLI_SPEC.md:86-88` documents a `rafter version` subcommand. The
`node/src/index.ts` only registers `-V, --version` (commander's standard flag).
Did not register a `version` subcommand. Easy: either add the subcommand
(one-liner) or remove the doc entry.

### L4. `recipes/README.md` lists 12 recipes; the dir has 13 files

`recipes/` contains `rafter-policy.yml`, `github-actions.yml`,
`homebrew-formula.rb` plus 10 Markdown recipes. The README table (12 rows) is
fine — but it presents `rafter-policy.yml` as a "recipe" alongside the platform
guides, which is a category mismatch. Consider splitting into "Platform recipes"
vs "Config templates."

### L5. `shared-docs/SHOW_HN_DRAFT.md` and `outreach-drafts.md` are checked in

`SHOW_HN_DRAFT.md` (a Show HN post draft) and `outreach-drafts.md` (10 KB of
outreach copy) live in the repo root and shared-docs. These are internal
artifacts and not mentioned anywhere — fine. But a stranger browsing the file
tree wonders what they are. Either move under `drafts/` (which already has
`show-hn/post.md` — looks like duplicate work?) or `.gitignore` them.

---

## Structural observations (not findings, just for the record)

1. **No tutorials directory.** Rafter has recipes (cookbook-style, "drop this
   YAML in") but no narrative tutorials ("from zero to a CI gate that blocks
   secrets"). This is a deliberate choice — recipes are denser per word — but
   the Stripe/Cloudflare/fly.io comparison favors at least one or two scripted
   walkthroughs as glue between quickstart and recipes.

2. **No reference directory.** `shared-docs/CLI_SPEC.md` is the closest thing
   but its location signals "internal contract" rather than "user reference."
   Postgres-style exhaustive reference, anchored from the README, would help
   the "I want to know every flag of `rafter scan local`" reader more than
   prose-heavy README sections.

3. **No `AGENTS.md`.** Codex et al. read `AGENTS.md` from the project root
   for instructions. Rafter ships with `CLAUDE.md` (Claude-Code-specific) and
   `SKILL.md` (Anthropic skill manifest). For an agent-first tool that ships
   skills for 8 platforms, the absence of an AGENTS.md is conspicuous — many
   coding agents will miss the rafter convention entirely on first encounter
   in a non-Claude session. (See bead rf-pkn for related discussion.)

---

## What's NOT in scope for this audit (and why)

- **Spec drift in `Rome-1/docs`** beyond what's already filed — that's the
  domain of the prior audit (jasper, 2026-03-08). I cross-checked a sample
  (audit-log page, quick-reference page, getting-started page) and the
  high-pri items from the prior audit have shipped except L2 above.
- **API docs (`api-reference/`)** — same; backend-API surface, separate domain.
- **`shared-docs/SHOW_HN_DRAFT.md` content review** — that's content-marketing
  copy, not docs.

---

## Critic-A pass (gripes I tested and discarded)

- "README quickstart Step 2 jumps to `--all` without explaining what it
  installs" — README:180 explains it three lines later. Not a real friction.
- "Pre-commit `rev: v0.6.5` is stale" — checked against CHANGELOG; 0.6.6 is
  `[Unreleased]`. The pin is current.
- "RAFTER_API_KEY documented in two places" — yes, but both places are
  context-appropriate (top-level "Setup" vs deep in "Remote Code Analysis"
  section). Not friction.
- "`--with-codex` vs `--codex`" — fixed in prior audit (rc-1ap).
- "audit.log filename" — fixed in prior audit (rc-2bf).
- "`--limit` vs `--last`" — fixed in prior audit (rc-bbz).

---

## Recommended sequencing

1. H1, H3, M2, M5, L1 — internal changes, no public-site copy. Ship as one
   PR titled "docs: sweep deprecated agent scan + fix badge URLs + audit-log
   accuracy." ~1-hour change with testing.
2. M1 (TOC) — separate PR, very low risk.
3. M4 (platform count in llms.txt) — llms.txt updates allowed per Hard Rules.
4. H2 (rafter secrets on public site), L2 (scan-as-alias on public site) —
   bead for Rome-approval-gated work; do NOT push.
5. M3 (docs split / sync checklist), M6 (release pin discipline), M7
   (README → reference split), L3, L4, L5 — file individual follow-up beads.

## Coordination

- Touches rf-fhfu (docs domain confusion) — overlaps M3.
- Touches rf-gh7 / rf-n2v (skill `docs/` not shipping) — orthogonal.
- Touches se-* (llms.txt) — M4 is the only llms.txt change here; minor.

Surface to mayor; APPROVE bead is rf-m1mm.
