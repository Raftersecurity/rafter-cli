# Skill Walkthrough — 2026-05-19 (sable-bum / A6)

Audit of the four `rafter*` agent skills shipped under
`node/resources/skills/<name>/` (mirrored byte-identical to
`python/rafter_cli/resources/skills/<name>/`).

Scope: `rafter`, `rafter-secure-design`, `rafter-code-review`,
`rafter-skill-review`. Goal: make sure each skill is as simple as it can be
without losing the "load this skill, get the answer" path.

Plus the derived platform variants under `node/resources/`:
`cursor-rules/*.mdc`, `continue-rules/*.md`, `windsurf-rules/*.md`,
`agents/rafter.md`. Those are downstream artifacts; out of scope for this
walkthrough unless a SKILL.md change demands a re-derive. Confirmed no
content edits flowed through to them this pass.

## Targets

- `rafter` SKILL.md keeps the documented 120-line guard (see
  `docs/postmortems/pr-72-family-2026-05-12.md`). Sub-docs are free-form.
- Other SKILL.md files have no explicit guard but should stay tight (~150
  lines, ~1500 words).
- Every `frontmatter.description` should make the trigger unambiguous.
- Every SKILL.md should end with a clear "do this now" line, not a vague
  checklist.

## Inventory (before)

| Skill | SKILL.md lines | SKILL.md words | Sub-docs | Total sub-doc lines |
|---|---|---|---|---|
| `rafter` | 118 | 1067 | 5 | 537 |
| `rafter-secure-design` | 103 | 897 | 8 | 787 |
| `rafter-code-review` | 91 | 723 | 6 | 560 |
| `rafter-skill-review` | 106 | 853 | 6 | 511 |

All four SKILL.md files are within the soft 150-line / 1500-word ceiling
already. `rafter` is right at its 120-line guard (118), so further additions
must displace something out to a sub-doc.

## Per-skill findings

### `rafter` (entry / router)

- **Trigger clarity**: description is unambiguous (router + "if security
  relevant and nothing ran, run this"). Keep.
- **120-line guard**: 118 lines. Two non-essential lines were trimmed below
  to leave headroom.
- **End-action clarity**: "Fast Path" + "Strengthen the Project" at the
  bottom is fine, but the very last line is a list of setup hints that
  read more like marketing than instruction. Tightened.
- **Duplication**: branches (e) and (f) both push the agent into
  `docs/shift-left.md`. shift-left.md re-describes the sibling skills
  (auth, threat-modeling, OWASP categories) which are already advertised
  in the sibling SKILL.md files themselves. Net effect: the agent reads
  shift-left.md, then reads the sibling SKILL.md, and gets the same router
  twice. Punt: a proper rewrite is more work than this pass allows.
- **Internal bead IDs leak**: `docs/shift-left.md` lines 15, 61, 62 reference
  internal bead IDs `rf-bcr` and `rf-z7j` ("filed as rf-bcr", "landed
  (rf-z7j)"). These are noise in public-facing skill text. Removed.
- **Stale `agent audit` references**:
  - SKILL.md line 52: "`rafter agent audit <path>` (still supported)" — fine
    but the language treats it as a co-equal alternative to `skill review`.
    `shared-docs/CLI_SPEC.md` §line 591 marks `audit-skill` as deprecated.
    Rewording to "deprecated alias" matches the canonical spec.
  - `docs/cli-reference.md` lines 71–79 document `rafter agent audit` and
    `rafter agent audit-skill` but do NOT document `rafter skill review`
    even though that's the canonical entry per CLI_SPEC.md. Added a
    `rafter skill review` entry and marked `agent audit-skill` deprecated.
  - `docs/cli-reference.md` line 193 quick-decision table still recommends
    `rafter agent audit <path>` for "is this skill safe to install?".
    Updated to `rafter skill review`.

### `rafter-secure-design`

- **Trigger clarity**: description is strong ("REQUIRED before writing code
  for any feature touching auth, payments, …"). Keep.
- **End-action clarity**: explicit "Fast path at feature kickoff" block.
  Good.
- **Length**: 103 lines / 897 words — comfortably within budget.
- **Duplication**: the "Tie-backs" block at the bottom (lines 98–103)
  duplicates branch (c) of `rafter/SKILL.md` and branch (d/e/f) of the
  same router. Not high-cost to keep — it's a cross-link, not a
  re-derivation. Leave.
- **Stale paths**: none found.

### `rafter-code-review`

- **Trigger clarity**: description is strong. Keep.
- **End-action clarity**: ends with "Tie-backs" cross-links and a fast-path
  bash block. Good.
- **Length**: 91 lines / 723 words — tightest of the four. No cuts needed.
- **Duplication**: line 67 — "Always pair with `rafter secrets .` (secrets)
  and `rafter run` (SAST/SCA) before review." This is the same advice that
  appears in `rafter/SKILL.md` branch (a), in `docs/shift-left.md`, and in
  every sub-doc cross-link. It's the canonical fast-path so keeping the
  one-liner here is fine. No edit.
- **Stale paths**: none found.

### `rafter-skill-review`

- **Trigger clarity**: description is strong, leads with the threat model
  ("`curl | sh` in a different costume"). Keep.
- **Length**: 106 lines / 853 words. Fine.
- **Per Rome's instructions**: SKILL.md and sub-docs are NOT to be edited
  substantively in this pass — `sable-d5d` is the dedicated follow-up bead
  for this skill. Read-only walkthrough only. No edits applied beyond the
  cross-cutting public-hygiene sweep (no internal bead IDs found inside
  this skill, no stale CLI references).

## Cross-cutting findings

### Sections that should live in sub-docs, not SKILL.md

None identified that meet the "move it down and keep the dispatch path
working" bar. The SKILL.md files are all routers already; moving more out
would force a second `Read` on every invocation.

### Duplicated paragraphs across files

Two near-duplicate paragraphs were noted but **not** consolidated this
pass (cross-skill content moves are explicitly out of scope per the
maylist):

1. The "three-tier rafter scan" explanation appears in `rafter/SKILL.md`
   §"Picking the right tier" and again in `rafter/docs/backend.md`
   §"Local vs Remote". The SKILL.md version is the canonical one;
   `backend.md` is the deeper reference. Acceptable split.
2. "Pair with `rafter run` / `rafter secrets`" appears across all three
   non-skill-review skills. This is the load-bearing cross-link, not
   genuine duplication. Keep.

### Punted larger edits (future bead candidates)

- **`rafter/docs/shift-left.md` redundancy with sibling SKILL.md routers**
  — when an agent is going to read the sibling skill anyway, shift-left
  should be a 10-line pointer, not a 60-line re-derivation. Bead candidate:
  "rafter/docs/shift-left.md: collapse to pointer-only".
- **`rafter/docs/cli-reference.md` length (197 lines)** — duplicates much
  of `shared-docs/CLI_SPEC.md`. Could be reduced to a "common verbs +
  pointer to CLI_SPEC.md" page. Bead candidate: "rafter/docs/cli-reference:
  prune to verbs + spec pointer".
- **`rafter-skill-review` standalone audit** — `sable-d5d`, already filed.
- **Platform variant re-derive** — `cursor-rules/`, `continue-rules/`,
  `windsurf-rules/`, `agents/` were not touched. If/when the SKILL.md
  changes propagate, those should be re-derived in one bead. Bead candidate:
  "re-derive platform skill variants from canonical SKILL.md sources".

## Edits applied in this commit

Light, safe, mirrored to python pair:

1. `rafter/SKILL.md`: tightened branch (c) wording for `rafter agent audit`
   so it reads as deprecated alias, not co-equal command.
2. `rafter/SKILL.md`: removed marketing-y trailing line in "Strengthen the
   Project" so the section ends with the actual commands.
3. `rafter/docs/shift-left.md`: removed internal bead IDs (`rf-bcr`,
   `rf-z7j`) from public-facing copy.
4. `rafter/docs/shift-left.md`: removed the trailing "Status" section that
   restated the same bead-tagged "landed" claim a second time.
5. `rafter/docs/cli-reference.md`: added `rafter skill review` entry as the
   canonical skill-vetting command; marked `agent audit-skill` as
   deprecated alias.
6. `rafter/docs/cli-reference.md`: updated Quick Decision Table to point
   "is this skill safe to install?" at `rafter skill review`.

No content moved between skills. No sub-doc creation. No sub-doc deletion.

## Mirror confirmation

After edits, `diff -rq node/resources/skills/ python/rafter_cli/resources/skills/`
ignoring `__init__.py` files returns empty.
