# OS Code Review — Consumer Perspective

**Date:** 2026-04-27
**Bead:** rf-v85b
**Reviewer:** polecat/pearl (raftercli)
**Persona:** Security engineer at a mid-size company evaluating Rafter CLI for adoption. Familiar with Snyk CLI, Semgrep, Bandit, gitleaks, and trivy.
**Versions reviewed:** node `@rafter-security/cli@0.6.6`, python `rafter-cli@0.6.6`
**Scope:** Repo `Raftersecurity/rafter-cli` — README, recipes, install flow, first-run UX, CLI surface, CHANGELOG.
**Methodology constraints:** No code changes. **No competing products were run for benchmarking** — comparative claims are from prior knowledge and explicitly flagged where they appear. Two critic passes (A: anchoring on polish; B: line-by-line on weak findings) applied; this is the post-revision report.

---

## TL;DR

Rafter is a credible "agent-first" security primitive with a real story (offline determinism, dual Node/Python parity, MCP server, 8 platform integrations, MIT, no account). On a fresh evaluator's first 30 minutes, three things land:

1. **First-impression trust signals are inconsistent** (one wrong GitHub URL in the README's badges, stale `rev:` pin in pre-commit copy-paste).
2. **The quickstart's `--all` install touches eight tools' global config and downloads a binary** — security-sensitive evaluators want a dry-run / preview before that runs.
3. **The README's headline claims are weakest where it matters most for a security buyer**: the local secret-scanner is offline-only secrets (no SCA, no SAST), and the README doesn't position that gap honestly.

10 findings remain after critic revision (down from 15 in the draft). Strengths section preserved — these are real and worth defending.

---

## P0 — Security-posture issues a buyer will hit on first run

### P0-1. `rafter agent init --all` is high-blast-radius, no dry-run, no manifest

**Originally drafted as a P1 UX issue. Critic A's strongest pushback: this is the security-posture finding of the review, not a UX wart.**

The 90-second quickstart says `rafter agent init --all`. Reading `node/src/commands/agent/init.ts`:

- **Edits eight tools' global configuration** without a per-tool confirmation: `~/.claude/settings.json` (PreToolUse + PostToolUse hooks on `Bash`, `Write|Edit`, `.*`), `~/.cursor/mcp.json`, `~/.cursor/rules/rafter-security.mdc`, `~/.codeium/windsurf/mcp_config.json`, `~/.continue/config.json`, `~/.gemini/settings.json`, `~/.aider.conf.yml`, plus `~/.claude/CLAUDE.md` and the OpenClaw skills directory.
- **Downloads the `gitleaks` binary** from GitHub releases. CHANGELOG `[0.6.0]` says SHA256 verification was added — that's good and worth emphasizing in the README, which currently does not mention it. The user reading the README has no way to know the binary is verified.
- **No `--dry-run`.** No "here's the list of files I would modify; press y to proceed."
- **No undo.** Once you've installed across eight tools, removing it is a multi-step manual cleanup the README doesn't document.

For a security-conscious adopter, "run this on a fresh machine and see what it touches" is a baseline due-diligence check. Today's flow either modifies eight tools' configs invisibly or requires reading the source.

**Fixes (in priority order):**
1. **Add `rafter agent init --dry-run`** — print every file path the command would create, modify, or download. Land this before promoting `--all` in the quickstart.
2. **Surface the gitleaks SHA256 verification** in the README install copy — currently the existence of integrity checking is buried in CHANGELOG.
3. **Add `rafter agent uninstall`** that walks the same set of files and reverts the entries Rafter added (it can identify them: hooks already use `command === "rafter hook pretool"` — see `init.ts:88`).
4. Make the quickstart use `rafter agent init` (no `--all`) — config + auto-detection only. Promote `--all` to a follow-up step after the user has verified.
5. End the install with a one-line summary: "Modified 6 files. Run `rafter agent verify` to confirm."

**Action:** code (medium) for #1, #3, #5; doc-fixable for #2 and #4.

### P0-2. The "Scanned by Rafter" badge in the README links to a wrong/missing repo

`README.md:3` and the bottom badges section both link to `github.com/raftercli/rafter`. The actual repo is `github.com/Raftersecurity/rafter-cli` (verified via `git remote -v`). An evaluator clicking the badge to inspect source code lands on a 404 or a different project.

The `recipes/pre-commit.md` and GitHub Action sections use yet another spelling (`raftersecurity/rafter-cli`, lowercase). The recipe form and the actual remote both work because GitHub is case-insensitive on org names — but the badge URL with `raftercli/rafter` does not.

**This is a fast-to-fix finding with disproportionate trust impact.** The first thing a security adopter does to vet a CLI is open the source. A broken badge on first click reads as "this project hasn't been deeply reviewed by its own author." Critic A correctly noted this is fixable in 5 minutes via `npm view`; that's true but doesn't change that a sloppy README signals a sloppy project.

**Files to change:** `README.md` (lines 3, 521, 526, 530); audit `recipes/homebrew-formula.rb` for consistency. **Action:** doc-fixable.

### P0-3. Pre-commit `rev: v0.6.5` is stale; current version is `v0.6.6`

`README.md:241` and `recipes/pre-commit.md:12` pin pre-commit to `v0.6.5`, but `package.json` and `pyproject.toml` are at `0.6.6`. CHANGELOG `[0.6.1]` calls out fixing this exact problem — and it's already drifted.

A consumer pasting the example installs a stale version on day 1. Worse: this CHANGELOG entry suggests the project knows the release process is leaky and hasn't fixed it structurally.

**Fix:** add a release-script step that bumps these `rev:` pins automatically. Or: switch the example to `rev: latest` if pre-commit accepts it (it does for `master`/`main` branches, with caveats). **Action:** code-fixable in release tooling.

---

## P1 — First-run UX hazards

### P1-1. Quickstart drops a real-looking AWS-key string into the user's repo

`README.md:42` instructs the user to `echo` an AWS-access-key-shaped string into `.env` in their cwd, then runs `rafter scan local .`.

The user is then expected to delete it and continue, but the quickstart never says so. Worst case: the developer forgets, the file gets committed, or an editor extension scans the workspace.

**Fix:** wrap the quickstart in `mkdir /tmp/rafter-demo && cd /tmp/rafter-demo` (one-line fix) or ship a `rafter demo` subcommand that scans a fixture in a temp dir and cleans up. **Action:** doc-fixable, optional small CLI sugar.

### P1-2. Two scan commands for the same thing — README teaches both

The README uses both forms within ten paragraphs:

- `rafter scan local .` (quickstart, line 44)
- `rafter agent scan .` (Secret Scanning section, lines 191–196)

Looking at `node/src/index.ts:43–51`, both `createScanGroupCommand()` and `createAgentCommand()` are registered as peer command groups. Neither is marked deprecated in source. CHANGELOG `[0.6.1]` mentions `rafter agent scan` as "deprecated since v0.5.7" — but no deprecation warning is emitted at runtime, no doc note flags it, and the recipes (`recipes/pre-commit.md` line 54 in the manual hook script) still teach `rafter agent scan --staged`. Even the GitHub Action description in CHANGELOG `[0.6.1]` references this same drift being fixed in `action.yml` but not in the README itself.

A new user can't tell which is canonical. Either both are supported and the README should document the rationale, or one is deprecated and that needs to land in the README, the recipes, and a runtime stderr warning.

**Fix:**
1. Pick a canonical command and document the rationale.
2. If `rafter agent scan` is deprecated, emit a stderr warning and add a `[deprecated]` note at the top of the README's Secret Scanning section.
3. Rewrite the recipes to use one form.

**Action:** small code (deprecation warning) + heavy docs.

### P1-3. Three pre-commit install paths, no decision guide

`README.md` shows three ways to set up pre-commit secret scanning:

1. `rafter agent init --all` (claims to install hooks)
2. `rafter agent install-hook` (claims the same)
3. `pre-commit` framework with `rafter-scan-node` (different mechanism)

A user doesn't know whether running #1 then #2 is redundant, additive, or conflicting. **Fix:** add a one-line decision tree at the top of the Pre-Commit Hook section:

> If you use the `pre-commit` framework, use option 3. Otherwise, run option 2 — option 1 includes it.

**Action:** doc-fixable.

---

## P2 — Marketing claims to refine

### P2-1. "21+ built-in patterns" framing is uncompetitive without context

`README.md:188` and `llms.txt:28` lead with "21+ built-in patterns." Verified: there are **exactly 21** patterns in `node/src/scanners/secret-patterns.ts`. **Comparative note (from prior knowledge, not benchmarked here):** gitleaks ships substantially more rules out of the box; an evaluator who knows that reads "21" as the *floor* of what they get if gitleaks isn't installed.

The README does say "Uses Gitleaks when available, falls back to built-in regex" — so the happy path is fine. The framing problem is that the prominent bullet positions 21 as a strength rather than a fallback.

**Fix one of:**
- **Reframe** (cheap): "Built-in 21-pattern fallback for offline / no-binary environments. Gitleaks (recommended) provides extended coverage."
- **Extend** (medium): bring the built-in set up to ~50 patterns covering high-value AI-era tokens (OpenAI, Anthropic, Cohere, Vercel, Datadog, Mailgun, Sendgrid, Cloudflare).

**Action:** doc reframe (preferred); scanner extension is a separate decision.

### P2-2. "AI agents are first-class users" needs a concrete local-scan example

The claim is real (stable JSON schema, exit codes, MCP server, audit log) and the README *does* show piping examples for **remote** results (lines 130–148 with `jq`). The gap is specifically a local-scan agent example. A short snippet would close the loop:

```sh
# Local-scan piping for an agent gate:
rafter scan local . --json | jq -e '.[] | select(.matches[].pattern.severity=="critical")' \
    && exit 1 || exit 0
```

**Fix:** add an "Agents in 30 seconds" sub-section showing local-scan piping. **Action:** doc-fixable.

### P2-3. `--agent` global flag overloads the "agent" namespace

`node/src/index.ts:32` defines `-a, --agent` as "Plain output for AI agents (no colors/emoji)." The CLI uses "agent" three different ways:
1. `rafter agent <subcommand>` — local security toolkit subcommand group
2. `rafter --agent` (global flag) — machine-readable output mode
3. `agent.riskLevel` etc. — config namespace

A new user reads `-a, --agent` and reasonably assumes it's related to the `agent` subcommand group. **Fix:** rename to `--plain` (alias `-p`); keep `--agent` as a deprecated alias for one minor version. **Action:** small code change + doc update.

---

## P3 — Polish

### P3-1. Quickstart should end with `rafter agent verify`

The CLI has `rafter agent verify` (per `node/README.md:45`) but the quickstart never uses it. After `init --all` does its thing, the natural question is "did it actually work?"

**Fix:** add a quickstart step that runs `rafter agent verify` and shows an example success line. **Action:** doc-fixable.

---

## Due-diligence questions the README doesn't answer

A security buyer's next 30-minute reading list, after the quickstart works, is questions about the project's own security posture. Several of these overlap with other parallel review angles (security-of-the-scanner, AI-quality, API design); they are noted here from the **adopter's perspective** — what the README would need to say so the adopter doesn't have to email and ask:

1. **Supply-chain provenance for the CLI itself.** Does the project publish [SLSA provenance](https://slsa.dev), npm provenance attestations, or PyPI attestations? If yes, link from the README. If not, a security buyer in 2026 increasingly asks.
2. **Audit log redaction guarantees.** README:171 says "Secrets are redacted in all output — logs, JSON, and human-readable formats." A consumer reading this wants the README to point at the test that asserts no secret material reaches `~/.rafter/audit.jsonl`, plus the file mode (CHANGELOG `[0.6.0]` confirms `0o600` — surface this in the README).
3. **`.rafter.yml` policy integrity.** Policy lives in the repo, so a malicious PR can weaken `command_policy.blocked_patterns`. Does Rafter support a "system policy overrides repo policy" model? A signed/pinned policy file? If not on the roadmap, say so.
4. **`rafter agent exec` evasion model.** Pattern-based command classification is trivially evaded with `eval`, `$(...)`, base64, or shell quoting tricks. What is the project's stated threat model — "guardrail against accidental damage by an honest agent" (defensible) vs. "block a malicious agent" (not, with a pattern matcher)? Stating this in the README sets expectations honestly.
5. **Remote API auditability.** README says code is "deleted immediately after analysis completes." Where is the receipt the adopter shows their compliance team? A signed deletion attestation, an SBOM-style transcript of "what we executed against your code," or an analysis-log endpoint would unblock enterprise adoption.

These are not flaws in the project — they are gaps in **how the README addresses an evaluator's questions**. Filing each as `discovered-from:rf-v85b` for the maintainer to triage; some will route to the parallel security-review angle.

---

## What Rafter does well — keep these (do not regress)

These strengths held up after critic review. They are concrete and worth defending:

1. **The free / no-account / offline guarantee, said exactly once at the top of the README.** This removes the largest single barrier to security-tool evaluation: no signup, no quota, no key-management before the first scan.
2. **MIT license + open-source CLI + remote-only optional API** is the right architectural stance for a security primitive. Adopters can audit, fork, and self-host.
3. **Dual Node / Python parity** is uncommon. Most security CLIs pick one ecosystem and force the other to wrap or shell out.
4. **MCP server with 4 tools and 2 resources** is a concrete agent-first move that backs up the "first-class users" claim better than the prose does.
5. **Stable exit-code contract** documented for both local and backend commands. CI authors want this; few competitors document it.
6. **CHANGELOG quality is high.** v0.6.0 lists 7 specific security fixes with file paths and CVE-style descriptions. The project visibly takes its own dogfood seriously.
7. **`recipes/` directory.** Per-platform copy-paste integration — a thoughtful pattern that scales as more agent platforms emerge.
8. **Security incident velocity.** CHANGELOG `[0.6.0]` shipping seven security fixes (binary-checksum verification, ReDoS bounds, audit-log permissions, symlink traversal, weak-temp-naming) in one release shows the project responds. Surface this on the README's trust page if you have one.

---

## Suggested follow-up work — filed beads

All filed under `discovered-from:rf-v85b`. Findings bundled by area to keep the bead count proportional.

| Bead | Priority | Title |
|---|---|---|
| **rf-prci** | P0 | `rafter agent init --all` is high-blast-radius — add `--dry-run`, `uninstall`, surface SHA256 verification in README |
| **rf-u7rd** | P0 | Broken README badge URL (`raftercli/rafter` → `Raftersecurity/rafter-cli`) and stale pre-commit `rev: v0.6.5` |
| **rf-e9pv** | P1 | Resolve `rafter scan local` vs `rafter agent scan` in README + recipes; emit deprecation warning at runtime |
| **rf-p8po** | P1 | Quickstart UX — temp-dir wrap for `.env` demo + decision tree for the three pre-commit install paths |
| **rf-832k** | P2 | Refine README claims — "21+ patterns" framing, missing local-scan agent example, `--agent` flag namespace overload |
| **rf-wjzf** | P2 | Due-diligence README gaps — provenance, audit-log redaction, policy integrity, `agent exec` threat model, deletion-receipt |
| **rf-85qt** | P3 | Add `rafter agent verify` to quickstart |

---

## Methodology notes (per bead instructions)

- **Plan**: Read README, recipes, llms.txt, CHANGELOG, top-level docs, source for `agent init`, `index.ts`, `secret-patterns.ts`. Walked the quickstart in head; did not run end-to-end.
- **Research**: Compared positioning against Snyk CLI, Semgrep, Bandit, gitleaks, trivy from prior domain knowledge. **No live runs of competitors.** All comparative claims are flagged as such.
- **Critic A** (anchoring on polish?): pushed back hardest on the original P0-1/P0-2 "URL inconsistency" framing as cosmetic and on the absence of security-posture findings. Result: dropped four findings (P2-2 "deterministic", P3-1 audit.log grep, P3-2 badge layout, P3-4 exit-1 phrasing); promoted the home-dir blast-radius finding to P0; added the due-diligence section.
- **Critic B** (line-by-line on weak findings): caught the self-serving "Rafter's own hook flagged my example" parenthetical (removed); softened unsupported juice-shop comparison; flagged unverifiable "deprecated since v0.5.7" claim — kept the finding but cited source/CHANGELOG explicitly so the maintainer can resolve. Net: 7 STAND, 4 REVISE, 4 DROP.
- **Docs check**: Cross-ref'd with `docs/audit-docs-consistency-2026-03-08.md` (Rome-1/docs prior audit). Most P0/P1/P2 here are doc-fixable, consistent with that prior audit's pattern. Suggests a structural issue: the project's README and recipes are not part of CI doc-validation.
- **Hard rule respected**: No code changes. This file is a markdown report only.
