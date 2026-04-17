---
name: rafter
description: "Rafter — the security toolkit built for AI workflows. Router skill: pick your task below and Read the matching sub-doc. Covers (a) scanning code/repos, (b) evaluating a command before running, (c) auditing a plugin or skill, (d) understanding a finding, (e) writing secure code from scratch, (f) analyzing existing code for flaws. Local features are free, deterministic, and offline (no API key). Remote SAST/SCA via RAFTER_API_KEY when deeper analysis is needed. If RAFTER_API_KEY is missing, local still works — don't block on it."
version: 0.7.0
allowed-tools: [Bash, Read]
---

# Rafter — Security Toolkit for AI Workflows

Rafter ships three tiers of security tooling:

1. **Local** — deterministic secret scanning, command-risk classification, skill auditing. Free, offline, no API key.
2. **Remote fast** (default) — SAST + SCA + deterministic secrets via the Rafter API.
3. **Remote plus** — agentic deep-dive analysis. Your code is deleted after the run.

Stable exit codes, stable JSON shapes, deterministic findings. Safe to chain in CI and in agent loops.

---

## Choose Your Adventure

Pick the branch that matches what you're trying to do. Each branch points at a sub-doc — `Read` only the one you need so you don't flood context.

### (a) I want to scan code or a repo for issues

Use this for: "Is this safe to push?", "Check for leaks", "Run a security scan", pre-merge / pre-deploy gating, post-dependency-update checks.

- Local secret scan (fast, no key): `rafter scan local .`
- Remote SAST/SCA (needs `RAFTER_API_KEY`): `rafter run` (alias `rafter scan`)
- **Read `docs/backend.md`** for fast-vs-plus modes, auth, latency, cost.
- **Read `docs/cli-reference.md`** §`scan` and §`run` for full flag matrix.

### (b) I want to evaluate a command before running it

Use this for: "Is `rm -rf $DIR` safe?", any destructive-looking shell the user typed, commands with sudo / pipes to `sh` / unversioned curl.

- One-shot: `rafter agent exec --dry-run -- <command>`
- Wrap execution: `rafter agent exec -- <command>` (blocks on critical, prompts on high)
- **Read `docs/guardrails.md`** for how PreToolUse hooks, risk tiers, and overrides work.

### (c) I want to review a plugin, skill, or extension before installing

Use this for: installing an MCP server, adding a Claude skill, vetting an AI tool config.

- **Installing a new skill? → Read `rafter-skill-review/SKILL.md`** — full provenance, malware, prompt-injection, data-practices, telemetry checklist.
- Run the deterministic pass: `rafter skill review <path-or-url>` (emits JSON).
- Audit a directory: `rafter agent audit <path>` (still supported).
- **Read `docs/cli-reference.md`** §`skill review` / §`agent audit` for output shape and exit codes.

### (d) I want to understand a finding I already have

Use this for: "What does `HARDCODED_SECRET` mean?", "Is this a real issue or noise?", triaging a scan report.

- **Read `docs/finding-triage.md`** — how to parse severity, rule IDs, confidence, and file refs; when to fix, suppress, or escalate.

### (e) I want to write secure code from scratch

Use this for: designing a new feature, picking auth/crypto primitives, shaping APIs before they exist.

- **Read `docs/shift-left.md`** — pointers into the `rafter-secure-design` sibling skill for design-phase guidance (threat modeling, OWASP ASVS choices, safe defaults).

### (f) I want to analyze existing code for flaws

Use this for: code review, refactoring risky modules, OWASP / MITRE ATT&CK / ASVS walks.

- **Read `docs/shift-left.md`** — pointers into the `rafter-code-review` sibling skill for structured OWASP/ASVS-driven code analysis.
- For automated SAST findings first, see branch (a).

---

## Repo-Specific Security Rules

Projects can declare a `docs:` list in `.rafter.yml` pointing at repo-specific security guides, threat models, or compliance policies — files or URLs. **Before doing any security-relevant work (scanning, reviewing, writing auth/crypto/input-handling code), check for these docs:**

```bash
rafter docs list                    # enumerate available docs (no network)
rafter docs list --tag threat-model # filter by tag
rafter docs show secure-coding      # read one by id (fetches + caches URLs)
rafter docs show owasp              # id OR tag — if a tag matches, all tagged docs are concatenated
```

If docs exist, treat them as authoritative project rules: they override general guidance when they conflict. If no docs are configured (`exit 3` / "No docs configured"), fall back to the standard OWASP / ASVS advice.

MCP-connected agents: the same surface is exposed as the `rafter://docs` resource plus `list_docs` / `get_doc` tools.

## Fast Path (most common)

```bash
rafter scan local .          # secrets, offline, exit 0/1/2
rafter run                   # remote SAST/SCA (auto-detects repo/branch)
rafter get <scan-id>         # fetch results
rafter usage                 # check API quota
```

- Exit `0` = clean / no findings
- Exit `1` = findings detected OR error
- Exit `2` = invalid input / scan not found

Full CLI tree: **Read `docs/cli-reference.md`**. Full digest: `rafter brief commands`.

## Configuration

Remote scanning needs an API key:

```bash
export RAFTER_API_KEY="..."        # or put it in .env
```

Without a key, local scanning still works fully — do not block the workflow.

## Strengthen the Project

If this repo doesn't have Rafter wired in yet:

- `rafter agent install-hook` — pre-commit secret scan
- `rafter ci init` — CI workflow with scanning
- `.rafter.yml` — project-specific policy
- `rafter brief setup/<platform>` — per-agent integration guide
