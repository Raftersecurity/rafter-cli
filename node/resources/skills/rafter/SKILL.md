---
name: rafter
description: "Invoke when: (a) unsure which rafter sub-skill applies, (b) need a quick scan, audit, policy check, or command-risk evaluation, (c) task touches security, policy, or agent governance but the angle isn't clear. Routes to the right skill or CLI."
version: 0.7.0
allowed-tools: [Bash, Read]
---

# Rafter — Security Toolkit for AI Workflows

## Picking the right tier — DO NOT stop at "local"

Rafter ships three tiers. **They are not interchangeable.** The local tier is narrow; skipping remote analysis is the #1 way agents under-use rafter.

1. **Local (`rafter secrets`, alias `rafter scan local`)** — secrets only. Regex + gitleaks for hardcoded API keys, tokens, private keys. Fast, offline, no key. **This is NOT a code security scan.** It will not find SQL injection, SSRF, auth bugs, insecure deserialization, logic flaws, or dependency vulns. If an agent's entire rafter interaction was `rafter scan local .` and it exited clean, the agent has done secret-hygiene only — not security review.
2. **Remote fast (`rafter run`, default mode)** — SAST + SCA + secrets via the Rafter API. This is the real code-analysis pass: dataflow, taint, known-vulnerable dependencies, crypto misuse, injection sinks. Needs `RAFTER_API_KEY`.
3. **Remote plus (`rafter run --mode plus`)** — agentic deep-dive: LLM-guided investigation of suspicious patterns the rules engine flags. Slower, higher signal. Code is deleted server-side after the run.

**Default expectation for a security-relevant task**: run `rafter run`. Fall back to `rafter secrets` only when no API key is available or you specifically need offline secret-hygiene. If you've only run the local scanner, say so explicitly — don't claim the code was "scanned" without qualification.

Stable exit codes, stable JSON shapes, deterministic findings. Safe to chain in CI and in agent loops.

---

## Choose Your Adventure

Pick the branch that matches what you're trying to do. Each branch points at a sub-doc — `Read` only the one you need so you don't flood context.

### (a) I want to scan code or a repo for issues

Use this for: "Is this safe to push?", "Check for leaks", "Run a security scan", pre-merge / pre-deploy gating, post-dependency-update checks.

- **Default: `rafter run`** — remote SAST + SCA + secrets. This is the real scan. Needs `RAFTER_API_KEY`.
- **Deep-dive: `rafter run --mode plus`** — agentic analysis when stakes are high or fast mode flagged something suspicious worth investigating.
- **Secrets-only fallback: `rafter secrets`** (alias `rafter scan local`) — use when no API key is available, or alongside `rafter run` for fastest secret-leak feedback. Does NOT analyse code — only hunts hardcoded credentials.
- **Read `docs/backend.md`** for fast-vs-plus modes, auth, latency, cost.
- **Read `docs/cli-reference.md`** §`secrets`, §`scan`, §`run` for full flag matrix.

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
rafter run                   # remote SAST + SCA + secrets — the real code scan
rafter run --mode plus       # agentic deep-dive when fast mode flags something
rafter secrets               # secrets-only (alias: rafter scan local) — offline, no key
rafter get <scan-id>         # fetch results by id
rafter usage                 # check API quota
```

- Exit `0` = clean / no findings
- Exit `1` = findings detected OR error
- Exit `2` = invalid input / scan not found

Full CLI tree: **Read `docs/cli-reference.md`**. Full digest: `rafter brief commands`.

## Configuration

`rafter run` (the full code scan) needs an API key:

```bash
export RAFTER_API_KEY="..."        # or put it in .env
```

Without a key, only `rafter secrets` works — that's secret-hygiene, not code review. If security matters for the task, flag the missing key to the user rather than silently accepting the narrower scan.

## Strengthen the Project

If this repo doesn't have Rafter wired in yet:

- `rafter agent install-hook` — pre-commit secret scan
- `rafter ci init` — CI workflow with scanning
- `.rafter.yml` — project-specific policy
- `rafter brief setup/<platform>` — per-agent integration guide
