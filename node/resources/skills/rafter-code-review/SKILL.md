---
name: rafter-code-review
description: "Security review of code: auditing a codebase, finding vulnerabilities in a module, or reviewing a diff before calling work on auth, input, SQL, shell or crypto done. Walks a security-gate checklist (allowlists, auth checks, token and crypto validity, path containment, escaping, limits) and OWASP/CWE questions, with file:line evidence. NOT for secret scanning alone (rafter secrets)."
version: 0.8.1
allowed-tools: [Bash, Read, Glob, Grep]
---

# Rafter Code Review — Structured Security Walkthroughs

A reviewer's skill, not an audit generator. Each sub-doc is a set of **questions** to run against the code — what to grep for, what to trace, what to ask before you sign off. No monolithic reports.

> Pair with the `rafter` skill (detection: `rafter scan`, `rafter run`) and `rafter-secure-design` (prevention: design-phase walks). This skill is the middle stage — review before merge.

## When this applies (and when it doesn't)

**Auditing a whole codebase or module** ("audit this repo", "find the vulnerabilities in X"): start with `docs/security-gates.md`, then the category sub-doc below.

For a diff, scope by the **security surface of the diff**, not the task's label. Walk it fully when the change touches: user / untrusted input, SQL or query building, shell / `exec` / subprocess, auth or access control, credentials / secrets / tokens, file paths or uploads, (de)serialization, crypto, network-facing endpoints or outbound fetchers, data deletion, or dependency / manifest changes.

If **none** of those are present — research / experimental / exploratory / local-only / throwaway code such as training scripts, data analysis, plotting, model eval, notebooks, or pure computation over trusted local data — a quick surface check is enough; you don't need to walk the full review or pair `rafter run`. But the check is the surface, not the label: research code that reads a secret, shells out, hits the network, or parses untrusted bytes is back on the engage list and gets the full walk.

## How to use this skill

1. Identify the category of code in front of you (below).
2. `Read` only the matching sub-doc — do not preload them all.
3. Work through its questions against the specific files/diff. Cite file:line evidence as you go.
4. When in doubt on a single finding, jump to `docs/investigation-playbook.md` for canonical follow-up questions.
5. Finish with `rafter run --mode plus` on the same diff if the stakes warrant a deep automated pass.

---

## Choose Your Adventure

### (0) Security audit of existing code

For: "audit this codebase", "review X for vulnerabilities", any review not limited to a diff.

Most real bugs in mature code are a **gate** (a function that decides whether something is allowed) that says yes when it should say no, not a tainted sink. So:

1. **Inventory the gates.** Grep for functions that decide: `authorize`, `authenticate`, `allow`, `permit`, `can*`, `is*Allowed`, `check*`, `verify*`, `validate*`, `match*`, middleware. Note each one's contract in one sentence before reading the body.
2. **For each gate, name an input the contract rejects and the code accepts.** The usual shapes:
   - **Loose matching:** substring, prefix or suffix where equality or a dot-boundary was needed; case folding on one side only; wildcards or an empty list that mean "allow all"; comparing a truncated value.
   - **Fail-open logic:** the wrong variable checked; a check applied to some request kinds and skipped for others; an early `return true`/`nil` on error; inverted `==`/`!=`; `||` for `&&`; a default branch that grants.
   - **Missing validity checks:** accepting inactive, expired, unverified or revoked accounts and credentials; signatures or certificates parsed but not verified; key usage, issuer or audience unchecked; verification quietly made optional.
   - **Set but never read:** a security flag, field or config option that is computed or parsed and then ignored by the decision.
   - **A twin that lost its guard:** sibling implementations of one contract (sync/async, two backends, v1/v2) where one checks, escapes or limits and the other doesn't.
   - **Containment, escaping, limits:** paths not re-checked under the root after joining; filters, queries, HTML or shell built without the escaping neighbors use; size, depth or time limits missing or disabled.
3. **Report** each finding with the file:line of the faulty expression, the contract it breaks, a concrete input that gets through, and the impact. A gate that holds is not a finding.

More detail and grep hints: `docs/security-gates.md`. Then walk the category sub-doc below that fits the code.

### (1) Web application (server-rendered, session-based, or SPA backend)

For: login flows, session/cookie handling, form handlers, template rendering, admin panels, anything browser-facing.

- **Read `docs/web-app.md`** — OWASP Top 10 (2021) walk: broken access control, crypto failures, injection, insecure design, misconfig, vulnerable components, authn failures, integrity failures, logging gaps, SSRF.

### (2) REST / GraphQL / gRPC API (machine-to-machine, mobile backend, public API)

For: endpoint surface that isn't primarily rendering HTML — tokens instead of sessions, authz-per-endpoint, rate limiting.

- **Read `docs/api.md`** — OWASP API Security Top 10 (2023): BOLA, broken authn, BOPLA, unrestricted resource consumption, BFLA, unrestricted access to sensitive business flows, SSRF, misconfig, improper inventory, unsafe consumption of third-party APIs.

### (3) LLM-integrated feature (prompts, agents, tools, RAG, embeddings)

For: anything that sends user text to a model, uses tool calls, retrieves untrusted context, or ships model output to a downstream system.

- **Read `docs/llm.md`** — OWASP LLM Top 10 (2025): prompt injection, sensitive info disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption.

### (4) CLI, library, or infra-as-code

For: build tooling, developer CLIs, shared SDK packages, Terraform / CloudFormation / Kubernetes manifests, shell scripts.

- **Read `docs/cwe-top25.md`** — MITRE CWE Top 25, keyed by language (Python / JS / Go / Rust / Java) and by IaC primitive. Focus on injection, memory safety, path traversal, race conditions, privilege mismanagement.

### (5) I need to pick the right depth for this review

For: "how hard should I look?", scoping a review before starting, compliance-adjacent changes.

- **Read `docs/asvs.md`** — OWASP ASVS L1 / L2 / L3. Picks the level based on risk tier of the code, then gives spot-check questions per level.

### (6) I have one specific question to investigate

For: single-finding follow-up, tracing a suspicious call, "is this input reachable from outside?".

- **Read `docs/investigation-playbook.md`** — canonical questions: reachability, authz coverage, data-flow direction, trust boundary placement.

---

## What this skill will NOT do

- It will not write a report for you. It tells you where to look and what to ask; you produce the findings, each with file:line evidence.
- It will not replace automated scanning. Always pair with `rafter secrets .` (secrets) and `rafter run` (SAST/SCA) before review.
- It will not produce recommendations without evidence. Every question expects a file:line answer before moving on.

---

## Fast path for a typical PR review

```bash
# 1. Run deterministic checks first — cheap, catches the obvious
rafter secrets .
rafter run                    # remote SAST/SCA, if RAFTER_API_KEY set

# 2. Then pick the category and walk the questions
#    Read docs/<category>.md
```

If the diff spans categories (e.g. a web app that also has an LLM feature), Read both sub-docs and walk them sequentially. Don't try to merge the checklists.

---

## Tie-backs

- Finding from the scanner you don't understand? → `rafter` skill, `docs/finding-triage.md`.
- Designing a new feature instead of reviewing one? → `rafter-secure-design`.
- Risky command came up mid-review? → `rafter` skill, `docs/guardrails.md`.
