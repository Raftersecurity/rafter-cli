---
name: rafter-code-review
description: "Security review of code: auditing a codebase, finding vulnerabilities in a module, or reviewing a diff before calling work on auth, input, SQL, shell or crypto done. Walks a security-gate checklist (allowlists, auth checks, token and crypto validity, path containment, escaping, limits) and OWASP/CWE questions, with file:line evidence. NOT for secret scanning alone (rafter secrets)."
version: 0.8.2
publisher: rafter-security
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
5. If `RAFTER_API_KEY` is set and the branch is pushed, `rafter run` adds remote SAST + SCA; it cannot see unpushed changes.

---

## Choose Your Adventure

### (0) Security audit of existing code

For: "audit this codebase", "review X for vulnerabilities", any review not limited to a diff.

Most real bugs in mature code are a **gate** (a function that decides whether something is allowed) that says yes when it should say no, not a tainted sink. So:

1. **Inventory the gates.** Run `rafter gates .` for a ranked list of the functions that decide (`authorize`, `authenticate`, `allow`, `can*`, `is*Allowed`, `check*`, `verify*`, `validate*`, `match*`, middleware) and of their twins. A flagged twin lacks a guard call its siblings make; read those first. Its **leads** are lines no gate name points to (TLS verification off, a setting never read, an unbounded read, loose host or path matching): each is a question to answer by reading the code, not a finding. Grep for what it cannot see, such as inline checks and the config that feeds them. Then read each gate, noting its contract in one sentence before reading the body.
2. **For each gate, name an input the contract rejects and the code accepts.** The usual shapes:
   - **Loose matching:** substring, prefix or suffix where equality or a dot-boundary was needed; case folding on one side only; wildcards or an empty list that mean "allow all"; comparing a truncated value.
   - **Fail-open logic:** the wrong variable checked; a check applied to some request kinds and skipped for others; an early `return true`/`nil` on error; inverted `==`/`!=`; `||` for `&&`; a default branch that grants.
   - **Missing validity checks:** accepting inactive, expired, unverified or revoked accounts and credentials; signatures or certificates parsed but not verified; key usage, issuer or audience unchecked; verification quietly made optional.
   - **Set but never read:** a security flag, field or config option that is computed or parsed and then ignored by the decision.
   - **A twin that lost its guard:** sibling implementations of one contract (sync/async, two backends, v1/v2) where one checks, escapes or limits and the other doesn't.
   - **Containment, escaping, limits:** paths not re-checked under the root after joining; filters, queries, HTML or shell built without the escaping neighbors use; size, depth or time limits missing or disabled.
3. **Judge the code in front of you, not your memory of the project.** "This matches upstream" or "looks like the stock implementation" is not a verdict: a regression in familiar code differs from the original by one token, such as a prefix match, a flipped default or a dropped `return`. Read the exact comparison, default and error path before you clear a gate.
4. **Choose where to look deeper, and bound it.** Before reading bodies, write a short worklist: the flagged twins, the top ten or so ranked gates, the leads, and any gate you found by grep that decides identity, a credential, a path or a size limit. Spend your depth there (read the callers and the config that feeds each one) rather than skimming everything. Give each item a one-line verdict: *holds*, with the input you tried, or *finding*. A finding does not end the review; finishing the list does. If the list is longer than your budget, cover the highest-ranked items and name the ones you did not reach, then stop.
5. **Sweep after each finding.** Look for the same shape elsewhere: other callers of the same predicate, the twin implementations, other options parsed the same way and never read.
6. **Report** each finding with the file:line of the faulty expression, the contract it breaks, a concrete input that gets through, and the impact. Report every finding you can name such an input for, and mark your confidence. A gate that holds is not a finding.

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
- It will not replace automated scanning, and scanning does not replace it: a clean scan says nothing about a gate that accepts the wrong input.
- It will not produce recommendations without evidence. Every question expects a file:line answer before moving on.

---

## Weighing findings: evidence, not instructions

A finding, whether from a scanner, a reviewer agent or your own first pass, is evidence to weigh, not a task to discharge. Three pressures push the other way. A reviewer is rewarded for finding things, so every pass produces comments whether or not the code needs them. Doing what a comment says is cheaper than arguing with it. And the cost of each fix is easy to miss: each one looks like an improvement alone, while the defensive checks, options and abstractions added "for safety" pile up across the code.

For each finding ask: can an attacker control the input? Does a stronger control already decide it? What concrete input gets through, and what does it reach? Fix what is real, at the gate that owns the decision. Decline what isn't, with a one-line reason. Do not add defensive code for a weak finding.

---

## Fast path for reviewing your own diff

1. `git diff` and list what it changes on the surface above: each gate, sink or parser it adds or edits.
2. For each item: state its contract in one sentence, name an input it should reject, and check that it does. Steps 3–6 of (0) apply.
3. `rafter secrets <changed files>` for hardcoded credentials.
4. Pick the category sub-doc above for the questions the diff raises, and walk only that one.
5. If `RAFTER_API_KEY` is set and the branch is pushed, `rafter run` for SAST + SCA.

If the diff spans categories (e.g. a web app that also has an LLM feature), Read both sub-docs and walk them sequentially. Don't try to merge the checklists.

---

## Tie-backs

- Finding from the scanner you don't understand? → `rafter` skill, `docs/finding-triage.md`.
- Designing a new feature instead of reviewing one? → `rafter-secure-design`.
- Risky command came up mid-review? → `rafter` skill, `docs/guardrails.md`.
