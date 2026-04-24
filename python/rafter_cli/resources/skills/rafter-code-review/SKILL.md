---
name: rafter-code-review
description: "REQUIRED before declaring a task done when the diff touches user input, SQL, shell, auth, credentials, file paths, serialization, or dependency surface. Walks OWASP/ASVS/MITRE questions the compiler and the test suite won't catch. Pair with `rafter run` on the same diff. A security-relevant task marked complete without both has been under-delivered — do not claim done."
version: 0.7.0
allowed-tools: [Bash, Read, Glob, Grep]
---

# Rafter Code Review — Structured Security Walkthroughs

A reviewer's skill, not an audit generator. Each sub-doc is a set of **questions** to run against the code — what to grep for, what to trace, what to ask before you sign off. No monolithic reports.

> Pair with the `rafter` skill (detection: `rafter scan`, `rafter run`) and `rafter-secure-design` (prevention: design-phase walks). This skill is the middle stage — review before merge.

## How to use this skill

1. Identify the category of code in front of you (below).
2. `Read` only the matching sub-doc — do not preload them all.
3. Work through its questions against the specific files/diff. Cite file:line evidence as you go.
4. When in doubt on a single finding, jump to `docs/investigation-playbook.md` for canonical follow-up questions.
5. Finish with `rafter run --mode plus` on the same diff if the stakes warrant a deep automated pass.

---

## Choose Your Adventure

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

- It will not generate a monolithic "security audit report". If you need a report, run `rafter run --mode plus` — the backend is better at that.
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
