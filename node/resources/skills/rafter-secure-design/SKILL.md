---
name: rafter-secure-design
description: "REQUIRED before writing code for any feature touching auth, payments, credentials, tokens, sessions, file upload, user data, or data deletion. Invoke it, record answers inline in the design doc or PR description, then write the code. Skipping this is how auth bypass, token leakage, and delete-the-wrong-record bugs ship. If the feature touches any of those surfaces and this hasn't run, the design is incomplete — do not proceed to implementation."
version: 0.1.0
allowed-tools: [Read, Glob, Grep]
---

# Rafter Secure Design — Designing It Right The First Time

A designer's skill, not a scanner. The goal is to catch the flaw in the whiteboard sketch, not three weeks later in a PR. Each sub-doc asks the questions a security engineer would ask at kickoff — "which primitive, which boundary, which default?"

> Pair with `rafter-code-review` (structured review *during* PR) and the `rafter` skill (automated detection of what slipped through). This skill is the earliest stage — prevention before the code exists.

## How to use this skill

1. Identify what's being designed (below). If multiple apply, walk them in the order listed — `threat-modeling` last, as a capstone.
2. `Read` only the matching sub-doc. Do not preload them all; pick-and-load keeps the conversation tight.
3. Work through its questions against the *proposed* design. Capture the answer inline (architecture doc, design RFC, PR description). If you can't answer a question, that's a design gap — resolve it before writing code.
4. When the design is stable, run the `threat-modeling` walk to stress-test it.
5. Hand off to `rafter-code-review` during implementation.

---

## Choose Your Adventure

### (1) Authentication & Authorization

For: login, sessions, tokens, service-to-service identity, multi-tenant access, role-based permissions, anything that answers "who is this and what can they do?"

- **Read `docs/auth.md`** — Primitive selection (session vs. JWT vs. OAuth), authZ model (RBAC / ABAC / ReBAC), token lifetime + revocation, MFA surface, service identity. Questions phrased as "pick one and say why".

### (2) Data storage — at rest, in transit, PII

For: database schema design, file storage, caches, logs, anything that decides *where* sensitive data lives and *who* holds the keys.

- **Read `docs/data-storage.md`** — Classification (what is PII/PHI/PCI here?), encryption choices, key management, retention + deletion, backup scope, tenancy isolation. Anti-patterns: encrypt-everything-as-a-religion, homegrown crypto, keys next to data.

### (3) API surface — REST / GraphQL / gRPC / webhooks

For: designing new endpoints, shaping request/response schemas, choosing between resource styles, rate limiting, versioning, exposing internal services.

- **Read `docs/api-design.md`** — Resource modeling for authz (is this endpoint BOLA-shaped?), write-vs-read boundaries, idempotency, rate-limit keys, error taxonomy (what leaks?), webhook delivery + replay.

### (4) Ingestion — inputs, uploads, parsers, user content

For: anything that accepts user-controlled bytes: form posts, file uploads, webhook payloads, imports, content rendering, search indexing.

- **Read `docs/ingestion.md`** — Trust boundaries (where does untrusted become trusted?), parser choice (safe default vs. fast), size + shape limits, content sniffing, SSRF-adjacent fetchers, deserialization surface.

### (5) Deployment — topology, network, secrets, runtime

For: infra plan, service boundaries, secret distribution, egress policy, CI/CD pipeline, build-time vs. run-time separation.

- **Read `docs/deployment.md`** — Network zones, least-privilege IAM, secret distribution (not "put it in env"), build provenance, runtime posture (read-only FS, non-root), multi-region / DR assumptions.

### (6) Dependencies & supply chain

For: picking a library, adopting a framework, pulling a container base image, introducing a new SaaS, wiring a postinstall script.

- **Read `docs/dependencies.md`** — Pick-vs-write, maintenance signal, install-time execution, pinning + lockfiles, SBOM + SCA hooks, vendoring vs. registry, typosquat / slopsquat checks.

### (7) Threat model — STRIDE walk of the full design

For: the capstone pass *after* the above decisions are drafted. Also good for any greenfield service review.

- **Read `docs/threat-modeling.md`** — STRIDE applied to the specific design (not the generic checklist). Trust boundaries, data-flow diagrams as prose, abuse cases, negative-space questions ("what did we implicitly assume?").

### (8) Which standards / frameworks should bound this?

For: scoping compliance, picking a baseline, answering "how much is enough?"

- **Read `docs/standards-pointers.md`** — Pointers to ASVS (app sec), NIST SSDF (lifecycle), CSA CCM (cloud), OWASP SAMM (program maturity), plus the cheap-and-fast subset to start with.

---

## What this skill will NOT do

- It will not write the design document for you. It walks *your* draft through structured questions.
- It will not replace a dedicated threat-modeling session with the team. It prepares you for one.
- It will not produce a checklist to mechanically tick through. Every question expects a deliberate answer; "N/A because..." is fine, "skip" is not.

---

## Fast path at feature kickoff

```text
1. Sketch the design (one-pager, box-and-arrow).
2. Walk the sub-doc that matches the riskiest choice you're about to make.
3. Walk threat-modeling.md as a capstone.
4. Write the decisions into the design doc as "decided / rejected / why".
5. Start coding — and loop in `rafter-code-review` when the PR lands.
```

If you're revisiting an existing design (refactor, migration), same flow: treat the current shape as "proposed" and walk the relevant sub-docs as questions.

---

## Tie-backs

- Ready to review the code that implements the design? → `rafter-code-review`.
- Implementation landed, need automated checks? → `rafter` skill, `rafter run` / `rafter secrets`.
- Risky command came up mid-design (spike, data migration)? → `rafter` skill, `docs/guardrails.md`.
- Have a specific finding from a scan? → `rafter` skill, `docs/finding-triage.md`.
