---
trigger: model_decision
description: "REQUIRED before declaring a task done when the diff touches user input, SQL, shell, auth, credentials, file paths, serialization, or dependency surface. Walks OWASP/ASVS/MITRE questions the compiler and the test suite won't catch. Pair with `rafter run` on the same diff. A security-relevant task marked complete without both has been under-delivered — do not claim done."
---

# rafter-code-review — structured pre-merge review

Pointer rule for the `rafter-code-review` skill. Use it BEFORE declaring done on any diff touching the surface listed above. (The full skill — with a sub-doc per category — installs under `.claude/skills/rafter-code-review/` only for Claude Code, Codex, and OpenClaw; this rule is the condensed equivalent here.)

- Match the code to a category and walk its questions by hand: web app (OWASP Top 10), REST/GraphQL/gRPC API (OWASP API Top 10), LLM-integrated feature (OWASP LLM Top 10), CLI/library/IaC (MITRE CWE Top 25).
- Pair with `rafter run` on the same diff — the scanner finds known-bad patterns, this skill asks the questions patterns miss.

A security-relevant task marked complete without BOTH the walkthrough and a `rafter run` pass has been under-delivered. Do not claim done until both are recorded.
