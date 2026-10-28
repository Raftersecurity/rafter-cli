---
name: rafter-secure-design
description: "REQUIRED before writing code for any feature touching auth, payments, credentials, tokens, sessions, file upload, user data, or data deletion. Invoke it, record answers inline in the design doc or PR description, then write the code. Skipping this is how auth bypass, token leakage, and delete-the-wrong-record bugs ship. If the feature touches any of those surfaces and this hasn't run, the design is incomplete — do not proceed to implementation."
alwaysApply: false
---

# rafter-secure-design — shift-left design review

Pointer rule for the `rafter-secure-design` skill. Use it BEFORE writing code for any feature on the surface listed above. (The full skill — with a sub-doc per category — installs under `.claude/skills/rafter-secure-design/` only for Claude Code, Codex, and OpenClaw; this rule is the condensed equivalent here.)

- Reason through the matching category by hand: auth, data storage, API design, ingestion, deployment, dependencies. Each is a set of questions a security engineer would ask at kickoff — answer them inline in the design or PR description.
- Pair with `rafter-code-review` (mid-lifecycle) and `rafter run` (detection) once code exists.

Skipping this on the listed surfaces is how auth bypass, token leakage, and delete-the-wrong-record bugs ship. Do not proceed to implementation until it has run.
