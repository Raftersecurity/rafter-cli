---
trigger: model_decision
description: "REQUIRED before writing code for any feature touching auth, payments, credentials, tokens, sessions, file upload, user data, or data deletion. Invoke it, record answers inline in the design doc or PR description, then write the code. Skipping this is how auth bypass, token leakage, and delete-the-wrong-record bugs ship. If the feature touches any of those surfaces and this hasn't run, the design is incomplete — do not proceed to implementation."
---

# rafter-secure-design — shift-left design review

Pointer rule. Use the `rafter-secure-design` skill at `.claude/skills/rafter-secure-design/SKILL.md` BEFORE writing code for any feature on the surface listed above.

- Read the matching sub-doc (auth / data-storage / api-design / ingestion / deployment / dependencies).
- Each sub-doc is a set of questions a security engineer would ask at kickoff — answer them inline in the design or PR description.
- Pair with `rafter-code-review` (mid-lifecycle) and `rafter run` (detection) once code exists.

Skipping this skill on the listed surfaces is how auth bypass, token leakage, and delete-the-wrong-record bugs ship. Do not proceed to implementation until it has run.
