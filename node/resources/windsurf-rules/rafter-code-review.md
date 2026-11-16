---
trigger: model_decision
description: "Use for a security review of code: auditing a codebase, finding vulnerabilities in a module, or reviewing a diff before calling work on auth, input, SQL, shell or crypto done. Walks a security-gate checklist (allowlists, auth checks, token and crypto validity, path containment, escaping, limits) and OWASP/CWE questions, with file:line evidence. NOT for secret scanning alone (rafter secrets)."
---

# rafter-code-review — structured pre-merge review

Pointer rule for the `rafter-code-review` skill. Use it BEFORE declaring done on any diff touching the surface listed above. (The full skill — with a sub-doc per category — installs as its own skill directory only for Claude Code (`.claude/skills/rafter-code-review/`) and for Codex and Gemini (`.agents/skills/rafter-code-review/`); this rule is the condensed equivalent here.)

- Match the code to a category and walk its questions by hand: web app (OWASP Top 10), REST/GraphQL/gRPC API (OWASP API Top 10), LLM-integrated feature (OWASP LLM Top 10), CLI/library/IaC (MITRE CWE Top 25).
- Judge the code in front of you, not your memory of the project: "matches upstream" is not a verdict. Give each gate a verdict; the review ends when the list does, not at the first finding.
- If the branch is pushed and `RAFTER_API_KEY` is set, `rafter run` adds the backend scan. It cannot see unpushed changes and does not replace this review.

Security-relevant code is not done until you have reviewed it yourself.
