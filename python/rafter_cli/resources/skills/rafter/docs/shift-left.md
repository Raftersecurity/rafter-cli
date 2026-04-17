# Shift-Left — Secure Design & Code Review Skills

`rafter` (this skill) handles **detection**: scanners, hooks, risk classifiers. Two sibling skills cover the earlier stages of the lifecycle — use them when prevention or structured review is more valuable than another scan pass.

## Decision Tree

| You're trying to … | Reach for |
|---|---|
| Write code that **doesn't have the flaw in the first place** (design phase, picking primitives, shaping APIs) | `rafter-secure-design` |
| **Review existing code** against OWASP Top 10 / MITRE ATT&CK / ASVS with a structured walkthrough | `rafter-code-review` |
| Find concrete bugs / leaks / CVEs automatically | stay in this skill — see branch (a) in SKILL.md |

The three skills compose: design well (secure-design) → write it → review it (code-review) → detect what slipped through (rafter scan + guardrails).

## `rafter-secure-design` (filed as rf-bcr)

Use at feature kickoff or during architecture review, *before* code exists. It's a CYOA over design decisions:

- Authn / authz primitives: which to pick, which to refuse (e.g. homegrown JWT signing).
- Input boundaries: where to validate, where to escape, where to parameterize.
- Secrets handling: storage, rotation, scoping of least-privilege credentials.
- Data-in-transit / data-at-rest defaults per language/framework.
- Threat modeling prompts: STRIDE-style walks you can run with an agent.

Invoke it by name in platforms that auto-trigger skills, or:
```bash
rafter brief shift-left      # this doc
# and then load the sibling:
#   Read skills/rafter-secure-design/SKILL.md
```

## `rafter-code-review` (filed as rf-z7j)

Use during code review — your own or an AI's. Structured walkthroughs driven by OWASP / MITRE / ASVS categories. It's the *analysis* counterpart to automated scanning:

- OWASP Top 10 pass: one branch per risk class.
- OWASP ASVS level 1 / 2 / 3 checklists, depending on risk tier of the code.
- MITRE ATT&CK framing for untrusted-input paths.
- Language-specific pitfalls (Python deserialization, JS prototype pollution, Go goroutine leaks, etc.).

Pair it with `rafter run --mode plus` when you want both a human-style walkthrough and the backend's deep pass on the same diff.

## When to use which (cheat sheet)

- Designing a new service → **secure-design**.
- Reviewing a teammate's PR by eye → **code-review**.
- CI gate / pre-push / scheduled scan → **rafter** (this skill), `rafter run` / `rafter scan local`.
- "I have a finding, now what?" → **rafter**, `docs/finding-triage.md`.
- "I have a risky command, is it safe?" → **rafter**, `docs/guardrails.md`.

Do not duplicate. If a sibling skill already owns the topic, Read it and stop — don't re-derive the checklist here.

## Status

Both sibling skills are tracked separately:
- `rafter-secure-design` — bead `rf-bcr` (new skill, shift-left design)
- `rafter-code-review` — bead `rf-z7j` (new skill, OWASP/ASVS code review)

If they're not yet installed on this machine, you can still use the patterns above as prompts to an agent; once they land, prefer invoking them directly for structured output.
