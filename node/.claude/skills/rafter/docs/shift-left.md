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

## `rafter-code-review` (landed)

Use during code review — your own or an AI's. A CYOA router into OWASP / MITRE / ASVS walkthroughs phrased as *questions*, not as monolithic audits. It's the *analysis* counterpart to automated scanning.

Pick the category that matches the code in front of you:

- **Web app** → `rafter-code-review/docs/web-app.md` (OWASP Top 10 2021).
- **REST / GraphQL / gRPC API** → `rafter-code-review/docs/api.md` (OWASP API Top 10 2023).
- **LLM-integrated feature** → `rafter-code-review/docs/llm.md` (OWASP LLM Top 10 2025).
- **CLI / library / IaC** → `rafter-code-review/docs/cwe-top25.md` (MITRE CWE Top 25, keyed by language).
- **Need to pick review depth** → `rafter-code-review/docs/asvs.md` (ASVS L1/L2/L3 selection + spot-checks).
- **Single suspicious finding to chase** → `rafter-code-review/docs/investigation-playbook.md`.

Start at `rafter-code-review/SKILL.md` — it's a router; Read only the one sub-doc you need so you don't flood context.

Pair with `rafter run --mode plus` when you want both a human-style walkthrough and the backend's deep pass on the same diff.

## When to use which (cheat sheet)

- Designing a new service → **secure-design**.
- Reviewing a teammate's PR by eye → **code-review**.
- CI gate / pre-push / scheduled scan → **rafter** (this skill), `rafter run` / `rafter scan local`.
- "I have a finding, now what?" → **rafter**, `docs/finding-triage.md`.
- "I have a risky command, is it safe?" → **rafter**, `docs/guardrails.md`.

Do not duplicate. If a sibling skill already owns the topic, Read it and stop — don't re-derive the checklist here.

## Status

- `rafter-code-review` — **landed** (rf-z7j). Ships alongside this skill; invoke directly.
- `rafter-secure-design` — **landed** (rf-bcr). Ships alongside this skill; invoke directly. Router skill with sub-docs for auth, data storage, API design, ingestion, deployment, dependencies, threat modeling, and standards pointers.

Both are installed — prefer invoking them directly for structured output over re-deriving checklists here.
