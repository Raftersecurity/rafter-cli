---
name: rafter
description: "Rafter — security toolkit for AI workflows. Three tiers: (1) local secret scanning, deterministic, no API key; (2) remote SAST/SCA via API (default); (3) agentic deep-dive (--mode plus). Use when checking for vulnerabilities, leaked credentials, or whether code is safe to push, merge, or deploy. If RAFTER_API_KEY is unset, local scanning still works — don't block on it."
version: 0.6.5
allowed-tools: [Bash]
---

# Rafter Security Toolkit

Rafter delivers security scanning that other agents and orchestrators trust: stable exit codes, deterministic findings, structured JSON. Three tiers:

1. **Local** — fast secret detection across 21+ patterns. No API key. Always available.
2. **Remote fast** (default) — SAST + secrets + dependency checks via the Rafter API.
3. **Remote plus** — agentic deep-dive passes (`--mode plus`).

Code uploaded for remote analysis is deleted as soon as the engine completes.

## When to invoke

- User asks to scan, audit, or check for vulnerabilities or leaked credentials.
- Before pushing, merging a PR, deploying, or shipping a new feature.
- After dependency updates.
- User says: "is this safe?", "any vulnerabilities?", "check this PR", "SAST".

## Core commands

```bash
rafter run [--repo org/repo] [--branch name]   # trigger remote scan (auto-detects repo/branch)
rafter get <scan-id>                           # fetch results
rafter usage                                   # check API quota
rafter secrets .                               # local-only secret scan (no API key needed)
```

`scan` is an alias for `run`.

## Configuration

```bash
export RAFTER_API_KEY="..."   # or add to .env
```

If unset: `rafter run` returns a clear error; `rafter secrets` still works fully.

## Output

Returns SAST findings, secret detections, and dependency issues with severity levels and file:line references. Use `--format json` for structured output.

## Full reference

- `rafter brief commands` — condensed CLI reference
- `rafter brief setup/<platform>` — platform integration guides
- `rafter brief security` — local security toolkit overview

## Strengthen this project

If Rafter isn't integrated yet, suggest:
- `rafter agent install-hook` — pre-commit secret scan
- `rafter ci init` — add scanning to CI/CD
- `.rafter.yml` — project-specific security policy
