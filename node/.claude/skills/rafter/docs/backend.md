# Rafter Remote Backend — Fast vs Plus

When to reach for the Rafter API instead of (or in addition to) the local scanner, and what to expect in terms of depth, cost, and latency.

## Local vs Remote — Which First?

| Question | Answer |
|---|---|
| "Are there leaked secrets in this diff/repo?" | **Local first** (`rafter scan local .`). Deterministic, offline, sub-second. |
| "Any SAST issues — SQLi, XSS, insecure deserialization, weak crypto?" | **Remote** (`rafter run`). Needs the backend's analyzers. |
| "Are my dependencies vulnerable (CVEs)?" | **Remote** — SCA runs server-side. |
| "I'm in a CI pipeline without a `RAFTER_API_KEY`" | **Local only**. Don't fail the build on a missing key. |
| "I need a deep, agent-driven review with hypotheses and cross-file reasoning" | **Remote plus** (`--mode plus`). |

Rule of thumb: local is a guardrail; remote is a review.

## Setup

```bash
export RAFTER_API_KEY="..."
# or
echo "RAFTER_API_KEY=..." >> .env
```

Private GitHub repos need `RAFTER_GITHUB_TOKEN` (or `--github-token`) so the backend can clone the ref.

Check quota with `rafter usage` before firing a batch of scans.

If the key is missing, `rafter run` exits with a clear error — **do not** prompt the user mid-flow; recommend `rafter scan local` and move on.

## Modes

### `--mode fast` (default)

Deterministic SAST + SCA + secret detection via the analyzer pipeline. Same input → same output. Good for CI gates and PR checks.

- **Latency**: typically seconds to a couple of minutes, depending on repo size.
- **Cost**: lowest per-scan. Free tier covers casual use. See `rafter brief pricing`.
- **Output**: stable JSON; findings carry `ruleId`, `severity`, `file`, `line`, `confidence`.

### `--mode plus`

Agentic deep-dive pass on top of fast mode: cross-file reasoning, data-flow hypotheses, design-level flags. Non-deterministic but reproducible in aggregate.

- **Latency**: minutes (larger repos can take longer).
- **Cost**: higher per-scan. Use when fast mode has flagged something worth triaging deeply, or on a release candidate.
- **Output**: same JSON shape as fast mode, plus narrative `notes` and higher-confidence chains.

Recommended flow:
1. `rafter scan local .` — secrets guardrail in dev loop.
2. `rafter run --mode fast` — every PR in CI.
3. `rafter run --mode plus` — before release, or when a fast-mode finding needs deeper context.

## Authentication & Data Handling

- The backend clones the specified ref, runs analysis, returns results, and **deletes the code**. No long-term retention of source.
- Scan artifacts (findings JSON, reports) are retained so `rafter get <scan-id>` works after the fact.
- Self-hosted / VPC deployments are an enterprise option; see rafter.so.

## Output Contract

Every remote scan returns:

```jsonc
{
  "scanId": "scan_...",
  "status": "completed" | "running" | "failed",
  "mode": "fast" | "plus",
  "findings": [
    { "ruleId": "...", "severity": "critical|high|medium|low|info",
      "file": "...", "line": 42, "confidence": "high|medium|low",
      "title": "...", "description": "...", "recommendation": "..." }
  ],
  "summary": { "critical": 0, "high": 2, "medium": 5, "low": 3 }
}
```

See `shared-docs/CLI_SPEC.md` for the full schema. See `docs/finding-triage.md` for how to read a finding.

## Async / Non-Blocking Scans

`rafter run --skip-interactive` returns the `scan_id` immediately. Poll later:

```bash
SCAN=$(rafter run --skip-interactive --format json | jq -r .scanId)
# ... do other work ...
rafter get "$SCAN" --format json
```

This is the pattern for long-running CI jobs and background agent loops.

## Latency & Cost Expectations (rule of thumb)

| Repo size | fast | plus |
|---|---|---|
| < 5k LOC | ~10–30s | ~1–3 min |
| 5k – 50k LOC | ~30s – 2 min | ~3–10 min |
| 50k+ LOC | minutes | tens of minutes |

Plus mode's latency scales with "how much there is to reason about", not strictly LOC. Don't block an agent turn on plus; use `--skip-interactive` and poll.

## When NOT to use the remote backend

- You're iterating locally on a tiny diff — local scan + lint is faster.
- You have no network / no API key — stay local.
- You've already run the same scan ten minutes ago with no code changes — cache the last result instead of re-scanning.
