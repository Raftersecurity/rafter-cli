# Exit Codes (Stable Contract)

[← Back to README](../README.md)

Exit codes are part of Rafter's output contract — CI pipelines and orchestrators can rely on these semantics across versions. See [`shared-docs/CLI_SPEC.md`](../shared-docs/CLI_SPEC.md) for the canonical specification.

## Local secret scan (`rafter secrets`)

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Clean — no secrets detected | Proceed |
| 1 | Findings — one or more secrets detected | Stop / review |
| 2 | Runtime error — path not found, not a git repo, invalid ref | Fix input and retry |

## Remote commands (`rafter run` / `rafter get` / `rafter usage`)

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success — scan completed or results retrieved | Proceed |
| 1 | General error | Investigate |
| 2 | Scan not found (HTTP 404) | Check scan ID |
| 3 | Quota exhausted (HTTP 429 or 403 scan-mode limit) | Back off / alert |
| 4 | Insufficient scope / forbidden (HTTP 403) | Check API key permissions |

## `rafter docs`

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (read failure, URL fetch failure with no cache) |
| 2 | Selector did not match any configured doc |
| 3 | No docs configured in `.rafter.yml` |

## See also

- [README](../README.md) — top-level overview
- [`shared-docs/CLI_SPEC.md`](../shared-docs/CLI_SPEC.md) — full output contract
