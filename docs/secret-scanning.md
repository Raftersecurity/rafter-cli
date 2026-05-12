# Secret Scanning

Fast, reliable, and deterministic for a given CLI version. 21+ built-in patterns covering
AWS, GitHub, Google, Slack, Stripe, Twilio, database connection strings, JWTs, private keys,
npm/PyPI tokens, and generic API keys. Same inputs always produce the same findings.

No account required. No data leaves your machine.

## Commands

```sh
rafter secrets .              # scan directory
rafter secrets ./config.js    # scan specific file
rafter secrets --staged       # scan git staged files only
rafter secrets --diff HEAD~1  # scan files changed since a git ref
rafter secrets --history      # scan full git history (requires betterleaks engine)
rafter secrets --json         # structured output
rafter secrets --quiet        # silent unless secrets found (CI-friendly)
```

Exit code `1` if secrets found, `0` if clean.

## Structured output (`--json`)

```json
[
  {
    "file": "/path/to/config.js",
    "matches": [
      {
        "pattern": { "name": "AWS Access Key", "severity": "critical" },
        "line": 42,
        "redacted": "AKIA************MPLE"
      }
    ]
  }
]
```

Raw secret values are never included in output. Pipe to `jq`, feed to CI gates, or hand to any tool that reads JSON.

## Engine selection

Rafter uses a dual-engine approach:

1. **Betterleaks** (preferred when installed) — the gitleaks successor by the original gitleaks authors. More patterns. Install via `rafter agent init --all`.
2. **Built-in regex scanner** — 21+ patterns, zero dependencies, works offline. Used as fallback or when explicitly selected.

Override with `--engine betterleaks|patterns|auto`.

## Custom patterns

Define your own secret patterns in `.rafter.yml`:

```yaml
# .rafter.yml
scan:
  custom_patterns:
    - name: "Internal API Key"
      regex: "INTERNAL_[A-Z0-9]{32}"
      severity: critical
      description: "Detects internal service API keys"
    - name: "Acme Corp Token"
      regex: "acme_live_[a-zA-Z0-9]{40}"
      severity: high
```

Custom patterns merge with built-in patterns at scan time and appear in all output formats.
