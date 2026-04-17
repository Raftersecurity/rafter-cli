# Finding Triage — Reading a Rafter Finding

How to go from a raw Rafter finding to a decision: **fix now**, **fix later**, **suppress**, or **escalate**.

## Anatomy of a Finding

Every finding (local or remote) has this shape:

```jsonc
{
  "ruleId": "HARDCODED_API_KEY",       // stable ID — use in overrides / baselines
  "severity": "critical",               // critical | high | medium | low | info
  "confidence": "high",                 // high | medium | low
  "file": "src/config/prod.ts",
  "line": 42,
  "title": "Hardcoded API key",
  "description": "...",
  "recommendation": "...",              // suggested fix, when available
  "evidence": "API_KEY = \"sk-...\""    // snippet (may be redacted)
}
```

Three fields do most of the work: **severity**, **confidence**, and **ruleId**.

## Decision Flow

1. **Severity `critical` + confidence `high`** → fix before merge. Non-negotiable. Examples: hardcoded production secrets, SQL injection, RCE via unsafe deserialization.
2. **Severity `high` + confidence `high`** → fix this PR unless there's a specific reason not to (document it in the baseline).
3. **`high` + confidence `medium/low`** → investigate. Often a real issue in a weird codepath; sometimes a pattern false-positive.
4. **`medium`** → fix within a reasonable window; batch with related work.
5. **`low` / `info`** → style/hygiene. Suppress at the rule level if consistently noisy.

Confidence matters: a `high`-severity, `low`-confidence finding is a hypothesis, not a verdict. Confirm by reading the evidence + surrounding code before acting.

## Common Rule Categories

| Rule family | What it means | First move |
|---|---|---|
| `HARDCODED_*` (secrets, tokens, keys) | A literal credential is in source | Rotate the credential, then remove from code & git history |
| `SQL_INJECTION`, `COMMAND_INJECTION` | Unsanitized input reaches a sink | Parameterize / use a safe API; fix at the source, not by escaping at the sink |
| `INSECURE_DESERIALIZATION` | `pickle`, `yaml.load`, `Marshal`, untrusted JSON → `eval` | Switch to safe loader; never deserialize untrusted data into native objects |
| `WEAK_CRYPTO` (`MD5`, `SHA1`, `DES`, `ECB`) | Algorithm/mode doesn't meet modern threat model | Swap algorithm; check for backwards-compat constraints |
| `PATH_TRAVERSAL` | User input flows into filesystem path | Canonicalize + verify within allow-rooted dir |
| `SSRF` | User input controls outbound URL | Allowlist hosts; resolve IPs and block internal ranges |
| `DEPENDENCY_CVE` (SCA) | Transitive/direct dep has known CVE | Bump to a patched version; if none, check if the vulnerable code path is reachable |

## Before Rotating or Nuking Something

If the finding is a leaked secret that was committed:
1. **Rotate first.** Assume the secret is compromised the moment it touched git history.
2. Remove from history if the repo is private *and* short-lived; otherwise rotation is the real fix.
3. Add the pattern to pre-commit (`rafter agent install-hook`) so it doesn't happen again.

## Suppression — When It's OK

Suppress only when the finding is a real false positive *for this context*, with a written reason. Two mechanisms:

- **Inline**: `// rafter-ignore: HARDCODED_API_KEY — test fixture, not a real key`
- **Baseline**: `rafter agent baseline` snapshots current findings; only *new* findings fail future scans. Good for adopting Rafter on a legacy codebase without a big bang.

Never suppress by:
- Commenting out the rule globally.
- Broadening an allow-pattern beyond the specific file/context.
- Deleting the scan step from CI.

## Escalation

Escalate a finding (to security team, or back to the user) when:
- It implicates production credentials or customer data.
- It's a design-level issue the local fix can't address (e.g. "the auth model is wrong").
- The fix requires coordination across services or a rotation playbook.

Provide `scanId`, `ruleId`, file + line, and the evidence snippet. Exit code + JSON makes this a copy-paste to a ticket.

## Tie-Backs

- Want depth on a single finding? Rerun with `--mode plus` (see `docs/backend.md`).
- Want to prevent the class of finding? See `docs/shift-left.md` → `rafter-secure-design`.
- Want structured review around the finding? See `docs/shift-left.md` → `rafter-code-review`.
