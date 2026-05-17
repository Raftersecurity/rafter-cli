# Feature-Finished Checklist

What to verify before declaring a security-relevant feature "done". Items are derived from a curated list of common pre-prod oversights — each is cheap to check, expensive to skip.

For the *why* and the *how* of each item, read the matching section in `rafter-secure-design/docs/operational-resilience.md`. This file is the gate; that file is the reasoning.

## How to use

- Paste the relevant items into the PR description as checkboxes.
- An item is checked when there's evidence (file:line, ticket, dashboard URL) — not just a developer assertion.
- "N/A because <reason>" is a valid answer; "skip" is not. Items below carry the curated numbering so a PR can reference `(item 12)` etc. unambiguously.

---

## Security-checklist items

- [ ] **(6) Hardcoded secrets in deployment scripts.** Diff has no literal secrets in CI YAML, Dockerfile, or Terraform variables. Deploy auth uses workload identity / short-lived federation. See operational-resilience §6.
- [ ] **(10) Database backups are restore-tested.** If the feature touches a new DB or new table: a scheduled restore-test job covers it (or an existing job already does, by name). See operational-resilience §10.
- [ ] **(12) Rate limiting at every public boundary.** New public endpoints have a rate-limit key + threshold + 429 handling. See operational-resilience §12.
- [ ] **(14) Error alerting.** New failure modes have a paging signal, an owner, and a runbook reference. See operational-resilience §14.
- [ ] **(15) Multi-step writes are transactional or idempotent.** Every new write that spans more than one row, table, or system has a transaction, saga, or idempotency key — and that's stated, not assumed. See operational-resilience §15.
- [ ] **(19) Third-party API fallback.** New external dep on a hot path has a stated degraded-mode plan. See operational-resilience §19.
- [ ] **(20) Logs ship off-host.** New log surface goes to a separately-trusted destination, not just local disk. See operational-resilience §20.
- [ ] **(21) Circuit breaker on external calls.** New outbound call sites have a circuit breaker with named open-threshold and fallback. See operational-resilience §21.
- [ ] **(23) Connection timeouts on outbound HTTP.** Every new outbound HTTP call sets connect + total timeout explicitly (no library defaults). See operational-resilience §23.
- [ ] **(25) Runbook for the feature's failure modes.** If this feature introduces a paging signal (item 14), a runbook is reachable during an incident and was exercised at least once. See operational-resilience §25.

---

## Tie-backs

- Designing the feature, not finishing it? → `rafter-secure-design` skill, `docs/operational-resilience.md`.
- Reviewing the diff for the absence of these? → `rafter-code-review` skill (the Tie-backs section points back here).
- Want automated checks for what's machine-detectable? → `rafter run --mode plus` on the diff. (Timeouts, missing rate limits, and missing transactions are partially detectable; the human-judgment items are not.)
