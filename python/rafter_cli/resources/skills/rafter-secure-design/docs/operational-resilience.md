# Operational Resilience — Design Questions

The class of failures that ship in features which "work in dev" — no rate limit, no backup verified, no alerting, no timeout. Each is a security defect because each gives an attacker (or an outage, or a clumsy migration) an unrecovered pathway through your system.

Pair with `deployment.md` (where the runtime posture is set) and `dependencies.md` (where the external surface is chosen). The items below carry Rome's curated numbering so they can be referenced in PR templates and feature-finished checklists.

---

## (6) Secrets in deployment scripts

**Why it matters:** secrets baked into CI YAML, Dockerfiles, or Terraform variables leak through CI logs, repo history, build artifacts, and pipeline-access audits. The repo doesn't need to be public — every contributor with read access has the secret forever, and rotation requires re-issuing across every fork and forked log.

- Where does each deploy-time secret enter the pipeline? Workload identity / OIDC-federated cloud auth > short-lived token > long-lived secret-manager pull > env var pasted into a YAML.
- Search the diff for: literal API keys, base64-encoded blobs, `aws_secret_access_key:`, `password:` outside of test fixtures.
- Is the CI job's secret scope minimum? Pull-request workflows triggered from forks must NOT see prod secrets.
- Are deploy logs scrubbed? `echo $SECRET` once in a pipeline puts the secret in the artifact retention permanently.
- Rotation: if the secret leaks, what's the rotation path? Named owner, named target system, named cutover step.

## (10) Database backups — restore is the only proof

**Why it matters:** "We back up nightly" is one half of a sentence. The other half — "and last week we restored to a parallel cluster and the app worked" — is the part that resists ransomware, destructive migrations, insider mistakes, and silent corruption.

- Is there a scheduled, automated restore test? Not "we could restore" — a job that actually does, into a sandbox, and verifies row counts / app-level invariants.
- Restore RTO and RPO are stated, not assumed. RTO = how long to bring it back. RPO = how much data you accept losing.
- Backup storage is in a different trust boundary than primary storage. Same account, same region, same IAM principal = ransomware encrypts both.
- Logical (per-table dump) and physical (snapshot) backups have different recovery shapes; the design names which it relies on for which failure mode.
- Encryption-at-rest for backups, key managed separately from the primary DB's key.

## (12) Rate limiting — at every public boundary, with a sane key

**Why it matters:** without rate limits you get brute force, credential stuffing, scraping, DoS, spam, API abuse, and bot traffic for free. The default fail-state of an unbounded endpoint is "exploit available, attacker pays nothing per attempt".

- Every authenticated endpoint: limit per-account.
- Every unauthenticated endpoint (login, signup, password-reset, public API, webhook receivers): limit per-IP **and** per-account-target. IP-only is bypassed by botnets; account-only is bypassed by enumeration.
- Burst vs. sustained: token bucket (allow short bursts, hard sustained limit) > fixed-window (cliffs at the boundary).
- Headers: surface remaining-quota / retry-after so legitimate clients can back off correctly.
- 429 vs. 403: rate-limited is not unauthorized. Mixing them confuses incident response.
- Cross-reference with `api-design.md` rate-limit-keys section.

## (14) Error alerting — silence is not success

**Why it matters:** the gap between a breach happening and a breach being noticed is where adversaries do their actual work. If 5xx surges, auth failures, or anomalous logins never page anyone, you find out via customer complaints — weeks late.

- Which signals page? Examples: spike in auth failures per IP, spike in 5xx, sudden egress to new destinations, unusual data-export volume, lateral-movement-shaped queries.
- Each alert names an owner and a runbook. An alert with no runbook is a future post-incident question of "what was this supposed to mean?"
- Severity tiers (critical = page, high = ticket, low = digest) match the response capacity of the team. P1 on everything = nothing is P1.
- Test the alert path quarterly. An untested pager rotation is an untested pager rotation.
- Pair with item (20) below — alerts without log retention are alerts that fire and then have nothing to investigate.

## (15) Transactions for multi-step writes

**Why it matters:** half-applied state is the security bug class. A signup that creates the user but fails to create the default org leaves an orphaned account; a refund that decrements inventory but fails to issue the credit creates a duplicate-charge attack; an authz change that updates role but fails to invalidate the session leaves stale privilege.

- Every multi-step write is enclosed in a transaction (DB transaction, distributed saga, idempotency-keyed compensating workflow). Pick one and name it.
- Idempotency keys on every write endpoint that a client might retry — webhook receivers, payment intents, POSTs that mutate billing.
- "Eventually consistent" requires a named convergence step and a named maximum staleness. If you can't state both, you don't have eventual consistency, you have a race.
- Read-your-writes guarantees inside a single user session: stated, or explicitly waived.
- Compensation paths for the multi-system case (payment + provisioning + email): each step has an undo, or the design accepts the inconsistency and names how it's reconciled.

## (19) Third-party API fallback

**Why it matters:** a hard dependency on a single SaaS makes the SaaS's outage your outage, and the SaaS's compromise your compromise.

- For each external dep: what's the failure mode if it's down for 30 minutes? Two hours? A day?
- Hard-fail vs. graceful-degrade vs. cached-response vs. queue-and-retry. Pick per dep; document it.
- Vendor compromise: assume the dep is now serving attacker-controlled responses. What invariants do you re-check on your side? (Signature verification on webhooks, schema validation on responses, sanity-bound numeric values.)
- Multi-region failover for the dep, when offered, is the cheap insurance.
- Long-term: is there a path to a second provider if the first becomes untenable (price, terms, security incident)? If "no", that's a constraint on the business, not an oversight.

## (20) Log destination — never just local disk

**Why it matters:** local logs disappear when the host disappears. Compromise that nukes the host nukes the audit trail. Disk fills, log rotation drops, container restarts — investigation evidence vanishes.

- Logs ship to a separate system (managed log service, central syslog, SIEM). Local files are buffer-only.
- The log destination is in a different trust boundary than the application. App compromise should not let an attacker delete the trail.
- Authentication to the log destination: workload identity, not a shared token in env. Token rotation has a named owner.
- Retention is set in the destination, not the app. App-side retention is for buffer, not for compliance.
- What classes of events MUST be logged: auth (success + failure), authz denials, data export/download, admin actions, configuration changes, secret reads.

## (21) Circuit breakers on external calls

**Why it matters:** when a dependency goes slow (not down — slow), every caller stacks up waiting on it. Threads, connections, and workers are finite; one slow dep cascades into service-wide unavailability.

- Each outbound call site has a circuit breaker (open / half-open / closed states) — pattern, not a one-liner library import.
- Open threshold: after N failures in window W, stop calling for cooldown C.
- Half-open probe: a single test request decides whether to close again.
- Fallback behavior in the open state: cached response, queued for retry, degraded mode, hard fail with a clear error. Name it per call site.
- Metrics: open-state count is a paging signal (per item 14).

## (23) Connection timeouts on outbound HTTP

**Why it matters:** the worst kind of outage is the silent hang. No timeout = a slow dep ties up your workers indefinitely. Workers exhaust, the pool fills, and the service is down without ever throwing an error.

- **Every** outbound HTTP call has a connection timeout AND a read/total timeout. Sane defaults: 5s connect, 30s total. Override per call only with justification.
- Library default timeouts are often "none" (Go stdlib, Python `requests` without `timeout=`, fetch in Node). Audit each.
- Long-poll / streaming endpoints have an explicit max-duration; nothing waits forever.
- Pair with (21) — a fired timeout should count toward the circuit-breaker failure threshold.
- DNS resolution timeout is separate; pin it too on platforms that allow.

## (25) Incident runbooks

**Why it matters:** during the first 30 minutes of an incident, the team responds at the speed of the slowest piece of institutional memory. A runbook turns "who has the credentials for X" and "how do we roll back the deploy" into a checklist instead of a hunt.

- Top-N incidents documented as runbooks: bad deploy rollback, DB primary failover, payment-provider outage, secret rotation, suspected credential leak, suspected user-data exfiltration, customer-reported breach.
- Each runbook has: who's on point, decision tree, commands to run, expected output, escalation triggers.
- Runbooks live in a system the on-call can reach during an incident (not behind the same auth that just failed). Static export to a known-stable location is fine.
- Quarterly tabletop exercise: pick a scenario, walk the runbook, find the broken step. A runbook that hasn't been exercised in a year is fiction.
- Post-incident: every novel-feeling step in the response gets added to the runbook before the next on-call rotation.

---

## Refuse-list

- "We'll add rate limiting later" on any public endpoint.
- Logs to local disk only.
- Outbound HTTP calls with no timeout (audit every library default).
- Multi-step writes outside any transaction or saga, with no idempotency key.
- "Nightly backup" that has never been restore-tested.
- Single-vendor dependency on a critical path with no degraded-mode plan.
- Alerts without runbooks; runbooks without exercise.
- Secrets pasted into CI YAML or printed in CI logs ("just for debugging").

---

## Exit criteria

- Item (6): no secrets in deploy scripts; deploy auth is workload identity or short-lived federation.
- Item (10): a restore test job exists, runs on a schedule, and verifies at least one app-level invariant.
- Item (12): rate-limit keys and thresholds named for every public endpoint.
- Item (14): paging signals enumerated, each with an owner and a runbook reference.
- Item (15): every multi-step write names its transaction or compensation mechanism + idempotency key.
- Item (19): degraded-mode plan documented for every external dep on a hot path.
- Item (20): logs ship off-host to a separately-trusted destination; retention is set there.
- Item (21): circuit breaker configured for every outbound call; open-state is a paging signal.
- Item (23): connect + total timeouts set explicitly on every outbound call (no library defaults relied on).
- Item (25): top-N runbooks exist, are reachable during an incident, and were exercised in the last quarter.
