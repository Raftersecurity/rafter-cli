# Threat Modeling — STRIDE on the Specific Design

This is the capstone. Walk after the individual decisions (auth, data, API, ingestion, deployment) are drafted. The goal: stress-test the design by asking "how would an attacker break *this specific thing*?"

## Setup — the diagram you actually need

Before STRIDE, draw two things. Prose is fine; ASCII is fine. Drawings get handwaved.

1. **Data-flow diagram**: boxes for processes, cylinders for stores, arrows for flows. Label each arrow with what crosses it (request type, data fields).
2. **Trust boundaries**: dotted lines *across* the arrows — every arrow that crosses a boundary is a security control point.

Minimum sketch:
```
[Browser] → [CDN/WAF] ┆→ [API Gateway] → [App Service] ┆→ [DB]
                                           ↓
                                     [Third-Party API]
```
Boundaries: browser↔edge, edge↔app, app↔DB, app↔third-party.

Each boundary is where STRIDE is most productive.

## STRIDE — one per category, per boundary

The trick is not to apply STRIDE globally; apply it to each trust-boundary crossing and each data-store.

### S — Spoofing (identity)

Applied per boundary: can the entity on the other side be impersonated?

- Browser → edge: can an attacker present a valid-looking session cookie / token they didn't earn? (Authn strength, token theft, XSS → cookie steal.)
- App → DB: is the DB credential stealable? Replayable? Scoped to the app's workload identity, or shared?
- App → third-party: does the third-party authenticate the calling app? (Mutual TLS? Signed request?) If not, anyone on their egress path can spoof.
- Human → admin console: how is admin access authenticated, and is that *separate* from user authN?

### T — Tampering (data integrity)

Per boundary + per store:

- Data in transit: TLS version, cert validation, downgrade defenses. "We assume the internal network is safe" is where tampering happens.
- Data at rest: can a DB compromise *modify* records undetectably? Append-only audit stores + signed rows are the high-assurance pattern.
- Data in cache / queue: is message integrity validated? (HMAC on queue payloads, especially if they cross services with different trust levels.)
- Build artifacts: tampering between build and deploy. Signed provenance catches it.

### R — Repudiation

- Is there an audit log that names the actor, the action, the resource, the time, and a request id?
- Are the actor's identity and the action tamper-evident in the log? A log the app writes to a DB the app can also update is repudiable.
- For high-value actions (payments, data exports, admin changes), is the log shipped to an append-only store? Separately from app storage?
- Agents acting on behalf of users: does the log name both? "User X, via agent Y, did Z at T."

### I — Information disclosure

Per boundary + per store:

- Errors: what do error responses reveal? (See `docs/api-design.md` error taxonomy.)
- Side-channels: timing of login responses (does valid vs invalid username take different time?), response size, cache-hit timing.
- Logs: what fields are logged? Do they contain credentials / PII / secrets?
- Backups: who can read them? Are they encrypted separately from live?
- Debug endpoints: `/debug`, `/metrics`, `/health` — what do they expose? `/metrics` with unauthenticated Prometheus is fine for latency, not for business counters that hint at usage.
- URL leakage: does the URL contain sensitive data (tokens, email in query string)? URLs end up in logs, browser history, referer headers.
- Third-party telemetry: does Datadog / Sentry / LogRocket see data it shouldn't? (Session replay tools are notorious for capturing PII.)

### D — Denial of service

- Rate limits exist per endpoint, per user, per IP (see `docs/api-design.md`).
- Resource exhaustion: big uploads, deep JSON, big arrays, catastrophic regex, zip bombs (see `docs/ingestion.md`).
- Downstream dep failures: what happens if the third-party API is down? Timeout, circuit-break, fallback? Synchronous calls with no timeout = cascading outage.
- Queue / cache exhaustion: can a user enqueue infinite work? Background jobs that fan out per user need per-user caps.
- Expensive operations (LLM calls, ML inference, PDF rendering): per-user and per-tenant quotas. Cost DoS is real.

### E — Elevation of privilege

- AuthZ gaps: user role → admin role escalation. Mass assignment of `role` / `is_admin`. Server-side role check on every sensitive endpoint.
- Tenant escalation: cross-tenant data access. Row-level isolation enforced by policy engine, not by convention.
- Horizontal privilege (same role, other user's data): the IDOR / BOLA surface. Resource-scoped authZ.
- Agent / service escalation: a compromised less-privileged service calling a more-privileged one. Per-caller authZ at the callee.
- Infra-level: a compromised container breaking out to the host, or to other containers. Non-root, read-only FS, seccomp, network policy.

## Negative-space questions

STRIDE catches the known categories. These catch what STRIDE misses:

- **What did we assume is safe?** List the implicit trust assumptions. "We trust the CDN", "we trust that service X has done authN", "we trust the user to provide their own tenant_id". Each is a fragile assumption to revisit.
- **What's the worst-case single compromise?** Pick one component — the web server, the DB, the build runner, a maintainer's laptop. How far does compromise spread? Is that acceptable, or does the design need more segmentation?
- **What's the attacker's goal?** Data theft (who pays for it?), financial fraud (how does it monetize?), denial (who benefits from us being offline?), reputational (activist / extortion). The feasible attacks depend on who'd try.
- **What changes in an incident?** Under compromise, can you freeze sessions, rotate secrets, disable endpoints? If the runbook starts with "we'll figure it out", design in the controls now.

## Abuse cases — the flipside of use cases

For each primary use case, write the abuse twin:

- "User invites a friend" → "Attacker invites 10,000 friends to spam; legitimate invitee sees their address used as spam source."
- "User uploads a profile picture" → "Attacker uploads a polyglot SVG to execute script in another user's browser."
- "User requests a password reset" → "Attacker bulk-enumerates emails or sends reset-spam."
- "User exports their data" → "Attacker exfiltrates via unthrottled export endpoint."

One abuse twin per use case is enough at kickoff. Each surfaces a control that *should* be in the design but often isn't.

## Agentic / LLM-specific threats (if in scope)

If the design includes LLM or agent components, add these to the walk:

- Prompt injection: untrusted content reaches the model. Can it alter behavior of subsequent tool calls?
- Excessive agency: what tools does the agent have access to? Tools that write (email, file, DB, shell) are the blast-radius questions. Read-only tools are low-stakes.
- Data poisoning: RAG indexes over user content — can a user plant content that affects another user's retrieval?
- Model theft / extraction: API designs that let attackers reconstruct model behavior.
- Cross-tenant context bleed: if the model sees data from tenant A during a tenant B session, even as a system prompt leak, it's a disclosure bug.

## Output

A threat-modeling pass should produce:

- The DFD / trust-boundary sketch (prose or image).
- For each boundary / store: the STRIDE findings and the proposed mitigations.
- The refuse-list items that surfaced (if any).
- A short list of residual risks the team is knowingly accepting, with a reason.
- Follow-up items to file as issues (new controls, instrumentation, tests).

---

## Exit criteria

- DFD + boundaries are drawn.
- STRIDE is applied per boundary (not globally).
- Negative-space questions are answered.
- At least one abuse twin is written per primary use case.
- Residual risks are explicit and accepted in writing, not implicit.
- Design is ready for implementation — `rafter-code-review` will walk the PR when it lands.
