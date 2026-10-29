# Investigation Playbook — Canonical Questions per Category

When one finding, suspicious pattern, or vague "this looks wrong" needs a follow-up — use this. Each section is a question you can actually answer with Grep / Read / trace.

## Reachability: "Can untrusted input get here?"

Before fixing anything, prove it's reachable.

- Where does the input originate? Trace upward from the sink: `app.post(...)` → handler → service → ... → the line in question.
- Are there layers that filter or transform along the way? Allowlist validator? JSON schema? ORM serializer?
- Is this code path actually called in production? Or is it a dead branch left from a refactor?
- If it's an internal service — is it exposed via a misconfigured ingress, reachable from the internet, accessible from a compromised pod? "Internal" is a policy, not a security boundary.
- Test: can you write a failing request/input that triggers the line? If you can write it in 5 minutes, an attacker can.

---

## Authz coverage: "Is every path checked?"

For an authz-critical operation (read user X, delete resource Y, invoke admin action):

- List every entry point (HTTP handler, gRPC method, queue worker, CLI command, background job). For each: is the check present?
- For HTTP: is the check in middleware (applies to all), or per-handler (easy to miss)? Grep for the check; count matches; count routes; compare.
- Does the check use *request-supplied* identity or *session-derived* identity? `X-User-Id: 42` header is not identity.
- Privilege escalation corner: can a user modify their own `role`, `tenant_id`, `permissions` via the same endpoint that updates their profile? (mass-assignment + authz = disaster.)
- Is authz re-checked after redirects / async continuations / token refreshes? Identity is not sticky across those.

---

## Data flow: "Does tainted data reach a dangerous sink?"

Source → sinks, both directions:

- **Top-down**: pick a source (request body, query string, file upload, DB read from a user-writable table). Grep how that variable flows. Does it reach a sink (SQL, shell, HTML, URL fetch, deserializer)?
- **Bottom-up**: pick a sink (every `subprocess.run`, every `db.raw`, every `innerHTML`). Trace backward. Is the input at the sink derivable from a source?
- Don't trust "it's validated upstream" without proof. Read the validator; check that the type after validation is strong enough (strings are weak, `UUID` is strong).
- Does the data go through serialization round-trips that could re-introduce metacharacters? JSON round-trip, URL-decoding at the wrong layer, base64 → string → SQL.

---

## Trust boundaries: "Where does untrusted become trusted?"

- Draw the boundary. What's on each side?
- At the boundary: is there validation (shape, type, range, allowlist)? Is there normalization (Unicode NFKC, lowercasing, path canonicalization)?
- Is the same boundary crossed more than once? (Controller → service → repo — does the repo re-validate, or trust the service?)
- Cross-service: does Service B trust Service A's payload? If A is compromised, what can B do?
- Cross-tenant: if a single process serves multiple tenants, where is the tenant id enforced? On every query? Or only at the top of the handler?

---

## Error paths: "What happens when this fails?"

- Every try/except / error branch: does it leak information (stack, internal IDs, DB errors) to the caller?
- Does the failure leave the system in a broken state (half-written file, partial DB row, orphaned session)?
- Does the failure log enough for you to debug a real incident? Generic "failed to process" without context is a blind spot.
- Are retries bounded? Does the retry code path itself re-authenticate, or reuse a possibly-stale token?

---

## Concurrency: "What happens with two of these at once?"

- Is there shared mutable state (module globals, singletons, caches, files)? Protected by a lock?
- Check-then-act races: `if not exists: create` — two requests can both pass the check. Use `INSERT ... ON CONFLICT` or transactions.
- Idempotency: can the client retry safely? Is there an idempotency key? Repeated payment, duplicate email, double-spend patterns.
- Async/await holding locks across `.await`: in Rust/Python, this deadlocks. In Go, it's fine but can cause fairness issues.

---

## Secrets lifecycle: "Where does this credential live, and who can read it?"

- Creation: how is it generated (entropy source)? Who knows it at creation time?
- Storage: env var, config file, KMS, DB, vault? File permissions?
- Transit: does it appear in logs, metrics, error messages, request bodies?
- Rotation: is there a story for rotating it? Automated or manual? What breaks during rotation?
- Revocation: if it leaks today, what's the time-to-revoke? Minutes, hours, or "we'd have to redeploy"?

---

## Input shape: "Can I break the parser?"

- Size: is there a max? What happens at the max+1? At 10×max?
- Depth: for JSON/XML/nested structures — max depth? Billion-laughs / deeply nested dicts can OOM.
- Encoding: UTF-8 vs UTF-16 vs Latin-1; BOM handling; surrogate pairs; null bytes in paths.
- Numeric: NaN, Infinity, -0, integer overflow, very large floats losing precision.
- Arrays: empty, one element, duplicate keys, sparse arrays, non-integer indices.

---

## How to record the outcome

For each finding that survives investigation, produce a one-line summary in this shape:

```
[severity] [ruleId or ad-hoc tag] file:line — <one-sentence issue> — <one-sentence fix direction>
```

Example:
```
[high] IDOR /orders/:id (orders.ts:88) — handler loads order by URL id without comparing to session user — add owner check before load, 404 (not 403) on mismatch
```

Feed these into the PR review comment or back to `rafter` for triage follow-up (`rafter/docs/finding-triage.md`).
