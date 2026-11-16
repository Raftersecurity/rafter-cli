# API Design — Design Questions

The shape of your API decides which vulnerabilities are *possible*. Good shape makes BOLA, BFLA, and mass assignment hard to write. Bad shape makes them hard to avoid.

## Resource modeling — is this endpoint BOLA-shaped?

- For each endpoint, what is the resource being named, and *how is it named*? `GET /orders/:id` names an order by global id — the caller can enumerate and try any id. Contrast with `GET /me/orders/:id` — scoped to the caller.
- The scoping prefix (`/me`, `/org/:org_id`) doesn't enforce authZ by itself, but it makes the enforcement gap visible. "I forgot to check" is harder when the URL structure announces the scope.
- Are identifiers **opaque** (random, unguessable) or **sequential**? Sequential ids aren't a security control, but combined with missing authZ they turn a 5-minute bug into a data breach. Opaque ids (UUIDv4, ULIDs with enough entropy) buy you a little defense-in-depth.
- GraphQL: the resource boundary is per-field, not per-endpoint. You need authZ on every resolver that returns a resource, including nested resolvers. Think: "can a query walk from a public node to a private one via an edge?"

## AuthZ enforcement point

- Where does each endpoint check authorization?
  - Before the handler (middleware / decorator): good for coarse checks (authenticated? role?).
  - Inside the domain layer, against the specific resource: required for resource-level checks (can user X read order Y?).
  - Both: middleware filters obvious unauthenticated traffic; domain checks the specific access.
- Missing authZ checks are the #1 API bug class. Is there a test that *proves* every endpoint either returns 401 without auth or has an authZ test that denies a different user?
- BFLA (broken function-level authz): admin actions on regular-user endpoints. Is there a single codepath that's reachable by multiple roles where only the check is different? That's the BFLA shape.

## Request shape — mass assignment

- Does the handler bind the full request body into a model, then save? `User.create(request.body)` is mass assignment — a client can set `is_admin: true` if the field exists on the model.
- Explicit allowlist per endpoint, even if it's verbose. Frameworks that "automatically filter" are a landmine — the filter is correct until a field is added.
- For updates: what fields are read-only? Created-at, created-by, tenant-id, owner-id — none of these should be settable by the client.

## Idempotency & safety

- Write endpoints: does the spec say idempotent or not? `PUT /things/:id` should be idempotent; `POST /things` usually isn't. Clients will retry — non-idempotent writes without an idempotency key will double-charge, double-send, double-create.
- If you accept an `Idempotency-Key` header (Stripe-style): how long is the key scoped? Per-user, per-hour, per-day? Too short = legitimate retries fail; too long = stale dedup.
- HTTP verb discipline: does the server accept verb-override headers (`X-HTTP-Method-Override`)? If yes, the "GET is safe" assumption breaks — any GET can become a POST.

## Rate limiting & abuse

- What are the **three** rate-limit keys? Per-IP (cheapest), per-API-key / per-user (account-level abuse), per-endpoint (expensive endpoints get lower limits).
- Authentication endpoints (login, password reset, MFA): count per-account *and* per-IP. Per-IP alone misses credential stuffing with rotating IPs; per-account alone misses enumeration.
- Webhook senders: self-rate-limit (queue, backoff). A storm of retries is a self-DoS.
- Abuse cost: for expensive operations (file upload, image processing, LLM calls), what prevents one user from burning all the budget? Quotas > rate limits for cost control.

## Error taxonomy — what leaks

- Do errors distinguish "record not found" from "record exists but you can't see it"? They should **not** — both return 404. Revealing existence is an oracle.
- Login errors: "invalid email" vs. "invalid password" = enumeration oracle. Both return "invalid credentials".
- Stack traces, SQL errors, file paths in error responses — all debugging aids that become disclosure bugs in production. What's the production error shape? Do you have tests that assert it doesn't leak?
- Error codes: are they stable and documented? "ERR_1042" isn't user-hostile; "database connection timeout on host db-prod-01.internal" is.

## Pagination & bulk ops

- Is there an upper bound on `limit`? Unbounded = trivial DoS and data exfil. What's the cap (1000 is common), and does the client know it was capped (via `has_next`)?
- Cursor vs. offset: cursor-based is better for deep pagination and for immutable-once-read semantics. Offset lets attackers enumerate by incrementing.
- Bulk ops (`POST /things/bulk`): per-element authZ, not just outer authZ. The handler might accept 500 resource ids and forget to check each one.

## Webhooks (outbound)

- Is the webhook destination user-supplied? If yes: this is SSRF-shaped. Allowlist the target (domain allowlist *plus* IP allowlist that excludes RFC1918, link-local, cloud metadata `169.254.169.254`).
- Signed payloads: HMAC with a per-receiver secret, signature in a header, timestamp in the payload. Receivers should verify signature *and* reject stale timestamps (replay protection).
- Retry policy: exponential backoff with a cap; max retries; dead-letter queue. Unbounded retries = self-DoS on receiver outages.
- Does the delivery include PII? If yes, the receiver URL is now part of your data flow for compliance purposes. You need a deletion story for their side too.

## Webhooks (inbound)

- Verification: HMAC check, timestamp tolerance (< 5 min), replay cache (seen this signature recently?).
- The payload is untrusted. Parse into a typed schema, reject unknown fields — don't echo into the DB.

## Versioning & deprecation

- How do you version? URL path (`/v1/`), header (`Accept: application/vnd.example.v1+json`), or query param? Pick one and stick with it.
- How do you deprecate an endpoint? Sunset date, `Deprecation` header, metrics on which clients still call it. Deprecation without metrics = deprecation forever.
- Old versions are old attack surface. Every live version is a maintenance cost.

## API keys & client credentials

- Scope per key (what endpoints, what data); expiration; revocation.
- Does the key identify a **principal** (user / service) or just a **contract**? Per-principal is easier to audit; "contract keys" that many services share lose attribution.
- Key display: show once at creation, store hashed. Rotation flow: overlap window (old + new valid) to avoid downtime.
- Per-key audit log: every authenticated call names the key.

## Refuse-list

- Endpoints that accept the full request body into an ORM model without an allowlist.
- 404 vs. 403 that leaks existence. (It's fine to 403 on a *permission* mismatch when the user knows the resource exists; not on resource-existence probes.)
- Unbounded `limit` parameters.
- User-supplied URLs fetched without an allowlist + IP denylist.
- Login / password-reset endpoints without rate limits on both IP *and* account.
- Error responses that include DB errors, file paths, or stack traces in production.
- Webhook verification that's only "is there a signature header" without validating it.
- API versioning schemes where v1 is never sunsetted (perpetual liability).

---

## Exit criteria

- Every endpoint has a one-line authZ rule ("caller's user_id must equal the resource's owner_id, or the caller's role must be admin").
- Mass-assignment story is explicit — allowlist, not auto-bind.
- Rate limit keys are defined and justified per endpoint class.
- Error taxonomy is in the spec, not up to the implementer.
- Webhook designs (if any) specify signing, replay protection, and (outbound) SSRF defense.
