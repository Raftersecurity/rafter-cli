# API Review — OWASP API Security Top 10 (2023)

REST / GraphQL / gRPC review: authz-per-endpoint, per-object and per-field; rate limiting; bulk operations. Walk each category as questions. Cite file:line before moving on.

## API1 — Broken Object Level Authorization (BOLA)

The most common API vuln. Per-object authz, not per-endpoint.

- For every handler that takes an id (`/orders/:id`, `/users/:user_id/settings`), is there a check that the id belongs to the caller? "Authenticated" is not "authorized".
- Grep patterns: `findById`, `SELECT ... WHERE id = ?`, `get_object_or_404`. Is the caller's identity in the query, or compared after?
- GraphQL: authz at the resolver level for *each* field that returns a user-owned object. Schema-level auth is not enough if resolvers fan out.
- UUIDs do not save you. They only slow discovery; they do not provide authorization.

## API2 — Broken Authentication

- Every unauthenticated endpoint — is it supposed to be? List them: grep for `@AnonymousAllowed`, `permission_classes = []`, middleware skips.
- Token lifetime, refresh, and revocation: where is a token invalidated on logout / password change / user deletion?
- JWT-specific: is `alg` pinned? Is the key rotated? Is `iss` / `aud` checked? Is clock skew bounded?
- API keys: how are they generated (entropy), stored (hashed?), scoped (per-tenant? per-capability?), rotated?
- Credential endpoints (login, reset, MFA enroll) — rate-limited separately from normal endpoints? Return generic errors? Constant-time compare?

## API3 — Broken Object Property Level Authorization (BOPLA)

Covers both mass-assignment and excessive data exposure.

- Serialization: when returning an object, are sensitive fields (`password_hash`, `mfa_secret`, `internal_notes`, `role`) explicitly excluded? "Return the model" is a red flag; "return a DTO" is the fix.
- Mass assignment: can the client set fields they shouldn't? `User.objects.update(**request.data)`, `req.body` spread into an ORM constructor, Rails `params.permit!`. Check every update/create path.
- GraphQL: schema exposes fields; are resolvers authz-checked per field? Can a non-admin introspect admin-only fields?

## API4 — Unrestricted Resource Consumption

- Pagination on every list endpoint? Max page size enforced server-side (not just a default)?
- Rate limits: per-user, per-IP, per-endpoint. Token bucket? What happens at the limit — 429 with `Retry-After`, or silent 500?
- Request size limits: body size, file upload size, JSON depth, GraphQL query depth / complexity.
- Expensive operations: image processing, PDF generation, report export — are they queued, timeboxed, cost-accounted?
- Amplification: does one API call trigger N outbound calls (email, SMS, push)? Can that N be user-controlled?

## API5 — Broken Function Level Authorization (BFLA)

Different from BOLA — this is "can a regular user invoke an admin function at all?", not "can user A touch user B's data?".

- List admin / privileged endpoints. For each, is there a role check? Is the role from a trusted source (session/token claim) or from the request (`X-Role: admin`)?
- HTTP verb confusion: does the handler accept PUT/PATCH/DELETE when only GET was authz'd? Are method restrictions on the router or in the handler?
- Feature flags: does the flag gate *access* or only *visibility*? If the endpoint is reachable when the flag is off, the flag isn't security.

## API6 — Unrestricted Access to Sensitive Business Flows

- Identify flows worth abusing: signup, promo code redemption, ticket/inventory purchase, "add friend", "send invite".
- Per-flow: is there anti-automation (captcha, proof of work, device fingerprint, delay between steps)? Rate limit per account *and* per payment instrument *and* per IP range?
- Does the flow leak enumeration? Signup "email already registered" is a known tradeoff — is it the right one here?

## API7 — Server-Side Request Forgery

(Same question set as web-app A10 — see `web-app.md`.)

- Webhook configurators, URL-based imports, OAuth discovery endpoints, image fetchers: any user-supplied URL that the server fetches?
- DNS rebinding: is the URL resolved once and then reused, or re-resolved on each redirect? Are redirects followed blindly?
- Cloud metadata (`169.254.169.254`, `metadata.google.internal`) explicitly blocked?

## API8 — Security Misconfiguration

- Error responses: do they include stack traces, SQL fragments, internal hostnames? Production should return stable error shapes only.
- CORS per-endpoint: any endpoint with `Allow-Credentials: true` *and* a reflected / wildcard origin?
- Default routes from frameworks still mounted (`/actuator/*`, `/debug/*`, `/_next/*` in dev mode)?
- Are OPTIONS responses correctly restrictive? Do HEAD and OPTIONS follow the same authz as GET?
- TLS: are older APIs allowed to accept plain HTTP for backwards compat? If yes — is that documented and scoped?

## API9 — Improper Inventory Management

A governance issue, but reviewable:

- Is there an API version registry? When this PR adds or changes an endpoint, is it documented (OpenAPI / GraphQL schema committed)?
- Are deprecated endpoints marked and scheduled for removal? Still reachable in production?
- Non-prod environments (staging, sandbox) — do they share data, credentials, or network paths with prod? Often the weakest link.

## API10 — Unsafe Consumption of Third-Party APIs

- Outbound API calls: is the response validated before use (schema, size, type)? "Trust the third party" is the failure mode.
- Credentials to third parties: scoped to least privilege? Rotated? Not shared across tenants?
- What happens on timeout / 5xx from the third party? Fallback to cached data? Log and surface?
- If the third party is compromised, what is the blast radius here? Does our data flow into untrusted callbacks?

---

## Exit criteria

- Every endpoint touched by the diff has a documented answer for API1 (per-object authz) and API5 (per-function authz).
- Every new third-party integration has answers for API10.
- Every new flow has a rate-limit story (API4) and an abuse story (API6).
- Scanner cross-check: run `rafter run` and reconcile SAST findings against this walk.
