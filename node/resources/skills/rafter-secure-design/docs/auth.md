# Authentication & Authorization — Design Questions

Answer each block *before* you write code. If the answer is "we'll figure it out later", you have a design gap, not a plan. Cite the proposed primitive (library, spec, service) in your answer.

## Identity — who is the user?

- Is this **end users** (humans), **services** (internal/external), or **agents** (LLMs, automations)? The authN primitive differs for each; do not use one pipeline for all three.
- For humans: are you federating (SSO / OIDC / SAML) or running your own password + MFA? Running your own is a maintenance burden — can you justify not federating?
- For services: mTLS? Signed JWTs with a trusted issuer? Workload identity (SPIFFE, cloud IAM)? What *refuses* a service call — is absence of credential a 401 or a silent allow?
- For agents: is the agent acting **as the user** (delegated) or **as itself** (service principal)? Delegated needs scoped tokens with user consent; as-itself needs audit trails that name the agent + the invoking user.

## AuthN — choose the primitive and say why

- Session cookies + server-side session store, or self-contained tokens (JWT / PASETO)?
  - Sessions: easier to revoke, harder to scale across regions without sticky state.
  - JWT: scales, harder to revoke — do you have a plan for revocation (short TTL + refresh, or a revocation list)?
- If JWT: which algorithm are you signing with? **Refuse `alg: none`** and **refuse HS256 with any key the verifier can confuse with a public key.** Prefer `EdDSA` or `RS256`/`ES256` with a clearly separated key store.
- If OAuth / OIDC: which flow? Authorization Code + PKCE for any client that isn't a trusted backend. **Never implicit flow in 2026.** If you have a reason, write it down.
- Password policy: bcrypt / scrypt / argon2id — which one and what cost? Do you plan to rehash on login when cost parameters bump? What's the plan for credential stuffing (rate limit, captcha, breach-list checks)?
- MFA: present at login only, or also at sensitive actions (password change, MFA enrollment, payment method change, export-all-data)? MFA enrollment itself needs anti-bypass (don't let "add a new device" bypass existing MFA).

## AuthZ — model the access, don't reinvent it

- Is the model **RBAC** (roles → permissions), **ABAC** (attributes → policy), or **ReBAC** (relationships, Zanzibar-style)?
  - RBAC: cheap, coarse. Fails on "users can only see their own records" — that's a resource-ownership check, not a role.
  - ABAC: flexible, hard to audit. If the policy is "user.org == resource.org AND (user.role == admin OR resource.owner == user)", write it as a policy engine input (Rego, Cedar), not scattered `if` statements.
  - ReBAC: best for hierarchical sharing (docs, folders, workspaces). Expensive to bolt on later — decide now if you'll need it.
- Where is authZ enforced? **At every entry point to the domain layer**, not per-route. Router-layer middleware checks authN, the domain layer checks authZ against the resource. If both live in the controller, the next developer will forget one.
- IDOR / BOLA: for every resource access, is the ID scoped to the caller? `GET /orders/:id` that returns any order in the database is a bug. Are you checking `order.tenant_id == user.tenant_id` *and* `order.user_id == user.id` (or a delegated-access rule)?

## Sessions / tokens — lifetime and revocation

- Session lifetime: idle timeout and absolute timeout? "Remember me" — what invalidates it on password change, MFA reset, account deletion?
- Refresh tokens: single-use (rotating) or replayable? Rotating + detection-on-reuse is the modern default. If you can't detect reuse, you lose the audit signal.
- Revocation list: where does it live? Is it read on every authZ check (expensive) or pushed to token TTL only? If the latter, your TTL *is* your worst-case revocation delay — be honest about that.
- Logout: does it actually invalidate server-side, or just clear the cookie? A logout that only clears the client is a lie.

## Multi-tenant isolation

- Tenancy is an authZ concern, not a DB trick. Is the tenant id on every query? What enforces that — raw SQL, ORM hook, policy engine? (ORM hook is easy to bypass with raw queries; policy engine with query-rewriting is strongest.)
- Is the tenant id from the **session**, never from the **request**? `?tenant_id=X` in the URL is a footgun.
- Cross-tenant sharing (delegation, impersonation for support, data export): designed explicitly, or accidental because of a missing check?

## Service-to-service

- Zero-trust posture: does every internal call still carry and verify identity, or is the internal network treated as trusted? (Treat-as-trusted has failed in every post-mortem for a decade.)
- How is service identity bootstrapped? Static long-lived secrets in env vars are the weakest option — workload identity (AWS IAM, GCP WIF, Kubernetes SA tokens, SPIFFE) is strongest.
- Does the callee log *which* service called it? Without that, you can't incident-respond.

## Refuse-list — if any of these are in the proposal, stop and redesign

- Homegrown password hashing (`sha256(pw + salt)` is not hashing).
- Homegrown JWT signing/verification (pick a maintained library, prefer PASETO for new designs).
- `alg: none` acceptance, or JWT libraries that don't pin algorithm.
- "The internal network is trusted, so we skip auth between services."
- Tenant id derived from the request path or query string rather than the session.
- MFA that can be bypassed by enrolling a new device without re-verifying.
- Password reset tokens that are long-lived, non-rotating, or tied to email only without rate-limit + recent-activity checks.

---

## Exit criteria

- Each subsection above has a one-line answer, naming a specific primitive or library.
- The refuse-list has been checked against the proposal; any hits are explicitly waived with a written "we accept this because...".
- AuthZ model chosen and a first sketch of the policy (RBAC table / ABAC rules / ReBAC relations) exists.
- You're ready to hand this section to the implementing engineer without ambiguity.
