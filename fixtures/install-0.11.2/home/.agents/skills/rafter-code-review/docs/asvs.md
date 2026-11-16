# OWASP ASVS — Picking a Level, Spot-Checking It

The Application Security Verification Standard (ASVS 4.0 / 5.0) is a catalog of verification requirements. Unlike Top 10 lists, it's exhaustive — which is why you pick a level first and spot-check, not walk every item.

## Step 1 — Pick the right level

| Level | Use for | Rough test |
|---|---|---|
| **L1** — Opportunistic | Low-value apps, internal tooling, marketing sites. "Protect against casual, opportunistic attackers." | Would losing this data be annoying but not damaging? |
| **L2** — Standard | Most apps that handle user data, B2B SaaS, line-of-business apps. "Default for apps handling sensitive data." | PII, payment, auth, health-adjacent, B2B tenants? |
| **L3** — Advanced | Apps where compromise leads to real harm: financial transactions, healthcare records, critical infrastructure, high-trust platforms. | Regulatory scrutiny? Lives/money at risk? |

**Rule of thumb**: pick the lowest level that matches the *highest-sensitivity* data flow in the scope. Don't average. A single admin endpoint that touches payment data pulls the whole service to L2 for that endpoint.

---

## Step 2 — Spot-check (not walk-every-item)

ASVS has 280+ requirements. You will not walk them all in a PR review. Instead, for the level you picked, ask the three questions below per category.

### V1 — Architecture, Design, Threat Modeling

- Is there a threat model for this feature? (L2+: yes; L3: reviewed and signed.)
- Are all components inventoried (deps, services, data stores)?
- Does the design document trust boundaries and assumptions?

### V2 — Authentication

- Password policy: min length 8 (L1) / 12 (L2) / 12+MFA (L3); hashed with argon2/bcrypt/scrypt; never truncated or case-normalized in storage.
- MFA: not required at L1; required for admin/sensitive at L2; required for all at L3.
- Credential recovery: does not bypass MFA; uses time-limited, single-use tokens; does not leak account existence.

### V3 — Session Management

- Server-side session store (or stateless token with revocation)?
- Session rotation on login / privilege change / logout?
- Cookie flags: `Secure`, `HttpOnly`, `SameSite=Lax` or stricter; `Domain` scoped tightly.

### V4 — Access Control

- Deny-by-default on new endpoints?
- Per-object authz (BOLA) enforced where user ids appear in URLs?
- Admin functions require re-authentication at L2+; require MFA step-up at L3.

### V5 — Validation, Sanitization, Encoding

- Input: validated at the trust boundary (not downstream) against a positive spec (allowlist, schema, regex anchored).
- Output: context-aware encoding (HTML / URL / JSON / shell / SQL). Templating auto-escapes?
- Parsers: safe loaders for YAML/XML/JSON; no string-concat into query languages.

### V6 — Stored Cryptography

- Algorithms: AES-GCM, ChaCha20-Poly1305, SHA-256+, HMAC-SHA-256+, PBKDF2/argon2 for passwords.
- Key management: keys not in source, rotated, scoped per-environment, stored in a managed KMS at L2+.
- Randomness: `secrets` / `crypto.randomBytes` / `crypto/rand` — never `rand()` / `Math.random()`.

### V7 — Error Handling & Logging

- No secrets / PII in logs (grep log statements).
- No stack traces to the user in production.
- Authn, authz, and sensitive actions logged with who/when/what.

### V8 — Data Protection

- PII classified? Access to it logged?
- Data at rest encrypted (disk, DB, backups, cache)? Keys managed separately?
- Data in transit: TLS 1.2+ with modern ciphers; HSTS.

### V9 — Communications

- TLS everywhere, including internal hops? At L3, mutual TLS between services.
- Certificate validation not disabled anywhere (grep `InsecureSkipVerify`, `verify=False`, `rejectUnauthorized: false`).

### V10 — Malicious Code

- No hardcoded backdoors, debug logins, "magic" accounts.
- Build pipeline integrity: signed artifacts, locked deps, reproducible where possible.

### V11 — Business Logic

- Sequential flows (checkout, signup, reset): can steps be skipped? Replayed? Reordered?
- Anti-automation on abuse-prone flows (captcha, proof of work, device fingerprint)?

### V12 — Files & Resources

- Uploads: type-sniffed (not extension-trusted), size-limited, stored outside web root, name-randomized.
- Downloads: path-confined; no `../` traversal; MIME set explicitly.
- Archives: zip-slip / tar-slip prevention when extracting.

### V13 — API & Web Service

- OpenAPI / GraphQL schema present and matches implementation?
- Auth per-endpoint, not per-service?
- Rate limits per-endpoint tier?

### V14 — Configuration

- Production config reviewed (debug off, defaults rotated, unused features off)?
- Dependencies: SCA in CI, lockfile committed, base images pinned.
- Secrets: none in source, rotated on exposure, scoped per environment.

---

## Step 3 — What to produce

Not an ASVS report. A list of **citations** keyed by (level, category, requirement), plus **gaps**. Example:

```
L2 / V4.1.3 (deny by default) — OK, `authMiddleware` registered globally in app.ts:41
L2 / V4.2.1 (per-object authz) — GAP, /orders/:id handler (orders.ts:88) lacks owner check
L2 / V5.1.1 (schema validation) — OK, zod schemas in routes/*.ts
```

---

## Tie-backs

- Concrete vulnerabilities (not requirements): go to `web-app.md` / `api.md` / `llm.md`.
- Specific finding investigation: `investigation-playbook.md`.
- Automated coverage: `rafter run --mode plus` produces ASVS-tagged findings.
