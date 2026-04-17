# Web Application Review — OWASP Top 10 (2021)

Walk each category as questions. Cite file:line evidence before moving on. If you can't answer a question, that *is* the finding.

## A01 — Broken Access Control

The #1 risk. Every authenticated route must answer: "who is allowed?"

- Grep for route handlers (`app.get`, `@app.route`, `router.handle`, controller annotations). For each: is there an explicit authz check? If you can't see one, trace the middleware chain — is it registered *before* this route?
- For every `where user_id = ?` pattern, is the id from the session, or from the request? `?id=123` in the URL that controls the DB lookup is IDOR-shaped.
- Are admin routes distinguished by URL prefix alone? If `/admin/*` is only protected by "don't tell users", that's not protection.
- Does the app rely on HTTP verb restrictions (GET safe, POST protected)? Can you POST to a GET-only endpoint? Does it accept `X-HTTP-Method-Override`?
- Is CORS configured with `Access-Control-Allow-Origin: *` alongside `Allow-Credentials: true`? That combination is almost always wrong.

## A02 — Cryptographic Failures

- What algorithms appear? Grep for `md5`, `sha1`, `des`, `rc4`, `ecb`. Any hit on user data, session tokens, or passwords is a finding.
- How are passwords hashed? Look for `bcrypt`, `scrypt`, `argon2`, `pbkdf2`. Absence is the finding. `sha256(password + salt)` is not password hashing.
- Are secrets in source? Run `rafter scan local .` first — but also grep for `private_key`, `api_key`, `BEGIN RSA`, `.pem`, `.p12`.
- Is TLS enforced? Look for redirect middleware, HSTS headers, cookie `Secure` flag. Cookies without `Secure` + `HttpOnly` + `SameSite` — ask why.
- Is randomness from `Math.random()` / `rand()` used for tokens, session ids, password resets? Must be `crypto.randomBytes` / `secrets.token_*` / `crypto/rand`.

## A03 — Injection

- SQL: every query that interpolates a variable (`f"SELECT ... {x}"`, backticks with `${x}`, `+` string concat into SQL). Must be parameterized. ORMs help but `.raw()` / `.query()` escape hatches don't.
- Command injection: `exec`, `spawn`, `system`, `subprocess.run(shell=True)`, `child_process.exec`. Any user input reaching these? Prefer array form, never `shell=True` with input.
- LDAP / NoSQL / XPath / template injection: same question — does user input reach a query language, and is it escaped by the library or by string concat?
- XSS: where does user-controlled data reach HTML? React/Vue auto-escape; `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, template literals rendered as HTML are the escape hatches. Server-side: is the template engine autoescaping? Jinja2 defaults off for `.txt`, on for `.html`.
- Deserialization: `pickle.loads`, `yaml.load` (without SafeLoader), `Marshal.load`, Java's `ObjectInputStream`. Any of these on untrusted bytes is RCE-shaped.

## A04 — Insecure Design

Design smells that code review *can* catch:

- Is there a single trust boundary, or does the same request cross it multiple times? (e.g. user → API → internal service that re-reads user input without re-validating.)
- Are rate limits on authentication and password reset flows? Count attempts per account *and* per IP.
- Does the password reset flow leak account existence? "Email sent if account exists" vs "no account with that email" — the latter is an oracle.
- Is the "remember me" token a long-lived bearer? What invalidates it on password change?

## A05 — Security Misconfiguration

- Debug mode / stack traces in production? Grep for `DEBUG = True`, `app.debug`, `NODE_ENV` comparisons.
- Default credentials in config files or seed scripts? Look in `seed.js`, `fixtures/`, `docker-compose.yml`.
- Unused frameworks/features enabled? Directory listing? Admin consoles (`/admin`, `/actuator`, `/console`) without authn?
- Security headers: CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Is there a helmet/`secure` middleware registered?
- Cloud metadata access — can the server be coerced into fetching `169.254.169.254`? (see also A10/SSRF.)

## A06 — Vulnerable & Outdated Components

- `rafter run` covers this via SCA. In review, check that the manifest is present (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`) and that the lockfile is committed.
- Is there a `postinstall` / `prepare` script running arbitrary code from dependencies? That's a supply-chain footgun.
- Are any dependencies pulled from raw git URLs or non-registry sources without pinning?

## A07 — Identification & Authentication Failures

- Session management: where is the session created, stored, invalidated? Does logout actually invalidate server-side, or just drop the cookie?
- Multi-factor: present on admin? On password change? On MFA enrollment itself (bypass via "add new device")?
- Credential stuffing: lockout policy, captcha on repeated failures, generic error messages.
- JWT: is `alg: none` accepted? Is the key confusion attack possible (HS256 verified against an RSA public key)? Is `kid` used to resolve arbitrary files?

## A08 — Software & Data Integrity Failures

- Update channels: does the app auto-update itself or pull config from remote? Is that channel signed and verified?
- CI/CD: does the pipeline verify signatures on built artifacts? Are secrets scoped per-job or leaked across?
- Deserialization (overlaps with A03): any untrusted blob fed to `pickle` / `yaml.load` / `unserialize` / `readObject`.

## A09 — Security Logging & Monitoring Failures

- Are authn failures logged with enough context (user id, ip, timestamp) to be useful?
- Do logs leak secrets? Grep log statements for `password`, `token`, request bodies printed wholesale.
- Is there a correlation id per request that survives across services?

## A10 — Server-Side Request Forgery (SSRF)

- Any endpoint that fetches a URL supplied by the user? (image proxy, webhook configurer, PDF-from-URL, OAuth callback that fetches `openid-configuration`.)
- Is the URL's host allowlisted? Does the allowlist resolve the hostname and re-check against an internal-IP denylist (RFC1918 + link-local + cloud metadata)?
- Does it follow redirects? Each redirect is a fresh SSRF check, not just the first URL.

---

## Exit criteria

- For each category above, either a file:line citation proving it's handled, OR a finding logged with ruleId-shaped summary, OR an explicit "N/A — feature not present in this diff".
- Pair with `rafter run` results: cross-reference scanner findings against your manual walk. Scanner-only hits are candidates for triage (`rafter/docs/finding-triage.md`); manual-only hits are the ones scanners miss.
