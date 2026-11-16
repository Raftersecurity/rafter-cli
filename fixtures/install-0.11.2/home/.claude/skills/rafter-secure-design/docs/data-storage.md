# Data Storage — Design Questions

Where data lives determines blast radius. Every decision here is about making compromise cheap: key rotation, minimal retention, isolation by default.

## Classify — what *is* this data?

Before anything else, tag each field the design stores:

- **Identifier**: email, username, account id. Useful to enumerate, often PII on its own.
- **Credential**: password, API key, OAuth token, session id. Compromise = account takeover.
- **PII / PHI / PCI**: personal / health / payment. Regulatory scope — GDPR, HIPAA, PCI-DSS apply. Which?
- **Secret**: business-internal (encryption keys, signing keys, webhook secrets).
- **Content**: user-generated text, files, comments. Defamation / CSAM risk is real — do you have a moderation path?
- **Derived**: embeddings, summaries, ML features. Often treated as "not the original data" but can leak it — an embedding can sometimes reconstruct input.
- **Audit / log**: who did what when. Usually keep-forever, but often contains identifiers — classify the fields, not just the collection.

If a field doesn't fit a bucket, ask why it's being stored at all. **Data you don't have can't leak.**

## Encryption at rest

- Is the store's default disk-encryption enough (AWS RDS / GCP Cloud SQL / DynamoDB with CMK)? For most data, yes — don't add a second layer without a reason.
- Application-level encryption is worth it when: (a) the DB operator is a different trust boundary than the app, (b) you need field-level access control tied to the app's authn, (c) compliance demands customer-managed keys. Don't encrypt application-side just to "feel safer" — you'll break queries, search, and analytics.
- Envelope encryption (KMS-wrapped DEKs) is the pattern for app-side encryption. Who holds the KEK? Can you rotate it without re-encrypting every row?
- Deterministic vs. randomized encryption: deterministic lets you query/join, but leaks equality. Decide per field.

## Keys — the *actual* security boundary

- Where do the keys live? KMS / HSM / Vault / env var? **Env var is weakest** — it ends up in logs, dumps, and `ps auxe` output.
- Who can *use* the key (decrypt) vs. who can *manage* the key (rotate, destroy)? These must be separate IAM principals.
- Rotation schedule: signing keys < 1 year, data keys rotated via envelope re-wrap (cheap), password hashing upgrade on login (transparent).
- Key separation by tenant: single tenant per key is strongest (revoke = delete tenant key) but expensive. Per-tenant DEK with a shared KEK is a good middle ground.
- Break-glass: how do you get out when KMS is down? Do you have a tested runbook, or will you find out during the incident?

## Secrets (the application's own)

- Application secrets (DB passwords, API keys, signing keys, webhook secrets) go in a secret manager (Vault, AWS Secrets Manager, GCP Secret Manager, Kubernetes Secrets with encryption-at-rest). **Not in env vars committed to repo; not in env vars set by deploy scripts that log them.**
- Rotation: can you rotate without an outage? If the answer is "restart every service", that's OK for weekly but not daily. For rotation under pressure (leak detected), test the runbook *before* the leak.
- Least privilege: each service gets its own secret with the smallest scope. The web frontend does not need the DB's admin password.

## Encryption in transit

- TLS everywhere, including internal. "Internal network is trusted" is not a posture, it's a wish.
- What TLS version floor? TLS 1.2 is the practical minimum in 2026; 1.3 is the default for new designs.
- Certificate management: automated (ACME, cert-manager, cloud-managed) or manual? Manual renewal is a recurring outage.
- mTLS for service-to-service? Worth it when services are owned by different teams or spans security zones.

## Retention & deletion

- How long does each class live? Default to **shortest defensible** — you're not obligated to keep it forever. Data you delete can't subpoena, leak, or breach.
- GDPR / CCPA deletion: when a user requests deletion, *what* is deleted? Logs, backups, analytics exports, ML training sets, embeddings? If the answer is "we'll figure it out", you'll fail an audit.
- Soft-delete vs. hard-delete: soft-delete is good for recovery windows, bad for compliance. After the window closes, hard-delete and prove it (cryptographic erasure = destroy the key).
- Backup scope: backups inherit the data's sensitivity. Are backups encrypted with a *different* key than live data (so a live-data compromise doesn't grant backups)?

## Tenancy isolation

- Row-level: single DB, tenant_id column. Cheapest, weakest — one missed `where tenant_id` = cross-tenant leak.
- Schema-per-tenant: same DB, separate schemas. Mid-cost, mid-strength — ORM must respect search_path.
- DB-per-tenant: separate DB per tenant. Most expensive, strongest — compromise of one DB doesn't leak others.
- Decide by the cost of a cross-tenant leak, not by current scale. Upgrading later means a data migration.

## Logs — the forgotten data store

- Do logs contain the data classified above? Request bodies wholesale, error messages with stack traces containing secrets, URL query strings with tokens, user inputs echoed back — all common.
- Who reads logs? A dev on their laptop? A SaaS log provider? Each hop is a trust boundary. Scrub secrets before the hop.
- Log retention is often longer than the application's data retention — a GDPR deletion that misses logs is incomplete.

## Caches, queues, search indices

- Redis / Memcached / Elasticsearch / SQS / Kafka — each is a secondary data store. Classify what's in it.
- Is the cache encrypted at rest? Accessible over TLS? Authenticated? **Unauthenticated Redis on a public IP is still the #1 cloud leak source in 2026.**
- Search indices often copy data verbatim — a deleted record in the DB can linger in Elasticsearch unless you wire the deletion into both.

## Refuse-list

- Custom crypto primitives ("we xor with a rotating key"). Pick `libsodium` / `AEAD` via a maintained library.
- Storing passwords reversibly. Ever.
- Log statements that print request bodies, auth headers, or token-bearing URLs.
- Backups in the same blast radius as live data (same account, same region, same key).
- Tenant isolation enforced only at the ORM layer (raw queries bypass it).
- Embeddings / ML features stored without the classification that the source data had.

---

## Exit criteria

- Every stored field has a classification and a retention policy.
- Encryption story names specific keys, a specific KMS, and a rotation cadence.
- Secret distribution path is explicit — not "env vars set by Terraform".
- Deletion path is defined for each data class, including logs and backups.
- Tenant isolation level is chosen with a written justification.
