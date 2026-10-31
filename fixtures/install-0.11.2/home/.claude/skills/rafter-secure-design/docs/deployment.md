# Deployment — Design Questions

Deployment is where "the app is secure" meets reality. Network boundaries, runtime posture, secret distribution, build provenance — each decided here survives every refactor of the code.

## Network topology — zones, not flat

- Sketch zones: public edge (LB / CDN / WAF), app tier, data tier, admin tier, third-party egress. Each is a distinct security zone.
- What traffic is allowed **between** zones, and what's denied by default? Default-deny is the only sane starting point. If the default is allow and you block selectively, you're one misconfiguration from exposure.
- Public edge: what terminates TLS? WAF in front or not? WAF is good for cheap-filter; not a substitute for app-side validation.
- Admin access (SSH, kube-exec, DB console): over the public internet? Over a VPN / zero-trust proxy (Tailscale, Cloudflare Access, Teleport)? The public-internet-with-a-bastion is a 2005 pattern.

## Egress — the forgotten boundary

- Can your app reach arbitrary internet destinations? Default should be "allowlist of known egress targets" (external APIs you integrate with, OS package mirrors, telemetry).
- Egress control is the best SSRF defense *and* the best data-exfiltration defense. If a compromised app can only reach `api.stripe.com`, the blast radius is Stripe calls.
- Metadata services (169.254.169.254): block at the network layer, not just the app. IMDSv2 on AWS (required hop limit = 1 + session token) blocks the rebinding variant.

## Identity & IAM

- Every compute workload has a workload identity (AWS IAM role, GCP service account, Kubernetes ServiceAccount + bound tokens, SPIFFE ID). **Not shared credentials, not long-lived keys.**
- Least privilege per workload. "The web service has DB read + DB write + admin on this one table" is better than "the web service has AdminAccess".
- Break-glass access: there's an auditable path for a human to gain emergency privileges. Not a shared `root` password.
- IAM changes go through code review (Terraform PR, Pulumi PR). Click-ops IAM is how wide-open permissions persist.

## Secret distribution

- Where does each service get its secrets? Secret manager (Vault, AWS SM, GCP SM, Kubernetes Secrets with sealed / external-secrets), *not* Terraform-plan output, *not* env vars set by a deploy script that logs them.
- Secrets rotate. Short-lived DB credentials (Vault dynamic secrets, IAM database auth) > long-lived passwords. If your design says "quarterly rotation of a static password", name who does it and how.
- Secrets are scoped per service. The web tier doesn't have the admin DB credential.
- Encryption-at-rest for the secret manager itself: by default on all cloud-managed; verify for self-hosted.
- Secrets in CI: scoped per job, never printed to logs, masked in output. PR workflows triggered from forks don't see secrets.

## Container / runtime posture

- Run as non-root. If `USER 0` or `runAsUser: 0`, flag it.
- Read-only root filesystem where possible. Writable mounts are explicit (`/tmp`, named volumes).
- Capabilities: drop all, add back only what's needed. `CAP_NET_BIND_SERVICE` is the usual one.
- Seccomp / AppArmor / SELinux profile: a real profile, not "Unconfined".
- Resource limits: CPU and memory limits per container. No limit = one compromised pod can starve the node.

## Base images

- Distroless / Alpine / minimal / scratch > Ubuntu full. Fewer packages = fewer CVEs, smaller attack surface.
- Pin by digest (`image@sha256:...`), not tag. `:latest` and even `:v1.2.3` can be overwritten; digests are immutable.
- SCA on base images in CI. Re-pull / rebuild cadence (weekly) to pick up upstream patches.
- Who maintains the base image? First-party (your team) > team-adjacent > "some Docker Hub account". Unmaintained bases rot.

## Build provenance & supply chain

- Is the build reproducible? Given the same inputs, does a rebuild produce the same artifact? Not always achievable, but worth asking.
- SLSA level: aim for SLSA 3 (hosted builder, signed provenance) for anything shipping to production. SLSA 1 (provenance exists) is the minimum.
- Artifact signing: Sigstore / Cosign / Notary. Signatures verified at deploy, not just at build.
- Dependency pinning: lockfile committed, lockfile verified in CI.
- `postinstall` / `prepare` scripts from dependencies: ban or audit. These execute arbitrary code on install — it's the npm supply-chain attack class.
- SBOM generation at build time. Store it with the artifact.

## CI/CD posture

- Who can deploy to prod? Production deploys gated on approval, signed tags, or protected branch merges.
- CI runners: ephemeral (fresh VM / container per job), not long-running hosts with persistent state.
- Workflow permissions: least-privilege GITHUB_TOKEN / equivalent. Write-all is the click-to-compromise default.
- Self-hosted runners + public repo = RCE. Either make the repo private, use GitHub-hosted runners for public workflows, or lock runners to specific workflows.
- Branch protection: required reviews, required status checks, no force-push to main. Linear history if you need audit simplicity.

## Production-vs-staging parity

- Same architecture in staging as prod, with masked / synthetic data. Staging that uses prod data = a second prod blast radius with half the controls.
- Config differences are explicit and minimal. "We disable auth in staging" is how auth gets disabled in prod one day by accident.
- Feature flags that default-off in prod and default-on in staging: tested in both states.

## Multi-region / DR

- If the design spans regions: is the active/passive or active/active model clear? What's replicated, what's per-region?
- Encryption keys per region, or a global key? (Global is simpler but expands blast radius.)
- Failover runbook exists and was tested in the last 12 months. Not-yet-tested = doesn't work.

## Logging & monitoring posture

- Structured logs, shipped to a separate system (not the same DB the app writes to). A compromise of app storage shouldn't delete the audit trail.
- Authentication to the log system: workload identity, not shared token.
- What paging signals exist? Login-anomaly rates, authZ denials, 5xx surges, unusual egress — without these, the breach is found by the customer.
- Retention: logs often outlive production data. Classify log contents and apply retention accordingly.

## Refuse-list

- Long-lived static cloud credentials baked into container images or env vars.
- Privileged containers (`privileged: true`, `runAsUser: 0` without justification).
- `:latest` tags or unpinned base images in production manifests.
- CI workflows with write-all GITHUB_TOKEN scope by default.
- "We'll add network policy later" — network default-allow is not a plan.
- Secrets set via Terraform variable with plan output visible in logs.
- Shared SSH keys, shared `root` password, shared admin console.
- Metadata service reachable from a public-facing container (IMDSv1, or IMDSv2 with unlimited hop count).

---

## Exit criteria

- Zone diagram exists; cross-zone traffic is allowlisted, not denylisted.
- Each workload has a named identity and a scoped IAM role.
- Secret distribution names the secret manager and the rotation model.
- Container runtime posture is specified: user, filesystem, capabilities, resource limits.
- Build pipeline specifies provenance (SLSA), signing, and dependency pinning.
- Log shipping + retention is set, independent of application storage.
