# Dependencies & Supply Chain — Design Questions

Every dependency is a trust transfer: their bugs become yours, their maintainers become your dependency on goodwill. The question at design time is "is this worth the transfer?"

## Pick vs. write — which one

- Cryptography, authN / authZ primitives, parsers for complex formats, protocol implementations: **pick, don't write.** The library has years of eyes and fuzz time.
- Glue code, config loaders, small utility functions: **write, don't pick.** A 5-line helper beats a transitively-huge dependency.
- The middle (rate limiters, retry logic, caches): depends on how mature your language's standard library is. Go stdlib + a small helper often beats pulling in a 300-line middleware framework.

## Maintenance signal — before you adopt

Read the repo before adopting. Answers to these in one sitting:

- When was the last commit, release, CVE response? Dormant ≠ dead, but "last release 2019" for a security-adjacent lib is a risk.
- How many maintainers? Solo-maintainer packages are a bus-factor and takeover risk (npm `event-stream`, PyPI `ctx`).
- Does the project publish a security policy (SECURITY.md, GHSA history)? Projects that have handled CVEs well handle them well.
- Download count and reverse-dependency count: high-popularity packages get eyes on them; low-popularity is higher chance of silent badness.
- Typosquat / slopsquat check: is this the real package name? LLM-generated install instructions now routinely hallucinate package names that bad actors then register. Verify from the project's own README / GitHub.

## Install-time execution

- `postinstall` / `preinstall` / `prepare` hooks in npm, arbitrary `setup.py` code in Python, Gradle init scripts, Cargo build scripts — all run with your developer's or CI's permissions.
- Does your package manager have a way to disable these? npm `--ignore-scripts`, `pnpm install --ignore-scripts` + allowlist via `packageExtensions`. Pip has `--no-binary` but less granular.
- CI should install with the strictest flags. Developers can run with scripts enabled *after* review.

## Pinning & lockfiles

- Lockfile (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `Cargo.lock`, `go.sum`) committed. No exceptions for "libraries" — downstream lockfiles are the user's responsibility, but your CI needs reproducibility.
- Range pinning in the manifest (`^1.2.3`) is fine for libraries; applications benefit from exact pins + a lockfile for reproducibility.
- Lockfile verification in CI (`npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`, `poetry install --no-update`). Without verification, a drifted lockfile ships unknown code.

## Vendoring vs. registry

- Registry (npm, PyPI, Go proxy, crates.io): convenient, but the registry is a trust root. Compromise of a maintainer account has shipped malware repeatedly.
- Registry mirror / proxy (Artifactory, Cloudsmith, Google Artifact Registry): lets you cache + scan + pin. Best-of-both for teams with infra.
- Vendoring: committing dependency code into your repo. Highest control, highest cost. Justified for (a) critical dependencies you need to patch locally, (b) airgapped builds, (c) compliance requirements.

## SCA — hook it in, don't treat it as a quarterly task

- SCA on every PR and on main: Dependabot, Renovate, Snyk, Trivy, Grype, `rafter run` (which aggregates SCA).
- Auto-PRs for dependency updates: accept them with tests gating. Batching 3 months of updates is worse than a weekly drip.
- Critical CVEs (known-exploited, CVSS ≥ 9): page on detection, not "log and review later".
- Noise management: not every CVE applies to how you use the library. Triage policy is part of the design — who decides what's accepted, and how is the decision logged?

## Supply chain attacks to design against

- **Typosquat / slopsquat**: package name misspellings, especially for names an LLM might generate. Pin from upstream README only.
- **Dependency confusion**: your private package name registered publicly. Publish a placeholder of your internal package names, or use scoped packages with registry routing.
- **Maintainer takeover**: compromised maintainer account publishes malware. Defenses: pin by digest (where supported), monitor for unexpected releases.
- **Protestware / hacktivism**: maintainer deliberately ships malware or destructive code (e.g., `node-ipc`). Pinning catches it; SCA post-mortem confirms.
- **Compromised CI**: build-time tamper that injects malware into your artifact. Defenses: reproducible builds, signed provenance (SLSA), isolated build environment.

## Transitive depth

- How deep is the dep tree? `npm ls` / `cargo tree` / `pipdeptree`. Dozens of transitive deps per direct dep = huge attack surface.
- Does each direct dep pull in its own HTTP client, its own JSON parser, its own date library? Consolidate at the application level where possible.
- Transitive version conflicts: which wins? In npm / pnpm, hoisting rules. In Python, last-wins. Explicit `overrides` / `resolutions` let you force a patched version.

## Container images as dependencies

- Base images are dependencies — same maintenance questions apply. Distroless (Google-maintained) and Chainguard (security-first) are first-party; random Docker Hub images are not.
- Pin by digest. `image:tag` is mutable.
- Multi-stage builds: builder image can be heavy; final image should be minimal. Don't ship your build toolchain to prod.
- Image scanning in CI: `trivy image`, `grype`, cloud-native scanners. Block deploys on critical findings for production.

## SaaS dependencies

- Adopting a SaaS is also a dep: your data, their availability and security posture.
- Do they publish a SOC 2 / ISO 27001 / security whitepaper? Not gospel, but absence is a signal.
- Where does the data live (region, sub-processors)? For PII, this is a compliance question.
- Offboarding: if they vanish or you churn, how do you migrate? Vendor lock-in is a security issue too (can't rotate away from a breach).

## LLM / AI libraries — the new supply chain

- Model weights are dependencies. Which model, which version, hosted where?
- Inference SDKs (openai, anthropic, litellm) are dependencies with the standard risks *plus* credential-surface (API keys per provider).
- Vector DB clients (pinecone, qdrant, chroma) are dependencies that also hold your embeddings — classify accordingly.
- `prompt-injection-guard` style libraries are pattern-based and will never catch novel attacks — adopt but don't trust absolutely.

## Refuse-list

- Pulling a dependency from a raw git URL or GitHub tarball without pinning commit SHA.
- Adopting a package because an LLM suggested the name, without verifying it exists upstream (slopsquat bait).
- `:latest` tags on base images or dependency versions.
- CI that installs with `postinstall` enabled on every run without script review.
- Solo-maintained packages in your critical path (auth, crypto, payments) without a forking / vendoring plan.
- Adopting a SaaS for a compliance-scoped workload without reviewing their posture.
- Skipping the lockfile because "we're a library".
- SCA as a quarterly scan rather than a PR-level gate.

---

## Exit criteria

- Every new direct dependency has a one-line justification (pick vs. write, maintenance signal reviewed).
- Install-time execution policy is specified for CI.
- Lockfile + verification in CI is confirmed.
- SCA tool is wired to PRs, with a triage policy for findings.
- Base images are pinned by digest with a rebuild cadence.
- If the design uses a SaaS or LLM provider, the data-flow and credential-scope are drawn.
