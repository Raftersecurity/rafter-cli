# Standards & Frameworks — Pointers

This skill won't re-derive a compliance checklist. Pick the right baseline for your context, read the small number of sections that actually apply, and point your design doc at them. The goal is *known-adequate*, not *comprehensive*.

## How to choose a baseline

Answer these three before picking a framework:

1. **Regulatory scope**: GDPR / CCPA (personal data)? HIPAA (health)? PCI-DSS (payment cards)? SOX (financial reporting)? Each forces specific controls; skipping the wrong one is non-negotiable risk.
2. **Maturity goal**: "We need something defensible in review" (ASVS L1), "We handle meaningful PII" (ASVS L2 + SAMM intermediate), "We're a high-value target or regulated" (ASVS L3 + NIST SSDF + SOC 2).
3. **Audit horizon**: will anyone external look at this? If yes, align with their expected framework early; retrofitting evidence is expensive.

## App security baseline — OWASP ASVS

[OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/).

- **L1 — opportunistic**: external-facing apps without sensitive data. Covers basic auth, input validation, encoding, config. This is the floor; below L1 is "indefensible."
- **L2 — standard**: apps handling PII, business-critical data, or B2B integrations. Adds cryptography requirements, session depth, access-control rigor.
- **L3 — advanced**: high-value targets, regulated industries, critical infrastructure. Adds deep crypto requirements, defense-in-depth, hostile-environment assumptions.

**Design-time use**: pick your level, scan the chapter for your domain (auth → V2, session → V3, access control → V4, validation → V5, crypto → V6, etc.), lift the requirements that match your design. Don't copy all 280+ requirements — that's audit prep, not design.

`rafter-code-review/docs/asvs.md` has a deeper walk for review time.

## Secure development lifecycle — NIST SSDF / SP 800-218

[NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf).

Four practice areas — *PO* (prepare the org), *PS* (protect the software), *PW* (produce well-secured software), *RV* (respond to vulnerabilities). Most relevant at design time:

- **PW.1**: design software to meet security requirements and mitigate risks — the "why are we doing this skill" requirement.
- **PW.4**: reuse existing well-secured software — dependency selection (see `docs/dependencies.md`).
- **PW.6**: configure compilation/build/runtime for security — deployment posture.
- **RV.1**: identify vulnerabilities on ongoing basis — SCA + scanning.

Use SSDF as the program-level framework; ASVS fills in the per-app details.

## Cloud & infra — CSA CCM / CIS Benchmarks / AWS Well-Architected

- **[CSA Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)**: cloud-native control framework, maps to ISO 27001 / SOC 2 / NIST / etc. Good for answering "are we doing the cloud thing right?"
- **[CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)** per cloud / OS / Kubernetes: concrete configuration checklists. Use for hardening specific components.
- **[AWS Well-Architected — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)** (or GCP/Azure equivalents): opinionated cloud-architecture guidance. Start here before CCM for most AWS-native designs.

Pick one per component. Don't adopt all three to "maximize coverage" — they overlap and you'll drown.

## Threat modeling reference

- **[Microsoft STRIDE](https://learn.microsoft.com/en-us/security/securing-devops/threat-modeling)** — the classic, used in `docs/threat-modeling.md`.
- **[MITRE ATT&CK](https://attack.mitre.org/)** — tactics/techniques for *real-world* attacker behavior. Use to sanity-check "what would an attacker actually do?"
- **[OWASP ASVS-companion ATM process](https://owasp.org/www-project-threat-modeling/)** — OWASP-flavored threat modeling methodology.
- **[LINDDUN](https://linddun.org/)** — privacy-focused threat modeling (complement to STRIDE for PII-heavy designs).

## Privacy & compliance

- **GDPR**: data minimization, purpose limitation, user rights (access, deletion, portability), data transfer restrictions. Design-time decisions: what you collect, why, how long, where it lives.
- **CCPA / CPRA**: similar shape, California-specific. Know-your-rights, opt-out of sale.
- **HIPAA** (US health): PHI definition, covered entity / BA relationships. Requires BAAs with sub-processors.
- **PCI-DSS** (cards): scope reduction is the name of the game — tokenize early, keep cardholder data out of your systems.
- **SOC 2**: not a regulation, a report. Trust Services Criteria (Security, Availability, Confidentiality, Processing Integrity, Privacy). Design maps to controls; audit reads evidence.
- **ISO 27001**: information security management system. Certification is program-level, not design-level, but many controls live in design decisions.

At design time, the answer is usually "we're in scope for X, Y; Z doesn't apply; here's the mapping." Not a full compliance plan — just a pointer.

## AI / LLM-specific

- **[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** (2025): prompt injection, data disclosure, supply chain, poisoning, improper output handling, excessive agency, prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption.
- **[MITRE ATLAS](https://atlas.mitre.org/)**: ATT&CK for AI/ML systems.
- **[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)**: risk management framework for AI (govern, map, measure, manage).
- **EU AI Act** (if you ship in EU): risk categories + obligations. High-risk systems have heavy requirements; general-purpose AI has lighter.

`rafter-code-review/docs/llm.md` walks LLM top 10 for review time.

## Cheap-and-fast subset to start with

If you have 30 minutes and need a defensible baseline for a new feature:

1. Pick ASVS L1 or L2 (L2 if any PII).
2. Read the chapter that matches your design's top risk (auth / input / access control / crypto — whichever is most novel).
3. Check CIS Benchmark for your cloud + one container-level CIS (if containerized).
4. Write the applicable compliance scope (GDPR? HIPAA? none?).
5. Document the threat-model pass result (from `docs/threat-modeling.md`).

This is less than a full compliance program and more than "we winged it." Most features don't need more at kickoff.

## When to hire the specialist

The pointers above get you to "informed designer." They do not replace:

- A pentester on a high-risk launch.
- A compliance counsel for novel regulatory scope (PCI-DSS 4.0, GDPR cross-border, HIPAA BAs).
- A third-party audit for SOC 2 / ISO 27001 / FedRAMP.

Budget for these where the risk warrants. Skipping them is a risk transfer to the future, usually at a higher cost.

---

## Exit criteria

- The applicable regulatory scope is named (or "none, B2B internal only, accepted").
- The baseline framework is picked (ASVS L?, SSDF yes/no).
- The specific sections of the framework that match this design's novel risks are cited in the design doc.
- Compliance obligations (if any) are routed to a human owner, not left as "TBD".
