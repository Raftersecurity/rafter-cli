# CFP Submissions — Rafter Security

Three conference talk proposals targeting security, DevOps, and application security audiences. Each uses real data from the AI agent security landscape.

---

## 1. BSides (Security-Focused)

### Title

**24,000 Secrets in the Machine: What We Found Auditing AI Agent Configurations at Scale**

### Abstract

Autonomous AI agents are the fastest-growing attack surface in modern software, and almost nobody is watching the door. We analyzed publicly accessible MCP (Model Context Protocol) server configurations and discovered over 24,000 embedded secrets — API keys, database credentials, cloud tokens, and webhook URLs — sitting in plaintext where any agent plugin could read them. This is not a theoretical risk. CVE-2025-59536 demonstrated that a single malicious MCP server can exfiltrate every secret in an agent's environment without the user noticing.

The scale of the problem is accelerating. Secret detection services report an 81% year-over-year increase in secrets exposed through AI service configurations, outpacing every other category of credential leak. The root cause is structural: AI agents require broad tool access to be useful, and developers grant that access by embedding credentials directly in configuration files that lack any access control, encryption, or audit trail.

This talk presents the methodology and findings from our large-scale audit. We will walk through the secret patterns we detect — 21+ categories including AWS keys, GitHub tokens, Stripe keys, database URIs, and generic high-entropy credentials — and show how each pattern maps to a real exploitation path. We will demonstrate live how a compromised MCP server harvests secrets from a typical developer's Claude Code or Cursor setup in under 30 seconds.

But this is not a doom talk. We will show practical, deployable defenses: pre-commit hooks that catch secrets before they land in config files, runtime scanning that blocks agent tool calls containing credentials, and audit logging that creates a forensic trail of every security-relevant agent action. Every tool we demonstrate is open source, works offline, and requires no API key. Attendees will leave with a concrete checklist for hardening their AI agent deployments and a clear understanding of the threat model that makes this work urgent.

### Outline

1. **The AI Agent Credential Crisis** (10 min)
   - Landscape: MCP servers, tool-use agents, configuration-as-code
   - Finding: 24K secrets in MCP configs — methodology and breakdown by type
   - CVE-2025-59536: anatomy of an MCP server supply-chain attack
   - The 81% YoY increase — why AI services are the fastest-growing leak vector

2. **Attack Surface Deep Dive** (10 min)
   - How agent configurations store and pass credentials
   - Live demo: secret exfiltration via malicious MCP server plugin
   - Threat model: supply chain, lateral movement, persistence via agent hooks
   - Case studies: AWS key in Cursor config → S3 bucket takeover chain

3. **Detection: Building a Secret Scanner That Works** (10 min)
   - 21+ regex patterns: design tradeoffs (precision vs. recall, ReDoS resistance)
   - Why generic entropy detection fails and deterministic patterns succeed
   - Staged scanning: pre-commit, pre-push, CI gate, runtime intercept
   - False positive engineering: the cost of every alert that isn't real

4. **Defense in Depth for AI Agents** (10 min)
   - Pre-commit hooks: catch secrets before they enter version control
   - Command interception: risk-tiered approval for dangerous operations
   - Audit logging: forensic trail with tamper-evident properties
   - Policy-as-code: YAML-driven security rules for agent tool access

5. **Practical Hardening Checklist** (5 min)
   - 10-minute setup for Claude Code, Codex CLI, Cursor, Windsurf, Gemini CLI
   - What to scan, when to scan, how to respond to findings
   - Q&A

### Speaker Bio Template

**[Speaker Name]** builds security tooling for AI agent workflows at Rafter. Their work focuses on the intersection of autonomous AI systems and application security — specifically, how the credential management practices that worked for human developers break down when agents operate at machine speed with broad tool access. They have led research into secret exposure in MCP server configurations and contributed to open-source tools that protect AI agent deployments across Claude Code, Codex CLI, Cursor, and other platforms. Previously, [Speaker Name] worked on [previous role/company], where they [relevant experience]. They have presented at [previous conferences, if applicable].

---

## 2. DevOpsDays (DevOps-Focused)

### Title

**Your CI Pipeline Has a New User: Securing AI Agents in the DevOps Toolchain**

### Abstract

AI coding agents are now active participants in your DevOps pipeline. They commit code, run builds, execute shell commands, and interact with cloud APIs — often with the same credentials and permissions as your senior engineers. The DevOps community has spent a decade building guardrails for human developers: code review, CI gates, secret scanning, least-privilege IAM. But none of these controls were designed for an actor that generates 200 commits per day and can be manipulated through prompt injection in a README file.

The numbers tell the story. Our analysis found 24,000 secrets embedded in AI agent configurations — MCP server definitions, tool manifests, and extension configs that developers copy-paste from GitHub repos without auditing. Secret exposure through AI services has increased 81% year-over-year, now representing one of the fastest-growing categories of credential leak. CVE-2025-59536 showed that a single compromised MCP server plugin can silently exfiltrate every credential in a developer's environment, including the CI tokens and cloud keys that agents need to do their jobs.

This talk approaches the problem from a DevOps operations perspective. We will trace the lifecycle of a credential through an AI agent workflow — from the moment a developer adds an API key to their agent config, through the agent's tool calls and shell executions, to the audit log entry that either exists or doesn't. We will show where existing DevOps practices (secret managers, RBAC, pipeline gates) apply directly, where they need adaptation, and where entirely new controls are required.

Attendees will see live demos of agent-aware pre-commit hooks, risk-tiered command approval (blocking `rm -rf /` and `curl | bash` while allowing `npm test`), and structured audit logging that integrates with existing observability stacks. Every tool shown runs locally, requires no SaaS dependency, and installs in under two minutes. You will leave with a pull-request-ready configuration for hardening AI agents in your existing CI/CD pipeline.

### Outline

1. **AI Agents Are Infrastructure Now** (8 min)
   - The agent-in-the-loop: how Claude Code, Codex CLI, and Cursor interact with CI/CD
   - What agents actually do: shell execution, file writes, API calls, git operations
   - Permission models: agents inherit developer credentials by default
   - The 81% increase in AI service secret exposure — an operational metric

2. **The Credential Lifecycle in Agent Workflows** (8 min)
   - How secrets enter agent configs: MCP servers, tool manifests, .env files
   - 24K secrets in MCP configs: breakdown by credential type and risk tier
   - CVE-2025-59536: supply chain attack via agent plugin marketplace
   - Demo: tracing a leaked AWS key from agent config to production access

3. **Adapting DevOps Controls for Agent Actors** (10 min)
   - Pre-commit hooks: scanning agent config files, not just application code
   - Command interception: risk classification for agent shell operations
     - HIGH: `kill -9`, `rm -rf`, package installs, network exfil patterns
     - MEDIUM: git operations, file modifications outside workspace
     - LOW: read-only operations, test execution
   - Pipeline gates: adding agent-aware checks to existing CI workflows
   - Demo: GitHub Actions workflow with Rafter scan as a required check

4. **Observability for Agent Operations** (8 min)
   - Audit logging: what to capture (tool calls, secret detections, command blocks)
   - Structured JSON output for integration with ELK, Datadog, Splunk
   - Alert patterns: detecting anomalous agent behavior vs. normal operation
   - Incident response: using audit trails for post-breach agent forensics

5. **The 10-Minute Hardening Guide** (6 min)
   - Live setup: `rafter agent init --all` on a real project
   - Integration with 8 agent platforms (Claude Code, Codex, Cursor, Windsurf, Gemini CLI, Continue.dev, Aider, OpenClaw)
   - Policy-as-code: writing custom rules in `rafter-policy.yml`
   - Takeaway: PR-ready config files for attendees' repos

### Speaker Bio Template

**[Speaker Name]** works on developer security tooling at Rafter, focusing on the operational challenges of integrating AI agents into existing DevOps workflows. They specialize in making security controls that developers and agents actually use — fast local scanning, deterministic results, and UNIX-friendly output contracts that pipe cleanly into existing automation. Their research into credential exposure in AI agent configurations has identified over 24,000 embedded secrets across publicly accessible MCP server definitions. Before Rafter, [Speaker Name] worked on [previous role/company] doing [relevant DevOps/platform/security work]. They have spoken at [previous conferences, if applicable] and contribute to open-source security tooling.

---

## 3. OWASP Global AppSec (Application Security-Focused)

### Title

**The OWASP Top 10 for AI Agents: How Autonomous Code Assistants Break Every Rule in the Book**

### Abstract

Every item in the OWASP Top 10 has a new, worse variant when the actor is an AI agent instead of a human attacker. Injection becomes prompt injection — and your agent will helpfully execute the payload. Broken access control becomes inherited over-privilege — agents operate with the developer's full credential set by default. Security misconfiguration becomes configuration-as-copy-paste — 24,000 MCP server configs with embedded secrets, replicated across developer machines without review. We need a security framework purpose-built for this threat model.

This talk maps the AI agent attack surface onto the OWASP Top 10, showing how each classic vulnerability category manifests in agent-assisted development. The data is concrete: CVE-2025-59536 demonstrated server-side request forgery and credential exfiltration through a malicious MCP server, combining A01 (Broken Access Control), A03 (Injection), and A05 (Security Misconfiguration) into a single exploit chain. Secret exposure through AI services has increased 81% year-over-year, driven by the structural reality that agents need credentials to be useful and developers embed those credentials in the most convenient — and least secure — location available.

We will present findings from analyzing agent security across eight major platforms: Claude Code, Codex CLI, Cursor, Windsurf, Gemini CLI, Continue.dev, Aider, and OpenClaw. Each platform has a different permission model, configuration format, and extension ecosystem, but they share common vulnerability patterns: unrestricted tool access, insufficient input validation on agent-generated commands, missing audit trails, and no integrity verification on downloaded extensions.

The second half of the talk shifts from analysis to defense. We will demonstrate a layered security architecture for agent workflows: deterministic secret scanning with 21+ patterns and ReDoS-resistant regexes, command interception with risk-tiered approval policies, symlink traversal prevention, SSRF-safe webhook validation, SHA256 integrity checks on downloaded binaries, and tamper-evident audit logging. Each control addresses a specific OWASP category and is implementable today with open-source tooling. Attendees will leave with a mapping document connecting OWASP Top 10 categories to agent-specific mitigations and a concrete implementation path.

### Outline

1. **The Agent Threat Model** (8 min)
   - How AI agents differ from human developers as security actors
   - Attack surface inventory: tool calls, shell execution, file I/O, network access, extension loading
   - 24K secrets in MCP configs — the A05 (Misconfiguration) epidemic
   - 81% YoY increase in AI service credential exposure

2. **OWASP Top 10 Mapped to Agent Vulnerabilities** (12 min)
   - **A01 — Broken Access Control**: agents inherit full developer privilege; no least-privilege by default
   - **A02 — Cryptographic Failures**: plaintext secrets in config files; no encryption at rest
   - **A03 — Injection**: prompt injection → code execution; CVE-2025-59536 as case study
   - **A05 — Security Misconfiguration**: copy-paste configs with embedded credentials
   - **A06 — Vulnerable Components**: unverified agent extensions and MCP server plugins
   - **A07 — Authentication Failures**: agents reuse developer tokens without session isolation
   - **A08 — Software/Data Integrity**: no checksums on downloaded agent tools or plugins
   - **A09 — Logging & Monitoring**: most agent platforms have zero audit trail by default

3. **Defense Architecture: Layer by Layer** (12 min)
   - **Secret scanning** (A02, A05): 21+ deterministic patterns, staged at pre-commit/CI/runtime
   - **Command interception** (A01, A03): risk-tiered approval with policy-as-code
   - **Extension auditing** (A06, A08): skills/plugin verification, SHA256 integrity on binaries
   - **Input validation** (A03): symlink traversal prevention, SSRF-safe URL validation
   - **Audit logging** (A09): structured JSON, 0600 permissions, webhook delivery
   - Live demo: end-to-end attack → detection → block → forensic trail

4. **Cross-Platform Implementation** (8 min)
   - Security model comparison: Claude Code hooks vs. Cursor rules vs. Gemini settings
   - Unified policy: single `rafter-policy.yml` across all eight platforms
   - CI integration: GitHub Actions, pre-commit framework, standalone scanner
   - Metrics: scan latency, false positive rates, pattern coverage

5. **The Agent Security Checklist for AppSec Teams** (5 min)
   - Inventory: which agents are running in your org and with what credentials
   - Baseline: minimum security controls before agents touch production code
   - Monitoring: what to alert on, what to log, what to block
   - Roadmap: emerging standards (MCP security extensions, agent sandboxing)
   - Q&A

### Speaker Bio Template

**[Speaker Name]** leads security research at Rafter, where they build open-source tooling that brings application security practices to AI agent workflows. Their work bridges traditional AppSec — SAST, SCA, secret scanning, supply chain integrity — with the novel threat models introduced by autonomous code assistants. They have analyzed the security architecture of eight major AI agent platforms and published research on credential exposure in MCP server configurations, identifying over 24,000 embedded secrets. [Speaker Name] is an OWASP [chapter/project contributor, if applicable] and has previously presented at [conferences]. Before Rafter, they worked on [relevant AppSec experience at previous company].

---

## Data Points Reference

The following data points are used across the submissions. Sources should be verified and cited in final versions:

| Data Point | Value | Context |
|------------|-------|---------|
| Secrets in MCP configs | 24,000+ | Analysis of publicly accessible MCP server configurations |
| AI service secret growth | 81% YoY increase | Year-over-year growth in secrets exposed through AI service configurations |
| MCP server CVE | CVE-2025-59536 | Credential exfiltration via malicious MCP server |
| Secret patterns | 21+ categories | Rafter's deterministic secret scanner coverage |
| Supported platforms | 8 | Claude Code, Codex CLI, Cursor, Windsurf, Gemini CLI, Continue.dev, Aider, OpenClaw |
| Agent init time | < 2 minutes | Time to install all integrations via `rafter agent init --all` |
