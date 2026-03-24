# Competitive Comparison: AI Agent Security Tools

A factual comparison of tools that secure AI coding agents — secret scanning,
command interception, policy enforcement, and audit logging for autonomous
development workflows.

Last updated: 2026-03-24

## Tools Compared

| Tool | Vendor | Primary Focus |
|------|--------|---------------|
| [Rafter CLI](https://rafter.so) | Rafter Security | Full-stack agent security: secrets, command interception, audit, MCP |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Snyk | Agent skill/MCP configuration scanning |
| [Knostic Kirin](https://www.getkirin.com/) | Knostic | IDE-layer agent governance and data protection |
| [GitGuardian MCP](https://github.com/GitGuardian/ggmcp) | GitGuardian | Secret scanning via MCP server (API-backed) |

---

## Feature Matrix

| Capability | Rafter CLI | Snyk Agent Scan | Knostic Kirin | GitGuardian MCP |
|------------|-----------|-----------------|---------------|-----------------|
| **Platforms supported** | 8 | 9 (scan) / 3 (guard) | 3 (+ 3 coming soon) | 4 |
| **Install method** | `npm` / `pip` | `uvx` / `pip` / `brew` | IDE extension (.vsix) | `uvx` / `pip` |
| **Install friction** | One command, no account | Requires Snyk account + API token | Extension install, account for full features | Requires GitGuardian API account |
| **Free tier** | Yes — full agent security, no API key | Yes — scan only (free Snyk account) | Yes — individual tier (basic features) | Yes — MIT server, free GG account (25 devs) |
| **Secret scanning** | 21+ built-in patterns (local) | 2 skill-level checks (not general-purpose) | Real-time redaction (no published pattern count) | 500+ detectors (API-based, not local) |
| **Command interception** | Yes — 4-tier risk classification | Private preview only (Agent Guard) | Yes — blocks risky commands | No |
| **MCP server** | Yes — scan, evaluate, audit, config | Snyk Studio (enterprise MCP server) | MCP proxy for monitoring | Yes — scan, honeytokens, incidents |
| **Audit logging** | Yes — local JSONL, queryable by event/date | No (scan) / Private preview (guard) | Yes — logs every allow/block decision | No |
| **CI/CD integration** | GitHub Actions, GitLab CI, CircleCI, pre-commit | CLI usable in CI (no templates) | IDE + CI/CD dependency scanning | Not the MCP server (ggshield is separate) |
| **Pre-commit hook** | Yes — built-in + pre-commit framework | No | No | No (ggshield has this separately) |
| **Skill/extension auditing** | Yes — quick scan + deep analysis | Yes — core feature (16 issue codes) | Yes — monitors extensions/plugins | No |
| **Works offline** | Yes — all agent security features | No — requires Snyk API | Unclear — cloud components likely | No — requires GitGuardian API |
| **Open source** | Yes (MIT) | Agent Scan is open source | No | Yes (MIT) |

---

## Platform Support Detail

| Agent / IDE | Rafter | Snyk Agent Scan | Knostic Kirin | GitGuardian MCP |
|-------------|--------|-----------------|---------------|-----------------|
| Claude Code | Hooks + Skills | Yes | Yes | No |
| Codex CLI / OpenClaw | Skills | Yes | Coming soon | No |
| Gemini CLI | MCP server | Yes | No | No |
| Cursor | MCP server | Yes | Yes | Yes |
| Windsurf | MCP server | Yes | Coming soon | Yes |
| Continue.dev | MCP server | No | No | No |
| Aider | MCP server | No | No | No |
| Claude Desktop | — | Yes | No | Yes |
| VS Code | — | Yes | No | No |
| GitHub Copilot | — | No | Yes | No |
| JetBrains | — | No | Coming soon | No |
| Zed | — | No | No | Yes |

---

## Installation Comparison

### Rafter CLI

```sh
npm install -g @rafter-security/cli    # Node.js
pip install rafter-cli                  # Python
rafter agent init --all                 # auto-detect and configure agents
```

No account required for agent security features. One command installs, one
command configures all detected agents.

### Snyk Agent Scan

```sh
uvx snyk-agent-scan@latest             # requires uv package manager
# or
pip install snyk-agent-scan
# or
brew install snyk-agent-scan
```

Requires a free Snyk account and API token from app.snyk.io before first use.
Agent Guard (runtime command interception) is in private preview — requires
enrollment as a design partner.

### Knostic Kirin

Download the `.vsix` extension from GitHub and install in Cursor or VS Code.
No npm or pip package. Account required for team/enterprise features.

### GitGuardian MCP

```sh
uvx --from git+https://github.com/GitGuardian/ggmcp.git developer-mcp-server
```

Requires a GitGuardian API account (free tier available for up to 25
developers). Authentication via OAuth 2.0 or Personal Access Token.

---

## Secret Scanning

| Attribute | Rafter | Snyk Agent Scan | Knostic Kirin | GitGuardian MCP |
|-----------|--------|-----------------|---------------|-----------------|
| Detection method | Local regex (21+ patterns) | Skill-definition checks (2 codes) | Real-time redaction | Cloud API (500+ detectors) |
| Runs locally | Yes | Partially (sends data to Snyk) | Yes (IDE-layer) | No (sends to GG API) |
| Gitleaks integration | Yes (optional, more patterns) | No | No | No |
| Staged-file scanning | Yes (`--staged`) | No | No | No |
| Diff scanning | Yes (`--diff HEAD~1`) | No | No | No |
| Deterministic | Yes (same inputs = same findings) | N/A | Unclear | No (API-dependent) |
| Pre-commit blocking | Yes | No | No | No (ggshield does this separately) |

Rafter's built-in scanner covers AWS keys, GitHub tokens, Google API keys,
Slack tokens, Stripe keys, Twilio credentials, database connection strings,
JWTs, private keys, npm/PyPI tokens, and generic API keys. The same CLI
version always produces the same findings for the same input — no flaky CI.

GitGuardian has the broadest pattern library (500+) but requires sending file
contents to their cloud API. This is a trade-off: more detectors vs. data
leaving your machine.

---

## Command Interception

| Attribute | Rafter | Snyk Agent Guard | Knostic Kirin | GitGuardian MCP |
|-----------|--------|-----------------|---------------|-----------------|
| Available | Yes (GA) | Private preview | Yes | No |
| Risk classification | 4 tiers (critical/high/medium/low) | Hybrid rules + ML | Policy-based blocking | N/A |
| Blocks destructive commands | Yes (`rm -rf /`, fork bombs, `dd`) | Yes (design partners only) | Yes | N/A |
| Approval workflow | Yes (high-risk requires approval) | Yes | Yes | N/A |
| Git-aware | Yes (scans staged files on commit/push) | Unclear | Unclear | N/A |
| Policy file | Yes (`.rafter.yml` per-repo) | No public docs | Centralized policy | N/A |

Rafter is the only tool with generally available, documented command
interception and a published risk taxonomy. Snyk's Agent Guard offers similar
runtime capabilities but is not publicly available. Knostic Kirin blocks risky
commands but details on classification tiers are not published.

---

## Audit Logging

| Attribute | Rafter | Snyk Agent Scan | Knostic Kirin | GitGuardian MCP |
|-----------|--------|-----------------|---------------|-----------------|
| Local audit log | Yes (`~/.rafter/audit.jsonl`) | No | Yes | No |
| Event types | 6 (command, secret, sanitize, policy, scan, config) | N/A | Allow/block decisions | N/A |
| Queryable | Yes (by event type, date, count) | N/A | Dashboard-based | N/A |
| Format | JSON Lines | N/A | Centralized logs | N/A |
| Retention config | Yes (configurable days) | N/A | Enterprise feature | N/A |

---

## MCP Support

| Attribute | Rafter | Snyk | Knostic Kirin | GitGuardian MCP |
|-----------|--------|------|---------------|-----------------|
| MCP server | Yes (`rafter mcp serve`) | Snyk Studio (enterprise) | MCP proxy (monitoring) | Yes (`developer-mcp-server`) |
| Tools exposed | scan_secrets, evaluate_command, read_audit_log, get_config | Code scanning via Studio | N/A (proxy, not tool server) | scan_secrets, list_detectors, honeytokens, incidents |
| MCP config scanning | No | Yes (core feature — discovers and audits MCP configs) | Yes (real-time MCP inspection) | No |
| Transport | stdio | N/A | Proxy | stdio, HTTP/SSE |

Snyk and Knostic focus on _scanning MCP configurations_ for vulnerabilities
(prompt injection, tool shadowing). Rafter and GitGuardian _are_ MCP servers
that agents call for security operations. These are complementary approaches.

---

## CI/CD Integration

| Attribute | Rafter | Snyk Agent Scan | Knostic Kirin | GitGuardian MCP |
|-----------|--------|-----------------|---------------|-----------------|
| GitHub Actions | Yes (reusable action) | CLI usable (no action) | Unclear | No (ggshield has this) |
| GitLab CI | Yes (generator) | No | Unclear | No |
| CircleCI | Yes (generator) | No | Unclear | No |
| pre-commit framework | Yes (hook ID: `rafter-scan`) | No | No | No |
| CI config generator | Yes (`rafter ci init`) | No | No | No |

Rafter provides `rafter ci init` to auto-generate pipeline configuration for
GitHub Actions, GitLab CI, and CircleCI. It also publishes a reusable GitHub
Action (`Raftersecurity/rafter-cli@v0`) and a pre-commit hook.

---

## Unique Strengths by Tool

### Rafter CLI
- **Broadest agent coverage** — 8 platforms with documented integration paths
- **Zero-friction install** — `npm install` or `pip install`, no account needed
- **Fully offline** — all agent security features work without network access
- **Stable output contract** — documented exit codes, consistent JSON, UNIX-friendly
- **CI pipeline generator** — one command creates CI config for 3 platforms
- **Dual-mode** — combines local agent security with remote SAST/SCA code analysis

### Snyk Agent Scan
- **MCP skill security scanning** — 16 issue codes covering prompt injection, tool shadowing, toxic data flows
- **Agent red teaming** — simulates multi-step attack scenarios (unique capability)
- **Skill ecosystem research** — analyzed 3,984 skills, found 36.8% had security issues
- **Broad scan coverage** — discovers configs for 9 agent platforms

### Knostic Kirin
- **IDE-native governance** — operates at the IDE layer as an extension
- **Shadow AI detection** — discovers unauthorized AI tool usage across teams
- **Enterprise policy enforcement** — centralized policy management across organizations
- **Data protection** — DLP/DSPM integration for AI workflows

### GitGuardian MCP
- **Deepest secret detection** — 500+ detectors via GitGuardian's proven engine
- **Honeytoken management** — generate and deploy AWS honeytokens as tripwires
- **Incident remediation** — guided removal with file paths, line numbers, git cleanup commands
- **Self-hosted support** — works with on-premise GitGuardian instances

---

## Summary

Rafter provides the broadest platform coverage and lowest installation friction
of any tool in this comparison. It is the only tool that combines local secret
scanning, command interception, audit logging, MCP server, CI/CD integration,
and pre-commit hooks in a single, free, offline-capable package — installable
with one command and no account signup.

Other tools excel in specific areas: GitGuardian has deeper secret detection
(500+ patterns via API), Snyk has unique MCP skill auditing and red teaming
capabilities, and Knostic offers enterprise-grade governance and shadow AI
detection. However, each requires account setup, has platform limitations, or
gates key features behind private previews or enterprise tiers.

For teams that need agent security working in minutes across the most platforms
with the least friction, Rafter is the clear choice.
