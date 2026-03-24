# Awesome List Submissions for Rafter CLI

Prepared PR content and submission instructions for each target awesome list.

---

## 1. awesome-mcp-servers

**Repo:** [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers)

### Submission Method

Fork repo, edit `README.md`, submit PR. Append `🤖🤖🤖` to PR title for expedited merge.

### Section

`### 🔒 Security` — insert alphabetically (after entries starting with "q", before "rad-security").

### Entry (copy-paste into README.md)

```markdown
- [Raftersecurity/rafter-cli](https://github.com/Raftersecurity/rafter-cli) 📇 🏠 🍎 🪟 🐧 - Security agent CLI with MCP server for AI coding workflows. Provides SAST/SCA code analysis, secret scanning, command risk assessment, and audit logging via `rafter mcp serve`.
```

### PR Title

```
Add Raftersecurity/rafter-cli to Security section 🤖🤖🤖
```

### PR Description

```markdown
## What

Adds [Rafter CLI](https://github.com/Raftersecurity/rafter-cli) to the Security section.

## About Rafter

Rafter is a security agent CLI that exposes an MCP server via `rafter mcp serve`. It provides:

- **SAST/SCA code analysis** — Remote code analysis on GitHub repos via the Rafter API
- **Secret scanning** — 21+ credential patterns with deterministic detection
- **Command risk assessment** — Risk-tiered approval for dangerous commands
- **Audit logging** — Full audit trail for AI agent sessions

Rafter is designed as a delegation primitive: AI agents and orchestrators defer security decisions to it and trust the structured outputs. It works with Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Continue.dev, and Aider.

- **License:** MIT
- **Language:** TypeScript/JavaScript (Node.js) + Python
- **Runs locally** — no API key required for agent security features
- **Platforms:** macOS, Windows, Linux
```

### Contribution Guidelines Notes

- Maintain alphabetical order within the Security section
- One server per line
- Use correct emoji codes: `📇` (TypeScript/JS), `🏠` (local), `🍎` (macOS), `🪟` (Windows), `🐧` (Linux)

---

## 2. awesome-claude-code

**Repo:** [hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code)

### Submission Method

**DO NOT open a PR.** Submissions must be made via the GitHub web UI issue form:
https://github.com/hesreallyhim/awesome-claude-code/issues/new?template=recommend-resource.yml

**DO NOT use the `gh` CLI** — this is explicitly banned.

**Submissions must be made by a human**, not an agent.

### Category

**Tooling** (General) — Rafter is a standalone CLI that wraps around Claude Code to provide security guardrails, similar to existing Tooling entries like `claude-code-tools` and `Container Use`.

### Issue Form Fields

| Field | Value |
|-------|-------|
| **Display Name** | Rafter |
| **Category** | Tooling |
| **Sub-Category** | Security |
| **Primary Link** | https://github.com/Raftersecurity/rafter-cli |
| **Author Name** | Rafter Security |
| **Author Link** | https://github.com/Raftersecurity |
| **License** | MIT |

### Description (1-3 sentences, no emojis, descriptive not promotional)

```
Security agent CLI that provides guardrails for Claude Code sessions. Installs pre-commit hooks, performs secret scanning with 21+ credential patterns, intercepts commands with risk-tiered approval, audits skills and extensions, and maintains audit logs. Integrates via `rafter agent init --with-claude-code`.
```

### Expected Entry Format (once accepted)

```markdown
- [Rafter](https://github.com/Raftersecurity/rafter-cli) by [Rafter Security](https://github.com/Raftersecurity) - Security agent CLI that provides guardrails for Claude Code sessions. Installs pre-commit hooks, performs secret scanning with 21+ credential patterns, intercepts commands with risk-tiered approval, audits skills and extensions, and maintains audit logs.
```

### Contribution Guidelines Notes

- The maintainer will run `.claude/commands/evaluate-repository.md` against the repo — consider running this evaluation first
- Resources must be at least one week old since first public commit
- If the tool makes network calls beyond Anthropic servers, this must be clearly stated
- Claims must be evidence-based — provide demo, video, or reproduction steps
- Security tools are heavily scrutinized — document permissions and network behavior clearly

---

## 3. awesome-security

**Repo:** [sbilly/awesome-security](https://github.com/sbilly/awesome-security)

### Submission Method

Fork repo, edit `README.md`, submit PR. One suggestion per PR.

### Section

**Web > Development** — where existing SAST and code-scanning tools live (Insider CLI, Bearer, Checkov, etc.). Add at the bottom of the section.

### Entry (copy-paste into README.md)

```markdown
- [Rafter](https://github.com/Raftersecurity/rafter-cli) - A security CLI for SAST/SCA code analysis, secret scanning (21+ patterns), pre-commit hooks, command risk assessment, and audit logging. Designed as a delegation primitive for AI agent security workflows.
```

### PR Title

```
Add Rafter CLI to Web > Development section
```

### PR Description

```markdown
## What

Adds [Rafter CLI](https://github.com/Raftersecurity/rafter-cli) to the Web > Development section.

## About Rafter

Rafter is a multi-language security CLI that provides:

- **SAST/SCA code analysis** — Remote static analysis on GitHub repos with structured vulnerability reports
- **Secret scanning** — 21+ credential patterns (AWS keys, API tokens, private keys, etc.) with deterministic detection
- **Pre-commit hooks** — Blocks commits containing secrets before they reach the repo
- **Command risk assessment** — Risk-tiered approval for dangerous shell commands
- **Audit logging** — Complete audit trail of security events

Rafter works as a delegation primitive for AI coding agents (Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, etc.), but is equally useful as a standalone security tool.

- **License:** MIT
- **Platforms:** macOS, Windows, Linux
- **Install:** `npm install -g @anthropic/rafter` or `pip install rafter-security`
```

### Contribution Guidelines Notes

- Search previous suggestions to avoid duplicates
- New links go at the bottom of the relevant category
- Check spelling and grammar
- Remove trailing whitespace

---

## 4. awesome-static-analysis

**Repo:** [analysis-tools-dev/static-analysis](https://github.com/analysis-tools-dev/static-analysis)

### Submission Method

Fork repo, create `data/tools/rafter.yml`, submit PR. The README is auto-generated from YAML files — **do not edit the README directly**.

### YAML File: `data/tools/rafter.yml`

```yaml
name: Rafter
categories:
  - linter
tags:
  - security
  - javascript
  - typescript
  - python
  - go
  - ruby
  - java
  - ci
license: MIT License
types:
  - cli
source: 'https://github.com/Raftersecurity/rafter-cli'
homepage: 'https://github.com/Raftersecurity/rafter-cli'
description: >-
  A security CLI for SAST/SCA code analysis and secret scanning with 21+
  credential patterns. Provides pre-commit hooks, command risk assessment,
  and audit logging. Designed as a delegation primitive for AI agent
  security workflows with structured JSON output.
```

### PR Title

```
Add Rafter — SAST/SCA and secret scanning CLI
```

### PR Description

```markdown
## What

Adds [Rafter CLI](https://github.com/Raftersecurity/rafter-cli) as a new tool entry.

## About Rafter

Rafter is a multi-language security CLI for SAST/SCA code analysis and secret scanning. Key features:

- **SAST/SCA analysis** — Static analysis on GitHub repos with structured vulnerability reports (JSON/Markdown)
- **Secret scanning** — 21+ credential patterns with deterministic detection
- **Pre-commit hooks** — Blocks commits containing secrets
- **Structured output** — Stable JSON contract for CI/CD integration and automated pipelines
- **AI agent integration** — Works as a security delegation primitive for Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, and more

Similar to existing entries like Semgrep, Gitleaks, and detect-secrets, but with additional focus on AI agent workflow security.

- **License:** MIT
- **Language:** TypeScript/JavaScript + Python
- **Category:** Linter (security)
```

### Contribution Guidelines Notes

- Tool must be actively maintained (more than one contributor)
- Tool should have 20+ GitHub stars or similar impact
- Project should exist for at least 3 months
- Description limited to 500 characters
- Use existing tags from `data/tags.yml`
- Run `make render` locally to validate before submitting

---

## Summary

| List | Repo | Method | Section/Category |
|------|------|--------|-----------------|
| awesome-mcp-servers | punkpeye/awesome-mcp-servers | PR to README.md | 🔒 Security |
| awesome-claude-code | hesreallyhim/awesome-claude-code | Web UI issue form (human only) | Tooling > Security |
| awesome-security | sbilly/awesome-security | PR to README.md | Web > Development |
| awesome-static-analysis | analysis-tools-dev/static-analysis | PR adding data/tools/rafter.yml | Multiple Languages (auto-generated) |

### Priority Order

1. **awesome-mcp-servers** — Highest traffic for MCP tool discovery, direct audience match
2. **awesome-claude-code** — Direct audience for Claude Code users, but requires human web submission
3. **awesome-static-analysis** — Large established list (756+ tools), good for SAST/secret scanning discovery
4. **awesome-security** — Broad security audience, good for general visibility
