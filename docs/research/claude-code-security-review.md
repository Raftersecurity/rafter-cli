# Research: claude-code-security-review

**Source**: https://github.com/anthropics/claude-code-security-review
**Date**: 2026-03-05
**Bead**: rc-q8c

## Overview

An AI-powered GitHub Action that uses Claude to perform semantic security review of
pull request code changes. It goes beyond pattern matching (traditional SAST) by using
Claude's reasoning to understand code semantics, intent, and context.

**Architecture**: Python-based GitHub Action that:
1. Fetches PR diff and metadata via GitHub API
2. Generates a structured security audit prompt
3. Runs Claude Code CLI (`claude --output-format json`) against the repo
4. Filters findings through hard rules + Claude API second-pass
5. Posts findings as PR review comments

## Security Rules and Checks Enforced

### Vulnerability Categories Scanned

| Category | Specific Checks |
|----------|----------------|
| **Input Validation** | SQL injection, command injection, XXE, template injection, NoSQL injection, path traversal |
| **Auth & Authz** | Authentication bypass, privilege escalation, session flaws, JWT vulnerabilities, authorization logic bypasses |
| **Crypto & Secrets** | Hardcoded API keys/passwords/tokens, weak algorithms, improper key storage, insecure RNG, cert validation bypass |
| **Injection & Code Exec** | RCE via deserialization, pickle injection, YAML deserialization, eval injection, XSS (reflected/stored/DOM) |
| **Data Exposure** | Sensitive data logging, PII handling violations, API data leakage, debug info exposure |
| **Business Logic** | Race conditions, TOCTOU issues |
| **Config Security** | Insecure defaults, missing security headers, permissive CORS |
| **Supply Chain** | Vulnerable dependencies, typosquatting |

### Severity Model

- **HIGH**: Directly exploitable (RCE, data breach, auth bypass) - confidence >0.9
- **MEDIUM**: Requires specific conditions but significant impact - confidence >0.8
- **LOW**: Defense-in-depth issues - confidence >0.7
- Below 0.7 confidence: not reported (too speculative)

### Structured Output

Findings are JSON with: `file`, `line`, `severity`, `category`, `description`,
`exploit_scenario`, `recommendation`, `confidence` score.

## False Positive Filtering System

The tool has a sophisticated two-stage filtering pipeline:

### Stage 1: Hard Exclusion Rules (regex-based, no API call)

Pre-compiled regex patterns auto-exclude:

| Pattern Category | What Gets Excluded |
|-----------------|-------------------|
| DOS/Resource Exhaustion | "denial of service", "exhaust/overwhelm resources", "infinite/unbounded loop/recursion" |
| Rate Limiting | "missing rate limit", "implement rate limit", "unlimited requests" |
| Resource Leaks | "resource/memory/file leak", "unclosed resource/file/connection", "potential memory leak" |
| Open Redirects | "open redirect", "unvalidated redirect", "malicious redirect" |
| Memory Safety (non-C/C++) | Buffer overflow, use-after-free, null pointer deref, segfault - only in non-C/C++ files |
| Regex Injection | "regex injection", "regex denial of service" |
| SSRF in HTML files | Server-side request forgery in client-side HTML |
| Markdown files | Any finding in `.md` files |

### Stage 2: Claude API Filtering (LLM second-pass)

Each surviving finding is sent to Claude API with detailed filtering instructions.
Key exclusion precedents:

1. **Env vars and CLI flags are trusted** - attacks requiring control of env vars are invalid
2. **UUIDs are unguessable** - vulns requiring UUID guessing are invalid
3. **React/Angular auto-escape XSS** - don't flag XSS unless using `dangerouslySetInnerHTML`
4. **Client-side auth checks not needed** - backend is responsible for auth validation
5. **Shell script command injection rarely exploitable** - requires specific untrusted input path
6. **SSRF only valid if controls host/protocol** - path-only SSRF is excluded
7. **AI prompt injection is not a vulnerability** - user input in prompts is expected
8. **Logging non-PII is safe** - only flag if secrets/passwords/PII are logged
9. **Test files excluded** - unit test code is not production attack surface
10. **GitHub Action workflow vulns** - must have very specific attack path to be valid
11. **Log spoofing not a vulnerability**
12. **Internal/private dependency references are fine**
13. **Crashes without security impact are not vulnerabilities**

Confidence scoring: 1-3 (false positive), 4-6 (needs investigation), 7-10 (real vulnerability).
Only findings scoring 7+ are kept.

## Customization Points

### Custom Security Scan Instructions

Organizations can add domain-specific categories:
- Compliance checks (GDPR, HIPAA, PCI DSS)
- Technology-specific (GraphQL depth attacks, gRPC security)
- Business logic (payment replay, currency manipulation)

These are **appended** to default categories (additive, not replacement).

### Custom False Positive Filtering

Organizations can override the default filtering precedents with their own:
- Technology-specific exclusions
- Infrastructure assumptions
- Compliance requirements

### Directory Exclusion

Comma-separated directories to skip entirely (vendor, generated code, etc.).

### Generated File Detection

Auto-skips files with `@generated` markers, protobuf/OpenAPI generated code.

## Claude Code `/security-review` Slash Command

The repo also ships a Claude Code slash command (`.claude/commands/security-review.md`)
that provides the same analysis inline during development. Key design:

- Restricted tools: only git commands and read-only file tools
- Three-phase approach: (1) sub-task identifies vulns, (2) parallel sub-tasks filter
  false positives, (3) filter by confidence >= 8
- Output is markdown (not JSON) for human readability

## Insights for rafter-cli

### What We Could Incorporate

1. **Structured security prompt template**: The prompt engineering is the core value.
   The specific categories, severity guidelines, and confidence scoring could be
   adapted for rafter-cli's code generation/review features.

2. **Two-stage filtering pattern**: Hard regex rules catch obvious false positives
   cheaply (no API call), then LLM second-pass handles nuanced cases. This is
   efficient and could apply to any agent output validation.

3. **Exclusion precedents as agent guidelines**: The 17 filtering precedents
   (env vars trusted, UUIDs unguessable, client-side auth not needed, etc.) are
   practical secure coding knowledge that could be embedded in rafter-cli's
   agent system prompts to prevent agents from writing insecure code in the
   first place, rather than just catching it after the fact.

4. **Confidence-gated output**: Only surfacing findings above a confidence threshold
   reduces noise. This pattern applies broadly to any agent that produces
   recommendations or warnings.

5. **Language-aware exclusions**: Memory safety findings auto-excluded for non-C/C++
   languages. Framework-aware exclusions (React XSS). This context-sensitivity
   reduces false positives significantly.

6. **Customization model**: The additive custom instructions model (append, don't
   replace defaults) is a good pattern for extensible security policy.

### Key Architectural Decisions Worth Noting

- Uses Claude Code CLI as subprocess (not direct API) for the main audit - this gives
  Claude access to file exploration tools for deeper context
- Disallows `Bash(ps:*)` to prevent process inspection during audit
- Retries with diff omitted if prompt too long (graceful degradation)
- Caches per-PR to avoid re-running on every commit (configurable)
- Pin-hashed action dependencies (supply chain protection)

### What This Tool Does NOT Cover

- Runtime security (it's static analysis only)
- Infrastructure/deployment security
- Dependency vulnerability scanning (explicitly excluded, deferred to other tools)
- Secrets in committed files (deferred to other processes)
- DOS/availability concerns (explicitly excluded as low-signal)
