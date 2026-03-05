# Brainstorm: Secure Code Enforcement Strategies for Agent-Initialized Rafter CLI

**Bead**: rc-s1b
**Date**: 2026-03-05
**Status**: Draft
**Builds on**: rc-q8c (claude-code-security-review research), rc-1qt (secure-coding guardrails proposal)

## Context

Rafter CLI already provides reactive security enforcement via PreToolUse hooks
(command interception), secret scanning (gitleaks), and audit logging. The
secure-coding guardrails proposal (rc-1qt) adds proactive CLAUDE.md-based prompt
guidance. This document brainstorms **additional enforcement strategies** beyond
those two layers, with feasibility assessments.

The central question: what might an agent miss that a human wouldn't?

## What Agents Get Wrong (Threat Model)

Agents writing code have specific failure modes distinct from human developers:

1. **Over-trust of generated patterns** — agents repeat patterns from training
   data without evaluating whether they're appropriate for the current context
   (e.g., using `eval()` because it appeared in similar code)
2. **Missing implicit security requirements** — a human knows "this handles
   payment data, so encrypt it"; an agent implements the feature literally
3. **Dependency sprawl** — agents add packages without evaluating their security
   posture or necessity
4. **Secret leakage in examples** — agents generate placeholder secrets that look
   real or accidentally hardcode values from context
5. **Incomplete threat modeling** — agents implement the happy path and error
   handling but skip adversarial input consideration
6. **Copy-paste vulnerabilities** — agents reproduce known-vulnerable code
   patterns from training data
7. **Framework misuse** — agents use framework features incorrectly (e.g.,
   disabling CSRF protection "to make it work")

## Prioritized Strategy List

### Tier 1: High Impact, High Feasibility (Implement First)

#### 1. CLAUDE.md Secure-Coding Guardrails (Already Proposed — rc-1qt)

**Mechanism**: Inject secure-coding guidelines into CLAUDE.md during `rafter agent init`
**Coverage**: Prevents false-positive security noise; teaches agents trust boundaries
**Status**: Fully designed in rc-1qt, ready for implementation
**Feasibility**: HIGH — writing to a text file during init is trivial
**Impact**: HIGH — always-on context that shapes every code generation
**Gap addressed**: Agent over-hardening (false positives) and trust boundary confusion

#### 2. PostToolUse Secret Scan on File Writes

**Mechanism**: Extend the existing PostToolUse hook to scan written/edited files
for secrets immediately after each Write/Edit tool call, not just at commit time
**How**: After Write/Edit completes, run rafter's regex scanner against the
modified file. If secrets detected, emit a warning to stderr (non-blocking) or
block (configurable).
**Feasibility**: HIGH — PostToolUse hook already fires on `.*`; regex scanner
already exists. Just need to read the file path from tool output and scan it.
**Impact**: HIGH — catches secrets the moment they're written, before they
propagate to other files or get committed
**Gap addressed**: Secret leakage in examples, hardcoded values from context
**Implementation sketch**:
```
posttool handler:
  if tool_name in (Write, Edit):
    file_path = extract from tool_input
    findings = regexScanner.scanFile(file_path)
    if findings.length > 0:
      emit warning or block
```

#### 3. Dependency Addition Gate

**Mechanism**: PreToolUse hook detects package install commands (`npm install`,
`pip install`, `go get`, `cargo add`, etc.) and checks the package against:
  - Known vulnerability databases (npm audit, pip-audit, cargo audit)
  - Typosquatting detection (Levenshtein distance from popular packages)
  - Package age/popularity thresholds (new/unpopular packages flagged)
**Feasibility**: HIGH for basic detection (pattern match on install commands),
MEDIUM for full audit integration (requires network calls)
**Impact**: MEDIUM-HIGH — agents frequently add unnecessary dependencies
**Gap addressed**: Dependency sprawl, supply chain risks
**Implementation sketch**: Add patterns to risk-rules.ts for package install
commands at medium risk level. The PreToolUse hook already evaluates commands
against risk patterns. For deeper analysis, add a PostToolUse handler that runs
`npm audit` / `pip-audit` after installs complete.

#### 4. Pre-Commit Security Scan Enhancement

**Mechanism**: Enhance the existing pre-commit hook (installed by `rafter agent
install-hook`) to run not just gitleaks secret scanning but also:
  - Pattern-based SAST for the specific languages in the staged diff
  - Check for common dangerous function usage (eval, exec, innerHTML assignment,
    SQL string concatenation, deserialization of untrusted data)
**Feasibility**: HIGH — the pre-commit hook infrastructure exists; add more
patterns to the regex scanner
**Impact**: MEDIUM-HIGH — catches dangerous patterns at the last gate before
code enters the repo
**Gap addressed**: Over-trust of generated patterns, copy-paste vulnerabilities

### Tier 2: Medium Impact, Medium Feasibility (Implement Next)

#### 5. Agent-Aware Security Linting Rules (SAST-Lite)

**Mechanism**: Ship a curated set of regex-based security lint rules that run as
part of `rafter scan local`. Focus on patterns agents specifically get wrong:

| Language | Pattern | Why agents get this wrong |
|----------|---------|--------------------------|
| JS/TS | `eval(`, `new Function(` | Training data includes eval-based solutions |
| JS/TS | `dangerouslySetInnerHTML` | Agents use it to "fix" rendering issues |
| Python | `pickle.loads(`, `yaml.load(` (without SafeLoader) | Common in training data |
| Python | `subprocess.shell=True` with f-string | Agents concatenate user input into shell commands |
| Go | `sql.Query(fmt.Sprintf(` | String-formatted SQL instead of parameterized queries |
| Any | `// nosec`, `# nosec`, `nolint:gosec` | Agents add suppression comments to silence linters |
| Any | `TODO: add authentication` | Agents defer security to TODOs |
| Any | `password = "`, `api_key = "`, `secret = "` | Hardcoded credential patterns |

**Feasibility**: MEDIUM — need to curate rules carefully to avoid false positives
(exactly what claude-code-security-review's filtering teaches us)
**Impact**: MEDIUM — catches specific agent failure modes
**Gap addressed**: Copy-paste vulnerabilities, framework misuse

#### 6. Diff-Aware Security Review Integration

**Mechanism**: Add a `rafter scan diff` command (or enhance `rafter scan auto`)
that integrates with `claude-code-security-review`'s approach: scan only the
diff, filter through hard rules, then optionally use an LLM second pass.
**Feasibility**: MEDIUM — the claude-code-security-review repo provides the
architecture; needs adaptation for local (non-GitHub-Action) use
**Impact**: MEDIUM-HIGH — semantic analysis catches things regex misses
**Gap addressed**: Missing implicit security requirements, incomplete threat
modeling
**Note**: This overlaps with the existing `rafter scan local` and backend
scanning. Position as a "deep scan" option for pre-PR review.

#### 7. Security Context Injection via .rafter.yml

**Mechanism**: Allow `.rafter.yml` to declare project-specific security context
that gets injected into agent prompts:
```yaml
security_context:
  data_classification: "handles PII (email, name, address)"
  auth_model: "OAuth2 + RBAC, backend validates all requests"
  sensitive_paths:
    - "src/auth/" # authentication logic
    - "src/payments/" # payment processing
    - "migrations/" # database schema changes
  required_reviews:
    - path: "src/auth/**"
      reason: "Authentication changes require security review"
```
**Feasibility**: MEDIUM — schema extension is simple; the challenge is getting
this context into agent prompts effectively (CLAUDE.md generation from config)
**Impact**: MEDIUM — project-specific context is what agents most lack
**Gap addressed**: Missing implicit security requirements

#### 8. Runtime Behavior Monitoring (Audit Pattern Analysis)

**Mechanism**: Analyze the audit log (`~/.rafter/audit.jsonl`) for suspicious
patterns that indicate an agent may be doing something wrong:
  - Repeated blocked commands (agent trying to bypass restrictions)
  - Rapid file creation in sensitive directories
  - Installation of many packages in a short window
  - Write operations to config files (.env, settings, credentials)
**Feasibility**: MEDIUM — audit log exists; need analysis logic and alerting
**Impact**: MEDIUM — detects behavioral anomalies, not just code patterns
**Gap addressed**: Agent over-trust, adversarial agent behavior
**Implementation**: `rafter agent audit --analyze` command that reads recent
log entries and flags anomalous patterns.

### Tier 3: High Impact, Lower Feasibility (Invest Later)

#### 9. LLM-Based Code Review Gate

**Mechanism**: Optional PostToolUse handler that sends code diffs to an LLM
(Claude) for security review before allowing commits. Similar to
claude-code-security-review but running locally in real-time.
**Feasibility**: LOW-MEDIUM — requires API access, adds latency, cost per
review, and complexity. Risk of infinite loops (agent reviewing agent's code).
**Impact**: HIGH — semantic analysis catches what regex cannot
**Gap addressed**: All agent failure modes
**Mitigation for feasibility concerns**: Make it opt-in, run only at commit
time (not every edit), use confidence thresholds to minimize noise.

#### 10. Security Test Generation Prompts

**Mechanism**: When an agent creates a new endpoint, API route, or data handler,
prompt it to also generate security-focused test cases:
  - SQL injection test cases
  - XSS payload test cases
  - Authentication bypass attempts
  - Authorization boundary tests
**Feasibility**: LOW-MEDIUM — requires understanding what code was written and
generating appropriate test prompts. Could be implemented as a CLAUDE.md
instruction: "When creating endpoints that handle user input, also create
security test cases."
**Impact**: MEDIUM — tests catch vulnerabilities and serve as documentation
**Gap addressed**: Incomplete threat modeling

#### 11. Supply Chain Verification Layer

**Mechanism**: Before any `npm install`, `pip install`, etc. completes, verify:
  - Package is not on known malicious package lists
  - Package has been published for >30 days (configurable)
  - Package has >100 weekly downloads (configurable)
  - Package maintainer email domain is not disposable
  - Lock file diff shows only expected changes
**Feasibility**: LOW — requires maintaining package reputation databases or
integrating with services like Socket.dev, Snyk, or npm audit
**Impact**: HIGH — supply chain attacks are a real and growing threat
**Gap addressed**: Dependency sprawl, supply chain attacks

#### 12. Sandboxed Execution Environment

**Mechanism**: Run agent-generated code in a sandboxed environment before
allowing it to be committed. Detect runtime security violations:
  - Unexpected network connections
  - File system access outside project directory
  - Privilege escalation attempts
  - Resource exhaustion
**Feasibility**: LOW — requires container/sandbox infrastructure, significant
complexity, varies by language/platform
**Impact**: HIGH — catches runtime vulnerabilities that static analysis misses
**Gap addressed**: All runtime security concerns

### Tier 4: Low Effort, Incremental Value (Quick Wins)

#### 13. Dangerous Pattern Warnings in CLAUDE.md

**Mechanism**: Add to the CLAUDE.md guardrails (from rc-1qt) a "NEVER do this"
section listing patterns agents should avoid:
```markdown
## Patterns to Avoid
- NEVER use eval(), new Function(), or exec() unless explicitly required
- NEVER disable CSRF, CORS, or authentication middleware to "fix" errors
- NEVER add `// nosec` or `# nosec` comments to suppress security warnings
- NEVER store secrets in source code, even as "defaults" or "examples"
- NEVER use string concatenation for SQL queries
- NEVER use pickle.loads() or yaml.load() without SafeLoader on untrusted data
```
**Feasibility**: HIGH — just text in a file
**Impact**: LOW-MEDIUM — agents generally follow CLAUDE.md instructions
**Gap addressed**: Copy-paste vulnerabilities, framework misuse

#### 14. Git Hook for Security-Sensitive File Changes

**Mechanism**: Extend the pre-commit hook to flag changes to security-sensitive
files and require explicit confirmation:
  - `.env*` files (secret exposure)
  - `**/auth/**`, `**/security/**` (auth logic changes)
  - `Dockerfile`, `docker-compose.yml` (container security)
  - CI/CD pipeline files (`.github/workflows/`, `Jenkinsfile`)
  - Package lock files with unexpected changes
**Feasibility**: HIGH — extend existing pre-commit hook with path patterns
**Impact**: LOW-MEDIUM — creates awareness of high-risk changes
**Gap addressed**: Missing implicit security requirements

#### 15. Security Checklist Skill

**Mechanism**: Add a new skill (`rafter-security-checklist`) that agents can
invoke before submitting code, providing a structured checklist:
  - [ ] No hardcoded secrets
  - [ ] Input validation on all user-facing endpoints
  - [ ] Parameterized queries for all database access
  - [ ] Authentication/authorization checks on new endpoints
  - [ ] No new dependencies without justification
  - [ ] Security-sensitive file changes reviewed
**Feasibility**: HIGH — skill file authoring is well-understood
**Impact**: LOW-MEDIUM — depends on agents actually invoking it
**Gap addressed**: Incomplete threat modeling

## Strategy Comparison Matrix

| # | Strategy | Impact | Feasibility | Effort | Coverage |
|---|----------|--------|-------------|--------|----------|
| 1 | CLAUDE.md guardrails | HIGH | HIGH | Low | Proactive guidance |
| 2 | PostToolUse secret scan | HIGH | HIGH | Low | Secret detection |
| 3 | Dependency addition gate | MED-HIGH | HIGH | Low-Med | Supply chain |
| 4 | Pre-commit SAST enhancement | MED-HIGH | HIGH | Medium | Dangerous patterns |
| 5 | Security lint rules | MEDIUM | MEDIUM | Medium | Language-specific |
| 6 | Diff-aware review | MED-HIGH | MEDIUM | High | Semantic analysis |
| 7 | .rafter.yml security context | MEDIUM | MEDIUM | Medium | Project context |
| 8 | Audit pattern analysis | MEDIUM | MEDIUM | Medium | Behavioral |
| 9 | LLM code review gate | HIGH | LOW-MED | High | All |
| 10 | Security test generation | MEDIUM | LOW-MED | Medium | Testing |
| 11 | Supply chain verification | HIGH | LOW | High | Dependencies |
| 12 | Sandboxed execution | HIGH | LOW | Very High | Runtime |
| 13 | Dangerous pattern warnings | LOW-MED | HIGH | Very Low | Agent guidance |
| 14 | Security-sensitive file gate | LOW-MED | HIGH | Low | File awareness |
| 15 | Security checklist skill | LOW-MED | HIGH | Low | Process |

## Recommended Implementation Order

### Phase 1: Foundation (low effort, high return)
1. **CLAUDE.md guardrails** (rc-1qt) — already designed, implement immediately
2. **PostToolUse secret scan** — extend existing hook, minimal new code
3. **Dangerous pattern warnings** — append to CLAUDE.md content from rc-1qt

### Phase 2: Active Enforcement (medium effort)
4. **Dependency addition gate** — add package install patterns to risk-rules
5. **Pre-commit SAST enhancement** — extend regex scanner with language patterns
6. **Security-sensitive file gate** — extend pre-commit hook with path patterns
7. **Security checklist skill** — new skill file

### Phase 3: Deep Analysis (higher effort)
8. **Security lint rules** — curated SAST-lite for agent-specific mistakes
9. **.rafter.yml security context** — project-specific agent guidance
10. **Audit pattern analysis** — behavioral anomaly detection

### Phase 4: Advanced (significant investment)
11. **Diff-aware security review** — local claude-code-security-review adaptation
12. **LLM code review gate** — optional real-time semantic review
13. **Security test generation** — prompt-based test case creation
14. **Supply chain verification** — package reputation checking
15. **Sandboxed execution** — runtime security analysis

## Architecture: Layered Security Model

The strategies above form a defense-in-depth model with four layers:

```
Layer 4: Semantic Analysis (LLM review, diff-aware scanning)
Layer 3: Active Enforcement (dependency gates, SAST, audit analysis)
Layer 2: Reactive Detection (hooks, secret scanning, pre-commit)
Layer 1: Proactive Guidance (CLAUDE.md guardrails, security context)
```

**Current rafter-cli coverage**: Layer 2 (reactive detection) is solid.
**Immediate opportunity**: Layer 1 (proactive guidance) via rc-1qt.
**Next frontier**: Layer 3 (active enforcement) via strategies 3-5.
**Long-term**: Layer 4 (semantic analysis) for the highest-value catches.

## Key Insight: What Agents Miss That Humans Don't

The fundamental gap is **contextual security reasoning**. A human developer
knows:
- "This is a payments service, so I need PCI compliance"
- "Our auth is handled by the API gateway, so I don't need to check here"
- "This data comes from an internal service, so it's pre-validated"
- "We've had SQL injection bugs in this module before"

Agents lack this context unless it's explicitly provided. The highest-leverage
strategies are those that **inject project-specific security context** (strategies
1, 7, 13) rather than trying to catch everything with pattern matching (which
will always have gaps and false positives).

The second insight is **timing**. Catching issues earlier is exponentially
cheaper. Writing secure code (Layer 1) > catching at edit time (Layer 2) >
catching at commit time (Layer 3) > catching at review time (Layer 4).
