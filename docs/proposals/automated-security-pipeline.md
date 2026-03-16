# Proposal: Automated Vulnerability Prevention Pipeline

**Bead**: rc-6mb
**Date**: 2026-03-05
**Status**: Draft
**Depends on**: rc-1qt (secure-coding guardrails), rc-q8c (claude-code-security-review research)

## Problem

Rafter-cli currently provides **point solutions** for agent security: secret scanning
(`rafter scan`), command interception (`rafter agent exec`), skill auditing
(`/rafter-audit-skill`), and prompt-level secure coding guardrails (rc-1qt proposal).
These are valuable individually, but there is no **unified pipeline** that orchestrates
them into a coherent, zero-trust workflow for agent-generated code.

Agents produce code at high velocity. Without an automated pipeline that gates every
commit, vulnerabilities slip through the cracks between individual tools. The goal is
a single `rafter pipeline` command that chains analysis stages together and blocks
unsafe code from reaching the repository.

## Architecture Overview

```
Agent writes code
       |
       v
+----------------------------------------------+
|           rafter pipeline (orchestrator)       |
|                                                |
|  Stage 1: Static Analysis (fast, local)        |
|    - Rafter code analysis engine (SAST)        |
|    - language-specific linters                  |
|    - secret detection (existing rafter scan)    |
|                                                |
|  Stage 2: Dependency Scanning (fast, local)    |
|    - npm audit / pip-audit / cargo-audit       |
|    - license compliance check                  |
|                                                |
|  Stage 3: OWASP Validation (medium, local)     |
|    - pattern-based OWASP Top 10 checks         |
|    - framework-aware filtering                 |
|                                                |
|  Stage 4: AI Security Review (slow, optional)  |
|    - Claude-based semantic analysis            |
|    - two-stage filtering (hard rules + LLM)    |
|    - confidence-gated output (>=7 only)        |
|                                                |
|  Stage 5: Report & Gate                        |
|    - aggregate findings, deduplicate           |
|    - apply severity threshold                  |
|    - block/warn/pass decision                  |
+----------------------------------------------+
       |
       v
  Commit allowed / blocked
```

### Design Principles

1. **Fast stages first**: Static analysis and dependency scanning run in seconds.
   AI review is optional and runs last (or async).
2. **Additive, not replacement**: Each stage adds findings. Existing `rafter scan`
   becomes Stage 1c rather than being replaced.
3. **Zero-trust by default**: All agent-generated code is untrusted until it passes
   the pipeline. The pipeline is the trust boundary.
4. **Configurable strictness**: Teams choose which stages run and what severity
   threshold gates commits (matching existing `agent.riskLevel` config).
5. **Framework-aware**: Apply the filtering precedents from rc-q8c/rc-1qt to reduce
   false positives across all stages.

## Stage 1: Static Analysis Integration

### 1a. Rafter Code Analysis Engine (Multi-Language SAST)

Rafter's built-in code analysis engine is language-agnostic, supports custom rules,
and is fast (no compilation needed). It excels at detecting injection patterns, auth
issues, and crypto misuse.

**Integration approach**:
```bash
rafter pipeline run --stage static
# Internally runs Rafter's code analysis engine against changed files
```

**Rafter-specific rule pack** (`rafter-rules.yml`):
- OWASP Top 10 patterns per language
- Agent-specific anti-patterns (e.g., hardcoded URLs that should be configurable)
- Framework-aware rules that complement rc-1qt guardrails

**Configuration**:
```yaml
# .rafter/pipeline.yml
static_analysis:
  code_analysis:
    enabled: true
    configs:
      - auto                    # Rafter's curated rules
      - rafter://owasp-top10    # rafter-maintained OWASP rules
    severity_threshold: WARNING # ERROR, WARNING, INFO
    exclude:
      - "test/**"
      - "**/*.test.*"
      - "vendor/**"
```

### 1b. Language-Specific Linters (Security-Focused)

These catch vulnerabilities that the code analysis engine may miss due to language-specific semantics:

| Language | Tool | What it catches |
|----------|------|----------------|
| Python | bandit | eval/exec, hardcoded passwords, weak crypto, shell injection |
| JavaScript/TS | eslint-plugin-security | object injection, non-literal require, regex DOS |
| Go | gosec | SQL injection, crypto misuse, file permissions |
| Rust | cargo-clippy (security lints) | unsafe blocks, unchecked indexing |
| Ruby | brakeman | Rails-specific: mass assignment, XSS, CSRF |
| Java | spotbugs (find-sec-bugs) | injection, crypto, SSRF |

**Auto-detection**: Rafter detects the project's language(s) from file extensions and
lock files, then runs the appropriate linter(s). No manual configuration needed.

```yaml
static_analysis:
  language_linters:
    enabled: true
    auto_detect: true          # default: detect from project files
    # Or explicit:
    # tools: [bandit, eslint-plugin-security]
```

### 1c. Secret Detection (Existing `rafter scan`)

The existing `rafter scan local` becomes Stage 1c. No changes needed — it already
produces structured JSON output with file, line, pattern, and severity.

**Enhancements for pipeline integration**:
- Add `--pipeline-json` output flag for consistent finding format across stages
- Add `--changed-only` flag to scan only git-changed files (speed optimization)
- Add custom pattern support via `.rafter/secret-patterns.yml`

### Secret Detection Improvements (Beyond Generic Patterns)

Current `rafter scan` detects 21+ patterns. Proposed additions:

| Category | New Patterns |
|----------|-------------|
| Cloud providers | GCP service account keys, Azure client secrets, DigitalOcean tokens |
| CI/CD | CircleCI tokens, Travis CI tokens, Buildkite agent tokens |
| Databases | MongoDB connection strings, Redis AUTH passwords, Elasticsearch creds |
| SaaS | Twilio auth tokens, SendGrid keys, Datadog API keys, PagerDuty tokens |
| Internal | JWT signing keys (HS256/RS256), HMAC secrets, encryption keys |
| Contextual | `password=` in config files, `secret:` in YAML, bearer tokens in code |

**Entropy-based detection**: For patterns that can't be matched by regex (random
strings used as secrets), add entropy analysis for string literals in sensitive
contexts (config files, environment setup, connection strings).

## Stage 2: Dependency Vulnerability Scanning

### Tool Selection by Ecosystem

| Ecosystem | Tool | Integration |
|-----------|------|-------------|
| npm/yarn/pnpm | `npm audit --json` | Parse advisory JSON, map to CVE |
| Python (pip) | `pip-audit --format=json` | Parse JSON output |
| Python (poetry) | `pip-audit` (reads poetry.lock) | Same as pip |
| Rust | `cargo-audit --json` | Parse JSON output |
| Go | `govulncheck -json` | Parse JSON output |
| Ruby | `bundler-audit --format=json` | Parse JSON output |
| Java/Kotlin | OWASP dependency-check | Parse SARIF output |

### Pipeline Behavior

```bash
rafter pipeline run --stage deps
```

1. Detect ecosystem(s) from lock files
2. Run appropriate audit tool(s)
3. Map findings to unified format: `{package, version, cve, severity, fix_version}`
4. Apply policy:
   - **CRITICAL/HIGH CVEs**: Block commit (configurable)
   - **MEDIUM**: Warn
   - **LOW**: Log only

### Configuration

```yaml
dependency_scanning:
  enabled: true
  auto_detect: true
  block_on:
    - severity: CRITICAL
    - severity: HIGH
      age_days: 30            # only block if CVE is >30 days old (gives time for fixes)
  ignore:
    - CVE-2024-XXXXX          # known false positive for our usage
  license_check:
    enabled: false             # opt-in: block copyleft licenses in proprietary projects
    blocked_licenses: [GPL-3.0, AGPL-3.0]
```

## Stage 3: OWASP Top 10 Validation

This stage applies targeted checks for OWASP Top 10 categories, with
**framework-aware filtering** based on the rc-1qt guardrails research.

### Check Matrix

| OWASP Category | Check | Framework Exceptions |
|----------------|-------|---------------------|
| A01: Broken Access Control | Path traversal patterns, missing auth middleware | Skip for test files |
| A02: Cryptographic Failures | Weak algorithms (MD5, SHA1 for auth), hardcoded keys | Allow in test fixtures |
| A03: Injection | SQL concat, shell exec with variables, eval/exec | Skip when input is env var or CLI flag (rc-1qt #1) |
| A04: Insecure Design | Missing input validation at system boundaries | Skip internal function calls |
| A05: Security Misconfiguration | Debug mode enabled, default credentials, permissive CORS | Skip in dev configs |
| A06: Vulnerable Components | (Covered by Stage 2) | — |
| A07: Auth Failures | Hardcoded passwords, missing session expiry | Skip test files (rc-1qt #9) |
| A08: Data Integrity | Deserialization without validation, unsigned updates | — |
| A09: Logging Failures | Missing audit logging at auth events | Skip non-PII logging (rc-1qt #8) |
| A10: SSRF | HTTP requests with user-controlled URLs | Skip path-only URLs (rc-1qt #6) |

### Framework-Aware Filtering

The rc-1qt filtering precedents are applied as suppressions:

```yaml
owasp_validation:
  enabled: true
  framework_aware: true        # apply rc-1qt filtering precedents
  # Explicit overrides:
  suppress:
    - rule: xss-raw-output
      when: framework in [react, angular, vue, svelte]
    - rule: ssrf-user-url
      when: only_path_controlled
    - rule: injection-shell
      when: input_source in [env_var, cli_flag, hardcoded]
```

## Stage 4: AI Security Review (Optional)

For teams that want the deepest analysis, an optional Claude-based review stage
that mirrors the `claude-code-security-review` architecture.

### When to Use

- **Always**: High-security projects (fintech, healthcare, auth systems)
- **On PR**: As a CI check (mirrors the GitHub Action from rc-q8c)
- **Never**: Fast iteration, low-risk internal tools

### Architecture

```
Changed files (from git diff)
       |
       v
  Structured security prompt
  (categories, severity model, exclusion precedents)
       |
       v
  Claude Code CLI (--output-format json)
  (with file exploration tools for context)
       |
       v
  Stage 1 filter: hard regex exclusions
  (DOS, rate limiting, resource leaks, etc.)
       |
       v
  Stage 2 filter: Claude API second-pass
  (confidence scoring, 7+ threshold)
       |
       v
  Filtered findings (JSON)
```

This directly reuses the two-stage filtering pattern from `claude-code-security-review`
(rc-q8c research). The hard exclusion rules and LLM filtering precedents are
maintained as configuration, not hardcoded.

### Configuration

```yaml
ai_review:
  enabled: false               # opt-in
  provider: claude             # future: support other models
  model: claude-sonnet-4-6   # cost-effective for review
  confidence_threshold: 7      # 1-10 scale, only report >= threshold
  max_files: 50                # skip if diff is too large
  custom_categories: []        # additive domain-specific checks
  custom_exclusions: []        # additive false-positive rules
```

## Stage 5: Security Test Generation

When the pipeline identifies a vulnerability pattern, it can optionally generate
a targeted security test that validates the fix.

### Approach

1. Pipeline finds: "SQL injection in `getUserById` — string concatenation with
   user input"
2. Test generator creates: a test case that passes a SQL injection payload and
   asserts it's properly parameterized
3. Test is placed in the project's test directory following existing conventions

### Implementation

```bash
rafter pipeline run --generate-tests
```

This uses Claude to generate tests, scoped to:
- Only findings with severity >= HIGH
- Only findings with a clear remediation path
- Tests follow the project's existing test framework (detected from existing tests)

```yaml
test_generation:
  enabled: false               # opt-in
  framework: auto              # detect from existing tests
  output_dir: auto             # detect from existing test structure
  max_tests_per_run: 5         # limit to avoid overwhelming
  categories:
    - injection                # SQL, command, template injection
    - auth_bypass              # authentication/authorization
    - path_traversal           # file access
```

### Example Generated Test (Python/pytest)

```python
def test_get_user_by_id_sql_injection():
    """Verify getUserById is not vulnerable to SQL injection."""
    malicious_id = "1; DROP TABLE users; --"
    # Should use parameterized query, not string concatenation
    result = get_user_by_id(malicious_id)
    # If parameterized: returns None (no user found)
    # If vulnerable: would execute DROP TABLE
    assert result is None or isinstance(result, User)
```

## Stage 6: Report and Gate

The final stage aggregates all findings, deduplicates, and makes a gate decision.

### Unified Finding Format

All stages produce findings in a common format:

```json
{
  "stage": "static|deps|owasp|ai|test",
  "tool": "rafter-sast|bandit|npm-audit|...",
  "file": "src/api/users.ts",
  "line": 42,
  "severity": "HIGH|MEDIUM|LOW|INFO",
  "category": "injection|auth|crypto|...",
  "title": "SQL injection via string concatenation",
  "description": "User input flows into SQL query without parameterization",
  "recommendation": "Use parameterized query: db.query('SELECT ...', [userId])",
  "confidence": 0.92,
  "suppressed": false,
  "suppression_reason": null
}
```

### Deduplication

Findings from different stages targeting the same file:line are merged. The highest
severity and confidence win. Source stages are listed for traceability.

### Gate Decision

```yaml
gate:
  # Block commit if ANY finding meets these criteria:
  block:
    - severity: CRITICAL
    - severity: HIGH
      confidence: 0.9
  # Warn but allow:
  warn:
    - severity: HIGH
      confidence: 0.7
    - severity: MEDIUM
  # Ignore:
  ignore:
    - severity: LOW
    - severity: INFO
```

### Output Formats

| Format | Use case |
|--------|---------|
| `--format=terminal` | Human-readable with colors (default) |
| `--format=json` | Machine-readable for CI integration |
| `--format=sarif` | GitHub Code Scanning integration |
| `--format=markdown` | PR comment body |

## Sandboxing Recommendations

Agent-generated code should execute in sandboxed environments. Rafter can enforce
sandboxing at two levels:

### Level 1: Command-Level Sandboxing (Existing)

The existing `rafter agent exec` / PreToolUse hook already sandboxes individual
commands. Enhancements:

- **Network namespace isolation**: Block outbound network for commands that shouldn't
  need it (e.g., `go build`, `cargo test`)
- **Filesystem scope**: Restrict write access to the project directory + temp
- **Time limits**: Kill commands that exceed expected duration (runaway processes)

### Level 2: Pipeline-Level Sandboxing

The pipeline itself runs analysis tools in isolation:

```yaml
sandbox:
  enabled: true
  network: deny               # analysis tools don't need network (except deps stage)
  filesystem:
    read: [project_dir, /usr, /lib]
    write: [/tmp/rafter-pipeline-*]
  time_limit: 300              # 5 minutes max per stage
  memory_limit: 2G
```

Implementation options:
- **Linux**: `bubblewrap` (bwrap) — lightweight, no root needed
- **macOS**: `sandbox-exec` (deprecated but functional) or container
- **Cross-platform**: Run in ephemeral Docker container

### Level 3: Full Environment Sandboxing (Future)

For maximum isolation, agents run in ephemeral VMs or containers:

- **Firecracker microVMs**: Sub-second startup, strong isolation
- **gVisor**: Container runtime with syscall filtering
- **Devcontainers**: IDE-integrated, already has ecosystem support

This is out of scope for rafter-cli v1 but should be designed for in the pipeline
architecture (stages should be runnable in remote sandboxes via a driver interface).

## Integration Points

### Hook-Based (Automatic)

```bash
rafter agent init
# Installs PreToolUse hook that runs pipeline on:
#   - git commit (scan staged files)
#   - file write (scan written file)
#   - bash commands (existing command interception + new pipeline)
```

### CI/CD

```yaml
# GitHub Actions
- name: Rafter Security Pipeline
  uses: rafter/pipeline-action@v1
  with:
    stages: static,deps,owasp
    severity_threshold: HIGH
    sarif_output: true

# The AI review stage can run as a separate, optional job
- name: Rafter AI Review
  uses: rafter/ai-review-action@v1
  if: github.event.pull_request
```

### CLI (Manual)

```bash
# Run full pipeline on changed files
rafter pipeline run

# Run specific stages
rafter pipeline run --stage static,deps

# Run on specific files
rafter pipeline run --files src/api/users.ts

# Dry run (report only, don't gate)
rafter pipeline run --dry-run

# Generate SARIF report
rafter pipeline run --format=sarif > report.sarif
```

## Configuration Hierarchy

```
Built-in defaults (rafter-cli)
       |
       v
User config (~/.rafter/pipeline.yml)
       |
       v
Project config (.rafter/pipeline.yml)
       |
       v
CLI flags (--stage, --severity-threshold, etc.)
```

Each level overrides the previous. Project config is the primary customization point.

### Minimal Default Config (Zero Configuration)

Out of the box, `rafter pipeline run` should work with no config file:

```yaml
# Implicit defaults when no .rafter/pipeline.yml exists:
static_analysis:
  code_analysis:
    enabled: true
    configs: [auto]
  language_linters:
    enabled: true
    auto_detect: true
  secret_detection:
    enabled: true
dependency_scanning:
  enabled: true
  auto_detect: true
  block_on:
    - severity: CRITICAL
owasp_validation:
  enabled: true
  framework_aware: true
ai_review:
  enabled: false
test_generation:
  enabled: false
gate:
  block:
    - severity: CRITICAL
      confidence: 0.9
  warn:
    - severity: HIGH
```

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-3)

**Goal**: Unified finding format and pipeline orchestrator.

1. Define `Finding` schema (JSON Schema + TypeScript/Python types)
2. Implement pipeline orchestrator (`rafter pipeline run`)
   - Stage registration, ordering, parallel execution
   - Finding aggregation, deduplication
   - Gate decision logic
3. Wrap existing `rafter scan` as Stage 1c with `--pipeline-json` output
4. Add `--changed-only` to `rafter scan` for speed
5. Config file parsing (`.rafter/pipeline.yml`)

**Deliverable**: `rafter pipeline run` works with secret detection only.

### Phase 2: Static Analysis (Weeks 3-5)

**Goal**: Code analysis engine + language linter integration.

6. Code analysis engine integration (rule management, output parsing)
7. Rafter OWASP rule pack (initial set for Python, JS/TS, Go)
8. Language linter auto-detection and integration (bandit, eslint-plugin-security)
9. Framework-aware filtering layer (apply rc-1qt precedents as suppressions)

**Deliverable**: `rafter pipeline run --stage static` catches SAST findings.

### Phase 3: Dependency Scanning (Weeks 5-6)

**Goal**: Multi-ecosystem dependency vulnerability scanning.

10. npm audit integration (parse JSON, map to Finding format)
11. pip-audit integration
12. cargo-audit / govulncheck integration
13. Lock file auto-detection
14. CVE ignore list and age-based policy

**Deliverable**: `rafter pipeline run --stage deps` scans dependencies.

### Phase 4: OWASP Validation (Weeks 6-8)

**Goal**: Targeted OWASP Top 10 checks with framework awareness.

15. OWASP check implementations (pattern-based, per-category)
16. Framework detection (React, Angular, Django, Rails, etc.)
17. Suppression system (rc-1qt precedents as built-in suppressions)
18. Custom suppression config

**Deliverable**: `rafter pipeline run --stage owasp` with low false-positive rate.

### Phase 5: Secret Detection Improvements (Weeks 8-9)

**Goal**: Expand beyond current 21 patterns.

19. Add cloud provider patterns (GCP, Azure, DigitalOcean)
20. Add CI/CD and SaaS patterns
21. Entropy-based detection for config files
22. Custom pattern support (`.rafter/secret-patterns.yml`)

**Deliverable**: Secret detection covers 50+ pattern categories.

### Phase 6: AI Review Integration (Weeks 9-11)

**Goal**: Optional Claude-based semantic review.

23. Adapt `claude-code-security-review` prompt template for pipeline use
24. Implement two-stage filtering (hard rules + LLM second-pass)
25. Confidence-gated output
26. Rate limiting and cost controls

**Deliverable**: `rafter pipeline run --stage ai` for deep analysis.

### Phase 7: Test Generation (Weeks 11-13)

**Goal**: Security test generation for identified vulnerabilities.

27. Test framework detection
28. Finding-to-test-prompt mapping
29. Test generation via Claude
30. Test placement in project structure

**Deliverable**: `rafter pipeline run --generate-tests` creates targeted security tests.

### Phase 8: CI/CD & Sandboxing (Weeks 13-15)

**Goal**: Production deployment and sandboxing.

31. GitHub Action for pipeline
32. SARIF output for GitHub Code Scanning
33. Bubblewrap sandboxing for Linux
34. Docker-based sandboxing (cross-platform)

**Deliverable**: Full pipeline running in CI with sandboxed execution.

## Relationship to Existing Work

| Existing Component | Role in Pipeline | Changes Needed |
|-------------------|-----------------|----------------|
| `rafter scan` (secret detection) | Stage 1c | Add `--pipeline-json`, `--changed-only` |
| `rafter agent exec` (command interception) | Orthogonal — runtime, not analysis | No changes |
| `/rafter-audit-skill` (skill auditing) | Orthogonal — audits skills, not code | No changes |
| rc-1qt guardrails (CLAUDE.md injection) | Informs Stage 3 suppression rules | Guardrails reduce what pipeline catches |
| rc-q8c research (claude-code-security-review) | Informs Stage 4 architecture | Reuse prompt template and filtering |
| `agent.riskLevel` config | Maps to pipeline gate thresholds | Bridge config values |

### Complementary, Not Redundant

The security pipeline and the rc-1qt guardrails work together:

1. **Guardrails** (rc-1qt) prevent agents from writing insecure code in the first place
   (proactive, prompt-level)
2. **Pipeline** (this proposal) catches what slips through (reactive, analysis-level)

Both are needed. Guardrails reduce pipeline noise. Pipeline catches what guardrails miss.

## Success Metrics

1. **Coverage**: Pipeline runs on 100% of agent-generated commits
2. **Speed**: Stages 1-3 complete in <30 seconds for typical PRs
3. **Precision**: <10% false positive rate (measured by user suppressions)
4. **Catch rate**: Detects >80% of OWASP Top 10 patterns in agent-generated code
   (measured against synthetic vulnerable code benchmark)
5. **Adoption**: Zero-config default works for >80% of projects without customization

## Open Questions

1. **Tool installation**: Should `rafter pipeline run` auto-install missing tools
   (bandit, etc.) or require manual installation?
   - Recommendation: Auto-install to temp directory on first run, with `--no-install` flag
2. **Performance budget**: What's the acceptable latency for the pre-commit hook?
   - Recommendation: <10 seconds for stages 1-3, AI review is async/optional
3. **Monorepo support**: How to handle multiple languages/ecosystems in one repo?
   - Recommendation: Run all detected ecosystems, report per-directory
4. **Baseline management**: How to handle existing vulnerabilities in legacy code?
   - Recommendation: `rafter pipeline baseline` command that captures current state,
     then only flag new findings (similar to `rafter agent baseline`)
