# Deep Dive: claude-code-security-review Takeaways for rafter-cli

**Source**: https://github.com/anthropics/claude-code-security-review
**Date**: 2026-03-05
**Bead**: rc-2q2
**Prior work**: rc-q8c (initial research), rc-1qt (guardrails proposal)

## Executive Summary

`claude-code-security-review` is an AI-powered SAST GitHub Action that uses Claude
to perform semantic security analysis of PR diffs. After reading every source file
in the repo, this deep dive catalogs: what patterns it enforces, how it reduces
false positives, what it deliberately omits, and specific integration opportunities
for rafter-cli's agent init flow.

---

## 1. Architecture (Code-Level)

### Components

| File | Role | Key Insight |
|------|------|------------|
| `github_action_audit.py` | Main orchestrator | Fetches PR data, builds prompt, runs Claude CLI as subprocess, filters results, outputs JSON |
| `prompts.py` | Prompt engineering | Single function `get_security_audit_prompt()` - the core value of the entire tool |
| `findings_filter.py` | Two-stage filter pipeline | `HardExclusionRules` (regex, no API) + `FindingsFilter` (Claude API second-pass) |
| `claude_api_client.py` | Anthropic SDK wrapper | `analyze_single_finding()` sends each finding individually for false-positive assessment |
| `json_parser.py` | Robust JSON extraction | Handles markdown code blocks, brace-balanced extraction - necessary because Claude output isn't always clean JSON |
| `action.yml` | GitHub Action composite | Cache-based dedup (one run per PR by default), pin-hashed deps |
| `.claude/commands/security-review.md` | Slash command | Restricted tool access, 3-phase sub-task architecture, markdown output |
| `evals/eval_engine.py` | Eval framework | Git worktree-based PR evaluation, but no ground truth dataset |

### Execution Flow

```
PR opened
  -> GitHubActionClient.get_pr_data() + get_pr_diff()
  -> get_security_audit_prompt() builds prompt with diff + file list
  -> SimpleClaudeRunner.run_security_audit() shells out to `claude` CLI
     (--output-format json, --model claude-opus-4-1, --disallowed-tools Bash(ps:*))
  -> If "PROMPT_TOO_LONG" error: retry with diff omitted (graceful degradation)
  -> _extract_security_findings() unwraps Claude Code JSON wrapper
  -> HardExclusionRules.get_exclusion_reason() (regex stage)
  -> ClaudeAPIClient.analyze_single_finding() (LLM stage, per-finding)
  -> _is_finding_in_excluded_directory() (directory filter)
  -> Output JSON with findings + filtering_summary
  -> comment-pr-findings.js posts to PR
```

### Key Architecture Decisions

1. **Claude CLI as subprocess, not direct API**: The main audit uses `claude` CLI,
   which gives Claude access to file exploration tools (Read, Glob, Grep) for deeper
   context beyond just the diff. The false-positive filter uses direct API (no tools
   needed for classification).

2. **`--disallowed-tools Bash(ps:*)`**: Prevents Claude from inspecting running
   processes during audit. Minimal sandboxing.

3. **Per-PR caching**: `actions/cache` with key `claudecode-{repo_id}-pr-{number}-{sha}`.
   First run creates a reservation marker; subsequent pushes to the same PR skip
   re-running unless `run-every-commit: true`.

4. **Prompt size management**: If prompt exceeds limits, retries without the diff
   and tells Claude to use file exploration tools instead.

---

## 2. What Security Patterns It Checks

### Audit Prompt Categories (from `prompts.py`)

The prompt instructs Claude to examine five broad areas:

| Category | Specific Checks |
|----------|----------------|
| **Input Validation** | SQL injection, command injection, XXE, template injection, NoSQL injection, path traversal |
| **Auth & Authorization** | Auth bypass, privilege escalation, session flaws, JWT vulns, authz logic bypasses |
| **Crypto & Secrets** | Hardcoded keys/passwords/tokens, weak algorithms, improper key storage, insecure RNG, cert validation bypass |
| **Injection & Code Exec** | RCE via deserialization, pickle injection, YAML deser, eval injection, XSS (reflected/stored/DOM) |
| **Data Exposure** | Sensitive data logging, PII handling violations, API data leakage, debug info exposure |

### Analysis Methodology (3-phase)

The prompt prescribes a specific analysis methodology:

1. **Repository Context Research**: Use file tools to understand existing security
   frameworks, coding patterns, sanitization approaches
2. **Comparative Analysis**: Compare new code against existing patterns, flag deviations
3. **Vulnerability Assessment**: Trace data flow from user inputs to sensitive ops

### Severity and Confidence Model

| Severity | Criteria | Confidence Floor |
|----------|----------|-----------------|
| HIGH | Directly exploitable (RCE, data breach, auth bypass) | 0.9 |
| MEDIUM | Requires specific conditions, significant impact | 0.8 |
| LOW | Defense-in-depth | 0.7 |
| Not reported | Too speculative | < 0.7 |

### Explicit Exclusions in the Audit Prompt

Even before filtering, the audit prompt itself tells Claude to skip:
- Denial of Service vulnerabilities
- Secrets/credentials stored on disk (handled separately)
- Rate limiting / resource exhaustion
- Theoretical issues, style concerns, low-impact findings
- Existing security concerns (only flag NEW issues in the PR)

---

## 3. False Positive Filtering (Deep Analysis)

### Stage 1: Hard Exclusion Rules (`HardExclusionRules` class)

Pre-compiled regex patterns, zero API cost:

| Rule | Patterns | Files Affected |
|------|----------|---------------|
| DOS/Resource Exhaustion | "denial of service", "exhaust.*resource", "infinite.*loop" | All |
| Rate Limiting | "missing rate limit", "implement rate limit", "unlimited requests" | All |
| Resource Leaks | "resource/memory/file leak", "unclosed resource", "potential memory leak", "database/thread/socket leak" | All |
| Open Redirects | "open redirect", "unvalidated redirect", "malicious redirect" | All |
| Memory Safety | Buffer overflow, use-after-free, null pointer deref, segfault, integer overflow, OOB access | Non-C/C++ files only (`.c`, `.cc`, `.cpp`, `.h` exempt) |
| Regex Injection | "regex injection", "regex denial of service", "regex flooding" | All |
| SSRF in HTML | "ssrf", "server side request forgery" | `.html` files only |
| Markdown findings | Any finding | `.md` files |

**Design note**: The memory safety exclusion uses file extension matching. This is
pragmatic but imperfect - `.h` files could be C or C++ headers (kept), but Cython
`.pyx` files would be excluded despite having C-level memory concerns. Similarly,
Rust `.rs` files are correctly excluded since Rust is memory-safe.

### Stage 2: Claude API Filtering (`analyze_single_finding()`)

Each surviving finding is sent to Claude with:
- The finding JSON
- PR context (repo, title, description)
- **The actual file content** (read from disk)
- Detailed filtering instructions (17 hard exclusions + 17 precedents)

#### Hard Exclusions (in filtering prompt)

1. DOS / resource exhaustion
2. Secrets on disk (managed separately)
3. Rate limiting (services don't need to implement it)
4. Memory / CPU exhaustion
5. Input validation without proven security impact
6. Input sanitization for GitHub Action workflows
7. Lack of hardening measures (not expected to implement all best practices)
8. Theoretical race conditions / timing attacks
9. Outdated third-party library vulns (managed separately)
10. Memory safety in Rust (impossible)
11. Test-only files
12. Log spoofing
13. Path-only SSRF (must control host/protocol)
14. User content in AI prompts (not a vulnerability)
15. Internal/private dependency references
16. Crashes without security impact
17. Injecting into log queries (unless definitely exposes data to external users)

#### Filtering Precedents

1. Logging secrets = vuln; logging URLs = safe; logging request headers = dangerous
2. UUIDs are unguessable (122-bit entropy)
3. Audit logs not critical security feature
4. **Env vars and CLI flags are trusted** - attacks requiring env var control are invalid
5. Resource management issues (memory/FD leaks) not valid
6. Low-impact web vulns (tabnabbing, XS-Leaks, prototype pollution, open redirects) excluded
7. Outdated third-party library vulns excluded
8. **React XSS excluded** unless `dangerouslySetInnerHTML` / similar
9. **GitHub Action workflow vulns** must have very specific attack path
10. **Client-side JS auth checks not needed** - backend validates
11. Only include MEDIUM if obvious and concrete
12. **iPython notebook vulns** must have very specific attack path
13. Logging non-PII safe, even if "sensitive"
14. **Shell script command injection** rarely exploitable (no untrusted input)
15. **Client-side SSRF/path traversal invalid** (JS can't make server-side requests)
16. **HTTP path traversal with `../` not a problem** for HTTP requests (only for file reads)
17. Log query injection only if definitely exposes data externally

#### Confidence Scoring (in filter)

| Score | Meaning | Action |
|-------|---------|--------|
| 1-3 | Low confidence, likely false positive | Exclude |
| 4-6 | Medium, needs investigation | Exclude (threshold is 7) |
| 7-10 | High confidence, likely real | Keep |

---

## 4. The `/security-review` Slash Command

The `.claude/commands/security-review.md` ships as a Claude Code built-in slash
command. Key design differences from the GitHub Action:

| Aspect | GitHub Action | Slash Command |
|--------|--------------|---------------|
| **Scope** | PR diff | Branch diff vs `origin/HEAD` |
| **Tool access** | Claude CLI with full tools | Restricted: only git diff/status/log/show, Read, Glob, Grep, LS, Task |
| **Output format** | JSON | Markdown (human-readable) |
| **Execution** | Single Claude run + filter pass | 3 sub-tasks: (1) identify vulns, (2) parallel FP filtering, (3) confidence >= 8 filter |
| **Confidence threshold** | 7 | 8 (stricter for inline use) |
| **No Bash access** | Allowed (except ps) | Fully blocked |
| **File writes** | N/A | Explicitly forbidden |

The slash command is designed for developer workflow integration - you run it during
development, not in CI. The stricter confidence threshold (8 vs 7) and human-readable
output reflect this.

---

## 5. What It Misses / Does Not Cover

### Explicitly Deferred to Other Tools

| Gap | Reasoning |
|-----|-----------|
| **Dependency vulnerability scanning** | "Managed separately" - tools like Dependabot, Snyk |
| **Secrets in committed files** | "Managed by other processes" - tools like GitLeaks, TruffleHog |
| **DOS / availability** | Excluded as "low signal" |
| **Runtime security** | Static analysis only |

### Structural Gaps (Not Covered at All)

| Gap | Impact for rafter-cli |
|-----|----------------------|
| **Infrastructure-as-Code security** | No Terraform, CloudFormation, Kubernetes manifest checks. Agents writing IaC get no security review. |
| **Container security** | No Dockerfile analysis (privileged containers, exposed ports, root user) |
| **Cross-PR vulnerability chains** | Each PR analyzed in isolation. A vulnerability split across two PRs is invisible. |
| **OWASP API Security** | Limited to injection; no checks for API-specific issues like mass assignment, BOLA (beyond basic authz), excessive data exposure at API level |
| **Protocol-level issues** | No HTTP/2 smuggling, WebSocket security, gRPC auth checks |
| **Monorepo security contexts** | No service-boundary-aware analysis. A finding in a frontend component is treated the same as one in a backend service. |
| **SARIF output** | No standard format for integration with GitHub Code Scanning, IDEs, or other security tools |
| **Persistent knowledge base** | No memory of previously-found issues. Can't detect regression of a previously-fixed vulnerability. |
| **Code ownership routing** | Findings go to PR author only. No integration with CODEOWNERS or security team notification. |

### Implementation Weaknesses

| Weakness | Detail |
|----------|--------|
| **No ground truth eval dataset** | `evals/` has the engine but no canonical test cases. No way to measure precision/recall. |
| **File extension heuristic for language detection** | Memory safety exclusions rely on extension (`.c`, `.cc`, `.cpp`, `.h`). Cython, SWIG bindings, FFI wrappers could be missed. |
| **Single-finding filter isolation** | Each finding filtered independently in stage 2. Cross-finding context (e.g., "finding A and B together form a real attack chain") is lost. |
| **No incremental analysis** | Can't leverage previous scan results. Every run starts fresh. |
| **Generated file detection is basic** | Only checks for `@generated` markers. Misses many code gen patterns (protobuf without marker, auto-generated migrations, etc.) |
| **Prompt has typo** | `prompts.py:94` says "deseralization" (missing 'i'). Minor but indicates limited code review on the tool itself. |

---

## 6. Concrete Recommendations for rafter-cli Integration

### Recommendation 1: Embed Filtering Precedents as Agent Prompt Guidance

**Already proposed in rc-1qt.** The 10 Category A precedents should be injected
into CLAUDE.md during `rafter agent init`. This shifts security left - agents write
secure code by default rather than having it caught post-hoc.

**New insight from deep dive**: The filtering prompt's 17 hard exclusions and 17
precedents represent ~2 years of real-world false positive tuning. The Category A
selection in rc-1qt is well-chosen. No changes recommended to that proposal.

### Recommendation 2: Ship `/security-review` Integration in Agent Init

During `rafter agent init`, copy the `.claude/commands/security-review.md` slash
command to the user's project `.claude/commands/` directory. This gives every
rafter-initialized project inline security review capability.

**Customization opportunity**: Rafter could generate a project-specific version
that includes:
- Technology stack from `package.json` / `go.mod` / `requirements.txt` detection
- Custom security categories for the detected stack
- Project-specific false positive exclusions (from rafter config)

### Recommendation 3: Add Agent-Specific Security Categories

The default categories don't cover agent-specific threats. Rafter should add:

```markdown
**Agent Security:**
- Tool call injection (user input flowing into tool parameters)
- Prompt leakage (system prompts exposed in responses)
- Excessive permissions (agent requesting more tool access than needed)
- Unsafe file writes (agent writing to sensitive paths)
- Data exfiltration via tool calls (reading sensitive files, making network requests)
```

This would go into the custom security scan instructions, not the base prompt.

### Recommendation 4: Implement Two-Stage Filtering for Rafter's Review Pipeline

If rafter-cli adds any code review / security scan feature, adopt the two-stage
pattern:

1. **Hard rules** (regex, zero cost): Catch the obvious false positives that
   waste expensive API calls. The `HardExclusionRules` patterns are a proven
   starting set.
2. **LLM second-pass** (per-finding): For nuanced classification. Only called
   on findings that survive hard rules.

This reduces API costs and latency while maintaining recall.

### Recommendation 5: Build an Eval Dataset

The eval engine exists but has no ground truth. Rafter should create a curated
dataset of:
- Known-vulnerable PRs (true positives that MUST be caught)
- Known-safe PRs (true negatives that MUST NOT be flagged)
- Edge cases (where the filtering precedents matter most)

This enables measuring the precision/recall impact of any prompt changes and
validates that guardrails don't regress security coverage.

### Recommendation 6: Consider SARIF Output for CI Integration

If rafter-cli ever ships a CI security scanning feature, output SARIF (Static
Analysis Results Interchange Format). This integrates with:
- GitHub Code Scanning (appears in Security tab)
- VS Code SARIF Viewer
- Other security dashboards

The current JSON output format is custom and requires bespoke integration.

### Recommendation 7: Prompt-Injection Awareness

The README explicitly warns: "This action is not hardened against prompt injection
attacks and should only be used to review trusted PRs." This is a significant
limitation. An attacker could craft a PR with code comments that manipulate the
security review (e.g., "ignore the SQL injection on line 42").

For rafter-cli, if agents are reviewing untrusted code, the review prompt should:
- Instruct Claude to ignore natural language instructions in code comments
- Use structured delimiters between the prompt and the code being analyzed
- Flag any code that appears to address the reviewer directly

---

## 7. Key Takeaways (TL;DR)

1. **The prompt IS the product.** `prompts.py` contains the core security knowledge.
   Everything else is plumbing. Rafter should invest in prompt quality for any
   security feature.

2. **Two-stage filtering is the right pattern.** Cheap regex first, expensive LLM
   second. This is the architecture for any agent output validation.

3. **False positive filtering precedents are battle-tested secure coding knowledge.**
   Embed them in agent prompts to prevent insecure code, not just catch it.

4. **The tool has known blind spots** (IaC, containers, agent-specific threats,
   cross-PR chains, prompt injection in the review itself). Rafter should address
   these for its use cases.

5. **Eval infrastructure exists but is empty.** Building a ground truth dataset
   is essential for measuring any security improvement.

6. **The slash command is more useful than the Action for developer workflow.**
   Its restricted-tool, 3-phase sub-task design is the model for inline security
   review in agent-initialized projects.

7. **Confidence thresholds vary by context.** CI (threshold 7) vs inline (threshold 8).
   The right threshold depends on the tolerance for false positives in that context.
