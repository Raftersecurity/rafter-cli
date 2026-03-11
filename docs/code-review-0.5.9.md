# Code Review: Rafter CLI v0.5.9

**Date:** 2026-03-08
**Scope:** npm (`@rafter-security/cli`) and PyPI (`rafter-cli`) packages at v0.5.9
**Reviewer:** Polecat quartz (automated code review)

## Executive Summary

Reviewed all source files in both the Node.js and Python packages. Found **12 issues** across security vulnerabilities, bugs, and code quality concerns. The codebase demonstrates good security intent (safe_load for YAML, list-form subprocess, execFile over exec) but has gaps in input validation, temp file handling, regex safety, and supply chain integrity.

**Overall Risk Rating: MEDIUM-HIGH**

## Dependency Audit

| Package Manager | Findings |
|----------------|----------|
| npm | 1 high: `express-rate-limit` 8.2.0–8.2.1 (GHSA-46wh-pxpv-q5gq) — IPv4-mapped IPv6 addresses bypass rate limiting |
| PyPI | No known vulnerabilities detected (pip check clean) |

## Findings

### P1 — Critical Bugs

**1. Version Mismatch (rc-o6b)**
- Node: `src/index.ts:20` hardcodes `VERSION = "0.5.7"` while package.json says 0.5.9
- Python: `__init__.py` fallback is `"0.5.0"` instead of `"0.5.9"`
- Impact: `--version` reports wrong version; update checks unreliable

**2. Commander.js --format Option Shadowing (rc-c4g)**
- `commands/scan/index.ts:39`: parent `scanGroup` defines `--format` (json|md, default "md")
- `localCmd` redefines `--format` (text|json|sarif, default "text")
- Parent option shadows child; `rafter scan local --format json` is silently ignored
- Impact: Users cannot control output format for local scans

### P2 — Security Vulnerabilities

**3. express-rate-limit CVE (rc-3y8)**
- IPv4-mapped IPv6 addresses bypass per-client rate limiting on dual-stack servers
- Fix: `npm audit fix`

**4. SSRF in Webhook URL (rc-761)**
- Node `audit-logger.ts:116` and Python `audit_logger.py:65`: webhook URL from config passed to HTTP POST without validation
- Allows `file://`, `gopher://`, or internal network URLs
- Fix: Validate URL is HTTPS, reject private IP ranges

**5. PowerShell Command Injection (rc-p4y)**
- Node `binary-manager.ts:369`: shell string interpolation with paths in PowerShell command
- If temp path contains quotes/special chars, command breaks or injects
- Fix: Use `execFile()` array form instead of shell string

**6. No Binary Integrity Check (rc-yda)**
- Both packages download gitleaks binary from GitHub without checksum or GPG verification
- MITM or compromised CDN could deliver malicious binary
- Fix: Verify SHA256 checksum against published values

**7. ReDoS in Secret Patterns (rc-doa)**
- Node `secret-patterns.ts:107`: overlapping lookaheads `(?=...)(?=...)` with `{12,}` quantifier
- Python `pattern_engine.py:108`: user-supplied regex compiled without timeout
- Fix: Simplify patterns; add regex complexity limits

### P3 — Code Quality / Hardening

**8. Audit Log Permissions (rc-ffo)**
- Both packages create audit log without explicit file mode; defaults to umask (may be world-readable)
- Fix: Set mode `0o600` on creation

**9. Symlink Traversal (rc-oto)**
- Both packages follow symlinks during directory scanning without checks
- Can escape intended scan scope; infinite loops possible
- Fix: Check `isSymlink()` and skip or follow with depth limit

**10. Weak Temp File Handling (rc-74l)**
- Node: uses `Math.random()` (predictable) for temp filenames
- Python: `mkstemp()` then immediately closes fd before use (TOCTOU race)
- Fix: Use `crypto.randomBytes()` (Node) and `NamedTemporaryFile` context manager (Python)

**11. Custom Glob Matcher Bypass (rc-05n)**
- Both packages implement custom glob-to-regex conversion that's incomplete
- Edge cases allow suppression rule bypasses
- Fix: Use `minimatch` (Node) / `fnmatch` (Python)

**12. No Config Schema Validation (rc-b5y)**
- Both packages parse JSON/YAML config without schema validation
- Malformed config causes silent failures downstream
- Fix: Use `zod` (Node) / `pydantic` (Python) for config validation

## Additional Observations (Not Filed)

- API key may leak in error messages (`node/src/commands/backend/run.ts:79`)
- Gitleaks silently falls back to pattern scanning without warning user
- Secret redaction shows first/last 4 chars (may allow reconstruction)
- `git()` helper in Node uses string concatenation with `execSync` (safe currently but fragile)
- Audit log `cleanup()` exists but is never called automatically

## Recommendations

1. **Immediate**: Fix version mismatch and --format shadowing (P1 bugs)
2. **Short-term**: Run `npm audit fix`, add webhook URL validation, add binary checksum verification
3. **Medium-term**: Simplify regex patterns, use standard glob libraries, add config schema validation
4. **Long-term**: Add symlink handling, file permission hardening, automated audit log rotation
