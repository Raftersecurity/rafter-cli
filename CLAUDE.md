# Rafter CLI — Agent Guide

Rafter is a dual-implementation (Node.js + Python) security CLI for AI coding agents. Both implementations have full feature parity and must stay in sync.

## Quick Start

```bash
# Node.js
cd node && pnpm install && pnpm test

# Python
cd python && poetry install && pytest
```

## Architecture

```
├── node/                    # TypeScript implementation (@rafter-security/cli on npm)
│   ├── src/
│   │   ├── commands/        # CLI commands (commander.js)
│   │   │   ├── agent/       # agent init/scan/exec/audit/config
│   │   │   ├── mcp/         # MCP server (server.ts exports createServer)
│   │   │   ├── scan/        # scan local/remote
│   │   │   ├── hook/        # hook pretool/commit
│   │   │   ├── policy/      # policy export/validate
│   │   │   ├── ci/          # ci init
│   │   │   ├── brief.ts     # knowledge delivery
│   │   │   ├── notify.ts    # Slack/Discord webhooks
│   │   │   └── report.ts    # HTML security reports
│   │   ├── core/            # Shared logic
│   │   │   ├── command-interceptor.ts  # Risk classification + policy enforcement
│   │   │   ├── audit-logger.ts         # JSONL audit trail
│   │   │   └── config-manager.ts       # .rafter.yml + global config
│   │   └── scanners/
│   │       ├── gitleaks.ts             # Gitleaks binary integration
│   │       ├── secret-patterns.ts      # DEFAULT_SECRET_PATTERNS array (21+ patterns)
│   │       └── regex-scanner.ts        # RegexScanner class (imports secret-patterns)
│   └── tests/               # Vitest test files
├── python/                  # Python implementation (rafter-cli on PyPI)
│   ├── rafter_cli/
│   │   ├── commands/        # CLI commands (typer)
│   │   ├── core/            # Mirrors node/src/core/
│   │   └── scanners/        # secret_patterns.py + regex_scanner.py + gitleaks.py
│   └── tests/               # pytest test files
├── shared-docs/             # Canonical specs (both implementations follow these)
│   └── CLI_SPEC.md          # Output contracts, exit codes, JSON schemas
├── recipes/                 # Copy-paste integration guides per platform
├── vscode/                  # VS Code extension
├── github-action/           # GitHub Action wrapper
└── .github/workflows/       # CI: test + publish to npm/PyPI
```

## Key Concepts

**Dual implementation**: Every feature exists in both Node and Python. Versions must match (`node/package.json` ↔ `python/pyproject.toml`). CLI_SPEC.md is the source of truth for behavior.

**8-platform support**: Platform-specific installation logic lives in `node/src/commands/agent/init.ts` (functions like `installCursorMcp()`, `installGeminiMcp()`, etc.). `rafter agent init --with-<platform>` calls the corresponding install function.

**Risk classification**: Commands are classified into 4 tiers (critical/high/medium/low) by pattern matching in `command-interceptor.ts`. Policy files (`.rafter.yml`) can override defaults.

**Secret scanning**: Dual-engine — tries Gitleaks binary first (higher accuracy), falls back to built-in regex patterns (21+ patterns, zero dependencies). Deterministic for a given version.

**MCP server**: `rafter mcp serve` exposes 4 tools (`scan_secrets`, `evaluate_command`, `read_audit_log`, `get_config`) and 2 resources (`rafter://config`, `rafter://policy`) over stdio.

## Development

### Adding a new command

1. Create `node/src/commands/<name>.ts` exporting a `createXCommand()` function
2. Register it in `node/src/index.ts`
3. Create `python/rafter_cli/commands/<name>.py`
4. Register it in `python/rafter_cli/__main__.py`
5. Add tests in both `node/tests/` and `python/tests/`
6. Update `shared-docs/CLI_SPEC.md` with output contract

### Adding a new secret pattern

1. Add the regex to `node/src/scanners/secret-patterns.ts` in the `DEFAULT_SECRET_PATTERNS` array
2. Add the same regex to `python/rafter_cli/scanners/secret_patterns.py`
3. Add test cases with real-looking (but fake) secrets in both test suites
4. Pattern format: `{ name, severity, regex, description }`

### Adding a platform adapter

1. Add an install function in `node/src/commands/agent/init.ts` (follow existing `installCursorMcp()` pattern)
2. Add corresponding logic in `python/rafter_cli/commands/agent.py`
3. Add `--with-<platform>` flag to `agent init` in both implementations
4. Add a recipe in `recipes/<platform>.md`
5. Update README.md platform list

### Testing

```bash
# Node: Vitest (fast, parallel)
cd node && pnpm test                    # all tests
cd node && npx vitest run tests/mcp-server-integration.test.ts  # single file

# Python: pytest
cd python && pytest                     # all tests
cd python && pytest tests/test_mcp_server.py -v  # single file
```

### Building

```bash
# Node
cd node && pnpm run build               # TypeScript → dist/

# Python
cd python && python -m build            # wheel + sdist
```

### Version bumps

Both `node/package.json` and `python/pyproject.toml` must have the same version. CI enforces this via `validate-release.yml`.

## Security Invariants

This is a security tool. The following contracts must hold at all times — breaking them silently degrades the security guarantees Rafter provides to users.

**Secrets are never included in output.** Raw secret values must be redacted everywhere: stdout, stderr, audit logs, JSON output, and HTML reports. The redaction format is `XXXX***XXXX` (first/last 4 chars visible for values >8 chars, fully masked otherwise). Any code path that writes secrets verbatim is a bug.

**The audit log never contains raw secrets.** `~/.rafter/audit.jsonl` records event metadata (type, location, risk level) — never the matched value. For `secret_detected` events, log the pattern name and file path, not the credential.

**Exit codes are a stable versioned API.** CI pipelines depend on them. Local scan: `0` = clean, `1` = findings, `2` = runtime error. Backend commands: `0`–`4` per CLI_SPEC.md. Do not change these semantics or add new codes without updating CLI_SPEC.md and bumping the version.

**Dual-implementation parity.** Node and Python must produce byte-identical JSON output for the same inputs on the same platform. If you change a pattern, fix, or formatter in Node, mirror the change in Python. CI enforces this; do not merge if cross-runtime tests fail.

**Secret patterns must be deterministic.** For a given CLI version and input file, the scanner must return the same findings every time. Do not use probabilistic matching or caches that change results between runs.

**Test data for patterns uses fake credentials.** When writing test cases for secret patterns, use realistic-looking but syntactically invalid values (e.g., `AKIAIOSFODNN7EXAMPLE` for AWS key tests — the AWS format but a well-known example value). Never use real credentials, even in tests.

### Before committing changes to the scanner

Always dogfood your changes:

```bash
# Scan your own staged changes before committing
rafter scan local --staged

# Verify both engines produce consistent results on test fixtures
cd node && pnpm test -- --grep "scanner"
cd python && pytest tests/ -k "scanner"
```

## Output Contracts

All scan commands write results to stdout as JSON, status messages to stderr, and use documented exit codes:

- `0` — success / no findings
- `1` — findings detected / general error
- `2` — scan not found / invalid input

See `shared-docs/CLI_SPEC.md` for full JSON schemas and exit code matrix.

## AI Policy

We welcome AI-assisted contributions. If your PR was substantially written by an AI tool, add a `Co-Authored-By` trailer and note it in the PR description. We evaluate contributions on quality, not authorship.
