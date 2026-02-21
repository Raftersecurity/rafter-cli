# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2] - 2026-02-20

### Added
- `rafter agent install-hook` — Python CLI now supports pre-commit hook installation (local and global via `--global`) at parity with Node. Bundles hook template via `importlib.resources`; backs up any existing hook before overwriting.

### Fixed
- **Python crash on `rafter --help`**: upgraded `typer` to `^0.15.0` and pinned `click<9.0.0`. Typer 0.13.x + Click 8.3.x caused `TypeError: Parameter.make_metavar() missing 1 required positional argument: 'ctx'` on fresh installs.
- **Gitleaks silent fallback**: `rafter agent init` no longer silently falls back to pattern scanning when the gitleaks binary fails. On failure, both Node and Python now surface the download URL, binary path, `gitleaks version` stdout/stderr, `file <binary>` output, arch/platform info, and glibc/musl detection on Linux, plus actionable fix instructions. (Node: `binary-manager.ts`; Python: `gitleaks.py` + `agent.py`)

### CI
- Added npm packaging smoke test to `publish.yml` (prod push only): `npm pack`, tarball inspection for `resources/pre-commit-hook.sh`, and end-to-end `agent install-hook` run against the packed tarball.

## [0.5.1] - 2026-02-14

### Added
- `rafter mcp serve` command — MCP server over stdio for cross-platform agent integrations
- Four MCP tools: `scan_secrets`, `evaluate_command`, `read_audit_log`, `get_config`
- Two MCP resources: `rafter://config`, `rafter://policy`
- `rafter hook pretool` command — PreToolUse hook handler for Claude Code
- `rafter policy export --format claude|codex` — generate agent platform configs
- `rafter agent init --claude-code` — auto-install PreToolUse hooks into Claude Code settings
- `.rafter.yml` schema validation with field-level warnings and graceful degradation

### Fixed
- Command injection in Node.js gitleaks scanner (`exec` → `execFile` with array args)
- `curl.*|.*sh` regex matching `git push` due to unbounded alternation (now word-bounded)
- Python `shell=True` in agent exec command (now uses `shlex.split`)
- Unclosed file handle in Python gitleaks scanner
- Silent policy parse failures now warn on stderr
- Python config deserialization handles Node-written camelCase JSON
- Python `AuditLogger.log()` now respects `log_all_actions: false` config (parity with Node)
- Empty regex in `custom_patterns` now rejected by schema validation
- Audit log filename aligned to `audit.jsonl` in both languages

### Changed
- Risk assessment patterns extracted to shared modules (`risk-rules.ts`, `risk_rules.py`)
- Broad `except Exception` handlers replaced with specific exception types in Python
- `/tmp` usage replaced with `os.tmpdir()` + random filenames

### Dependencies
- Added `@modelcontextprotocol/sdk` (Node.js) and `mcp` (Python) for MCP protocol support

## [0.5.0] - 2026-02-10

### Added
- `rafter ci init` command — auto-generate CI/CD pipeline configs for GitHub Actions, GitLab CI, and CircleCI
- `rafter agent scan --diff <ref>` — scan only files changed since a git ref
- `.rafter.yml` policy file — project-level security policies (custom patterns, exclude paths, command policy overrides)
- `--agent` global flag — plain text output (no colors/emoji) for AI agent consumers
- `fmt` formatter module — centralized output formatting with agent mode support

### Changed
- `rafter agent scan` now loads policy-merged config for custom patterns and exclude paths
- `RegexScanner` accepts optional custom patterns at construction time
- `ConfigManager.loadWithPolicy()` merges `.rafter.yml` overrides into config
- `CommandInterceptor` uses policy-merged config for blocked/approval patterns
- Migrated `init`, `exec`, `audit`, and `scan` commands to use `fmt` formatter
- Extracted shared `outputScanResults()` function from scan command (removes duplication)

### Dependencies
- Added `js-yaml` (runtime) and `@types/js-yaml` (dev) for YAML policy file parsing

## [0.4.0] - 2026-02-09

### Added
- Agent security command group (`rafter agent`)
- Pattern-based secret scanning (21+ secret types: AWS, GitHub, Stripe, Slack, npm, PyPI, etc.)
- Gitleaks integration with automatic binary download and graceful fallback
- Command interception with risk assessment (critical/high/medium/low)
- Dangerous command blocking (fork bombs, `rm -rf /`, `dd /dev/sda`)
- High-risk command approval workflow (`git push --force`, `sudo rm`, etc.)
- Pre-execution secret scanning for git commits
- Config management system (`~/.rafter/config.json`) with dot-notation paths
- Structured audit logging (`~/.rafter/audit.log`)
- Init wizard with environment auto-detection (OpenClaw, Claude Code, Codex CLI)
- Skill auditing system with 12-dimension security analysis
- Pre-commit hooks (per-repo and global) for automatic secret scanning
- Claude Code integration (backend + agent security skills)
- Codex CLI integration (`.agents/skills/` convention)
- Non-nagging update checker (once per day, notifies once per new version)
- `scan` alias for `run` command
- CI/CD publish workflows
- MIT LICENSE

### Changed
- Modularized CLI structure (backend commands extracted to `commands/backend/`)
- Root README rewritten to cover both backend scanning and agent security

## [0.3.0] - 2025-12-15

### Added
- Backend scan commands (`rafter run`, `rafter get`, `rafter usage`)
- Git repository auto-detection
- Interactive scan setup wizard
- JSON output support (`--format json`)
- Quiet mode for CI (`--quiet`)
- Python CLI (`pip install rafter-cli`)
- Node.js CLI (`npm install -g @rafter-security/cli`)
