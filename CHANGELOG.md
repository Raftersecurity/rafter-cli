# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.5] - 2026-02-22

### Added
- **`rafter agent install-hook --push`** (Node + Python): new flag installs a pre-push git hook that scans commits being pushed using `rafter agent scan --diff <remote_sha>`. Blocks the push if secrets are detected. Works alongside existing `--pre-commit` hook.
- **`rafter agent baseline`** subcommand (Node + Python): manage a persistent allowlist at `~/.rafter/baseline.json`. Subcommands: `create` (snapshot current findings), `show` (list entries), `clear` (wipe all), `add <file> <pattern>` (add single entry). Entries support null-line matching to suppress all instances of a pattern in a file.
- **`rafter agent scan --baseline`** (Node + Python): filters scan output against the saved baseline, suppressing known/accepted findings.
- **Webhook/Slack notifications** (Node + Python): `agent.notifications.webhook` (URL) and `agent.notifications.minRiskLevel` (`high`/`critical`) config keys. When an audit event meets or exceeds the threshold, a JSON payload is POSTed to the webhook. Compatible with Slack incoming webhooks, Discord, and generic HTTP endpoints.
- **Shell completions expanded** (Node): `rafter completion` now generates bash, zsh, and fish scripts. Added completions for `baseline`, `update-gitleaks`, and `status` subcommands.

### Fixed
- **Force push detection** (Node + Python): risk rules now detect all force-push variants regardless of flag position: `--force`, `-f`, combined flags (`-vf`), `--force-with-lease`, `--force-if-includes`, and refspec notation (`git push origin +main`).
- **SARIF output** (Node): corrected `$schema` URL to `https://json.schemastore.org/sarif-2.1.0.json`, added `tool.driver.version`, and invalid `--format` values now exit with code 2.
- **`audit-skill` exit codes** (Node + Python): file-not-found exits 2 (was 1); clean scan exits 0; findings exit 1.

## [0.5.4] - 2026-02-21

### Added
- **`rafter agent update-gitleaks`** (Node + Python): new subcommand to reinstall or upgrade the managed gitleaks binary. Accepts `--version X.Y.Z` to pin a specific release; defaults to the bundled version. Shows current version before updating.
- **`rafter agent init --update`** (Node + Python): re-downloads gitleaks and reinstalls hooks/skills without touching existing config or risk level. Useful for repair or upgrading after a broken install.
- **Windows zip extraction** (Node + Python): `rafter agent init` and `update-gitleaks` now work on Windows. Node uses PowerShell's `Expand-Archive`; Python uses the built-in `zipfile` module. Previously both threw `NotImplementedError`/`"Windows support coming soon"`.

### Fixed
- **Gitleaks extraction broken by `strip:1`** (Node): `binary-manager.ts` `extractTarball` used `strip: 1`, which collapses single-component paths (like the root-level `gitleaks` binary) to empty strings—the filter never matched and the binary was silently skipped. Removed `strip: 1`; the basename filter alone is correct and sufficient.
- **`tarfile.extract(filter=)` TypeError on Python < 3.12** (Python): `filter="data"` was introduced in Python 3.12; passing it on 3.11 raised `TypeError`. Now conditional on `sys.version_info >= (3, 12)`.

## [0.5.3] - 2026-02-21

### Added
- **SARIF 2.1.0 output** (Node + Python): `rafter agent scan --format sarif` outputs GitHub/GitLab-compatible SARIF JSON. `--format` flag accepts `text` (default), `json`, and `sarif`; `--json` remains as alias for `json`.
- **Shell completions** (Node + Python): `rafter completion bash|zsh|fish` generates shell completion scripts. Node uses `eval "$(rafter completion bash)"` pattern; Python wraps Typer's built-in `--show-completion`.
- **Custom patterns from disk** (Node + Python): `~/.rafter/patterns/*.txt` (one regex per line) and `*.json` (`{name, pattern, severity}`) are loaded and merged with built-in patterns at `RegexScanner` init.
- **`.rafterignore` suppression** (Node + Python): `~/.rafter/.rafterignore` accepts path/glob lines (or `path:pattern-name`) to suppress findings at scan time. Supports `*` and `**` glob syntax.
- **`rafter agent status`** (Node + Python): new subcommand showing config presence, gitleaks version, PreToolUse/PostToolUse hook registration, OpenClaw skill detection, and audit log summary (totals + 5 recent events).
- **Python gitleaks auto-download**: `python/rafter_cli/utils/binary_manager.py` is a full port of `binary-manager.ts`—platform/arch detection, URL construction, `urllib` download with progress, tarfile extraction (binary only), `chmod 0o755`, subprocess verification, and diagnostic collection on failure. Wired into `agent init` and `agent verify`.

### Fixed
- **Force push detection** (Node + Python): added `git push -f`, `--force-with-lease`, `--force-if-includes`, and refspec force syntax (`git push origin +main`, `+HEAD:main`).
- **Gitleaks tarball extraction** (Node): `binary-manager.ts` now uses `strip: 1` + binary-only filter—prevents `LICENSE` and `README.md` from landing in `~/.rafter/bin/`.
- **`patterns/` README**: a `README.md` explaining the directory is written on first `agent init`, preventing user confusion about the empty folder.
- **Stale `VERSION` constant**: `node/src/index.ts` `VERSION` was hardcoded to `0.5.0`; now tracks the release version correctly.
- Documentation: `audit.log` references corrected to `audit.jsonl` across `README.md`, `node/README.md`, and `CHANGELOG.md`.

## [0.5.2] - 2026-02-21

### Added
- `rafter agent install-hook` — Python CLI now supports pre-commit hook installation (local and global via `--global`) at parity with Node. Bundles hook template via `importlib.resources`; backs up any existing hook before overwriting.
- `rafter agent verify` — new subcommand (Node + Python) checks gitleaks binary, `~/.rafter/config.json`, Claude Code hooks, and OpenClaw skill; exits 0 if all pass, 1 if any fail.
- `rafter agent audit-skill` — Python CLI now has full parity with Node's skill auditing command: secret detection, URL extraction, 11 high-risk command patterns, OpenClaw integration, manual review prompt generation, `--json` output.
- `rafter agent init` now surfaces verbose error detail when OpenClaw skill install fails (path, exit code, stdout/stderr).

### Fixed
- **Python crash on `rafter --help`**: upgraded `typer` to `^0.15.0` and pinned `click<9.0.0`. Typer 0.13.x + Click 8.3.x caused `TypeError: Parameter.make_metavar() missing 1 required positional argument: 'ctx'` on fresh installs.
- **Gitleaks silent fallback**: `rafter agent init` no longer silently falls back to pattern scanning when the gitleaks binary fails. Both Node and Python now surface the download URL, binary path, `gitleaks version` stdout/stderr, `file <binary>` output, arch/platform info, and glibc/musl detection on Linux, plus actionable fix instructions.
- **Node `agent init` PATH diagnostic gap**: when a PATH-installed gitleaks binary fails to execute, Node now calls `verifyGitleaksVerbose()` + `collectBinaryDiagnostics()` and surfaces structured diagnostics, matching Python behavior.
- **`agent scan` exit codes**: exit code 2 now reserved for runtime errors (was conflated with exit code 1 for findings). Stable contract: `0`=clean, `1`=findings, `2`=error.
- JSON output schema for `agent scan --json` aligned between Node and Python.

### Documentation
- Audit log JSONL schema documented in `CLI_SPEC.md`: all event types, field names/types, required vs optional, redaction behavior, rotation notes.

### CI
- Post-publish smoke tests added to `publish.yml` (prod push only): Node (`npm pack` → tarball inspect → `agent scan` fixture) and Python (clean venv → `pip install` → `--help` → `agent scan` fixture). Both gate after publish.
- npm packaging test: verifies `resources/pre-commit-hook.sh` present in tarball and `agent install-hook` works end-to-end.

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
- Structured audit logging (`~/.rafter/audit.jsonl`)
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
