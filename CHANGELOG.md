# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Claude Code `PostToolUse` hook matcher narrowed from `.*` to `Bash|Write|Edit|MultiEdit`** (Node + Python, sable-h0ah). `rafter agent init --with-claude-code` (and `rafter agent enable claude-code.hooks`) previously registered the `rafter hook posttool` redaction hook with a catch-all `.*` matcher, so it fired after **every** Claude Code tool call — including `Read` and MCP tools, which never produce secrets to redact — adding latency to every operation. The matcher now targets only the tools whose output is worth scanning: shell output (`Bash`) and file writes (`Write`/`Edit`/`MultiEdit`). PreToolUse matchers are unchanged. Codex (`.*` PostToolUse) and Gemini (`.*` AfterTool) have the same broad-matcher latency issue and are tracked separately for platform-correct narrow matchers.

## [0.8.9] - 2026-06-20

### Added
- **Opt-in `--deep` skill-review engine** (sable-7g7). `rafter skill review <path|dir|github:/gitlab:/npm:|--installed> --deep` (alias `--engine skill-scanner`) couples Cisco AI Defense's `skill-scanner` as a deeper pass — prompt injection, taint/dataflow exfiltration, YARA, and `.pyc` integrity — the blind spots the deterministic quick scan structurally cannot see. **Couple, not swap:** the zero-dependency quick scan stays the default; deep results attach a `deepScan` block (top-level for a single skill, per-skill for multi-skill / `--installed`), and only `critical`/`high`/`medium` deep findings are actionable (escalate severity + flip the exit code). **Offline analyzers only** — the argv never enables `--use-llm`/`--use-virustotal`/`--use-aidefense`/`--use-behavioral`, enforced by a `FORBIDDEN_FLAGS` test in both runtimes, so a regression that turns on a network analyzer fails CI. The engine is a heavy third-party package and is **not bundled**: the first `--deep` run offers to install it interactively (isolated, version-pinned `uv tool install`, pip `--user` fallback), or set it up ahead of time with `rafter agent update-skill-scanner` / `rafter agent init --with-skill-scanner`, and remove it with `rafter agent remove-skill-scanner`. Node + Python parity (both shell out to the same external CLI and parse identical JSON, mirroring the betterleaks pattern). `rafter agent audit-skill --deep` remains as a deprecated back-compat alias. Security-reviewed: list-form subprocess (no shell), version-pinned installer, untrusted skill paths passed as single argv elements.

### Fixed
- **Hardened `RAFTER_API_KEY` handling** (sable-q9to). Three credential gaps closed across Node + Python: (1) `~/.rafter/config.json` is now written `0600` (dir `0700`) and an existing looser-perm file is tightened on the next write; (2) `config show`/`get`/`set`, the MCP `get_config` tool, and the `rafter://config` / `rafter://policy` resources now **redact** values under credential-named keys (`api_?key|token|secret|password|credential` → `abcd****`) at every render path — the stored config is never mutated; (3) a key persisted via `rafter agent config set backend.apiKey` is now read as the lowest-precedence source (`--api-key` flag > `RAFTER_API_KEY` env > global config). Trust boundary verified: the config fallback is read only from the **global** config (`get` → `load`, never `loadWithPolicy`), so a hostile project-local `.rafter.yml` cannot inject a key that redirects scans to another account. `rafter-secure-design` run before coding.

### Changed
- **Pinned the `.rafter.yml` `ignore` matching contract in `CLI_SPEC.md`** (sable-eltr). The glob semantics are now specified exactly — `*` stays within a path segment, `**` crosses segments, bare patterns match the basename, relative globs auto-anchor anywhere — replacing the vague (and slightly inaccurate) "minimatch (Node) / fnmatch (Python)" wording. `rules` selectors now documented as matching a finding's **rule name or rule id** (case-insensitively). These semantics are honored identically by the local CLI engines and the remote `rafter run` backend, which adopted the CLI's matcher (rafter-backend ra-a8j, in response to rafter-cli#166) — so a suppression that works locally now works remotely. `suppress_finding` tool descriptions updated to match.



### Added
- **MCP `suppress_finding` tool** (sable-bjl). Agents and MCP clients can now triage a false positive directly through the MCP instead of hand-editing config. The tool persists an `ignore` rule (path glob, optional rule names, reason) into the project `.rafter.yml`, mirroring the loader's resolution precedence and creating a canonical dotfile at the git root when none exists. The merge is idempotent — re-suppressing the same path+rules scope updates the reason in place (order-insensitive) rather than appending a duplicate. Suppressed findings still surface under `_suppressed` in scan output, so the decision stays reviewable and version-controlled. This is the 7th MCP tool; Node + Python parity, with unit tests for the writer (create/append/update-in-place/dedup/empty-guard) and tool-registration assertions in both suites. Security-reviewed (CWE Top 25): the write target derives only from policy-file resolution, never from user input (no path traversal); YAML is read via safe loaders and written from structured objects (no injection); existing config is preserved.

### Changed
- **Finding-triage docs point to `.rafter.yml` + the new MCP tool** for suppression, and the previously documented-but-unimplemented inline `// rafter-ignore:` directive has been removed (product decision: not building it). See https://docs.rafter.so/suppression.

## [0.8.6] - 2026-06-13

### Added
- **Config-driven hook off-switch** (sable-bnl). The PreToolUse hook can now be disabled at runtime without uninstalling it — `RAFTER_DISABLE_HOOKS` (whole hook), `RAFTER_DISABLE_SECRET_SCAN`, and `RAFTER_DISABLE_COMMAND_POLICY` env vars (`1`/`true`/`yes`/`on` = off; `0`/`false` = force-on), or the global `~/.rafter/config.json` `agent.hooks.{enabled,secretScan,commandPolicy}` keys. Env overrides global; default enabled; a corrupt config or unrecognized value fails safe to enabled. **Honored only from these trusted, machine-owner-owned sources — never from project-local `.rafter.yml`** (a `rafter-secure-design` trust-boundary decision): otherwise cloning a hostile repo that ships `hooks: { enabled: false }` would silently disable a victim's secret scanning and command interception. `rafter agent status` (and `--json` `hook_control`) now report the effective state and which source set it. Node + Python, with cross-runtime parity tests including the security negative (a project-local disable attempt is ignored).
- **`shared-docs/CONFIG.md`** — consolidated, code-verified reference for the global (`~/.rafter/config.json`) and project (`.rafter.yml`) config layers: full key sets, the trust boundary, and a toggle matrix mapping every on/off switch to the code that enforces it.

### Fixed
- **CWE-367 TOCTOU in the betterleaks scanner** (sable-t0q). `betterleaks.ts` built its temp report path from a predictable `Date.now()` name in the shared tmpdir; replaced with `fs.mkdtempSync` (a private `0700` dir, created atomically) plus best-effort cleanup in `finally` (which also fixes prior temp-file leaks on error paths). Brings Node to parity with Python's existing `tempfile.TemporaryDirectory`.

### Notes
- Audit (sable-59s) surfaced that `agent.outputFiltering.redactSecrets` / `blockPatterns` are validated but **not enforced** at runtime (the PostToolUse hook always redacts) — tracked as sable-y2z; documented as a known gap in `CONFIG.md`.

## [0.8.5] - 2026-06-10

### Fixed
- **`hook pretool` staged-commit scan now honors `.rafter.yml` (matches `rafter secrets`)** (sable-55u). User report: `rafter hook pretool` blocked a `git commit` with "1 secret(s) detected in 1 staged file(s)" while `rafter secrets --staged` reported zero, on a 24-file diff with a large `package-lock.json`. Root cause: the hook's staged-file scan (and its `Write`/`Edit` content scan) ran `RegexScanner` directly on the raw files with **no config** — no custom patterns, no `scan.exclude_paths`, no `ignore` suppressions — so it phantom-blocked on a patterns false positive the CLI would have suppressed or excluded. (The user's "`rafter secrets` → zero" was a separate, now-fixed stale-betterleaks false negative — sable-o4k/sable-j85 — and the "not an array" warning is a CLI-path red herring: the hook never invokes betterleaks.) The hook now loads the policy-merged config via `ConfigManager.loadWithPolicy()` and applies the same `collectSuppressions → applyExcludePaths → applySuppressions` pipeline as `scan` before counting, so hook and CLI agree. The hook stays patterns-only by design (it runs on every tool call and must stay fast), which means betterleaks version skew can never affect it. Two UX improvements folded in: (1) the deny reason and audit log now name each offending `file:line — Pattern` instead of a bare count; (2) the reason notes the hook is pattern-only and points at `rafter secrets --staged` / an `exclude_paths`/`ignore` rule for false positives. Node + Python.

### Changed
- **`auto` scan mode now runs BOTH engines and unions the findings** (sable-j85, architectural fix for sable-h2y). Previously `auto` picked betterleaks whenever the binary was on disk and never also ran the patterns engine — so installing betterleaks could *narrow* coverage: betterleaks 1.1.x does not detect AWS access keys (`AKIA…`), and in `auto` mode those keys went unreported the moment the binary was present. `rafter secrets` / `scan local` (and the `scan_secrets` MCP tool) now run both engines whenever betterleaks is usable and union the results, deduplicating by `(file, line, matched text)`. When both engines flag the same secret the betterleaks rule-id is kept and both are recorded. Each finding in JSON output carries a new `engines` attribution array (`["betterleaks"]`, `["patterns"]`, or both); explicit `--engine betterleaks` / `--engine patterns` stay single-engine and omit it. `auto` still degrades to patterns-only when betterleaks is absent or a stale binary can't be refreshed (sable-o4k). Acceptance: a default-engine scan now catches an `AKIA…` key betterleaks misses. Performance: the default scan runs two engines instead of one (the regex walk overlaps the betterleaks subprocess); correctness is the goal. Node + Python.

### Added
- **Auto-update a stale managed betterleaks binary at scan time** (sable-o4k). A leftover `~/.rafter/bin/betterleaks` from an older rafter (a gitleaks-8.x install from before the rename, or an older betterleaks) runs `version` fine but emits a JSON report shape the current parser rejects — the parser returned `[]` with only a stderr warning, so the default `--engine betterleaks` path silently reported **zero findings** for anyone upgrading from `<0.8` to `>=0.8`. `rafter secrets` / `scan local` now detect a stale managed binary at engine-selection (reported version doesn't contain the pinned `BETTERLEAKS_VERSION`) and auto-update it to the pinned version before scanning. Default on; opt out with `--no-auto-update` or `scan.auto_update_betterleaks: false` (e.g. CI that provisions its own binary) — either disables it. In an interactive TTY the update is confirmed first. If the update is disabled, declined, or fails, the scan degrades to the patterns engine and prints a one-line CTA (`rafter agent update-betterleaks`) instead of a silent zero. Only the rafter-managed binary is auto-updated; a stale binary on `PATH` (which we can't safely overwrite) now warns with the same CTA via the parser. Node + Python.

### Changed
- **Purge remaining user-facing deprecated-alias references** (sable-8vh). `rafter secrets` is the canonical local secret-scan command; `rafter scan local` and `rafter agent scan` remain back-compat aliases (`agent scan` warns at runtime, `scan local` stays a quiet hidden alias to avoid breaking migrated CI). This pass mops up the last user-facing surfaces that still taught a deprecated form: `python/README.md` quick-reference (taught `rafter agent scan`), the `Dockerfile` usage comments, and `demo.tape`. README, recipes, and `CLI_SPEC.md` were already canonical. No code or behavior change.

## [0.8.4] - 2026-06-01

### Fixed
- **`rafter secrets` now honors `.rafter.yml scan.exclude_paths` on both engines** (#152, sable-yz0). Customer report: planting fake secrets in three `scan.exclude_paths` entries AND a non-excluded path → all three got flagged, `exclude_paths` silently ignored. Two root causes: (1) `BetterleaksScanner.scanDirectory()` never received `excludePaths`, so the `auto`-engine happy-path (the default when the binary is on disk) silently dropped customer policy; (2) the patterns engine's walker only matched entries against single directory NAMES (`entry.name`), so multi-segment paths like `components/common/Mermaid.tsx` got no filtering at all. Fix: post-filter chokepoint after both engines (and `--staged` / `--diff` modes) with path-aware semantics — exact path, directory-prefix (trailing `/` normalized), dir-name-anywhere (preserves the historical walker behavior for `node_modules`-style entries), and globs via minimatch (Node) / fnmatch (Python). Customer's exact repro now passes on both engines.

### Changed
- **CLI reads `.rafter/config.yml` indefinitely + accepts backend's flat-shape schema** (#154, sable-c1c). The cloud scanner (`rafter-backend`) reads policy at `.rafter/config.yml` (subdir + `config.yml`) with `exclude_paths` / `custom_patterns` flat at the top level, while the CLI canonical is `.rafter.yml` with `scan.*` nested. Customers writing either shape used to get honored by only one tool. CLI now reads all four candidates in precedence order (`.rafter.yml` → `.rafter.yaml` → `.rafter/config.yml` → `.rafter/config.yaml`) and accepts both schemas in either file — nested `scan.*` wins over top-level on collision. No deprecation; backend's file path stays a first-class location. Backend pairs this with `.rafter.yml` fallback + `scan.*` schema compat on their side to complete the bilateral alignment.

### Added
- **Hermes platform support** (#151, sable-gyw). `rafter agent init --with-hermes` merges the Rafter MCP server into `~/.hermes/config.yaml` under `mcp_servers.rafter` (snake_case, distinct from Cursor/Windsurf's `mcpServers` camelCase). Existing servers and other top-level YAML keys are preserved. Recipe at `recipes/hermes.md`. MCP-only v0 — hook surface deferred pending Hermes documenting one, mirroring how Gemini and Continue.dev were initially shipped. Brings the supported-platforms list to nine.
- **`rafter agent status --json`** (#153). Reports installed state, version, detected agents, installed git hooks, scanner availability, and config / audit paths. Schema documented in `shared-docs/CLI_SPEC.md`.

## [0.8.3] - 2026-05-31

### Changed
- **`github-action/` cloud variant: `severity-threshold` default is now `none` (report-only)** (#148). Previously a fresh install with no `severity-threshold` set would fail the build on any critical/high finding — so first-install on a real repo almost always broke CI on day one, the worst possible first impression for a security tool. The default now matches Snyk / CodeQL / Semgrep: scan completes, findings post as a PR comment, SARIF uploads to the Security tab, but the workflow exits 0 regardless of severity. When findings exist under the report-only default, the PR comment includes a one-line tip pointing to `severity-threshold: high` for opt-in enforcement. Workflows that set `severity-threshold` explicitly are unaffected. README updated with an "Enforce in CI (recommended after first scan)" example. Affects only the cloud-API action at `Raftersecurity/rafter-cli/github-action@…`; the root `Raftersecurity/rafter-cli@v…` local-secrets action is unchanged.

### Infrastructure
- `publish.yaml` migrated to npm Trusted Publishing (OIDC) — no more long-lived `NPM_TOKEN` (#142). Renamed `publish.yml` → `publish.yaml` to match npm's Trusted Publisher manifest, and added `--skip-existing` on the PyPI upload so retries of a partially-failed release no longer error on "File already exists" (#143).
- `node/package.json` now declares `repository` / `homepage` / `bugs` / `license` / `author` metadata so the npm listing renders sidebar links correctly (#145).
- Cursor recipe in the rafter SKILL `Setup` section now leads with `--local` for ephemeral / containerized setups (#147).

## [0.8.2] - 2026-05-26

### Changed
- **Local secrets scanner respects `.gitignore` by default.** `rafter secrets <dir>` (and the deprecated alias `rafter agent scan <dir>`) used to walk every file under the target directory regardless of `.gitignore`, surfacing findings in build outputs, vendored deps, and one-off scratch files that the repo had explicitly excluded. The directory walker now batches the candidate file list through `git check-ignore --stdin --no-index -z` inside the scan root's git work tree, so every gitignore semantic git itself supports — nested `.gitignore`, negations, `.git/info/exclude`, the configured global excludes file, the full pattern grammar — is honored exactly. Zero new dependencies. Scans against directories outside a git work tree (or with git missing) silently fall back to the prior behavior. Opt out with `--no-gitignore`. Honored by `rafter secrets`, `rafter agent scan`, and `rafter agent baseline create`. Betterleaks engine already honors `.gitignore` natively (gitleaks ancestry); this change brings the built-in pattern engine to parity. Node + Python.

## [0.8.1] - 2026-05-12

### Fixed
- **CI ClawHub publish auth + Node 22** (#101). The first post-0.8.0 publish failed with `Error: Not logged in. Run: clawhub login` on the `whoami` step — the assumption baked into the original ClawHub wiring that the CLI auto-reads `CLAWHUB_TOKEN` from env was wrong. Added an explicit `clawhub login --token "$CLAWHUB_TOKEN"` line before any `clawhub` call; the persisted token lives in the runner's ephemeral filesystem and is discarded when the job ends. Also bumped `setup-node` in the `publish-clawhub` job from 20 → 22 because clawhub's transitive dep `p-retry@8` requires Node ≥22 (Node 20 surfaced as an `EBADENGINE` warning in the failed run, but would have hit a real runtime error later).
- **Stale test diagnostic + obsolete assertions across the test suite.** rf-of20 (Claude Code sub-agent idempotency test: diagnostic now surfaces the actual divergence on failure), rf-b1hf (drop obsolete sub-docs mirror assertion in `brief.test.ts` — sub-docs no longer ship under skills root), rf-ax2p (e2e regex updated to match the wrapped "Secrets only" help text). Cross-runtime parity tests + the comprehensive test suite updated for the rf-0pch wrapped-JSON shape and to use `rafter secrets` in place of the deprecated `rafter scan local` alias.
- **rc-bc9: deleted `node/.claude/skills/`.** A stale development copy of the skill content that drifted from the canonical `node/resources/skills/`. Removing it eliminates the drift class entirely; the resources tree is the single source of truth.

## [0.8.0] - 2026-05-10

### Changed
- **Secret-scanning engine migrated from gitleaks to betterleaks** (Node + Python, rc-ksy / rc-963). [Betterleaks](https://github.com/betterleaks/betterleaks) v1.1.2 is the gitleaks successor maintained by the same authors. JSON report shape is unchanged; what changed is the binary, the CLI subcommand (`detect --no-git -s` → `dir <path>`), the release URL, and the checksum filename.
  - **Breaking:** the legacy CLI surface has been removed entirely. `--with-gitleaks`, `--engine gitleaks`, and `rafter agent update-gitleaks` now error out (unknown option / invalid engine / unknown command). Use `--with-betterleaks`, `--engine betterleaks`, and `rafter agent update-betterleaks`. **This is the reason for the 0.8.0 minor bump on a 0.x line.**
  - **Soft landing for existing installs:** `rafter agent verify` and `rafter agent status` continue to detect a leftover `~/.rafter/bin/gitleaks` (or `gitleaks` on PATH) and emit "legacy gitleaks at X — run: rafter agent update-betterleaks" instead of a confusing "not found". Verify exits 0 in this case (was a hard fail before this fix).
  - **Supply-chain hardening:** SHA256 hashes for the bundled `BETTERLEAKS_VERSION` are pinned in source, so the default install no longer trusts the release-page `checksums.txt` to authenticate itself. Tar/zip extraction now rejects symlink/hardlink/device entries (mitigates a malicious-release symlink-redirect that the subsequent `chmod +x` would have followed). Downloads refuse non-https URLs. The optional `--version` flag is validated against `^[A-Za-z0-9._-]+$` to neutralize URL injection. Targets passed to betterleaks are preceded by `--` so a path beginning with `-` isn't parsed as a flag.
  - Internal renames: `GitleaksScanner` → `BetterleaksScanner`, `*_gitleaks` methods → `*_betterleaks`, `GITLEAKS_VERSION` → `BETTERLEAKS_VERSION`. New tests cover pinned-hash table completeness, `--version` validation, non-https refusal, and the alias-removal contract.
- **Purge user-facing `scan local` references** (rc-dmp). The Commander/Typer subcommand was already hidden behind `rafter secrets` — this pass mops up the surfaces that still recommended the alias: `.pre-commit-hooks.yaml` (3 hook entries), `fixtures/vulnerable-repo/README.md` demo commands, `node/.claude/skills/*` dev copies (9 refs), `node/src/commands/issues/from-scan.ts` `--from-local` help text, and `shared-docs/CLI_SPEC.md` baseline example. Alias plumbing, internal comments, and the alias-test path are intentionally retained for backward compat.

### Added
- **`rafter agent init --dry-run`** (Node + Python, rf-hrtd). Prints every file path the command would create, modify, or download — without making any changes. Lists the always-written `~/.rafter/config.json` and bin/patterns dirs, then per-enabled-platform sections (Claude Code, Codex, Gemini, Cursor, Windsurf, Continue.dev, Aider, OpenClaw) with file paths and short notes about what each write contains. Optional Betterleaks binary download is listed as `DOWNLOAD`. The plan is built from the same resolved `want_*` / `has_*` booleans the install path uses, so the listing mirrors what would actually run. Three new Node tests + three new Python tests confirm `--dry-run` writes nothing (not even the always-create `~/.rafter/config.json`) and lists every section under `--local --all`. Closes the rf-v85b P0-1 review concern: security-conscious adopters can preview every edit before accepting.
- **ClawHub auto-publish on release** (CI). `.github/workflows/publish.yml` now runs `clawhub skill publish` against the rafter-security SKILL.md after every `prod`-branch deploy. Skips on forks (gated on `secrets.CLAWHUB_TOKEN`); fails loudly on auth or publish errors on the canonical repo. `validate-release.yml` was extended to enforce that `version:` in both Node and Python copies of `rafter-security-skill.md` matches the package version — drift would silently ship a stale ClawHub release. OpenClaw users can now install rafter via `clawhub skill install rafter-security` as an alternative to `rafter agent init --with-openclaw`.

### Fixed
- **GitHub Action `finding-count` always 0** (rf-cfjc). The composite action's jq count query (`[.[].matches[]] | length`) errored on the wrapped JSON shape introduced in v0.7.7 (rf-0pch: `{_note, scan_mode, triage_applied, results: [...]}`) and silently fell through to `"0"`. Test Composite Action's `detect secrets in fixture` job had been failing on every push since betterleaks merged, even though the scanner was correctly detecting the AKIA fixture. Replaced with a type-aware query that handles both the wrapped object (current) and the bare array (older `version:` pins).
- **CI ClawHub publish handle** (#96). The actual ClawHub owner handle is `rafter`, not `raftersecurity`. Without this, the first real ClawHub publish would have failed with "owner not found".
- **README pre-commit rev pins** (rf-z6sv, #97). Both pre-commit examples in README.md were stuck at v0.7.1; bumped to track the latest published tag so new adopters get the rf-zfhj GitHub Action fix, the rf-zgwj OpenClaw ClawHub-shape fix, and the audit-log hash-chain hardening.

## [0.7.9] - 2026-05-08

### Fixed
- **GitHub Action `@v1` tag YAML parse error** (rf-zfhj). The `v1` major-version tag was stuck at a commit whose root `action.yml` had unquoted descriptions with embedded colons (`description: Path to scan for secrets (default: repository root)`), causing GitHub Actions to fail every PR run with `Mapping values are not allowed in this context`. `v1` now points at current main HEAD, which has the description-quoting fix and the `--fail-with-body` curl rewrite from PR #76.
- **CI `Validate Release` test-build job green** (rf-6s9l, rf-b9l8, rf-blvo). 13 Node tests across 4 files updated to match shape changes that already landed on main: rf-0pch (`rafter scan local --json` now wraps results in `{_note, scan_mode, triage_applied, results, _suppressed?}`), rf-d8s (`Suppression` gained a `source: ".rafterignore" | ".rafter.yml"` field), and rf-zgwj (OpenClaw skill install path moved to the canonical ClawHub `~/.openclaw/workspace/skills/rafter-security/SKILL.md`). Test-only changes; no production behavior shift.

### Changed
- **OpenClaw integration rebuilt as a ClawHub-shaped skill** (Node + Python, rf-zgwj). Previously rafter wrote a single markdown file at `~/.openclaw/skills/rafter-security.md` — a path OpenClaw never read at runtime. ClawHub auto-discovers skills from `<workspace>/skills/<name>/SKILL.md`. The new install:
  - Writes `~/.openclaw/workspace/skills/rafter-security/SKILL.md` (the canonical ClawHub path).
  - Adds the ClawHub-required top-level frontmatter (`name`, `description`, `version`) alongside the existing `openclaw:` runtime block. Now passes ClawHub's metadata schema check.
  - Migration: reinstall on top of the rafter ≤ 0.7.7 layout strips the legacy `~/.openclaw/skills/rafter-security.md`. Verify warns when only the legacy file is present and prints the migration command.
  - **Re-included in `--all`**: the rf-0lig demote is reverted because the new shape is what OpenClaw actually consumes. `--with-openclaw` still works as explicit opt-in.
  - Detection now uses `~/.openclaw/` (the platform root) instead of `~/.openclaw/skills/` (the no-longer-correct skills dir), so a fresh OpenClaw install is detected without needing a hand-installed skill.
  - Backed by 5 new Node tests in `openclaw-integration.test.ts` (canonical-path install, ClawHub frontmatter, legacy-strip migration, plus the existing 14) and 5 new Python tests in `TestInstallOpenClawSkill` + `TestCheckOpenClaw`. Recipe rewritten to match the new shape.

### Added
- **`docs/adding-a-platform.md` onboarding contract** (rf-o329 / rf-cia phase d). Single canonical doc for adding rafter integration to a new agent CLI / IDE: 5-question pre-flight (hooks, skills, instruction file, MCP, sub-agent), file-by-file checklist across both impls, decision tree per integration shape, dual-impl rule, verification gate (file-presence tests + `agent verify --probe`), and a worked example for a fictional "Cleo" platform. Documents known exceptions (OpenClaw category mismatch, Aider's read-only-context-only shape, no-hook-surface platforms). Linked from README "Documentation".

- **`rafter agent verify` — Python parity, Continue/Aider coverage, `--json`, and `--probe` runtime mode** (Node + Python, rf-65zg / rf-cia phase d). Verify is now 10 checks across all 8 supported platforms in both implementations:
  - **Python parity:** added `_check_gemini`, `_check_cursor`, `_check_windsurf` so Python now covers everything Node covers (was MCP-only / Claude-only before).
  - **Continue.dev + Aider:** new `checkContinueDev` (Node) / `_check_continue_dev` (Python) verifies the MCP entry. New `checkAider` / `_check_aider` reads `.aider.conf.yml` and confirms `RAFTER.md` is in `read:` AND on disk (rf-du2o-aware).
  - **`--json`:** emits a single JSON object (`checks[]` + `summary`) with stable `pass | warn | fail` status — intended for CI consumption. Schema documented in `shared-docs/CLI_SPEC.md`.
  - **`--probe`:** runtime probe for Claude Code that synthesizes a `PreToolUse` stdin payload with a known-dangerous sentinel command, invokes `rafter hook pretool`, and asserts `~/.rafter/audit.jsonl` recorded a `command_intercepted` entry for the sentinel. Catches the rf-luk-style "wrote file but the hook never fires" failure mode without driving Claude Code itself. Codex/Cursor/Gemini probes can be added in follow-ups using each platform's documented payload format.
  - The `Claude Code` and Python claude-hook check now substring-match the hook command, so `rafter hook pretool` and `<abs-path>/rafter hook pretool` (Python install style) both verify clean.

### Changed
- **Codex hook matchers now intercept `apply_patch` (file edits) in addition to `Bash`** (Node + Python, rf-ovql / rf-cia phase c). Schema verified against `developers.openai.com/codex/hooks` — Codex's `PreToolUse` documents support for Bash, `apply_patch` file edits, and MCP tool calls; we previously only matched `Bash`. Updated `~/.codex/hooks.json` `PreToolUse.matcher` from `"Bash"` to `"Bash|apply_patch"` so file edits actually fire the rafter pretool hook. The known Codex limitation that hooks don't fire for every shell call (per upstream issues #16732 / #20204) is unchanged from our side.
- **Gemini hook matchers now use the documented Gemini built-in tool names** (Node + Python, rf-044o / rf-cia phase c). Schema verified against `geminicli.com/docs/hooks/reference` — `BeforeTool`/`AfterTool` are the canonical events, `matcher` is a regex against the built-in tool name. Updated `~/.gemini/settings.json` `BeforeTool.matcher` from the implicit-substring `"shell|write_file"` to the explicit `"run_shell_command|write_file|replace|edit"` so the install reads cleanly against current docs and is robust if Gemini ever tightens the matcher to exact-name.

### Added
- **`rafter agent init --with-claude-code` installs a first-class `.claude/agents/rafter.md` sub-agent** (Node + Python, rf-q7j): alongside the existing skills install, drops a Claude Code sub-agent definition that the calling agent can invoke via `Agent(subagent_type="rafter")`. Sub-agents appear in the main agent's tool list (skills only surface in the activation prompt), making delegation the natural motion for "is this safe / secure / production worthy?" questions. Sub-agent body documents the tier hierarchy — `rafter run` (default, SAST+SCA, needs `RAFTER_API_KEY`), `rafter run --mode plus` (agentic deep-dive), `rafter secrets` (offline secrets-only fallback) — and is hard-restricted to `Bash`, `Read`, `Grep` (no code modification, no commits, no non-rafter scanners).

- **Continue.dev per-skill workspace rules + project-scope (`--local`) install** (Node + Python, rf-acz0 / rf-cia phase c). `rafter agent init --with-continue` now ships:
  - 4 per-skill rule files at `.continue/rules/<skill>.md` with Continue.dev YAML frontmatter (`name:`, `description:`, `alwaysApply: false`) — `rafter`, `rafter-secure-design`, `rafter-code-review`, `rafter-skill-review`.
  - `--local` (project) scope install, in addition to user scope. Project install ships rules only; user install additionally registers the MCP entry under `~/.continue/config.json`.
  - New `continue.rules` ComponentSpec, manageable via `rafter agent enable/disable`.
  - Backed by 2 new Node tests + 3 new Python tests; combined-platforms integration test asserts the rules ship; recipe rewritten to match.

- **Aider read-only context: `RAFTER.md` + `.aider.conf.yml read:` entry** (Node + Python, rf-du2o / rf-cia phase c). Aider has no plugin/hook system and no native MCP support — `read:` in `.aider.conf.yml` is its only documented persistent-context primitive. `rafter agent init --with-aider` now writes:
  - `RAFTER.md` at workspace root with the rafter security context block (`<!-- rafter:start --> ... <!-- rafter:end -->`).
  - Adds `RAFTER.md` to the `read:` list in `.aider.conf.yml` (preserves existing keys and existing `read:` entries; idempotent across reinstalls).
  - Reinstalls on top of older layouts strip the legacy `mcp-server-command: rafter mcp serve` line (silent no-op — Aider ignored unknown YAML keys per its docs).
  - Now installs at `--local` (project) scope. Backed by 6 new Node tests + 6 new Python tests; recipe rewritten to match.

- **Windsurf deep support: per-skill workspace rules + AGENTS.md + project-scope (`--local`) install** (Node + Python, rf-0vr3 / rf-cia phase c). `rafter agent init --with-windsurf` now ships Windsurf the way it actually consumes context:
  - Writes 4 per-skill rules under `.windsurf/rules/<skill>.md` with Windsurf YAML frontmatter (`trigger: model_decision`, `description:`) so the agent fetches the right rule per task description.
  - Writes `AGENTS.md` at workspace root — Windsurf reads it natively (so does Codex; one file covers both). `<!-- rafter:start --> ... <!-- rafter:end -->` marker preserves user content.
  - Now installs at `--local` (project) scope as well as user scope. Project install ships rules + AGENTS.md; user install additionally registers the MCP entry under `~/.codeium/windsurf/mcp_config.json`.
  - Backed by 5 new Node tests + 4 new Python tests, plus updates to the existing combined-platforms integration test.

- **Cursor deep support: per-skill rules + sub-agent + full pre/post-tool hooks** (Node + Python, rf-svn3 / rf-cia phase c). `rafter agent init --with-cursor` now ships Cursor to Claude-Code parity:
  - Hooks at `~/.cursor/hooks.json` cover `preToolUse` + `postToolUse` + `beforeShellExecution` (was `beforeShellExecution` only). Idempotent across all three events; non-rafter entries preserved.
  - Replaces the single consolidated `.cursor/rules/rafter-security.mdc` with **four per-skill rules** (`rafter.mdc`, `rafter-secure-design.mdc`, `rafter-code-review.mdc`, `rafter-skill-review.mdc`). Each rule's frontmatter description is reused verbatim from the skill's `SKILL.md` (trigger-first), `alwaysApply: false`. The legacy file is auto-removed on reinstall.
  - Drops the rafter sub-agent at `.cursor/agents/rafter.md`, reusing the rf-q7j Claude-Code sub-agent body with the `tools:` line stripped (Cursor's frontmatter doesn't have it; tools inherit from parent).
  - Backed by 13 new Node tests and 12 new Python tests. The `cursor.instructions` component now manages rules + sub-agent together for `rafter agent enable/disable`.

### Removed
- **`rafter agent init --with-aider` no longer appends `mcp-server-command: rafter mcp serve` to `.aider.conf.yml`** (Node + Python, rf-du2o): Aider has no native MCP support; the unknown YAML key was silently ignored at runtime (independently flagged by gap reports rf-p1ri / rf-vayl and research bead rf-s1n3). Removed `installAiderMcp` from the Node init flow, `_aider_mcp` ComponentSpec from both Node and Python registries (replaced by `aider.read`), and the matching test expectations. Reinstalling on top of an older `.aider.conf.yml` strips the legacy line as a migration step.

- **`rafter agent init --with-windsurf` no longer writes `~/.windsurf/hooks.json`** (Node + Python, rf-0vr3): Windsurf has no documented hook surface in current versions — `pre_run_command` / `pre_write_code` were not consumed by the IDE at runtime. The install was a silent no-op (independently flagged by gap reports rf-p1ri / rf-vayl and research bead rf-s1n3). Pruned along the same pattern as the Continue.dev hooks prune. Removed `installWindsurfHooks` from the Node init flow, `_windsurf_hooks` ComponentSpec from both registries, and the matching test expectations. The MCP install at `~/.codeium/windsurf/mcp_config.json` is unchanged.

- **`rafter agent init --with-continue` no longer writes `~/.continue/settings.json`** (Node + Python, rf-cia): Continue.dev does not read `settings.json` and has no `hooks.PreToolUse`/`PostToolUse` field in its config schema (current versions use `config.yaml`, legacy uses `config.json`). The hook install was a silent no-op at runtime — files written, never consumed. Removed `installContinueDevHooks` from the Node init flow, `_continue_hooks` ComponentSpec from both Node and Python `rafter agent enable/disable` registries, and the matching test expectations. MCP install (`.continue/config.json` mcpServers entry) is unchanged. Continue.dev integration is now MCP-only — matches what `recipes/continue-dev.md` always claimed.

## [0.7.4] - 2026-04-21

### Added
- **`rafter agent init --with-gemini` now installs and registers skills** (Node + Python, rf-yit): Gemini adapter previously only wrote MCP config and GEMINI.md — gemini never saw rafter's SKILL.md files. Now mirrors the Codex installer: copies `rafter`, `rafter-secure-design`, and `rafter-code-review` SKILL.md files into `<root>/.agents/skills/` (shared with Codex), then calls `gemini skills link <abs-path>` for each so gemini registers them in its native skill system. Missing `gemini` binary, missing `skills` subcommand (needs gemini ≥ 0.35), or per-skill registration failures are warnings, not errors — on-disk install still succeeds.

## [0.7.3] - 2026-04-20

### Added
- **`rafter agent init --with-codex` writes AGENTS.md** (Node + Python, rf-djw): Codex adapter now installs a `<!-- rafter:start -->…<!-- rafter:end -->` instruction block to `~/.codex/AGENTS.md` (user scope) or `<cwd>/AGENTS.md` (project scope), pointing Codex at the installed rafter skills. Idempotent marker-block write preserves user content.
- **`rafter agent init --with-gemini` writes GEMINI.md** (Node + Python, rf-xx9): Gemini adapter gets the same treatment — marker-block injection into `~/.gemini/GEMINI.md` or `<cwd>/GEMINI.md`.

### Changed
- **Consolidated `rafter-agent-security` skill** (Node + Python, rc-0ba): merged its content into the `rafter` router and `rafter-skill-review`; removed the standalone SKILL.md, registry entry, and brief topic. `AGENT_SKILLS` is now the canonical three: `rafter`, `rafter-secure-design`, `rafter-code-review`.

## [0.7.2] - 2026-04-17

### Changed
- **Version bump only.** 0.7.1 published to npm successfully but PyPI upload failed (400 Bad Request). Re-publishing under 0.7.2 to keep Node + Python in parity — no code changes vs 0.7.1.

## [0.7.1] - 2026-04-17

### Added
- **`rafter agent init --local`** (Node + Python): install integration configs into the current working directory instead of the user home. Writes `./.claude/`, `./.agents/`, `./.gemini/`, `./.cursor/` etc. Supports `--with-claude-code`, `--with-codex`, `--with-gemini`, `--with-cursor`. User-scope side effects (auto-detection, `agent.environments.*.enabled`, gitleaks download) are suppressed in `--local` mode. Unblocks benchmark harnesses, CI runners, and ephemeral containers that need per-repo opt-in without mutating user-global config.

### Fixed
- **Claude Code + Codex skill install now wires all 4 skills** (Node + Python): `installClaudeCodeSkills` and `installCodexSkills` previously only copied `rafter` and `rafter-agent-security`, silently dropping `rafter-secure-design` and `rafter-code-review` even though their `SKILL.md` files ship in `resources/skills/`. Replaced the hardcoded list with a table-driven `AGENT_SKILLS` so every bundled skill is delivered by `agent init`.
- **Python agent install parity** (Python): the Python implementation had drifted — no `_install_claude_code_skills` or `_install_global_instructions` existed, so `agent init --with-claude-code` on Python was missing skill delivery and the project-level `CLAUDE.md` instructions file. Both now implemented and match the Node installer.

### Changed
- **Secret pattern consistency** (Python): tightened Generic Secret regex to require both digit and letter with 12+ char minimum (was 8+, digit-only). Tightened Bearer Token regex to require both digit and letter with 20+ char minimum (was 1+). Now matches Node behavior for reduced false positives.
- **Config schema parity** (Python): added 5 missing environment configs (gemini, aider, cursor, windsurf, continue_dev) and `skills` config section (autoUpdate, installOnInit, backupBeforeUpdate) to match Node.
- **API base URL** (Python): normalized `API_BASE` to include trailing slash, matching Node constant.

## [0.6.2] - 2026-03-12

### Added
- **Scan modes** (Node + Python): new `--mode` / `-m` flag for `rafter run`, `rafter scan`, and `rafter scan remote`. Accepted values: `fast` (default) and `plus`. Sends `scan_mode` in the API request body to select scan depth.

## [0.6.1] - 2026-03-09

### Fixed
- **Claude Code hook errors** (Python): `rafter agent init --with-claude-code` registered hooks with bare `rafter` command, which fails in Claude Code's minimal shell environment (no user PATH). Now resolves the absolute path to the rafter binary at install time.
- **CI broken since v0.6.0**: `validate-release` and `publish` workflows used pnpm@9, but `pnpm-workspace.yaml` uses pnpm v10 features (`onlyBuiltDependencies`, workspace-level `overrides`), causing `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` on every run. Upgraded to pnpm@10.
- **MCP server version hardcoded** (Node): `rafter mcp serve` reported version `0.5.0` to MCP clients. Now reports correct version.
- **GitHub Action uses deprecated command**: `action.yml` referenced `rafter agent scan` (deprecated since v0.5.7). Updated to `rafter scan local`.
- **Pre-commit hooks use deprecated command**: `.pre-commit-hooks.yaml` entries referenced `rafter agent scan`. Updated to `rafter scan local`.
- **README pre-commit rev outdated**: pinned revision updated from `v0.5.6` to `v0.6.1`.

## [0.6.0] - 2026-03-08

### Security
- **SSRF in webhook URL** (Node + Python): audit logger accepted arbitrary webhook URLs from config without validation. Now blocks non-HTTPS schemes, localhost, private IPs, and link-local addresses.
- **Shell injection in PowerShell extraction** (Node): `Expand-Archive` command in `binary-manager.ts` interpolated file paths unsafely. Single quotes in paths are now escaped before interpolation.
- **No integrity check on gitleaks binary** (Node + Python): downloaded gitleaks binaries were verified only by file size. Now downloads `checksums.txt` from the release and validates SHA256 before extraction.
- **express-rate-limit CVE** (Node): updated express-rate-limit to >=8.2.2 to fix GHSA-46wh-pxpv-q5gq (IPv4-mapped IPv6 bypass).
- **ReDoS in secret patterns** (Node + Python): complex regexes with overlapping lookaheads and unbounded quantifiers could cause catastrophic backtracking. Added upper bounds to all unbounded quantifiers and eliminated overlapping character classes.
- **Symlink traversal in directory scanner** (Node + Python): scanner followed symlinks, allowing traversal outside the intended scan scope. Now skips symlinks via `lstat`.
- **Audit log world-readable** (Node + Python): audit log files were created without setting permissions. Now sets 0o600 (files) and 0o700 (directories).
- **Weak temp file naming** (Node): used `Math.random()` for temp filenames; replaced with `crypto.randomBytes`. Python: fixed mkstemp TOCTOU race by keeping fd open.

### Fixed
- **Version mismatch** (Node): `--version` reported 0.5.7 due to hardcoded constant. Now reads version from `package.json` at runtime.
- **`--format` flag ignored for `scan local`** (Node): parent `scan` command's `--format` option shadowed the child `local` command's option in Commander.js. Fixed with `enablePositionalOptions()`.
- **`agent audit` crash** (Node): TypeError when audit entries lack `securityCheck` property (e.g., from hook pretool/posttool). Added null guards.
- **Rich markup leak to stdout** (Python): issues commands printed raw Rich markup tags (`[cyan]...[/cyan]`) instead of rendered ANSI. Now uses Rich Console for stderr output.
- **Traceback leak on `gh` failure** (Python): `issues create from-text` showed full Python traceback when `gh` CLI failed. Now catches `CalledProcessError` and shows clean error message.
- **Custom glob matcher bypassable** (Node + Python): replaced fragile custom glob implementation with `minimatch` (Node) and `fnmatch` (Python).
- **Config/policy schema validation** (Node + Python): JSON/YAML config and custom pattern files were parsed but not validated. Added schema validation after parse.

### Changed
- **Python fallback version** updated from 0.5.0 to 0.6.0.

## [0.5.9] - 2026-03-08

### Fixed
- **[CRITICAL] Gitleaks file-scan false negatives** (Node): catch block in `gitleaks.ts` deleted tmpReport before checking exit code 1 (leaks found), making leak recovery unreachable. Reordered to read report before cleanup.
- **Staged/diff path resolution** (Node): `--staged` and `--diff` scans resolved file paths relative to cwd instead of git repo root, causing missed files when run from subdirectories. Now uses `git rev-parse --show-toplevel`.
- **Output format consistency** (Node): `--staged`/`--diff` with no files output plain text even when `--format json` was set. Early returns now route through `outputScanResults` to respect format flag.
- **Gitleaks verify false failures** (Node + Python): `binary-manager` required specific stdout content from `gitleaks version`. Now accepts any exit code 0 regardless of output format.
- **Engine/format validation** (Node): invalid `--engine` values (e.g. `--engine nope`) were silently accepted and ran as auto. Invalid `--format` values started scanning before failing. Both now validate before any work begins.

### Changed
- **Reduced false positives** (Node): added default directory excludes (`.venv`, `vendor`, `results`, `__pycache__`, `.terraform`, etc.) to regex scanner. Tightened Generic Secret regex (requires 12+ chars with both digits and letters) and Bearer Token regex (requires 20+ chars) to reduce noise on code/docs text.
- **`rafter agent init` UX: opt-in not skip** (Node + Python): replaced `--skip-*` flags with `--with-*` opt-in flags. Integrations are no longer installed by default — use `--with-claude-code`, `--with-openclaw`, etc. or `--all` to install all detected.

## [0.5.8] - 2026-02-27

### Added
- **`rafter agent audit --share`** (Node + Python): generates a redacted diagnostic excerpt safe for pasting into GitHub issues. Includes CLI version, OS/arch, a 16-char SHA-256 fingerprint of the effective policy (including `.rafter.yml` overrides), and the last 5 audit events with truncated commands.
- **90-second quickstart** in README: concrete walkthrough showing scan, hook install, commit block, and audit review.

### Changed
- **Structured pretool hook messages** (Node + Python): block and approval-required messages now show the matched rule, risk level with human-readable description, and actionable next steps (`rafter agent exec --approve`, config adjustment).

### Fixed
- **Gitleaks version check** (Python): `verify_gitleaks_verbose` checked for `"gitleaks version"` in stdout, but gitleaks v8.x outputs just the version string. Now checks exit code 0 + non-empty output.

## [0.5.7] - 2026-02-27

### Added
- **`rafter scan` command group** (Node + Python): new top-level command with two subcommands.
  - `rafter scan` / `rafter scan remote` — triggers a remote backend scan (same as `rafter run`)
  - `rafter scan local [path]` — runs the local secret scanner (formerly `rafter agent scan`)
- **`rafter run`** unchanged; continues to work as before.

### Deprecated
- **`rafter agent scan`** — still works but now prints a deprecation warning to stderr: `"Warning: rafter agent scan is deprecated and will be removed in a future major version. Use rafter scan local instead."` Will be removed in a future major version.

### Changed
- All hook scripts, CI templates, skill files, and user-facing output updated to reference `rafter scan local` instead of `rafter agent scan`.

## [0.5.6] - 2026-02-26

### Added
- **`rafter agent scan --watch`** (Node + Python): new flag polls the target path on a 5-second interval, re-running the scan on every change. Useful for continuous feedback during development.

### Fixed
- **Gitleaks version check** (Node + Python): `verifyGitleaks` was checking for the string `"gitleaks version"` in stdout, but gitleaks v8.x outputs only the version string (`v8.18.2`). The check always returned false, causing `rafter agent verify` to report a working binary as failed. Now accepts any successful exit (code 0) with non-empty stdout. Stdout is also surfaced in the error detail when the binary genuinely fails.
- **OpenClaw install silent failure** (Node + Python): `rafter agent init` printed "Restart OpenClaw to load skill" in Next Steps even when the skill install had just failed. Next Steps suggestions are now gated on actual install success.
- **Broad `curl|sh` pattern migration** (Node + Python): existing `~/.rafter/config.json` files written by older installs contained `curl.*\|.*sh` / `wget.*\|.*sh` as literal regex strings. Because `|` is alternation in regex, these matched any command containing `sh`—including `git push`, `grep` with shell patterns, and `.sh` filenames. `ConfigManager` now silently upgrades the old patterns to word-bounded equivalents (`curl.*\|\s*(bash|sh|zsh|dash)\b`) on first load.

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
- `rafter agent init --with-claude-code` — auto-install PreToolUse hooks into Claude Code settings
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
