# Rafter CLI Reference

Full command tree for the `rafter` CLI. Commands group by concern: **scanning**, **agent** (local security primitives), **hook** (platform bridges), **policy**, **ci**, **mcp**, **docs/brief**, **notify**, **report**.

Global flags:
- `-a, --agent` — plain output (no colors/emoji) for AI consumers.
- `--version`, `version` — print version.

Exit codes (consistent across commands):
- `0` — success / no findings
- `1` — findings detected OR general error
- `2` — invalid input / scan not found

All scan commands write results as JSON on stdout and status on stderr; safe to pipe.

---

## Scanning

### `rafter run [opts]` · `rafter scan [opts]` · `rafter scan remote [opts]`

Trigger a remote security scan on a GitHub repo. Auto-detects current repo/branch.

When to reach for it:
- "Is this branch safe to merge?"
- Pre-deploy / post-dependency-update gating.
- Any request for SAST, SCA, or "security audit" of a repo.

Key options: `--repo org/repo`, `--branch <name>`, `--mode fast|plus`, `--format json|md`, `--api-key <key>`, `--github-token <pat>` (private repos), `--skip-interactive`, `--quiet`.

Example: `rafter run --repo myorg/api --branch feature/auth --mode plus --format json`

### `rafter secrets [path]`

Local secret scan. Deterministic, offline, no API key. Dual-engine: Gitleaks binary if present, built-in regex fallback (21+ patterns).

When: pre-commit, pre-push, fast first pass before remote scan, air-gapped envs.

Useful flags: `--history` (scan git history with Gitleaks), `--format json`, `--quiet`.

Example: `rafter secrets . --format json`

(Back-compat aliases: `rafter scan local` and `rafter agent scan`. Prefer `rafter secrets`.)

### `rafter get <scan-id>`

Retrieve results of a previously triggered remote scan.

When: after `rafter run --skip-interactive`, or when a scan id was shown and you need the report.

Example: `rafter get scan_abc123xyz --format json`

### `rafter usage`

Show API quota / usage for `RAFTER_API_KEY`.

When: before firing multiple remote scans, or when the user asks about limits.

---

## Agent (Local Security Primitives)

### `rafter agent exec -- <command>`

Classify and optionally run a shell command through Rafter's risk tiers (critical / high / medium / low).

When: any time a destructive-looking command is about to be executed by an agent. Use `--dry-run` to classify without running.

Example: `rafter agent exec --dry-run -- rm -rf $WORK_DIR`

### `rafter agent audit [path]`

Audit a directory for suspicious or risky code patterns — focused on plugins, skills, extensions, and tooling a user might install.

When: vetting a third-party skill, MCP server, or CLI plugin before install.

### `rafter agent audit-skill <path>`

Audit a single skill file (SKILL.md). Flags prompt-injection, unbounded tool use, exfiltration patterns.

### `rafter agent status` · `rafter agent verify`

`status`: dump config, hook state, gitleaks availability, audit log location.
`verify`: sanity-check installation; exit non-zero if anything is broken.

### `rafter agent init [--with-<platform>]`

Install rafter skills and/or hooks into a supported agent (`claude-code`, `codex`, `gemini`, `cursor`, `windsurf`, `aider`, `openclaw`, `continue`). See `rafter brief setup/<platform>`.

### `rafter agent init-project`

Scaffold `.rafter.yml` and a baseline for the current repo.

### `rafter agent install-hook`

Install a pre-commit hook that runs `rafter secrets --staged` before every commit.

### `rafter agent config [get|set|list]`

Read/write Rafter config (global `~/.rafter/config.yml` and local `.rafter.yml`).

### `rafter agent baseline`

Snapshot current findings so only *new* ones fail future scans.

### `rafter agent instruction-block`

Emit a ready-to-paste instruction block for an agent's system prompt.

### `rafter agent update-gitleaks`

Download / upgrade the Gitleaks binary Rafter uses for local scans.

---

## Hooks (Agent Platform Bridges)

### `rafter hook pretool`

Stdin → JSON pretool event from an agent (e.g. Claude Code). Classifies the pending tool call and returns approve/block with reasoning.

### `rafter hook posttool`

Stdin → JSON posttool event. Logs to audit trail, optionally post-scans written files for secrets.

See `docs/guardrails.md` for how these plug into Claude Code / other platforms.

---

## Policy

### `rafter policy export [--format yml|json]`

Emit the effective merged policy (defaults + global + `.rafter.yml`).

### `rafter policy validate <file>`

Lint a policy file. Non-zero exit on invalid structure.

---

## CI

### `rafter ci init [--provider github|gitlab|circle|...]`

Generate a CI workflow that runs `rafter scan` on PR + main, with sensible defaults (caching, JSON artifact, comment-on-PR where supported).

---

## MCP

### `rafter mcp serve`

Start the Rafter MCP server over stdio. Exposes:
- Tools: `scan_secrets`, `evaluate_command`, `read_audit_log`, `get_config`
- Resources: `rafter://config`, `rafter://policy`

Use from any MCP-capable client (Gemini, Cursor, Windsurf, Aider, Continue.dev). See `rafter brief setup/<platform>`.

---

## Knowledge / Meta

### `rafter brief [topic]`

Print rafter knowledge for any agent. Topics include: `security`, `scanning`, `commands`, `pricing`, `setup`, `setup/<platform>`, `all`, plus sub-doc topics (`cli-reference`, `guardrails`, `backend`, `shift-left`, `finding-triage`).

### `rafter notify --scan-id <id> --to <slack|discord-webhook>`

Post a scan summary to Slack or Discord.

### `rafter report --scan-id <id> [--out report.html]`

Generate a self-contained HTML security report for sharing.

### `rafter issues sync --scan-id <id>`

Open / update GitHub Issues from scan findings (one issue per rule).

### `rafter completion <bash|zsh|fish>`

Emit shell completion script.

---

## Quick Decision Table

| User intent | Command |
|---|---|
| Fast secret check locally | `rafter secrets .` |
| Full repo security review | `rafter run` (then `rafter get <id>`) |
| "Is this command safe?" | `rafter agent exec --dry-run -- <cmd>` |
| "Is this skill safe to install?" | `rafter agent audit <path>` |
| Add pre-commit protection | `rafter agent install-hook` |
| Wire up CI | `rafter ci init` |
| Connect an agent | `rafter agent init --with-<platform>` |
| Share a report | `rafter report --scan-id <id>` |
