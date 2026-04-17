# Rafter CLI Command Spec

## Overview

Rafter is the security toolkit for developers. Stable output contracts mean any developer can classify outcomes (clean / findings / retryable error / fatal error) and act without reading prose.

**Free forever for individuals and open source.** No account required. No telemetry. All local security features (secret scanning, policy enforcement, pre-commit hooks, audit logging, MCP server) work without an API key, without network access, and without usage limits.

The CLI follows UNIX principles:

- **Scan results** go to **stdout** — consistent JSON structure, pipe-friendly
- **Status messages** go to **stderr**
- **Exit codes** are a **stable contract** — documented semantics across versions
- **Deterministic** — same inputs produce the same findings for a given CLI version
- **Side effects are explicit** — config and audit logs write to `~/.rafter/`; some commands (e.g. `ci init`, `policy export`) accept `--output` to write files
- **No exfiltration** — no code leaves your machine unless you explicitly use the remote API, and is deleted immediately after analysis completes

## Exit Codes

### Remote Commands (`rafter run`, `rafter get`, `rafter usage`)

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Scan not found (HTTP 404) |
| 3 | Quota exhausted (HTTP 429 or 403 scan-mode limit) |
| 4 | Insufficient scope / forbidden (HTTP 403) |

### Local Secret Scan (`rafter scan local` / `rafter agent scan`)

| Code | Meaning |
|------|---------|
| 0 | Clean — no secrets detected |
| 1 | Findings — one or more secrets detected |
| 2 | Runtime error — path not found, not a git repo, invalid ref |

### Docs (`rafter docs list`, `rafter docs show`)

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (read failure, URL fetch failure with no cache) |
| 2 | Selector did not match any configured doc |
| 3 | No docs configured in `.rafter.yml` |

---

## Global Options

- `-a, --agent` — Plain output (no colors, no emoji)
- `-V, --version` — Print version and exit (preferred form; `rafter version` subcommand also works)
- `-h, --help` — Show help

---

## Remote Code Analysis Commands

**Important**: The code analysis engine runs against the **remote repository** (e.g., on GitHub), not your local files. Auto-detection uses your local Git configuration to determine which remote repository and branch to scan.

### rafter run [OPTIONS]

Aliases: `rafter scan`, `rafter scan remote`

Trigger a new security scan for a repository.

- `-k, --api-key TEXT` — API key or `RAFTER_API_KEY` env var
- `-r, --repo TEXT` — org/repo (default: auto-detected from git remote)
- `-b, --branch TEXT` — branch (default: current branch or 'main')
- `-f, --format [json|md]` — output format (default: md)
- `-m, --mode [fast|plus]` — scan mode (default: fast). Fast runs SAST, secret detection, and dependency checks. Plus adds agentic deep-dive analysis that examines your codebase the way a professional cybersecurity auditor would — tracing data flows and reasoning about business logic on top of the full SAST/SCA toolchain.
- `--github-token TEXT` — GitHub PAT for private repos (or `RAFTER_GITHUB_TOKEN` env var)
- `--skip-interactive` — fire-and-forget mode (don't poll for completion)
- `--quiet` — suppress status messages on stderr
- `-h, --help`

### rafter get SCAN_ID [OPTIONS]

Retrieve results from a scan.

- `-k, --api-key TEXT` — API key or `RAFTER_API_KEY` env var
- `-f, --format [json|md]` — output format (default: md)
- `--interactive` — poll until scan completes (10-second intervals)
- `--quiet` — suppress status messages on stderr
- `-h, --help`

**Vulnerability levels (JSON output):** The `level` field on each vulnerability uses SARIF standard values: `"error"`, `"warning"`, or `"note"`.

### rafter usage [OPTIONS]

Check API quota and usage statistics.

- `-k, --api-key TEXT` — API key or `RAFTER_API_KEY` env var
- `-h, --help`

---

## Brief — Agent-Independent Knowledge Delivery

### rafter brief [TOPIC]

Print rafter knowledge reformatted for CLI output. Designed for any agent on any platform — pipe to memory, save to instructions, or just read in-session.

With no topic, lists available topics and usage examples.

**Topics:**

| Topic | Description |
|-------|-------------|
| `security` | Local security toolkit — scanning, auditing, policy enforcement |
| `scanning` | Remote SAST/SCA code analysis via Rafter API |
| `commands` | Condensed command reference for all rafter commands |
| `setup` | Setup instructions for all supported platforms |
| `setup/<platform>` | Platform-specific setup (claude-code, codex, gemini, cursor, windsurf, aider, openclaw, continue, generic) |
| `all` | Everything — full security + scanning + setup briefing |

**Examples:**

```bash
# List available topics
rafter brief

# Get the local security briefing
rafter brief security

# Platform-specific setup guide
rafter brief setup/claude-code

# For agents without native skill support — load context manually
rafter brief security    # save to memory/instructions
rafter brief commands    # save command reference

# Pipe to a file for manual skill creation
rafter brief scanning > ~/.agents/skills/rafter/SKILL.md
```

---

## Local Security Commands

All local security commands work offline. No API key required.

### rafter agent init [OPTIONS]

Initialize local security system. Creates config and detects available development environments. Integrations are **opt-in** — use `--with-*` flags or `--all` to install. There are NO `--skip-*` flags.

- `--risk-level <level>` — `minimal`, `moderate` (default), or `aggressive`
- `--with-openclaw` — install OpenClaw integration
- `--with-claude-code` — install Claude Code integration
- `--with-codex` — install Codex CLI integration
- `--with-gemini` — install Gemini CLI integration
- `--with-aider` — install Aider integration
- `--with-cursor` — install Cursor integration
- `--with-windsurf` — install Windsurf integration
- `--with-continue` — install Continue.dev integration
- `--with-gitleaks` — download and install Gitleaks binary
- `--all` — install all detected integrations and download Gitleaks
- `-i, --interactive` — guided setup — prompts for each detected integration (Node only)
- `--update` — re-download gitleaks and reinstall integrations without resetting config

### rafter agent list [OPTIONS]

List every installable component across all supported platforms with its current state. Useful for auditing what's active and for scripting toggles.

- `--json` — machine-readable output
- `--installed` — show only components currently installed
- `--detected` — show only components whose platform was detected on disk

A **component** is a `<platform>.<kind>` pair, where `kind ∈ {hooks, mcp, instructions, skills}`. Each component has a state:

| State | Meaning |
|-------|---------|
| `installed` | Rafter is active in this platform's config |
| `not-installed` | Platform is detected but Rafter is not wired in |
| `not-detected` | Platform config directory does not exist on disk |

#### JSON Output (`--json`)

```json
{
  "components": [
    {
      "id": "cursor.mcp",
      "platform": "cursor",
      "kind": "mcp",
      "description": "Cursor MCP server entry",
      "path": "/home/user/.cursor/mcp.json",
      "detected": true,
      "installed": true,
      "state": "installed"
    }
  ]
}
```

Exit code: 0 on success.

### rafter agent enable COMPONENTS... [OPTIONS]

Install one or more components. Accepts one or more component IDs (e.g. `cursor.mcp`, `claude-code.hooks`). Aliases: `claude.*` → `claude-code.*`, `continuedev.*` → `continue.*`.

- `--force` — install even when the platform is not detected (creates the platform directory)

Exit codes:
- `0` — all components installed (or were already installed — the operation is idempotent)
- `1` — unknown component ID (the error lists known IDs on stderr)
- `2` — platform not detected for one or more components (use `--force` to override)

Persists `agent.components.<id>.enabled = true` in `~/.rafter/config.json`.

### rafter agent disable COMPONENTS... [OPTIONS]

Uninstall one or more components without affecting other components on the same platform. For MCP files, removes the `rafter` server entry while preserving unrelated entries. For hooks, removes only rafter's hook commands. For instruction files, strips the `<!-- rafter:start -->` / `<!-- rafter:end -->` block and leaves surrounding content intact.

Exit code: 0 on success (missing/not-installed components are reported, not errored).

Persists `agent.components.<id>.enabled = false` in `~/.rafter/config.json`.

### rafter skill list [OPTIONS]

List rafter-authored skills shipped with this CLI and their install state across every supported platform. A skill is a bundled `SKILL.md` file (e.g. `rafter`, `rafter-agent-security`, `rafter-secure-design`, `rafter-code-review`, `rafter-skill-review`). A platform is one of `claude-code`, `codex`, `openclaw`, `cursor`.

- `--json` — machine-readable output
- `--installed` — only show `(skill, platform)` pairs where the skill is installed
- `--platform <name>` — restrict to a single platform

JSON shape (`--json`):

```json
{
  "skills": [
    { "name": "rafter-secure-design", "version": "0.1.0", "description": "..." }
  ],
  "installations": [
    {
      "name": "rafter-secure-design",
      "platform": "claude-code",
      "path": "/home/user/.claude/skills/rafter-secure-design/SKILL.md",
      "detected": true,
      "installed": true,
      "version": "0.1.0"
    }
  ]
}
```

Exit codes: `0` on success; `1` on unknown `--platform`.

### rafter skill install NAME [OPTIONS]

Install a rafter-authored skill. The SKILL.md file is copied (not symlinked) so the install is reproducible and does not depend on the CLI's installation path at run time.

- `--platform <name...>` — target platform(s); repeatable. Default: every platform whose config directory is detected on this machine.
- `--to <path>` — explicit destination. If `<path>` ends in `.md` or `.mdc`, used as the literal file path. Otherwise treated as a skills *base* directory, installing to `<path>/<name>/SKILL.md`.
- `--force` — when no `--platform` is given and no platform is detected, install to every known platform anyway.

Destinations per platform:

| Platform | Path |
|----------|------|
| `claude-code` | `~/.claude/skills/<name>/SKILL.md` |
| `codex` | `~/.agents/skills/<name>/SKILL.md` |
| `openclaw` | `~/.openclaw/skills/<name>.md` |
| `cursor` | `~/.cursor/rules/<name>.mdc` |

Exit codes:
- `0` — install(s) succeeded (re-running is idempotent; the file is overwritten in place)
- `1` — unknown skill name or unknown platform
- `2` — no target platform detected (and `--force` was not passed), or an explicit `--platform` was not detected and `--force` was not passed

Persists `skillInstallations.<platform>.<name> = { enabled: true, version, updatedAt }` in `~/.rafter/config.json`.

### rafter skill uninstall NAME [OPTIONS]

Remove a rafter-authored skill from one or more platforms.

- `--platform <name...>` — target platform(s). Default: every platform on which the skill is currently installed.

Missing files are reported, not errored. If the skill is not installed anywhere, the command exits 0 and reports "no changes".

Exit codes:
- `0` — uninstall(s) succeeded or were already absent
- `1` — unknown skill name or unknown platform

Persists `skillInstallations.<platform>.<name>.enabled = false` in `~/.rafter/config.json`.

### rafter scan local [PATH] [OPTIONS]

Alias: `rafter agent scan` (deprecated — use `rafter scan local`)

Scan files or directories for secrets (21+ patterns).

- `[PATH]` — file or directory (default: `.`)
- `-q, --quiet` — only output if secrets found
- `--json` — output as JSON
- `--format <format>` — output format: `text`, `json`, or `sarif` (default: `text`)
- `--staged` — scan git staged files only
- `--diff <ref>` — scan files changed since a git ref (e.g., `HEAD~1`, `main`)
- `--engine <engine>` — `gitleaks`, `patterns`, or `auto` (default)
- `--baseline` — filter findings present in the saved baseline (see `rafter agent baseline`)
- `--watch` — watch path for file changes and re-scan on each change; Ctrl+C exits

Exit codes: 0 = clean, 1 = secrets found, 2 = runtime error.

> **Note:** `--watch` mode does not exit on findings — it prints results inline and keeps watching. Findings are logged to `audit.jsonl` in real time. Requires `chokidar` (Node, bundled) or `watchdog` (Python: `pip install watchdog`).

#### JSON Output (`--json`)

When `--json` is passed, output is a JSON array to stdout. Both Node and Python produce identical schema:

```json
[
  {
    "file": "/absolute/path/to/file.ts",
    "matches": [
      {
        "pattern": {
          "name": "AWS Access Key",
          "severity": "critical",
          "description": "Detects AWS access key IDs"
        },
        "line": 42,
        "column": 7,
        "redacted": "AKIA************MPLE"
      }
    ]
  }
]
```

**Field reference:**

| Field | Type | Description |
|-------|------|-------------|
| `file` | string | Absolute path to the scanned file |
| `matches` | array | List of secret matches in this file |
| `matches[].pattern.name` | string | Human-readable pattern name |
| `matches[].pattern.severity` | string | `"low"`, `"medium"`, `"high"`, or `"critical"` |
| `matches[].pattern.description` | string | Pattern description (may be empty) |
| `matches[].line` | number\|null | 1-based line number, null if unknown |
| `matches[].column` | number\|null | 1-based column number, null if unknown |
| `matches[].redacted` | string | Redacted secret value (first/last 4 chars visible for values >8 chars, fully masked otherwise) |

The raw secret value is never included in JSON output.

### rafter agent exec COMMAND [OPTIONS]

Execute shell command with risk assessment and approval workflow.

- `COMMAND` — shell command string
- `--skip-scan` — skip pre-execution file scanning
- `--force` — skip approval prompts (logged as override)

Risk tiers: critical (blocked), high (approval required), medium (approval on moderate+), low (allowed).

### rafter skill review PATH_OR_URL [OPTIONS]

Security review of a third-party skill, plugin, or agent extension before installing it. Operates on a local file, a local directory, or a git URL (https / ssh / `.git`). Emits a structured deterministic report: secrets, external URLs, high-risk shell patterns, obfuscation signals, binary/suspicious file inventory, and `SKILL.md` frontmatter (`name`, `version`, `allowed-tools`).

- `PATH_OR_URL` — local path (file or directory) OR a git URL (shallow-cloned to a temp dir for the duration of the review; removed on exit)
- `--json` — emit JSON to stdout (shortcut for `--format json`)
- `--format text|json` — output format (default: `text`)

JSON shape (`--json`):

```json
{
  "target": {
    "input": "./their-skill/",
    "kind": "directory",
    "resolvedPath": "/abs/path/to/their-skill"
  },
  "frontmatter": [
    {
      "file": "SKILL.md",
      "name": "their-skill",
      "version": "0.1.0",
      "description": "...",
      "allowedTools": ["Bash", "Read"]
    }
  ],
  "secrets": [
    { "pattern": "AWS Secret Access Key", "severity": "critical", "file": "SKILL.md", "line": 17, "redacted": "AWS_***EKEY" }
  ],
  "urls": ["https://example.com/install.sh"],
  "highRiskCommands": [
    { "command": "curl | sh", "file": "SKILL.md", "line": 11 }
  ],
  "obfuscation": [
    { "kind": "bidi-override", "file": "SKILL.md", "line": 16, "sample": "U+202E" }
  ],
  "inventory": {
    "textFiles": 8,
    "binaryFiles": 1,
    "suspiciousFiles": [ { "path": "helper.so", "bytes": 4, "kind": "binary" } ]
  },
  "summary": {
    "severity": "critical",
    "findings": 4,
    "reasons": ["1 secret finding(s)", "1 high-risk command(s)", "1 hard obfuscation signal(s)"]
  }
}
```

**Obfuscation kinds**: `zero-width-char`, `bidi-override`, `base64-blob`, `hex-escape-rope`, `html-comment-imperative`.

**Severity tiers** (in `summary.severity`): `clean`, `low`, `medium`, `high`, `critical`. A `bidi-override` or `html-comment-imperative` is always `critical`. High-risk commands escalate to at least `high`. Long base64 blobs / zero-width chars / binary-blob files escalate to at least `medium`.

Exit codes:
- `0` — `summary.severity == "clean"` (no findings)
- `1` — one or more findings (any non-`clean` severity)
- `2` — input path does not exist, or git clone failed

Limits: directory walks skip `.git` / `node_modules` / `.venv`, cap at 2,000 files, and treat files larger than 2 MiB as suspicious binaries. Files containing null bytes in the first 4 KiB are treated as binary.

### rafter agent audit-skill SKILL_PATH [OPTIONS]

**Deprecated** — use `rafter skill review <path-or-url>` instead. Still functional; emits a deprecation warning to stderr.

- `SKILL_PATH` — path to skill file (.md)
- `--skip-openclaw` — skip OpenClaw integration, show manual review prompt
- `--json` — output as JSON

Quick scan: secrets, URLs, high-risk commands. Deep analysis (OpenClaw): 12-dimension review.

### rafter agent audit [OPTIONS]

View security audit log.

- `--last <n>` — show last N entries (default: 10)
- `--event <type>` — filter by event type
- `--agent <type>` — filter by agent type (`openclaw`, `claude-code`)
- `--since <date>` — entries since date (YYYY-MM-DD)
- `--share` — generate a redacted excerpt for issue reports

Event types: `command_intercepted`, `secret_detected`, `content_sanitized`, `policy_override`, `scan_executed`, `config_changed`.

#### Audit Log Schema

The audit log is written to `~/.rafter/audit.jsonl` as newline-delimited JSON (JSONL). Each line is one event. Both Node and Python CLIs write to the same file.

**Base fields (all events):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string (ISO 8601) | yes | UTC timestamp of the event |
| `sessionId` | string | yes | Unique session identifier (`{epoch_ms}-{random}`) |
| `eventType` | string | yes | One of the event types below |
| `agentType` | string | no | `"openclaw"` or `"claude-code"` |

**`action` object (optional):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action.command` | string | no | Shell command string (present on `command_intercepted`, optional on `policy_override`) |
| `action.tool` | string | no | Tool name that triggered the event |
| `action.riskLevel` | string | no | `"low"`, `"medium"`, `"high"`, or `"critical"` |

**`securityCheck` object (required):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `securityCheck.passed` | boolean | yes | Whether the security check passed |
| `securityCheck.reason` | string | no | Human-readable explanation |
| `securityCheck.details` | object | no | Structured details (used by `content_sanitized`) |

**`resolution` object (required):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resolution.actionTaken` | string | yes | `"blocked"`, `"allowed"`, `"overridden"`, or `"redacted"` |
| `resolution.overrideReason` | string | no | Reason for override (only on `policy_override`) |

**Event types:**

| Event | Description | Typical `actionTaken` |
|-------|-------------|----------------------|
| `command_intercepted` | Shell command evaluated against policy | `allowed`, `blocked`, `overridden` |
| `secret_detected` | Secret found in files or staged content | `blocked`, `allowed` |
| `content_sanitized` | Sensitive patterns redacted from output | `redacted` |
| `policy_override` | User overrode a security policy | `overridden` |
| `scan_executed` | File scan performed | — |
| `config_changed` | Security configuration modified | — |

**Redaction behavior:** The audit log never contains raw secret values. For `secret_detected` events, only the secret type and location are recorded (e.g., `"AWS Access Key detected in config.js"`). For `content_sanitized`, only the count and content type are stored.

**Example entries:**

```jsonl
{"timestamp":"2026-02-20T10:30:45.123Z","sessionId":"1740047445123-abc123","eventType":"command_intercepted","agentType":"claude-code","action":{"command":"git push --force","riskLevel":"high"},"securityCheck":{"passed":false,"reason":"High-risk command requires approval"},"resolution":{"actionTaken":"blocked"}}
{"timestamp":"2026-02-20T10:25:12.456Z","sessionId":"1740047445123-abc123","eventType":"secret_detected","agentType":"openclaw","action":{"riskLevel":"critical"},"securityCheck":{"passed":false,"reason":"AWS Access Key detected in config.js"},"resolution":{"actionTaken":"blocked"}}
```

**Size and rotation:**

- No automatic rotation or size limit. The file grows unbounded until cleanup runs.
- Time-based retention: entries older than `agent.audit.retentionDays` (default: 30) are purged by `cleanup()`.
- Cleanup is not scheduled automatically; invoke via the API or manually.

**Configuration** (in `~/.rafter/config.json` or `.rafter.yml`):

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `agent.audit.logAllActions` | boolean | `true` | Master switch — if `false`, no events are written |
| `agent.audit.retentionDays` | number | `30` | Days to retain log entries |
| `agent.audit.logLevel` | string | `"info"` | Stored but not currently used for filtering |

#### Webhook Notifications

When configured, the audit logger sends a POST request to a webhook URL for events at or above a minimum risk level. This works with Slack incoming webhooks, Discord webhooks, and generic HTTP endpoints.

**Configuration** (in `~/.rafter/config.json` or `.rafter.yml`):

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `agent.notifications.webhook` | string | — | Webhook URL to POST notifications to |
| `agent.notifications.minRiskLevel` | string | `"high"` | Minimum risk level to trigger notification (`"high"` or `"critical"`) |

**Webhook payload:**

```json
{
  "event": "command_intercepted",
  "risk": "high",
  "command": "git push --force",
  "timestamp": "2026-02-21T10:30:45.123Z",
  "agent": "claude-code",
  "text": "[rafter] high-risk event: command_intercepted — git push --force",
  "content": "[rafter] high-risk event: command_intercepted — git push --force"
}
```

The `text` field provides Slack compatibility. The `content` field provides Discord compatibility. Both contain a human-readable summary.

Webhook delivery is fire-and-forget with a 5-second timeout. Failures are silently ignored to avoid disrupting audit logging.

**Setup examples:**

```bash
# Configure webhook URL
rafter agent config set agent.notifications.webhook https://hooks.slack.com/services/T.../B.../xxx

# Only notify on critical events
rafter agent config set agent.notifications.minRiskLevel critical

# Disable notifications
rafter agent config set agent.notifications.webhook ""
```

### rafter agent install-hook [OPTIONS]

Install git pre-commit hook for automatic secret scanning.

- `--global` — install globally for all repos (sets `core.hooksPath`)
- `--push` — install pre-push hook instead of pre-commit

### rafter agent config SUBCOMMAND

Manage agent configuration (dot-notation paths).

- `rafter agent config show` — display full config
- `rafter agent config get <key>` — read value
- `rafter agent config set <key> <value>` — write value

Config keys: `agent.riskLevel`, `agent.skills.autoUpdate`, `agent.skills.installOnInit`, `agent.skills.backupBeforeUpdate`, `agent.commandPolicy.mode`, `agent.commandPolicy.blockedPatterns`, `agent.commandPolicy.requireApproval`, `agent.outputFiltering.redactSecrets`, `agent.audit.logAllActions`, `agent.audit.retentionDays`, `agent.audit.logLevel`, `agent.notifications.webhook`, `agent.notifications.minRiskLevel`.

### rafter agent init-project [OPTIONS]

Generate project-level instruction files so AI agents discover Rafter at session start. Creates `.cursorrules`, `AGENTS.md`, or other platform-specific files in the project root.

- `--only <platforms>` — comma-separated list of platforms to target (`claude-code`, `codex`, `gemini`, `cursor`, `windsurf`, `continue`, `aider`)
- `--list` — list which files would be created without writing them

Node only. Not yet implemented in Python.

### rafter agent verify

Check agent security integration status. Reports whether config files, hooks, and platform integrations are properly installed.

### rafter agent status

Show agent security status dashboard. Displays config summary, installed integrations, audit log summary, and recent events.

### rafter agent update-gitleaks [OPTIONS]

Update (or reinstall) the managed gitleaks binary.

- `--version <version>` — specific gitleaks version to install (default: current bundled version)

### rafter agent baseline SUBCOMMAND

Manage the findings baseline (allowlist for known findings). Baseline entries suppress matched findings in `scan local --baseline`.

- `rafter agent baseline create [path]` — scan and save all current findings as the baseline
- `rafter agent baseline show` — show current baseline entries
- `rafter agent baseline clear` — remove all baseline entries
- `rafter agent baseline add` — manually add a finding to the baseline

### rafter ci init [OPTIONS]

Generate CI/CD pipeline configuration for secret scanning.

- `--platform <platform>` — `github`, `gitlab`, or `circleci` (default: auto-detect)
- `--output <path>` — output file path (default: platform-specific)
- `--with-remote` — include remote security audit job (requires `RAFTER_API_KEY`)
- `--with-backend` — deprecated alias for `--with-remote`

Auto-detection: checks for `.github/`, `.gitlab-ci.yml`, `.circleci/` in cwd.

### GitHub Action (`action.yml`)

Composite action at repo root. Usage:

```yaml
- uses: Raftersecurity/rafter-cli@v1
  with:
    scan-path: '.'        # default
    args: '--quiet'       # default
    version: 'latest'     # default
    install-method: 'npm' # or 'pip'
```

### rafter hook pretool [OPTIONS]

PreToolUse hook handler. Reads tool call JSON from stdin, evaluates risk, and writes a JSON decision to stdout. Used by agent platforms (Claude Code, Cursor, etc.) for pre-tool interception.

- `--format <format>` — output format: `claude` (default, also works for Codex/Continue), `cursor`, `gemini`, `windsurf`

### rafter hook posttool [OPTIONS]

PostToolUse hook handler. Reads tool output from stdin, redacts any secrets found, and writes JSON to stdout.

- `--format <format>` — output format: `claude` (default, also works for Codex/Continue), `cursor`, `gemini`, `windsurf`

### rafter mcp serve [OPTIONS]

Start MCP server over stdio transport. Exposes 6 tools and 3 resources.

- `--transport <type>` — transport type (currently only `stdio`, default: `stdio`)

#### MCP Tools

| Tool | Description | Required inputs |
|------|-------------|-----------------|
| `scan_secrets` | Scan files or directories for leaked secrets, API keys, tokens, passwords, and credentials | `path` (string) |
| `evaluate_command` | Check if a shell command is safe to run per the active security policy | `command` (string) |
| `read_audit_log` | Read security event history — blocked commands, detected secrets, policy overrides | none (optional: `limit`, `event_type`, `since`) |
| `get_config` | Read active Rafter configuration and policy | none (optional: `key` dot-path) |
| `list_docs` | List repo-specific security docs declared in `.rafter.yml` (metadata only, no content) | none (optional: `tag`) |
| `get_doc` | Return the content of a repo-specific security doc by id or tag | `id_or_tag` (string); optional: `refresh` (bool) |

**`scan_secrets` inputs:**
- `path` (required) — file or directory path to scan
- `engine` (optional) — `auto` (default), `gitleaks`, or `patterns`

**`evaluate_command` output schema:**
```json
{
  "allowed": true,
  "risk_level": "low",
  "requires_approval": false,
  "reason": "optional explanation string"
}
```

**`read_audit_log` inputs:**
- `limit` (optional, number) — max entries to return (default: 20)
- `event_type` (optional, string) — filter by event type (e.g. `command_intercepted`, `secret_detected`)
- `since` (optional, ISO 8601 string) — only return entries after this timestamp

**`get_config` inputs:**
- `key` (optional, string) — dot-path config key (e.g. `agent.commandPolicy`); omit for full config

**`list_docs` output schema:** array of `{ id, source, source_kind, description, tags, cache_status }` where `source_kind` is `"path"` or `"url"` and `cache_status` is one of `local` (path-backed), `cached`, `not-cached`, `stale`.

**`get_doc` output schema:** array of `{ id, source, source_kind, stale, content }`. Returns multiple entries when `id_or_tag` matches a tag shared by several docs; returns a single entry when it matches an `id` exactly.

#### MCP Resources

| URI | MIME type | Description |
|-----|-----------|-------------|
| `rafter://config` | `application/json` | Current Rafter configuration (`~/.rafter/config.json`) |
| `rafter://policy` | `application/json` | Active security policy — merged `.rafter.yml` + global config |
| `rafter://docs` | `application/json` | Repo-specific security docs declared in `.rafter.yml` (metadata only, no content) |

`rafter://policy` returns the result of merging the project-level `.rafter.yml` (if present) over the global config. It reflects the effective policy that `evaluate_command` and `scan_secrets` enforce.

`rafter://docs` returns the same array shape as the `list_docs` tool. Use `get_doc` to retrieve actual content.

### rafter policy export [OPTIONS]

Export Rafter policy for agent platforms.

- `--format <format>` — target format: `claude` or `codex`
- `--output <path>` — write to file instead of stdout

### rafter docs list [OPTIONS]

List repo-specific security docs declared under `docs:` in `.rafter.yml`. Never performs network I/O — for URL-backed docs, reports cache status only.

- `--tag <tag>` — filter to docs whose tags include this value
- `--json` — output as JSON

Human-readable output format:
```
<id>  <source>[ (cached|stale|not-cached)][ [tag1, tag2]][ — <description>]
```

JSON output (array):
```json
[
  {
    "id": "secure-coding",
    "source": "docs/security/secure.md",
    "source_kind": "path",
    "description": "Internal secure-coding rules",
    "tags": ["owasp", "internal"],
    "cache_status": "local"
  }
]
```

Exit codes: `0` on success, `3` if no docs configured.

### rafter docs show <ID_OR_TAG> [OPTIONS]

Print the content of a doc. If the argument exactly matches a doc `id`, prints that doc. Otherwise, any doc whose `tags` include the argument is concatenated with separator headers.

- `--refresh` — force re-fetch for URL-backed docs (bypass cache)
- `--json` — output as JSON array of `{ id, source, source_kind, stale, content }`

Behavior for URL docs:
- On cache hit within TTL, reads from cache.
- On miss or expired, fetches and updates cache.
- On network failure with a stale cache present, returns stale content and prints a warning to stderr.
- On network failure with no cache, exits `1`.

Exit codes: `0` ok, `1` fetch/read error, `2` selector did not match, `3` no docs configured.

### rafter notify [SCAN_ID] [OPTIONS]

Post scan results to Slack or Discord channels via webhooks.

- `[SCAN_ID]` — scan ID to fetch and post results for
- `-w, --webhook <url>` — webhook URL (Slack or Discord)
- `-k, --api-key <key>` — API key for fetching scan results
- `-p, --platform <platform>` — force platform: `slack`, `discord`, or `generic`
- `--quiet` — suppress status messages
- `--dry-run` — print payload without posting

### rafter report [INPUT] [OPTIONS]

Generate a standalone HTML security report from scan results.

- `[INPUT]` — path to JSON scan results (default: read from stdin)
- `-o, --output <path>` — output file path (default: stdout)
- `--title <title>` — report title (default: "Rafter Security Report")

Node only. Not yet implemented in Python.

### rafter issues create SUBCOMMAND

GitHub Issues integration — create issues from scan findings or natural text.

#### rafter issues create from-scan [OPTIONS]

Create GitHub issues from scan results.

- `--scan-id <id>` — remote scan ID to create issues from
- `--from-local <path>` — path to local scan JSON (from `rafter scan local --format json`)
- `-r, --repo <repo>` — target GitHub repo (`org/repo`)
- `-k, --api-key <key>` — Rafter API key (required with `--scan-id`)
- `--no-dedup` — skip deduplication check (create even if matching issue exists)
- `--dry-run` — show issues that would be created without actually creating them
- `--quiet` — suppress status messages

#### rafter issues create from-text [OPTIONS]

Create a GitHub issue from natural language text (stdin, file, or inline).

- `-r, --repo <repo>` — target GitHub repo (`org/repo`)
- `-t, --text <text>` — inline text to convert to an issue
- `-f, --file <path>` — read text from file
- `--title <title>` — override extracted title
- `--labels <labels>` — comma-separated labels to add
- `--dry-run` — show parsed issue without creating it
- `--quiet` — suppress status messages

### rafter completion <shell>

Generate shell completion scripts.

- `<shell>` — shell type: `bash`, `zsh`, or `fish`

### Pre-Commit Framework (`.pre-commit-hooks.yaml`)

Integration with [pre-commit](https://pre-commit.com/):

```yaml
repos:
  - repo: https://github.com/Raftersecurity/rafter-cli
    rev: v0.5.6
    hooks:
      - id: rafter-scan           # Node.js
      # - id: rafter-scan-python  # Python alternative
```

---

## Policy File (`.rafter.yml`)

Project-level security policy. Placed in project root; CLI walks from cwd to git root.

```yaml
version: "1"
risk_level: moderate
command_policy:
  mode: approve-dangerous
  blocked_patterns: ["rm -rf /"]
  require_approval: ["npm publish"]
scan:
  exclude_paths: ["vendor/", "third_party/"]
  custom_patterns:
    - name: "Internal API Key"
      regex: "INTERNAL_[A-Z0-9]{32}"
      severity: critical
audit:
  retention_days: 90
  log_level: info
docs:
  - id: secure-coding                 # optional — defaults to basename(path) without extension, or sha256(url)[:8]
    path: docs/security/secure.md     # exactly one of { path, url } is required
    description: Internal secure-coding rules
    tags: [owasp, internal]
  - id: app-threat-model
    url: https://internal.example.com/threat-model.md
    description: Application threat model
    tags: [threat-model]
    cache:
      ttl_seconds: 86400              # optional, default 86400; only valid with url
```

Precedence: policy file overrides `~/.rafter/config.json`. Arrays replace, not append.

**Docs validation rules:**
- Each entry must have exactly one of `path` or `url` — both or neither is skipped with a warning.
- Duplicate `id`s are skipped with a warning (first one wins).
- `tags` must be a list of strings if present.
- `cache.ttl_seconds` must be a positive number and is only valid for `url` entries.
- Unknown keys per-entry are ignored with a warning.

**URL caching:** URL-backed docs are cached at `~/.rafter/docs-cache/` keyed by `sha256(url)[:32]`. Default TTL is 86400 seconds. On network failure, a stale cached copy is served and a warning is printed. `docs list` never fetches; `docs show` fetches on miss/expired or when `--refresh` is set.

---

## Usage Examples

### Remote Code Analysis

```bash
# Run scan, auto-detect repo/branch
rafter run

# Scan specific repo
rafter scan --repo myorg/myrepo --branch main

# Get results as JSON
rafter get SCAN_ID --format json

# Pipe to jq
rafter get SCAN_ID --format json | jq '.vulnerabilities[] | select(.level=="error")'

# Count vulnerabilities
rafter get SCAN_ID --format json | jq '.vulnerabilities | length'

# Save to file
rafter get SCAN_ID > scan_results.json

# CSV export
rafter get SCAN_ID --format json --quiet | jq -r '.vulnerabilities[] | [.level, .rule_id, .file, .line] | @csv'

# CI gate
if rafter get SCAN_ID --format json | jq -e '.vulnerabilities | length > 0'; then
    echo "Vulnerabilities found!" && exit 1
fi
```

### Quiet Mode

```bash
# Suppress status messages, get just data
rafter get SCAN_ID --quiet | jq '.scan_id'

# Capture output in variable
scan_data=$(rafter run --quiet)
```

### Error Handling

```bash
if rafter get SCAN_ID; then
    echo "Scan found"
else
    case $? in
        2) echo "Scan not found" ;;
        3) echo "Quota exhausted or scan limit reached" ;;
        4) echo "Forbidden — check API key scope" ;;
        *) echo "Other error" ;;
    esac
fi
```

### Local Security

```bash
# Full setup
rafter agent init

# Scan for secrets
rafter scan local .
rafter scan local --staged --quiet  # CI-friendly

# Old command still works (deprecated)
# rafter agent scan .  — deprecated, use rafter scan local

# Pre-commit hook
rafter agent install-hook --global

# Safe command execution
rafter agent exec "git push origin main"

# Audit a skill before installing
rafter agent audit-skill untrusted-skill.md

# View security log
rafter agent audit --last 20

# Configure
rafter agent config set agent.riskLevel aggressive
```

---

## Notes

- API key: provided via `--api-key` flag, `RAFTER_API_KEY` env var, or `.env` file
- Git auto-detection works in CI (supports `GITHUB_REPOSITORY`, `GITHUB_REF_NAME`, `CI_REPOSITORY`, `CI_COMMIT_BRANCH`, `CI_BRANCH`)
- Remote code analysis targets the remote repository, not local files
- All scan data to stdout, all status messages to stderr
- `--quiet` suppresses stderr; stdout is unaffected
- Agent commands are available in both Node and Python implementations
