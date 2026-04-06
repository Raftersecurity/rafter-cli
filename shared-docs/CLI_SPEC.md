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

### Backend Commands (`rafter run`, `rafter get`, `rafter usage`)

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

---

## Global Options

- `-a, --agent` — Plain output (no colors, no emoji)
- `-V, --version` — Print version
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

### rafter version

Print version and exit.

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

### rafter scan local [PATH] [OPTIONS]

Alias: `rafter agent scan` (deprecated — use `rafter scan local`)

Scan files or directories for secrets (21+ patterns).

- `[PATH]` — file or directory (default: `.`)
- `-q, --quiet` — only output if secrets found
- `--json` — output as JSON
- `--staged` — scan git staged files only
- `--diff <ref>` — scan files changed since a git ref (e.g., `HEAD~1`, `main`)
- `--engine <engine>` — `gitleaks`, `patterns`, or `auto` (default)
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

### rafter agent audit-skill SKILL_PATH [OPTIONS]

Security audit of a skill/extension file before installation.

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

### rafter agent config SUBCOMMAND

Manage agent configuration (dot-notation paths).

- `rafter agent config show` — display full config
- `rafter agent config get <key>` — read value
- `rafter agent config set <key> <value>` — write value

Config keys: `agent.riskLevel`, `agent.skills.autoUpdate`, `agent.skills.installOnInit`, `agent.skills.backupBeforeUpdate`, `agent.commandPolicy.mode`, `agent.commandPolicy.blockedPatterns`, `agent.commandPolicy.requireApproval`, `agent.outputFiltering.redactSecrets`, `agent.audit.logAllActions`, `agent.audit.retentionDays`, `agent.audit.logLevel`, `agent.notifications.webhook`, `agent.notifications.minRiskLevel`.

### rafter ci init [OPTIONS]

Generate CI/CD pipeline configuration for secret scanning.

- `--platform <platform>` — `github`, `gitlab`, or `circleci` (default: auto-detect)
- `--output <path>` — output file path (default: platform-specific)
- `--with-backend` — include backend security audit job (requires `RAFTER_API_KEY`)

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

## MCP Server

`rafter mcp serve` exposes Rafter security capabilities over the [Model Context Protocol](https://modelcontextprotocol.io/) stdio transport, making them available to any MCP-compatible AI client (Cursor, Windsurf, Claude Desktop, Cline, etc.).

```sh
rafter mcp serve
```

MCP client configuration:

```json
{
  "rafter": {
    "command": "rafter",
    "args": ["mcp", "serve"]
  }
}
```

Server name: `rafter`. Version matches the installed CLI version.

### Tools

| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan files or directories for leaked secrets, API keys, tokens, and credentials |
| `evaluate_command` | Check if a shell command is allowed per active security policy |
| `read_audit_log` | Read security event history with optional filtering |
| `get_config` | Read current Rafter configuration |

#### `scan_secrets`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | File or directory path to scan |
| `engine` | string | no | `"auto"` (default), `"gitleaks"`, or `"patterns"` |

Returns a JSON array of file scan results. Each entry has the same shape as `rafter scan local --json` output.

#### `evaluate_command`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | string | yes | Shell command to evaluate |

Returns:

```json
{
  "allowed": true,
  "risk_level": "low",
  "requires_approval": false,
  "reason": "Optional human-readable explanation"
}
```

`reason` is only present when the command is blocked or flagged.

#### `read_audit_log`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | number | no | Maximum entries to return (default: 20) |
| `event_type` | string | no | Filter by event type (e.g. `command_intercepted`, `secret_detected`) |
| `since` | string | no | ISO 8601 timestamp — only return entries after this time |

Returns a JSON array of audit log entries. Entry schema matches the [Audit Log Schema](#audit-log-schema).

#### `get_config`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `key` | string | no | Dot-path config key (e.g. `agent.riskLevel`). Omit for full config. |

Returns the config value at the given key, or the full `RafterConfig` object if no key is specified.

### Resources

The MCP server exposes two readable resources. Clients can read these via `resources/read`.

#### `rafter://config`

**MIME type:** `application/json`

Returns the current Rafter configuration loaded from `~/.rafter/config.json`. If no config file exists, returns the default configuration. Falls back to defaults for any invalid fields.

**Schema** (`RafterConfig`):

```json
{
  "version": "1",
  "initialized": "2026-01-15T10:30:00.000Z",
  "backend": {
    "apiKey": "...",
    "endpoint": "https://api.rafter.so"
  },
  "agent": {
    "riskLevel": "moderate",
    "commandPolicy": {
      "mode": "approve-dangerous",
      "blockedPatterns": ["rm -rf /"],
      "requireApproval": ["git push --force"]
    },
    "outputFiltering": {
      "redactSecrets": true,
      "blockPatterns": true
    },
    "audit": {
      "logAllActions": true,
      "retentionDays": 30,
      "logLevel": "info"
    },
    "notifications": {
      "webhook": "",
      "minRiskLevel": "high"
    },
    "scan": {
      "excludePaths": ["vendor/", "node_modules/"],
      "customPatterns": [
        {
          "name": "Internal API Key",
          "regex": "INTERNAL_[A-Z0-9]{32}",
          "severity": "critical"
        }
      ]
    }
  }
}
```

**Field reference (`agent` block):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `agent.riskLevel` | string | `"moderate"` | `"minimal"`, `"moderate"`, or `"aggressive"` |
| `agent.commandPolicy.mode` | string | `"approve-dangerous"` | `"allow-all"`, `"approve-dangerous"`, or `"deny-list"` |
| `agent.commandPolicy.blockedPatterns` | string[] | `[]` | Shell patterns always blocked |
| `agent.commandPolicy.requireApproval` | string[] | `[]` | Shell patterns requiring approval |
| `agent.outputFiltering.redactSecrets` | boolean | `true` | Redact secrets from CLI output |
| `agent.outputFiltering.blockPatterns` | boolean | `true` | Block known-dangerous output patterns |
| `agent.audit.logAllActions` | boolean | `true` | Master switch for audit logging |
| `agent.audit.retentionDays` | number | `30` | Days to retain audit log entries |
| `agent.audit.logLevel` | string | `"info"` | `"debug"`, `"info"`, `"warn"`, or `"error"` |
| `agent.notifications.webhook` | string | `""` | Webhook URL for security event notifications |
| `agent.notifications.minRiskLevel` | string | `"high"` | Minimum risk level to notify: `"high"` or `"critical"` |

#### `rafter://policy`

**MIME type:** `application/json`

Returns the **merged** configuration — global `~/.rafter/config.json` with any `.rafter.yml` project policy applied on top. Use this resource (rather than `rafter://config`) to get the effective policy for the current project.

Merging rules:
- `.rafter.yml` values override `config.json` values for the same key
- Arrays **replace** (not append): a `.rafter.yml` `blocked_patterns` list replaces the global list entirely
- Missing `.rafter.yml` keys leave the global config value unchanged

**Schema:** Same as `rafter://config` (`RafterConfig`).

**Difference from `rafter://config`:** `rafter://config` returns raw global config. `rafter://policy` returns the effective config after project-level policy overrides are applied. If no `.rafter.yml` exists, both resources return identical data.

**When to use each:**

| Resource | Use when |
|----------|----------|
| `rafter://config` | Inspecting the user's global baseline settings |
| `rafter://policy` | Determining the active rules for the current project |

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
```

Precedence: policy file overrides `~/.rafter/config.json`. Arrays replace, not append.

---

## Usage Examples

### Backend Code Analysis

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
- Backend code analysis targets the remote repository, not local files
- All scan data to stdout, all status messages to stderr
- `--quiet` suppresses stderr; stdout is unaffected
- Agent commands are available in both Node and Python implementations
