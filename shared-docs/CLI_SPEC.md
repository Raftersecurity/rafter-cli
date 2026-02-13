# Rafter CLI Command Spec

## Overview

The Rafter CLI follows UNIX principles for automation-friendly operation:

- **Scan data** is output to **stdout** for easy piping
- **Status messages** are output to **stderr**
- **Exit codes** provide predictable failure modes
- **No file writing** — pure stdout output for maximum pipe-friendliness

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / secrets found |
| 2 | Scan not found |
| 3 | Quota exhausted |

---

## Global Options

- `-a, --agent` — Plain output for AI agents (no colors, no emoji)
- `-V, --version` — Print version
- `-h, --help` — Show help

---

## Backend Scanning Commands

**Important**: The scanner analyzes the **remote repository** (e.g., on GitHub), not your local files. Auto-detection uses your local Git configuration to determine which remote repository and branch to scan.

### rafter run [OPTIONS]

Alias: `rafter scan`

Trigger a new security scan for a repository.

- `-k, --api-key TEXT` — API key or `RAFTER_API_KEY` env var
- `-r, --repo TEXT` — org/repo (default: auto-detected from git remote)
- `-b, --branch TEXT` — branch (default: current branch or 'main')
- `-f, --format [json|md]` — output format (default: md)
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

### rafter usage [OPTIONS]

Check API quota and usage statistics.

- `-k, --api-key TEXT` — API key or `RAFTER_API_KEY` env var
- `-h, --help`

### rafter version

Print version and exit.

---

## Agent Security Commands

All agent commands work locally. No API key required.

### rafter agent init [OPTIONS]

Initialize agent security system. Creates config, downloads Gitleaks, auto-detects and installs skills for Claude Code, Codex CLI, and OpenClaw.

- `--risk-level <level>` — `minimal`, `moderate` (default), or `aggressive`
- `--skip-openclaw` — skip OpenClaw skill installation
- `--skip-claude-code` — skip Claude Code skill installation
- `--skip-codex` — skip Codex CLI skill installation
- `--skip-gitleaks` — skip Gitleaks binary download

### rafter agent scan [PATH] [OPTIONS]

Scan files or directories for secrets (21+ patterns).

- `[PATH]` — file or directory (default: `.`)
- `-q, --quiet` — only output if secrets found
- `--json` — output as JSON
- `--staged` — scan git staged files only
- `--diff <ref>` — scan files changed since a git ref (e.g., `HEAD~1`, `main`)
- `--engine <engine>` — `gitleaks`, `patterns`, or `auto` (default)

Exit code 1 if secrets found, 0 if clean.

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

### rafter agent install-hook [OPTIONS]

Install git pre-commit hook for automatic secret scanning.

- `--global` — install globally for all repos (sets `core.hooksPath`)

### rafter agent config SUBCOMMAND

Manage agent configuration (dot-notation paths).

- `rafter agent config show` — display full config
- `rafter agent config get <key>` — read value
- `rafter agent config set <key> <value>` — write value

Config keys: `agent.riskLevel`, `agent.commandPolicy.mode`, `agent.commandPolicy.blockedPatterns`, `agent.commandPolicy.requireApproval`, `agent.outputFiltering.redactSecrets`, `agent.audit.logAllActions`, `agent.audit.retentionDays`, `agent.audit.logLevel`.

### rafter ci init [OPTIONS]

Generate CI/CD pipeline configuration for secret scanning.

- `--platform <platform>` — `github`, `gitlab`, or `circleci` (default: auto-detect)
- `--output <path>` — output file path (default: platform-specific)
- `--with-backend` — include backend security audit job (requires `RAFTER_API_KEY`)

Auto-detection: checks for `.github/`, `.gitlab-ci.yml`, `.circleci/` in cwd.

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

### Backend Scanning

```bash
# Run scan, auto-detect repo/branch
rafter run

# Scan specific repo
rafter scan --repo myorg/myrepo --branch main

# Get results as JSON
rafter get SCAN_ID --format json

# Pipe to jq
rafter get SCAN_ID --format json | jq '.vulnerabilities[] | select(.level=="critical")'

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
        3) echo "Quota exhausted" ;;
        *) echo "Other error" ;;
    esac
fi
```

### Agent Security

```bash
# Full setup
rafter agent init

# Scan for secrets
rafter agent scan .
rafter agent scan --staged --quiet  # CI-friendly

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
- Backend scanning targets the remote repository, not local files
- All scan data to stdout, all status messages to stderr
- `--quiet` suppresses stderr; stdout is unaffected
- Agent commands are Node.js only; Python package provides backend scanning
