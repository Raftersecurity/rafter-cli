# @rafter-security/cli

A Node.js CLI for Rafter Security with backend scanning and agent security features.

**Features:**
- 🔍 **Backend Scanning**: Trigger security scans via Rafter API
- 🛡️ **Agent Security**: Local secret detection, command validation, audit logging
- 🤖 **Agent Integration**: OpenClaw and Claude Code support

## Installation

```bash
# Using npm
npm install -g @rafter-security/cli

# Using pnpm
pnpm add -g @rafter-security/cli

# Using yarn
yarn global add @rafter-security/cli
```

## Quick Start

### Backend Scanning

```bash
# Set your API key
export RAFTER_API_KEY="your-api-key-here"

# Run a security scan
rafter run

# Get scan results
rafter get <scan-id>

# Check API usage
rafter usage
```

### Agent Security

```bash
# Initialize agent security
rafter agent init

# Scan files for secrets
rafter agent scan .

# Execute commands safely
rafter agent exec "git commit -m 'Add feature'"

# View audit logs
rafter agent audit

# Manage configuration
rafter agent config show
```

## Commands

### `rafter run [options]`

Trigger a new security scan for your repository.

**Options:**
- `-r, --repo <repo>` - Repository in format `org/repo` (default: auto-detected)
- `-b, --branch <branch>` - Branch name (default: auto-detected)
- `-k, --api-key <key>` - API key (or set `RAFTER_API_KEY` env var)
- `-f, --format <format>` - Output format: `json` or `md` (default: `json`)
- `--skip-interactive` - Don't wait for scan completion
- `--quiet` - Suppress status messages

**Examples:**
```bash
# Basic scan with auto-detection
rafter run

# Scan specific repo/branch
rafter run --repo myorg/myrepo --branch feature-branch

# Non-interactive scan
rafter run --skip-interactive
```

### `rafter get <scan-id> [options]`

Retrieve results from a completed scan.

**Options:**
- `-k, --api-key <key>` - API key (or set `RAFTER_API_KEY` env var)
- `-f, --format <format>` - Output format: `json` or `md` (default: `json`)
- `--interactive` - Poll until scan completes
- `--quiet` - Suppress status messages

**Examples:**
```bash
# Get scan results
rafter get <scan-id>

# Wait for scan completion
rafter get <scan-id> --interactive
```

### `rafter usage [options]`

Check your API quota and usage.

**Options:**
- `-k, --api-key <key>` - API key (or set `RAFTER_API_KEY` env var)

**Example:**
```bash
rafter usage
```

---

## Agent Security Commands

Rafter provides local security features for autonomous agents (OpenClaw, Claude Code) to prevent secrets leakage and dangerous operations.

### `rafter agent init [options]`

Initialize agent security system.

**Options:**
- `--risk-level <level>` - Set risk level: `minimal`, `moderate`, or `aggressive` (default: `moderate`)
- `--skip-openclaw` - Skip OpenClaw skill installation

**What it does:**
- Creates `~/.rafter/config.json` configuration
- Initializes directory structure
- Detects and installs OpenClaw skill (if present)
- Sets up audit logging

**Example:**
```bash
rafter agent init
rafter agent init --risk-level aggressive
```

### `rafter agent scan [path] [options]`

Scan files or directories for secrets.

**Arguments:**
- `path` - File or directory to scan (default: current directory)

**Options:**
- `-q, --quiet` - Only output if secrets found
- `--json` - Output results as JSON

**Features:**
- Detects 21+ secret types (AWS, GitHub, Stripe, Google, Slack, etc.)
- Shows severity levels (critical/high/medium/low)
- Displays line and column numbers
- Smart redaction (shows first/last 4 chars)
- Exits with code 1 if secrets found (CI-friendly)

**Examples:**
```bash
# Scan current directory
rafter agent scan

# Scan specific file
rafter agent scan ./config.js

# Scan for CI (quiet mode)
rafter agent scan --quiet

# JSON output for processing
rafter agent scan --json
```

**Detected patterns:**
- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Google API Keys
- Slack Tokens & Webhooks
- Stripe API Keys
- Database connection strings
- JWT tokens
- npm & PyPI tokens
- Private keys (RSA, DSA, EC)
- Generic API keys and secrets

### `rafter agent exec <command> [options]`

Execute shell command with security validation.

**Arguments:**
- `command` - Shell command to execute

**Options:**
- `--skip-scan` - Skip pre-execution file scanning
- `--force` - Skip approval prompts (use with caution, logged in audit)

**Features:**
- Blocks critical commands automatically (rm -rf /, fork bombs)
- Requires approval for high-risk operations
- Scans staged files before git commits
- Logs all executions to audit log
- Risk assessment for all commands

**Command risk levels:**
- **Critical** (blocked): `rm -rf /`, fork bombs, `dd` to /dev, `mkfs`
- **High** (requires approval): `rm -rf`, `sudo rm`, `chmod 777`, `curl|sh`, `git push --force`
- **Medium** (requires approval on moderate+): `sudo`, `chmod`, `kill -9`
- **Low** (allowed): Most other commands

**Examples:**
```bash
# Safe command - executes immediately
rafter agent exec "npm install"

# Git commit - scans staged files first
rafter agent exec "git commit -m 'Add feature'"

# High-risk command - requires approval
rafter agent exec "sudo rm /tmp/old-files"

# Critical command - blocked
rafter agent exec "rm -rf /"
```

### `rafter agent config <subcommand>`

Manage agent configuration.

**Subcommands:**
- `show` - Display full configuration
- `get <key>` - Get specific configuration value
- `set <key> <value>` - Set configuration value

**Configuration keys:**
- `agent.riskLevel` - Risk level: `minimal`, `moderate`, `aggressive`
- `agent.commandPolicy.mode` - Policy mode: `allow-all`, `approve-dangerous`, `deny-list`
- `agent.outputFiltering.redactSecrets` - Redact secrets in output: `true` or `false`
- `agent.audit.logAllActions` - Log all actions: `true` or `false`
- `agent.audit.retentionDays` - Log retention period (days)

**Examples:**
```bash
# View all configuration
rafter agent config show

# Get risk level
rafter agent config get agent.riskLevel

# Set to aggressive mode
rafter agent config set agent.riskLevel aggressive

# Change command policy
rafter agent config set agent.commandPolicy.mode deny-list
```

### `rafter agent audit [options]`

View security audit logs.

**Options:**
- `--last <n>` - Show last N entries (default: 10)
- `--event <type>` - Filter by event type
- `--agent <type>` - Filter by agent type (`openclaw`, `claude-code`)
- `--since <date>` - Show entries since date (YYYY-MM-DD)

**Event types:**
- `command_intercepted` - Command execution attempts
- `secret_detected` - Secret found in files
- `content_sanitized` - Output redacted
- `policy_override` - User override of security policy
- `scan_executed` - File scan performed
- `config_changed` - Configuration modified

**Examples:**
```bash
# Show recent audit logs
rafter agent audit

# Show last 20 entries
rafter agent audit --last 20

# Filter by event type
rafter agent audit --event secret_detected

# Show logs since date
rafter agent audit --since 2026-02-01
```

---

## Configuration

### Environment Variables

- `RAFTER_API_KEY` - Your Rafter API key (alternative to `--api-key` flag)

### Git Auto-Detection

The CLI automatically detects your repository and branch from the current Git repository:

1. **Repository**: Extracted from Git remote URL
2. **Branch**: Current branch name, or `main` if on detached HEAD

**Note**: The CLI only scans remote repositories, not your current local branch.

### Agent Security Configuration

Agent security settings are stored in `~/.rafter/config.json`. Key settings:

**Risk Levels:**
- `minimal` - Basic guidance only, most commands allowed
- `moderate` - Standard protections, approval for high-risk commands (recommended)
- `aggressive` - Maximum security, requires approval for most operations

**Command Policy Modes:**
- `allow-all` - Allow all commands (not recommended for production)
- `approve-dangerous` - Require approval for high/critical risk commands (default)
- `deny-list` - Block specific patterns, allow everything else

**File Locations:**
- Config: `~/.rafter/config.json`
- Audit log: `~/.rafter/audit.log`
- Binaries: `~/.rafter/bin/`
- Patterns: `~/.rafter/patterns/`

## OpenClaw Integration

Rafter integrates seamlessly with [OpenClaw](https://openclaw.com) autonomous agents.

### Setup

When OpenClaw is detected, `rafter agent init` automatically installs a skill to `~/.openclaw/skills/rafter-security.md`.

**What the skill provides:**
- `/rafter-scan` - Scan files before commits
- `/rafter-bash` - Execute commands with validation (via `rafter agent exec`)
- `/rafter-audit` - View security logs

### Usage in OpenClaw

```bash
# In OpenClaw, use Rafter commands naturally:
"Scan this directory for secrets"
# OpenClaw will call: rafter agent scan .

"Commit these changes"
# OpenClaw will call: rafter agent exec "git commit -m '...'"
# Rafter scans staged files first, blocks if secrets found
```

### Best Practices

1. **Always scan before commits**: Run `rafter agent scan` before `git commit`
2. **Review blocked commands**: Check `rafter agent audit` when commands are blocked
3. **Configure appropriately**: Use `moderate` risk level for most use cases
4. **Keep patterns updated**: Patterns are updated automatically (future feature)

## Documentation

For comprehensive documentation, API reference, and examples, see [https://docs.rafter.so](https://docs.rafter.so). 