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

### Getting an API Key

To use backend scanning features, you'll need a Rafter API key:

1. **Sign up**: Create an account at [rafter.so](https://rafter.so)
2. **Get API key**: Navigate to Dashboard → Settings → API Keys
3. **Set environment variable**:
   ```bash
   export RAFTER_API_KEY="your-api-key-here"
   ```
4. **Or use `.env` file**:
   ```bash
   echo "RAFTER_API_KEY=your-api-key-here" >> .env
   ```

**Note**: Agent security features (secret scanning, command execution) work **without an API key**. Only backend scanning requires authentication.

### Backend Scanning

```bash
# Set your API key (from above)
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

### `rafter agent install-hook [options]`

Install git pre-commit hook to automatically scan for secrets before commits.

**Options:**
- `--global` - Install globally for all repos (via git config)

**Features:**
- Automatically scans staged files before each commit
- Blocks commits if secrets are detected
- Zero-configuration security for git workflows
- Can be bypassed with `git commit --no-verify` (not recommended)

**Examples:**
```bash
# Install for current repository
cd my-repo
rafter agent install-hook

# Install globally for all repositories
rafter agent install-hook --global

# Uninstall global hook
git config --global --unset core.hooksPath
```

**What it does:**
```bash
# When you commit:
git add .env
git commit -m "Update config"

# Rafter automatically scans:
🔍 Rafter: Scanning staged files for secrets...
❌ Commit blocked: Secrets detected in staged files

   Run: rafter agent scan --staged
   To see details and remediate.
```

**Why use pre-commit hooks?**

Pre-commit hooks provide the most effective protection against accidentally committing secrets to git:
- **Automatic**: No need to remember to scan manually
- **Fail-safe**: Prevents secrets from entering version control
- **CI-friendly**: Works locally before code reaches CI/CD
- **Team-wide**: Can be committed to `.git/hooks` or distributed via git config

Always install pre-commit hooks for repositories handling sensitive data.

### `rafter agent audit-skill <skill-path> [options]`

Security audit of a Claude Code skill file before installation.

**Arguments:**
- `skill-path` - Path to skill file to audit

**Options:**
- `--skip-openclaw` - Skip OpenClaw integration, show manual review prompt
- `--json` - Output results as JSON

**Features:**
- **Quick Scan**: Detects secrets, external URLs, high-risk commands
- **Deep Analysis**: Uses OpenClaw's skill-auditor for comprehensive review (if installed)
- **12 Security Dimensions**: Trust, network security, command safety, file access, credentials, input validation, data exfiltration, obfuscation, scope alignment, error handling, dependencies, environment manipulation
- **Risk Rating**: LOW/MEDIUM/HIGH/CRITICAL assessment
- **Actionable Recommendations**: Clear install/don't install guidance

**Security Dimensions Analyzed:**
1. Trust & Attribution - Source verification
2. Network Security - External communication
3. Command Execution - Shell command safety
4. File System Access - Read/write patterns
5. Credential Handling - Secret management
6. Input Validation - Injection risks
7. Data Exfiltration - What leaves the system
8. Obfuscation - Hidden behavior detection
9. Scope Alignment - Matches stated purpose
10. Error Handling - Information disclosure
11. Dependencies - Supply chain risks
12. Environment Manipulation - System modifications

**Examples:**
```bash
# Audit a skill file
rafter agent audit-skill ~/.openclaw/skills/untrusted-skill.md

# Audit with OpenClaw (comprehensive)
rafter agent audit-skill skill.md
# Then in OpenClaw: /rafter-audit-skill /path/to/skill.md

# Manual review prompt (no OpenClaw)
rafter agent audit-skill skill.md --skip-openclaw

# JSON output for automation
rafter agent audit-skill skill.md --json
```

**Example Output:**
```
🔍 Auditing skill: untrusted-skill.md
═══════════════════════════════════════════════════════════
📊 Quick Scan Results
⚠️  Secrets: 1 found
⚠️  External URLs: 2 found
   • https://api.example.com/v1/data
   • https://untrusted-cdn.com/script.js
⚠️  High-risk commands: 1 found
   • curl | bash (line 45)

🤖 For comprehensive security review:
   1. Open OpenClaw
   2. Run: /rafter-audit-skill /path/to/skill.md
```

**Why audit skills?**

Claude Code skills can:
- Execute shell commands
- Access sensitive files
- Make network requests
- Handle credentials
- Process user input

Always audit skills from untrusted sources before installation. The skill-auditor provides systematic analysis to identify security risks.

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
- `/rafter-audit-skill` - Comprehensive security audit of Claude Code skills
- `/rafter-audit` - View security logs

### Usage in OpenClaw

```bash
# In OpenClaw, use Rafter commands naturally:
"Scan this directory for secrets"
# OpenClaw will call: rafter agent scan .

"Audit this skill for security issues"
# OpenClaw will call: /rafter-audit-skill <path>
# Provides comprehensive 12-dimension security analysis

"Commit these changes"
# OpenClaw will call: rafter agent exec "git commit -m '...'"
# Rafter scans staged files first, blocks if secrets found
```

### Best Practices

1. **Install pre-commit hooks**: Run `rafter agent install-hook` to automatically scan before commits (recommended)
2. **Audit untrusted skills**: Run `/rafter-audit-skill` before installing skills from unknown sources
3. **Review blocked commands**: Check `rafter agent audit` when commands are blocked
4. **Configure appropriately**: Use `moderate` risk level for most use cases
5. **Keep patterns updated**: Patterns are updated automatically with CLI updates

## Claude Code Integration

Rafter provides TWO skills for Claude Code:

### 1. Backend Scanning Skill (Core Feature)

**Automatic Integration** - Claude can proactively suggest security scans

**Commands:**
- `rafter run` - Trigger security scan
- `rafter get <scan-id>` - Get results
- `rafter usage` - Check quota

**Installation:**
```bash
rafter agent init
# Auto-detects Claude Code and installs both skills
```

Or manually:
```bash
cp -r node/.claude/skills/rafter ~/.claude/skills/
```

**Usage:**
Claude will automatically suggest Rafter scans when you mention security, vulnerabilities, or code analysis. You can also invoke manually:
```
Can you run a Rafter security scan on this repo?
```

### 2. Agent Security Skill

**User-Invoked** - Requires explicit commands for safety

**Commands:**
- `/rafter-scan` - Scan files for secrets
- `/rafter-bash` - Execute commands safely
- `/rafter-audit-skill` - Audit skills before installing
- `/rafter-audit` - View security logs

**Installation:**
```bash
rafter agent init
# Installs automatically if Claude Code detected
```

Or manually:
```bash
cp -r node/.claude/skills/rafter-agent-security ~/.claude/skills/
```

**Usage:**
Explicitly invoke commands:
```
/rafter-scan .
/rafter-audit-skill untrusted-skill.md
```

### Why Two Skills?

- **Backend skill** - Safe for Claude to auto-invoke (read-only API calls)
- **Agent security skill** - Requires user permission (local file access, command execution)

This separation emphasizes Rafter's core backend scanning capabilities while keeping local security features safely behind user control.

## Documentation

For comprehensive documentation, API reference, and examples, see [https://docs.rafter.so](https://docs.rafter.so). 