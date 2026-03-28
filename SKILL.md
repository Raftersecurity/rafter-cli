# Rafter -- Security Toolkit for AI Coding Agents

Rafter is a security CLI that protects your codebase from leaked secrets, dangerous commands, and vulnerable dependencies. It works offline with zero config. No API key, no account, no telemetry.

This file teaches AI agents how to install and use Rafter. If you are an AI coding agent, follow these instructions.

## Install

```bash
# Node.js (recommended)
npm install -g @rafter-security/cli

# Python (full feature parity)
pip install rafter-cli
```

## Initialize for Your Platform

Run `rafter agent init` with the flag for your platform. This installs hooks, skills, or MCP config automatically.

```bash
# Auto-install all detected platforms
rafter agent init --all

# Or pick your platform
rafter agent init --with-claude-code   # Hooks (PreToolUse/PostToolUse) + skills
rafter agent init --with-codex         # Skills
rafter agent init --with-cursor        # MCP server
rafter agent init --with-gemini        # MCP server
rafter agent init --with-windsurf      # MCP server
rafter agent init --with-continue      # MCP server
rafter agent init --with-aider         # MCP server
rafter agent init --with-openclaw      # Skills

# Also download Gitleaks for enhanced scanning (optional, falls back to built-in 21-pattern regex)
rafter agent init --with-claude-code --with-gitleaks
```

**What init does per platform:**

| Platform | Integration type | What gets installed |
|----------|-----------------|---------------------|
| Claude Code | PreToolUse/PostToolUse hooks + skills | `~/.claude/settings.json` (hooks), `~/.claude/skills/rafter/` (skills) |
| Codex CLI | Skills | `~/.agents/skills/rafter/` |
| OpenClaw | Skills | `~/.openclaw/skills/rafter-security.md` |
| Cursor | MCP server | `~/.cursor/mcp.json` |
| Gemini CLI | MCP server | `~/.gemini/settings.json` |
| Windsurf | MCP server | `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | MCP server | `~/.continue/config.json` |
| Aider | MCP server | `~/.aider.conf.yml` |

## Scan for Secrets

Scan files or directories for hardcoded credentials. 21+ built-in patterns (AWS keys, GitHub tokens, Stripe keys, database URIs, private keys, JWTs, etc.). Deterministic -- same input always produces the same output.

```bash
# Scan a directory
rafter scan local .

# Scan a specific file
rafter scan local src/config.ts

# Scan only git staged files (use before commits)
rafter scan local --staged

# Scan files changed since a ref
rafter scan local --diff HEAD~1

# JSON output (structured, pipe-friendly)
rafter scan local . --json --quiet
```

**Exit codes (stable contract):**
- `0` -- clean, no secrets found
- `1` -- secrets detected
- `2` -- runtime error (bad path, not a git repo)

**JSON output schema** (`--json`):

```json
[
  {
    "file": "/absolute/path/to/file.ts",
    "matches": [
      {
        "pattern": { "name": "AWS Access Key", "severity": "critical" },
        "line": 42,
        "redacted": "AKIA************MPLE"
      }
    ]
  }
]
```

Raw secret values are never included in output.

## Pre-Commit Hook

Block commits that contain secrets:

```bash
# Current repo
rafter agent install-hook

# All repos on this machine
rafter agent install-hook --global
```

## Command Risk Assessment

Evaluate shell commands against a 4-tier risk policy:

```bash
rafter agent exec "npm install"           # low risk -- runs
rafter agent exec "git push --force"      # high risk -- requires approval
rafter agent exec "rm -rf /"              # critical -- blocked
```

| Risk | Action | Examples |
|------|--------|----------|
| Critical | Blocked | `rm -rf /`, fork bombs, `dd` to device |
| High | Approval required | `sudo rm`, `chmod 777`, `curl\|sh`, `npm publish` |
| Medium | Approval on moderate+ | `sudo`, `chmod`, `kill -9` |
| Low | Allowed | `npm install`, `git commit`, `ls` |

## Claude Code Hook Integration

When installed via `rafter agent init --with-claude-code`, Rafter registers hooks in `~/.claude/settings.json`:

- **PreToolUse** hooks on `Bash` and `Write|Edit` tool calls. Every shell command is evaluated against the risk policy before execution. Dangerous commands are blocked or require approval transparently -- no manual invocation needed.
- **PostToolUse** hooks on all tool calls (`.*` matcher). Scans output for accidentally leaked secrets and redacts them.

The hooks read JSON from stdin and write a `{"decision": "allow"}` or `{"decision": "deny", "reason": "..."}` response to stdout. This is the Claude Code hook protocol.

Manual hook config (if not using `rafter agent init`):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "rafter hook pretool" }] },
      { "matcher": "Write|Edit", "hooks": [{ "type": "command", "command": "rafter hook pretool" }] }
    ],
    "PostToolUse": [
      { "matcher": ".*", "hooks": [{ "type": "command", "command": "rafter hook posttool" }] }
    ]
  }
}
```

## MCP Server

For MCP-native platforms (Cursor, Gemini, Windsurf, Continue.dev, Aider), Rafter exposes tools over stdio:

```bash
rafter mcp serve
```

MCP client config:

```json
{
  "mcpServers": {
    "rafter": { "command": "rafter", "args": ["mcp", "serve"] }
  }
}
```

**Tools provided:**
- `scan_secrets` -- scan files/directories for secrets
- `evaluate_command` -- check if a shell command is allowed by policy
- `read_audit_log` -- read security event log with filters
- `get_config` -- read current Rafter configuration

**Resources:**
- `rafter://config` -- current configuration
- `rafter://policy` -- active security policy

## Remote Code Analysis (API)

SAST/SCA security audits on GitHub repos. Requires `RAFTER_API_KEY`. Code is deleted immediately after analysis.

```bash
export RAFTER_API_KEY="your-key"

rafter run                                        # scan current repo (auto-detected)
rafter scan --repo myorg/myrepo --branch main     # scan specific repo
rafter get SCAN_ID                                # retrieve results
rafter get SCAN_ID --format json                  # JSON output
rafter usage                                      # check quota
```

**Exit codes:**
- `0` -- success
- `1` -- error
- `2` -- scan not found
- `3` -- quota exhausted
- `4` -- forbidden (check API key)

## Policy File

Drop `.rafter.yml` in project root for per-repo security policy:

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
```

## Audit Log

Every security event is logged to `~/.rafter/audit.jsonl`:

```bash
rafter agent audit                        # last 10 entries
rafter agent audit --last 20              # last 20
rafter agent audit --event secret_detected
rafter agent audit --since 2026-01-01
```

Event types: `command_intercepted`, `secret_detected`, `content_sanitized`, `policy_override`, `scan_executed`, `config_changed`.

## Skill Auditing

Audit third-party skills/extensions before installing them:

```bash
rafter agent audit-skill path/to/untrusted-skill.md
```

Detects embedded secrets, external URLs, high-risk commands (`curl|sh`, `eval()`, `base64|sh`), and obfuscated code.

## Configuration

```bash
rafter agent config show                                      # view all
rafter agent config set agent.riskLevel aggressive            # set risk level
rafter agent config set agent.commandPolicy.mode deny-list    # set policy mode
```

Risk levels: `minimal` (guidance only), `moderate` (default), `aggressive` (approval for most ops).

## CI/CD

```bash
rafter ci init                     # auto-detect CI platform
rafter ci init --platform github   # GitHub Actions
```

GitHub Action:

```yaml
- uses: raftersecurity/rafter-cli@v1
  with:
    scan-path: '.'
    args: '--quiet'
```

## Quick Reference

```bash
rafter brief commands              # condensed CLI reference
rafter brief setup/claude-code     # platform-specific setup guide
rafter brief security              # local security toolkit overview
rafter brief all                   # everything
```
