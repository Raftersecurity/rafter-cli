# Rafter CLI

Multi-language CLI for [Rafter](https://rafter.so) — the default security agent for AI workflows.

> **Free forever for individuals and open source. No account required. No telemetry.**
>
> Agent security features work locally with zero setup — no API key, no sign-up, no usage limits.
> Enterprise teams that need dashboards, policy management, and compliance reporting can upgrade later.

Rafter is a **delegation primitive**: other agents and orchestrators defer security decisions to it and trust the outputs. Stable contracts, deterministic results, and low-noise defaults mean systems can act on Rafter's findings without reading prose.

**Two capabilities in one package:**

1. **Rafter Security Audits** — Remote SAST/SCA code analysis on GitHub repos via the Rafter API. Structured vulnerability reports in JSON or Markdown with consistent schemas and clear severity levels. Pipe to any tool, feed to any agent.

2. **Agent Security** (free, no account) — Local-first protection for autonomous AI agents. Fast, reliable secret scanning (21+ patterns, deterministic for a given version), command interception with risk-tiered approval, pre-commit hooks, skill/extension auditing, and full audit logging. Works with Claude Code, Codex CLI, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, and Aider. **No API key required. No telemetry. No data leaves your machine.**

The CLI follows UNIX principles and provides a **stable output contract**: scan results to stdout, status to stderr, documented exit codes, consistent JSON structure. No code leaves your machine unless you explicitly use the remote code analysis API, and is deleted immediately after the analysis engine completes. Orchestrators can classify outcomes (clean / findings / retryable error / fatal error) and act without human intervention.

## 90-Second Quickstart

See what Rafter does before reading another word.

**1. Scan a directory for leaked credentials**

```sh
# Drop a .env file with credentials in a test repo
echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' > .env

rafter scan local .
# → CRITICAL  .env:1  aws-access-key-id  AKIA***AMPLE
# → exit 1
```

**2. Install the pre-commit hook**

```sh
rafter agent init --all
# → Installs all detected integrations
# → Downloads Gitleaks (or falls back to built-in scanner)
```

**3. Try to commit—hook blocks it**

```sh
git add . && git commit -m 'add config'
# → [rafter] Scanning staged files for secrets...
# → CRITICAL  .env:1  aws-access-key-id
# → Commit blocked. Remove secrets or use git commit --no-verify to bypass.
```

**4. Review the audit log**

```sh
rafter agent audit --last 3
# → 2026-02-27T...  secret_detected  .env  aws-access-key-id
```

That's the core loop: scan → protect → audit. Everything works offline, no API key needed.

### What's Free?

| Feature | Free (individuals & OSS) | Enterprise |
|---------|:------------------------:|:----------:|
| Secret scanning (21+ patterns) | **Yes** | Yes |
| Pre-commit hooks | **Yes** | Yes |
| Command interception | **Yes** | Yes |
| Skill/extension auditing | **Yes** | Yes |
| Audit logging | **Yes** | Yes |
| MCP server | **Yes** | Yes |
| CI/CD integration | **Yes** | Yes |
| Remote SAST/SCA (API) | Free tier | Higher limits |
| Dashboards & policy management | — | Yes |
| Compliance reporting | — | Yes |

No account. No telemetry. No data collection. The CLI is MIT-licensed and all local features work without network access.

---

## Installation

### Node.js (full features: backend + agent security)

```sh
npm install -g @rafter-security/cli
# or
pnpm add -g @rafter-security/cli
```

### Python (full features)

```sh
pip install rafter-cli
```

Requires Python 3.10+. Full feature parity with Node.js including agent security and MCP server.

---

## Rafter Security Audits

Remote SAST/SCA code analysis via the Rafter API. The code analysis engine runs against the **remote repository** on GitHub, not local files. Your code is deleted immediately after analysis completes. Auto-detection uses your local Git config to determine which repo and branch to analyze.

```sh
export RAFTER_API_KEY="your-key"   # or use .env file

rafter run                                    # scan current repo (auto-detected)
rafter scan --repo myorg/myrepo --branch main # scan specific repo
rafter get SCAN_ID                            # retrieve results
rafter get SCAN_ID --interactive              # poll until complete
rafter usage                                  # check quota
```

### Piping and Automation

```sh
# Filter high-severity vulnerabilities (SARIF levels: error, warning, note)
rafter get SCAN_ID --format json | jq '.vulnerabilities[] | select(.level=="error")'

# Count vulnerabilities
rafter get SCAN_ID --format json | jq '.vulnerabilities | length'

# Extract all affected file paths
rafter get SCAN_ID --format json | jq -r '.vulnerabilities[].file' | sort | uniq

# CSV export
rafter get SCAN_ID --format json --quiet | jq -r '.vulnerabilities[] | [.level, .rule_id, .file, .line] | @csv'

# CI gate: fail if vulnerabilities found
if rafter get SCAN_ID --format json | jq -e '.vulnerabilities | length > 0'; then
    echo "Vulnerabilities found!" && exit 1
fi

# Save to file
rafter get SCAN_ID > scan_results.json
```

### API Key Setup

1. Sign up at [rafter.so](https://rafter.so)
2. Dashboard → Settings → API Keys
3. `export RAFTER_API_KEY="your-key"` or add to `.env`

---

## Global Options

| Flag | Description |
|------|-------------|
| `-a, --agent` | Plain output for AI agents (no colors, no emoji). Useful when piping to LLMs or automated systems. |

## Agent Security — Free, No Account Required

Local security features for autonomous AI agents. Everything below works offline — **no API key, no sign-up, no telemetry, no usage limits.** Free forever for individuals and open source.

**Trust guarantees:** No code leaves your machine unless you explicitly use the remote code analysis API, and is deleted immediately after the analysis engine completes. Secrets are redacted in all output — logs, JSON, and human-readable formats. No data is collected or phoned home.

### Setup

```sh
rafter agent init --all           # install all detected integrations
rafter agent init --with-claude-code  # or install specific ones
```

This command:
- Creates `~/.rafter/` config and audit log
- Auto-detects Claude Code, Codex CLI, OpenClaw, Gemini, Cursor, Windsurf, Continue.dev, and Aider
- With `--with-*` or `--all`: installs Rafter skills/extensions to opted-in agents
- With `--with-gitleaks` or `--all`: downloads [Gitleaks](https://github.com/gitleaks/gitleaks) for enhanced secret scanning (falls back to built-in 21-pattern regex scanner)

### Secret Scanning

Fast, reliable, and deterministic for a given CLI version. 21+ built-in patterns covering AWS, GitHub, Google, Slack, Stripe, Twilio, database connection strings, JWTs, private keys, npm/PyPI tokens, and generic API keys. Same inputs produce the same findings — no flaky CI, no phantom alerts.

```sh
rafter agent scan .              # scan directory
rafter agent scan ./config.js    # scan specific file
rafter agent scan --staged       # scan git staged files only
rafter agent scan --diff HEAD~1  # scan files changed since a git ref
rafter agent scan --json         # structured output
rafter agent scan --quiet        # silent unless secrets found (CI-friendly)
```

Exit code 1 if secrets found, 0 if clean.

**Engine selection:** Uses Gitleaks when available (more patterns), falls back to built-in regex. Override with `--engine gitleaks|patterns|auto`.

### Pre-Commit Hook

Automatically scan staged files before every `git commit`. The most effective way to prevent secrets from entering version control.

```sh
rafter agent install-hook           # current repo only
rafter agent install-hook --global  # all repos on this machine
```

Blocks commits when secrets are detected. Bypass with `git commit --no-verify` (not recommended).

#### pre-commit Framework

Rafter works as a [pre-commit](https://pre-commit.com) hook. Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/raftersecurity/rafter-cli
    rev: v0.6.5
    hooks:
      - id: rafter-scan-node
```

Requires `rafter` in PATH (install via `npm i -g @rafter-security/cli` or `pip install rafter-cli`).

### Command Interception

Execute shell commands through a risk-assessment layer. AI agents route commands through `rafter agent exec` to get guardrails on destructive operations.

```sh
rafter agent exec "npm install"                    # low risk → runs immediately
rafter agent exec "git commit -m 'Add feature'"    # scans staged files first
rafter agent exec "sudo rm /tmp/old-files"         # high risk → requires approval
rafter agent exec "rm -rf /"                       # critical → blocked
```

| Risk | Action | Examples |
|------|--------|----------|
| Critical | Blocked | `rm -rf /`, fork bombs, `dd` to device, `mkfs` |
| High | Approval required | `rm -rf`, `sudo rm`, `chmod 777`, `curl\|sh`, `git push --force`, `npm publish` |
| Medium | Approval on moderate+ | `sudo`, `chmod`, `kill -9`, `systemctl` |
| Low | Allowed | `npm install`, `git commit`, `ls`, `cat` |

For git commands (`git commit`, `git push`), Rafter scans staged files for secrets before execution and blocks if any are found.

### Skill Auditing

**Treat third-party agent skill ecosystems as hostile by default.** There have been reports of malware distributed through AI agent skill marketplaces, using social-engineering instructions to run obfuscated shell commands.

```sh
rafter agent audit-skill path/to/untrusted-skill.md
```

**Quick scan** (deterministic, runs instantly): detects embedded secrets, external URLs, and high-risk commands (`curl|sh`, `eval()`, `base64|sh`, fork bombs, etc.). Every finding includes file, line, rule ID, and a concrete fix hint — actionable, not just advisory.

**Deep analysis** (via OpenClaw, if installed): 12-dimension security review covering trust/attribution, network security, command execution, file system access, credential handling, input validation, data exfiltration, obfuscation, scope alignment, error handling, dependencies, and environment manipulation.

Without OpenClaw, generates an LLM-ready review prompt you can paste into any model.

### Audit Log

Every security-relevant event is logged to `~/.rafter/audit.jsonl` in JSON-lines format.

```sh
rafter agent audit                           # last 10 entries
rafter agent audit --last 20                 # last 20
rafter agent audit --event secret_detected   # filter by type
rafter agent audit --since 2026-02-01        # filter by date
```

Event types: `command_intercepted`, `secret_detected`, `content_sanitized`, `policy_override`, `scan_executed`, `config_changed`.

### Configuration

```sh
rafter agent config show                                    # view all settings
rafter agent config get agent.riskLevel                     # read a value
rafter agent config set agent.riskLevel aggressive          # write a value
rafter agent config set agent.commandPolicy.mode deny-list  # dot-notation paths
```

**Risk levels:** `minimal` (guidance only) · `moderate` (default, approval for dangerous ops) · `aggressive` (approval for most ops)

**Command policies:** `allow-all` · `approve-dangerous` (default) · `deny-list`

Config lives at `~/.rafter/config.json`. Project-level overrides via `.rafter.yml` (see below).

### Policy File (`.rafter.yml`)

Drop a `.rafter.yml` in your project root to define per-repo security policies. The CLI walks from cwd to git root looking for it.

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

Policy file values override `~/.rafter/config.json`. Arrays replace (not append).

### CI/CD Setup

Generate CI pipeline config for secret scanning:

```sh
rafter ci init                          # auto-detect platform
rafter ci init --platform github        # GitHub Actions
rafter ci init --platform gitlab        # GitLab CI
rafter ci init --platform circleci      # CircleCI
rafter ci init --with-backend           # include backend security audit job
```

#### GitHub Action

Use as a reusable action in any GitHub Actions workflow:

```yaml
- uses: raftersecurity/rafter-cli@v0
  with:
    scan-path: '.'       # default
    args: '--quiet'      # default; override for verbose output
    # install-method: 'pip'  # use pip instead of npm
```

Exit codes: `0` = clean, `1` = secrets found, `2` = scanner error.

Inputs:

| Input | Default | Description |
|-------|---------|-------------|
| `scan-path` | `.` | Path to scan |
| `args` | `--quiet` | Additional args to `rafter scan local` |
| `version` | `latest` | CLI version to install |
| `install-method` | `npm` | `npm` or `pip` |
| `format` | `json` | Output format: `json` or `text` |

Outputs:

| Output | Description |
|--------|-------------|
| `finding-count` | Number of secrets found (0 if clean) |
| `report` | Full scan report |
| `exit-code` | Scanner exit code |

#### Pre-Commit Framework

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/raftersecurity/rafter-cli
    rev: v0.6.5
    hooks:
      - id: rafter-scan-node      # auto-installs via npm
      # - id: rafter-scan-python  # auto-installs via pip
      # - id: rafter-scan         # uses system rafter binary
```

This integrates with the [pre-commit](https://pre-commit.com/) framework to scan staged files on every commit. The `rafter-scan-node` and `rafter-scan-python` hooks install the CLI automatically — no global install needed.

### MCP Server

Expose Rafter security tools to **any MCP-compatible client** (Cursor, Windsurf, Claude Desktop, Cline, etc.) over stdio:

```sh
rafter mcp serve
```

Add to any MCP client config:

```json
{
  "rafter": {
    "command": "rafter",
    "args": ["mcp", "serve"]
  }
}
```

**Tools provided:**
- `scan_secrets` — scan files/directories for hardcoded secrets
- `evaluate_command` — check if a shell command is allowed by policy
- `read_audit_log` — read audit log entries with filtering
- `get_config` — read Rafter configuration

**Resources:**
- `rafter://config` — current configuration
- `rafter://policy` — active security policy (merged `.rafter.yml` + config)

### Supported Agents

| Agent | Integration | Detection | Config installed to |
|-------|-------------|-----------|-------------------|
| Claude Code | Hooks + Skills | `~/.claude` | `~/.claude/skills/rafter/` and `rafter-agent-security/` |
| Codex CLI | Skills | `~/.codex` | `~/.agents/skills/rafter/` and `rafter-agent-security/` |
| OpenClaw | Skills | `~/.openclaw` | `~/.openclaw/skills/rafter-security.md` |
| Gemini CLI | MCP server | `~/.gemini` | `~/.gemini/settings.json` |
| Cursor | MCP server | `~/.cursor` | `~/.cursor/mcp.json` |
| Windsurf | MCP server | `~/.codeium/windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | MCP server | `~/.continue` | `~/.continue/config.json` |
| Aider | MCP server | `~/.aider.conf.yml` | `~/.aider.conf.yml` |

`rafter agent init` auto-detects which agents are installed. Use `--with-*` flags or `--all` to install integrations.

**Skill-based agents** (Claude Code, Codex, OpenClaw) get two skills per agent:

- **Rafter Security Audits** — Safe for the agent to auto-invoke (read-only API calls). Triggers remote code analysis, retrieves results.
- **Agent Security** — User-invoked only (local file access, command execution). Secret scanning, command interception, skill auditing, audit log.

**MCP-based agents** (Gemini, Cursor, Windsurf, Continue.dev, Aider) connect to the Rafter MCP server (`rafter mcp serve`), which exposes `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools. See individual setup recipes in [`recipes/`](recipes/).

---

## Exit Codes (Stable Contract)

Exit codes are part of Rafter's output contract — CI pipelines and orchestrators can rely on these semantics across versions.

### Local Secret Scan (`rafter scan local` / `rafter agent scan`)

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Clean — no secrets detected | Proceed |
| 1 | Findings — one or more secrets detected | Stop / review |
| 2 | Runtime error — path not found, invalid ref | Fix input and retry |

### Backend Commands (`rafter run` / `rafter get` / `rafter usage`)

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success — scan completed or results retrieved | Proceed |
| 1 | General error | Investigate |
| 2 | Scan not found | Check scan ID |
| 3 | Quota exhausted | Back off / alert |
| 4 | Insufficient scope / forbidden | Check API key permissions |

## File Locations

```
~/.rafter/
├── config.json        # Configuration
├── audit.jsonl        # Security event log (JSON lines)
├── bin/gitleaks       # Gitleaks binary
├── patterns/          # Custom patterns (reserved)
└── git-hooks/         # Global pre-commit hook (if --global)
```

## Development

This is a pnpm workspace. The Node CLI package lives in `node/`.

```sh
pnpm install          # install all dependencies (from repo root)
cd node && pnpm test  # run the Node test suite
cd node && pnpm build # build the Node CLI
```

Python package is in `python/` — see [`python/README.md`](python/README.md) for setup.

## Documentation

- **Full docs**: [docs.rafter.so](https://docs.rafter.so)
- **Node.js CLI**: See [`node/README.md`](node/README.md) for complete command reference
- **Python CLI**: See [`python/README.md`](python/README.md)
- **CLI Spec**: See [`shared-docs/CLI_SPEC.md`](shared-docs/CLI_SPEC.md) for flags and output formats

## License

[MIT](LICENSE)
