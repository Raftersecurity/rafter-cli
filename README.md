# Rafter CLI

Multi-language CLI for [Rafter](https://rafter.so) — zero-setup security for AI builders.

**Two things in one package:**

1. **Rafter Security Audits** — Trigger remote SAST/SCA scans on GitHub repos via the Rafter API. Get structured vulnerability reports in JSON or Markdown, pipe them anywhere.

2. **Agent Security** — Local-first protection for autonomous AI agents. Secret scanning (21+ patterns, Gitleaks integration), command interception with risk-tiered approval, pre-commit hooks, skill/extension auditing, and full audit logging. Works with Claude Code, Codex CLI, and OpenClaw. **No API key required.**

The CLI follows UNIX principles: scan data to stdout, status to stderr, predictable exit codes, no file writing. Everything pipes cleanly.

## Installation

### Node.js (full features: backend + agent security)

```sh
npm install -g @rafter-security/cli
# or
pnpm add -g @rafter-security/cli
```

### Python (backend scanning only)

```sh
pip install rafter-cli
```

Requires Python 3.10+. For agent security features, use the Node.js package.

---

## Rafter Security Audits

Remote SAST/SCA scanning via the Rafter API. Analyzes the **remote repository** on GitHub, not local files. Auto-detection uses your local Git config to determine which repo and branch to scan.

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
# Filter critical vulnerabilities
rafter get SCAN_ID --format json | jq '.vulnerabilities[] | select(.level=="critical")'

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

## Agent Security

Local security features for autonomous AI agents. Everything below works offline, no API key needed.

### Setup

```sh
rafter agent init
```

This single command:
- Creates `~/.rafter/` config and audit log
- Auto-detects Claude Code, Codex CLI, and OpenClaw
- Installs Rafter skills/extensions to each detected agent
- Downloads [Gitleaks](https://github.com/gitleaks/gitleaks) for enhanced secret scanning (falls back to built-in 21-pattern regex scanner)

### Secret Scanning

Scan files and directories for leaked credentials. 21+ built-in patterns covering AWS, GitHub, Google, Slack, Stripe, Twilio, database connection strings, JWTs, private keys, npm/PyPI tokens, and generic API keys.

```sh
rafter agent scan .              # scan directory
rafter agent scan ./config.js    # scan specific file
rafter agent scan --staged       # scan git staged files only
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

**Quick scan** (deterministic, runs instantly): detects embedded secrets, external URLs, and high-risk commands (`curl|sh`, `eval()`, `base64|sh`, fork bombs, etc.).

**Deep analysis** (via OpenClaw, if installed): 12-dimension security review covering trust/attribution, network security, command execution, file system access, credential handling, input validation, data exfiltration, obfuscation, scope alignment, error handling, dependencies, and environment manipulation.

Without OpenClaw, generates an LLM-ready review prompt you can paste into any model.

### Audit Log

Every security-relevant event is logged to `~/.rafter/audit.log` in JSON-lines format.

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

Config lives at `~/.rafter/config.json`.

### Supported Agents

| Agent | Detection | Skills installed to |
|-------|-----------|-------------------|
| Claude Code | `~/.claude` | `~/.claude/skills/rafter/` and `rafter-agent-security/` |
| Codex CLI | `~/.codex` | `~/.agents/skills/rafter/` and `rafter-agent-security/` |
| OpenClaw | `~/.openclaw` | `~/.openclaw/skills/rafter-security.md` |

`rafter agent init` auto-detects which agents are installed and installs the appropriate skills. Two skills per agent:

- **Rafter Security Audits** — Safe for the agent to auto-invoke (read-only API calls). Triggers remote scans, retrieves results.
- **Agent Security** — User-invoked only (local file access, command execution). Secret scanning, command interception, skill auditing, audit log.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / secrets found |
| 2 | Scan not found |
| 3 | Quota exhausted |

## File Locations

```
~/.rafter/
├── config.json        # Configuration
├── audit.log          # Security event log (JSON lines)
├── bin/gitleaks       # Gitleaks binary
├── patterns/          # Custom patterns (reserved)
└── git-hooks/         # Global pre-commit hook (if --global)
```

## Documentation

- **Full docs**: [docs.rafter.so](https://docs.rafter.so)
- **Node.js CLI**: See [`node/README.md`](node/README.md) for complete command reference
- **Python CLI**: See [`python/README.md`](python/README.md)
- **CLI Spec**: See [`shared-docs/CLI_SPEC.md`](shared-docs/CLI_SPEC.md) for flags and output formats

## License

[MIT](LICENSE)
