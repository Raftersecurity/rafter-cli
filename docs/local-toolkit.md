# Local Security Toolkit

[← Back to README](../README.md)

Security features that run on your machine. Everything below works offline — **no API key, no sign-up, no telemetry, no usage limits.** Free forever for individuals and open source.

Every developer gets the same policies and the same deterministic output.

**Trust guarantees:** No code leaves your machine unless you explicitly use the remote API. Secrets are redacted in all output — logs, JSON, and human-readable formats. No data is collected or phoned home.

## Contents

- [Setup](#setup)
- [Secret scanning](#secret-scanning)
- [Pre-commit hook](#pre-commit-hook)
- [Policy enforcement](#policy-enforcement)
- [Skills](#skills--install-audit-manage)
- [Audit log](#audit-log)
- [Configuration](#configuration)
- [Custom rules](#custom-rules)
- [Policy file (`.rafter.yml`)](#policy-file-rafteryml)
- [CI/CD setup](#cicd-setup)
- [MCP server](#mcp-server)

## Setup

```sh
rafter agent init --all                    # install all detected integrations
rafter agent init --with-claude-code       # or install specific ones
rafter agent init --local                  # write config to ./.rafter (not ~/.rafter)
rafter agent init --interactive            # guided prompts for each detected integration
rafter agent init --dry-run                # preview every path that would be touched
rafter agent list                          # show detected integrations + status
rafter agent enable claude-code            # opt a single platform in
rafter agent disable gemini                # opt a single platform out
```

This command:

- Creates `~/.rafter/` config and audit log (or `./.rafter/` with `--local` for ephemeral / containerized / benchmark setups)
- Auto-detects Claude Code, Codex CLI, OpenClaw, Gemini, Cursor, Windsurf, Continue.dev, and Aider
- With `--with-*` or `--all`: installs Rafter skills/extensions to opted-in agents
- With `--with-betterleaks` or `--all`: downloads [Betterleaks](https://github.com/betterleaks/betterleaks) (the gitleaks successor maintained by the original gitleaks authors) for enhanced secret scanning. Falls back to built-in 21-pattern regex scanner.

Available `--with-*` flags: `--with-claude-code`, `--with-codex`, `--with-openclaw`, `--with-gemini`, `--with-cursor`, `--with-windsurf`, `--with-continue`, `--with-aider`, `--with-betterleaks`.

Use `rafter agent list/enable/disable` for granular per-component control after the initial install — toggle any platform on or off without re-running `init`.

## Secret scanning

Fast, reliable, and deterministic for a given CLI version. 21+ built-in patterns covering AWS, GitHub, Google, Slack, Stripe, Twilio, database connection strings, JWTs, private keys, npm/PyPI tokens, and generic API keys. Same inputs produce the same findings — no flaky CI, no phantom alerts.

```sh
rafter secrets .                  # scan directory
rafter secrets ./config.js        # scan specific file
rafter secrets --staged           # scan git staged files only
rafter secrets --diff HEAD~1      # scan files changed since a git ref
rafter secrets --history          # scan full git history (requires betterleaks engine)
rafter secrets --json             # structured output (alias for --format json)
rafter secrets --format sarif     # SARIF 2.1.0 for GitHub/GitLab code-scanning
rafter secrets --quiet            # silent unless secrets found (CI-friendly)
rafter secrets --baseline         # suppress findings present in saved baseline
rafter secrets --watch            # re-scan on file change
```

Exit code 1 if secrets found, 0 if clean, 2 on runtime error.

**Structured output (`--json`):**

```json
[
  {
    "file": "/path/to/config.js",
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

Raw secret values are never included in output. Pipe to `jq`, feed to CI gates, or hand to any tool that reads JSON.

**Engine selection:** Uses Betterleaks when available (more patterns), falls back to built-in regex. Override with `--engine betterleaks|patterns|auto`.

## Pre-commit hook

Automatically scan staged files before every `git commit`. The most effective way to prevent secrets from entering version control.

```sh
rafter agent install-hook           # current repo only
rafter agent install-hook --global  # all repos on this machine
rafter agent install-hook --push    # install pre-push hook instead of pre-commit
```

Blocks commits when secrets are detected. Bypass with `git commit --no-verify` (not recommended).

### pre-commit framework

Rafter works as a [pre-commit](https://pre-commit.com) hook. Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Raftersecurity/rafter-cli
    rev: v0.7.9
    hooks:
      - id: rafter-scan-node      # auto-installs via npm
      # - id: rafter-scan-python  # auto-installs via pip
      # - id: rafter-scan         # uses system rafter binary
```

The `rafter-scan-node` and `rafter-scan-python` hooks install the CLI automatically — no global install needed. The `rafter-scan` hook requires `rafter` in `PATH`.

## Policy enforcement

Execute shell commands through a risk-assessment layer. Route commands through `rafter agent exec` to enforce policy on destructive operations — whether the command comes from a script, a CI job, or an AI agent.

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

## Skills — install, audit, manage

**Treat third-party agent skill ecosystems as hostile by default.** There have been reports of malware distributed through AI agent skill marketplaces, using social-engineering instructions to run obfuscated shell commands.

Rafter ships four first-party skills you can install into any supported agent:

| Skill | When to use |
|-------|-------------|
| `rafter` | CYOA router — detection (`rafter scan` / `rafter run`) and day-to-day usage |
| `rafter-code-review` | OWASP / MITRE / ASVS-style structured code review during PR / refactor |
| `rafter-secure-design` | Shift-left design-phase threat modeling at feature kickoff |
| `rafter-skill-review` | Guided security review of third-party skills before install |

```sh
rafter skill list                              # show installed + available skills
rafter skill install rafter-code-review        # install one
rafter skill install --all                     # install all four
rafter skill uninstall rafter-secure-design    # remove one
```

**Auditing untrusted skills** (preferred over deprecated `rafter agent audit-skill`):

```sh
rafter skill review ./path/to/skill           # local file or directory
rafter skill review github:owner/repo         # remote shorthand (also gitlab:, npm:)
rafter skill review --installed               # audit every skill already on disk
rafter skill review --installed --summary     # terse table across all agents
```

**Quick scan** (deterministic, runs instantly): detects embedded secrets, external URLs, high-risk commands (`curl|sh`, `eval()`, `base64|sh`, fork bombs), obfuscation signals, and binary/suspicious file inventory. Every finding includes file, line, rule ID, and a concrete fix hint.

**Persistent cache** for remote shorthands (`github:`, `gitlab:`, `npm:`) keeps repeated reviews fast — tune with `--cache-ttl 1h` or bypass via `--no-cache`.

**Deep analysis** (via OpenClaw, if installed): 12-dimension security review covering trust/attribution, network security, command execution, file system access, credential handling, input validation, data exfiltration, obfuscation, scope alignment, error handling, dependencies, and environment manipulation. Without OpenClaw, generates an LLM-ready review prompt you can paste into any model.

## Audit log

Every security-relevant event is logged to `~/.rafter/audit.jsonl` in JSON-lines format. Each entry carries a `prevHash` forming a SHA-256 chain, plus the `cwd` and enclosing `gitRepo` where the event was recorded — so tampering, truncation, and out-of-context replays are all detectable.

```sh
rafter agent audit                           # last 10 entries
rafter agent audit --last 20                 # last 20
rafter agent audit --event secret_detected   # filter by type
rafter agent audit --agent claude-code       # filter by agent type
rafter agent audit --since 2026-02-01        # filter by date
rafter agent audit --repo my-repo            # filter by git repo path (substring)
rafter agent audit --cwd /some/path          # filter by cwd (substring)
rafter agent audit --share                   # redacted excerpt for issue reports
rafter agent audit --verify                  # verify hash chain (exit 1 if tampered)
```

Event types: `command_intercepted`, `secret_detected`, `content_sanitized`, `policy_override`. `scan_executed` and `config_changed` are reserved for future use (defined in the type union but not yet emitted).

Point the log at a repo-local path by setting `agent.audit.logPath` in `.rafter.yml` (e.g. `.rafter/audit.jsonl`) so every contributor can verify their own chain independently. Retention pruning rewrites the log atomically and re-seals the chain, preserving a sidecar manifest (`audit.jsonl.retention.log`) that records the hashes of pruned entries — verify still passes after legitimate cleanup, and fails on forgery.

## Configuration

```sh
rafter agent config show                                    # view all settings
rafter agent config get agent.riskLevel                     # read a value
rafter agent config set agent.riskLevel aggressive          # write a value
rafter agent config set agent.commandPolicy.mode deny-list  # dot-notation paths
```

**Risk levels:** `minimal` (guidance only) · `moderate` (default, approval for dangerous ops) · `aggressive` (approval for most ops)

**Command policies:** `allow-all` · `approve-dangerous` (default) · `deny-list`

Config lives at `~/.rafter/config.json`. Project-level overrides via `.rafter.yml` (see below).

## Custom rules

Define your own secret patterns alongside the 21+ built-in ones. Add them to `.rafter.yml` in your project root:

```yaml
# .rafter.yml
scan:
  custom_patterns:
    - name: "Internal API Key"
      regex: "INTERNAL_[A-Z0-9]{32}"
      severity: critical
      description: "Detects internal service API keys"
    - name: "Acme Corp Token"
      regex: "acme_live_[a-zA-Z0-9]{40}"
      severity: high
```

Custom patterns are merged with built-in patterns at scan time. They appear in JSON output, audit logs, and pre-commit hooks — no difference from built-in rules.

## Policy file (`.rafter.yml`)

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

## CI/CD setup

Generate CI pipeline config for secret scanning:

```sh
rafter ci init                          # auto-detect platform
rafter ci init --platform github        # GitHub Actions
rafter ci init --platform gitlab        # GitLab CI
rafter ci init --platform circleci      # CircleCI
rafter ci init --with-remote            # include remote security audit job
```

### GitHub Action

Use as a reusable action in any GitHub Actions workflow:

```yaml
- uses: Raftersecurity/rafter-cli@v1
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
| `args` | `--quiet` | Additional args to `rafter secrets` |
| `version` | `latest` | CLI version to install |
| `install-method` | `npm` | `npm` or `pip` |
| `format` | `json` | Output format: `json` or `text` |

Outputs:

| Output | Description |
|--------|-------------|
| `finding-count` | Number of secrets found (0 if clean) |
| `report` | Full scan report |
| `exit-code` | Scanner exit code |

## MCP server

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

## See also

- [README](../README.md) — top-level overview
- [docs/remote-analysis.md](remote-analysis.md) — `rafter run` against the API
- [docs/supported-platforms.md](supported-platforms.md) — agent IDE integrations
- [docs/exit-codes.md](exit-codes.md) — exit-code contract
- [docs/file-locations.md](file-locations.md) — where Rafter writes config and logs
- [`shared-docs/CLI_SPEC.md`](../shared-docs/CLI_SPEC.md) — full output contract
