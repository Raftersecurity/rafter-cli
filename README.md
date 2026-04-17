# Rafter CLI

[![npm version](https://img.shields.io/npm/v/@rafter-security/cli)](https://www.npmjs.com/package/@rafter-security/cli) [![PyPI version](https://img.shields.io/pypi/v/rafter-cli)](https://pypi.org/project/rafter-cli/) [![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/raftercli/rafter) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<p>
  <a href="#supported-platforms"><img alt="Claude Code supported" src="https://img.shields.io/badge/Claude%20Code-supported-d97757?style=flat&labelColor=141413&logo=claude&logoColor=faf9f5"></a>
  <a href="#supported-platforms"><img alt="Codex supported" src="https://img.shields.io/badge/Codex-supported-f5f5f5?style=flat&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyBpZD0iTGF5ZXJfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB2ZXJzaW9uPSIxLjEiIHZpZXdCb3g9IjAgMCAxNTguNzEyOCAxNTcuMjk2Ij4KICA8IS0tIEdlbmVyYXRvcjogQWRvYmUgSWxsdXN0cmF0b3IgMjkuMi4xLCBTVkcgRXhwb3J0IFBsdWctSW4gLiBTVkcgVmVyc2lvbjogMi4xLjAgQnVpbGQgMTE2KSAgLS0%2BCiAgPHBhdGggZmlsbD0iI0ZGRkZGRiIgZD0iTTYwLjg3MzQsNTcuMjU1NnYtMTQuOTQzMmMwLTEuMjU4Ni40NzIyLTIuMjAyOSwxLjU3MjgtMi44MzE0bDMwLjA0NDMtMTcuMzAyM2M0LjA4OTktMi4zNTkzLDguOTY2Mi0zLjQ1OTksMTMuOTk4OC0zLjQ1OTksMTguODc1OSwwLDMwLjgzMDcsMTQuNjI4OSwzMC44MzA3LDMwLjIwMDYsMCwxLjEwMDcsMCwyLjM1OTMtLjE1OCwzLjYxNzhsLTMxLjE0NDYtMTguMjQ2N2MtMS44ODcyLTEuMTAwNi0zLjc3NTQtMS4xMDA2LTUuNjYyOSwwbC0zOS40ODEyLDIyLjk2NTFaTTEzMS4wMjc2LDExNS40NTYxdi0zNS43MDc0YzAtMi4yMDI4LS45NDQ2LTMuNzc1Ni0yLjgzMTgtNC44NzYzbC0zOS40ODEtMjIuOTY1MSwxMi44OTgyLTcuMzkzNGMxLjEwMDctLjYyODUsMi4wNDUzLS42Mjg1LDMuMTQ1OCwwbDMwLjA0NDEsMTcuMzAyNGM4LjY1MjMsNS4wMzQxLDE0LjQ3MDgsMTUuNzI5NiwxNC40NzA4LDI2LjExMDcsMCwxMS45NTM5LTcuMDc2OSwyMi45NjUtMTguMjQ2MSwyNy41Mjd2LjAwMjFaTTUxLjU5Myw4My45OTY0bC0xMi44OTgyLTcuNTQ5N2MtMS4xMDA3LS42Mjg1LTEuNTcyOC0xLjU3MjgtMS41NzI4LTIuODMxNHYtMzQuNjA0OGMwLTE2LjgzMDMsMTIuODk4Mi0yOS41NzIyLDMwLjM1ODUtMjkuNTcyMiw2LjYwNywwLDEyLjc0MDMsMi4yMDI5LDE3LjkzMjQsNi4xMzQ5bC0zMC45ODcsMTcuOTMyNGMtMS44ODcxLDEuMTAwNy0yLjgzMTQsMi42NzM1LTIuODMxNCw0Ljg3NjR2NDUuNjE1OWwtLjAwMTQtLjAwMTVaTTc5LjM1NjIsMTAwLjA0MDNsLTE4LjQ4MjktMTAuMzgxMXYtMjIuMDIwOWwxOC40ODI5LTEwLjM4MTEsMTguNDgxMiwxMC4zODExdjIyLjAyMDlsLTE4LjQ4MTIsMTAuMzgxMVpNOTEuMjMxOSwxNDcuODU5MWMtNi42MDcsMC0xMi43NDAzLTIuMjAzMS0xNy45MzI0LTYuMTM0NGwzMC45ODY2LTE3LjkzMzNjMS44ODcyLTEuMTAwNSwyLjgzMTgtMi42NzI4LDIuODMxOC00Ljg3NTl2LTQ1LjYxNmwxMy4wNTY0LDcuNTQ5OGMxLjEwMDUuNjI4NSwxLjU3MjMsMS41NzI4LDEuNTcyMywyLjgzMTR2MzQuNjA1MWMwLDE2LjgyOTctMTMuMDU2NCwyOS41NzIzLTMwLjUxNDcsMjkuNTcyM3YuMDAxWk01My45NTIyLDExMi43ODIybC0zMC4wNDQzLTE3LjMwMjRjLTguNjUyLTUuMDM0My0xNC40NzEtMTUuNzI5Ni0xNC40NzEtMjYuMTEwNywwLTEyLjExMTksNy4yMzU2LTIyLjk2NTIsMTguNDAzLTI3LjUyNzJ2MzUuODYzNGMwLDIuMjAyOC45NDQzLDMuNzc1NiwyLjgzMTQsNC44NzYzbDM5LjMyNDgsMjIuODA2OC0xMi44OTgyLDcuMzkzOGMtMS4xMDA3LjYyODctMi4wNDUuNjI4Ny0zLjE0NTYsMFpNNTIuMjIyOSwxMzguNTc5MWMtMTcuNzc0NSwwLTMwLjgzMDYtMTMuMzcxMy0zMC44MzA2LTI5Ljg4NzEsMC0xLjI1ODUuMTU3OC0yLjUxNjkuMzE0My0zLjc3NTRsMzAuOTg3LDE3LjkzMjNjMS44ODcxLDEuMTAwNSwzLjc3NTcsMS4xMDA1LDUuNjYyOCwwbDM5LjQ4MTEtMjIuODA3djE0Ljk0MzVjMCwxLjI1ODUtLjQ3MjEsMi4yMDIxLTEuNTcyOCwyLjgzMDhsLTMwLjA0NDMsMTcuMzAyNWMtNC4wODk4LDIuMzU5LTguOTY2MiwzLjQ2MDUtMTMuOTk4OSwzLjQ2MDVoLjAwMTRaTTkxLjIzMTksMTU3LjI5NmMxOS4wMzI3LDAsMzQuOTE4OC0xMy41MjcyLDM4LjUzODMtMzEuNDU5NCwxNy42MTY0LTQuNTYyLDI4Ljk0MjUtMjEuMDc3OSwyOC45NDI1LTM3LjkwOCwwLTExLjAxMTItNC43MTktMjEuNzA2Ni0xMy4yMTMzLTI5LjQxNDMuNzg2Ny0zLjMwMzUsMS4yNTk1LTYuNjA3LDEuMjU5NS05LjkwOSwwLTIyLjQ5MjktMTguMjQ3MS0zOS4zMjQ3LTM5LjMyNTEtMzkuMzI0Ny00LjI0NjEsMC04LjMzNjMuNjI4NS0xMi40MjYyLDIuMDQ1LTcuMDc5Mi02LjkyMTMtMTYuODMxOC0xMS4zMjU0LTI3LjUyNzEtMTEuMzI1NC0xOS4wMzMxLDAtMzQuOTE5MSwxMy41MjY4LTM4LjUzODQsMzEuNDU5MUMxMS4zMjU1LDM2LjAyMTIsMCw1Mi41MzczLDAsNjkuMzY3NWMwLDExLjAxMTIsNC43MTg0LDIxLjcwNjUsMTMuMjEyNSwyOS40MTQyLS43ODY1LDMuMzAzNS0xLjI1ODYsNi42MDY3LTEuMjU4Niw5LjkwOTIsMCwyMi40OTIzLDE4LjI0NjYsMzkuMzI0MSwzOS4zMjQ4LDM5LjMyNDEsNC4yNDYyLDAsOC4zMzYyLS42Mjc3LDEyLjQyNi0yLjA0NDEsNy4wNzc2LDYuOTIxLDE2LjgzMDIsMTEuMzI1MSwyNy41MjcxLDExLjMyNTFaIi8%2BCjwvc3ZnPg%3D%3D"></a>
  <a href="#supported-platforms"><img alt="Gemini CLI supported" src="https://img.shields.io/badge/Gemini%20CLI-supported-4285f4?style=flat&labelColor=202124&logo=googlegemini&logoColor=8e75b2"></a>
  <a href="#supported-platforms"><img alt="OpenCode supported" src="https://img.shields.io/badge/OpenCode-supported-cfcecd?style=flat&labelColor=565656&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAABzUlEQVR4AeycQQrCQBAEF1%2Bg6J%2F0o5LPCXmCnnNx0E2nNqGEPciw024VffV0PZ%2FfHo7BqflBCSgAxd%2BaAhQAE4DjbYACYAJwvA1QAEwAjrcBCgAIDBRpA2AZClAATACOtwEKgAnA8TZAATABOD7egNc8tz2ftJ%2B4gPQD9r5fAbDBDQXALx00XgGwGAUoACYAx9sABcAE4HgboACYABxvAxSwJHC7XFryLNP4bzYg7KBar4CKUHiugDDgar0CKkLhuQLCgKv1CqgIhecKCAOu1iugIhSeKyAMuFqvgIpQeK6AMOBq%2FXAC7o9H6z5fdlRAtp4PJ2BrAHSeAmADClAATACOtwEKgAnA8TZAATABON4GKAAmAMev2AD4JTuNVwAsTgEKgAnA8TZAATABON4GKAAmAMfbAAXABOB4G9ApoPe6AnoJdt5XQCfA3uvDCXhOU0ueXmBr3x9OwNoPHH2fAmBDClAATACOtwEKgAnA8TZAAX8QONAVGwDLVIACYAJwfLwByf%2F%2B2WJ32k9cQPoBe9%2BvANigAhQAE4DjbYACYAJw%2FA8NgH%2FpQeMVAItVgAJgAnC8DVAATACOtwEKgAnA8TZAATABON4GFALS4w8AAAD%2F%2Fx7wkLQAAAAGSURBVAMAKj5LkLSa6SQAAAAASUVORK5CYII%3D"></a>
  <a href="#supported-platforms"><img alt="OpenClaw supported" src="https://img.shields.io/badge/OpenClaw-supported-e8662a?style=flat&labelColor=1a1a1a"></a>
  <a href="#supported-platforms"><img alt="Cursor supported" src="https://img.shields.io/badge/Cursor-supported-d4d4d4?style=flat&labelColor=1c1c1c&logo=cursor&logoColor=white"></a>
  <a href="#supported-platforms"><img alt="Windsurf supported" src="https://img.shields.io/badge/Windsurf-supported-00c4b4?style=flat&labelColor=0a0a0a"></a>
  <a href="#supported-platforms"><img alt="Continue.dev supported" src="https://img.shields.io/badge/Continue.dev-supported-7c3aed?style=flat&labelColor=1e1b2e"></a>
  <a href="#supported-platforms"><img alt="Aider supported" src="https://img.shields.io/badge/Aider-supported-10b981?style=flat&labelColor=111827"></a>
</p>

Multi-language CLI for [Rafter](https://rafter.so) — the security toolkit built for AI coding agents and the developers who use them.

> **Free forever for individuals and open source. No account required. No telemetry.**
>
> All local security features work with zero setup — no API key, no sign-up, no usage limits.
> Enterprise teams that need advanced analysis and policy management can upgrade later.

Rafter is a **security primitive** that any developer or agent can call and trust. Stable contracts, deterministic results, and structured output mean you can pipe findings to `jq`, feed them to an orchestrator, or read them yourself. **AI agents are first-class users** — every command is designed for programmatic consumption, and the entire codebase welcomes agent-assisted contributions.

**Two capabilities in one package:**

1. **Local Security Toolkit** (free, no account) — Fast secret scanning (21+ built-in patterns, deterministic for a given version), policy enforcement with risk-tiered rules, pre-commit hooks, extension auditing, custom rule authoring, and full audit logging. Works offline. **No API key. No telemetry. No data leaves your machine.** Supports Claude Code, Codex CLI, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, and Aider.

2. **Remote Code Analysis** — Deep security audits that combine agentic analysis with a full SAST/SCA toolchain. Rafter's engine examines your codebase the way a professional penetration tester would — tracing data flows, reasoning about business logic, and surfacing vulnerabilities that static rules alone miss — then cross-references findings with industry-standard SAST, SCA, and secret-detection tools. Structured reports in JSON or Markdown. Pipe to any tool, feed to any workflow.

The CLI follows UNIX principles and provides a **stable output contract**: scan results to stdout as JSON, status to stderr, documented exit codes. No code leaves your machine unless you explicitly use the remote API, and is deleted immediately after analysis completes. Any developer can classify outcomes (clean / findings / retryable error / fatal error) and act without reading prose.

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
| Remote SAST/SCA/Agentic analysis (API) | Free tier | Higher limits |
| Dashboards ([rafter.so](https://rafter.so)) | **Yes** | Yes |

No account. No telemetry. No data collection. The CLI is MIT-licensed and all local features work without network access.

---

## Installation

### Node.js (full features: local security + remote analysis)

```sh
npm install -g @rafter-security/cli
# or
pnpm add -g @rafter-security/cli
```

### Python (full features)

```sh
pip install rafter-cli
```

Requires Python 3.10+. Full feature parity with Node.js including local security toolkit and MCP server.

---

## Remote Code Analysis

Agentic security audits backed by a full SAST/SCA toolchain, via the Rafter API. The analysis engine examines your codebase the way a professional cybersecurity auditor would — following data flows across files, reasoning about authentication and authorization logic, and identifying vulnerabilities that pattern-matching alone cannot catch — then validates and enriches findings with industry-standard static analysis, dependency scanning, and secret detection. Runs against the **remote repository** on GitHub, not local files. Your code is deleted immediately after analysis completes. Auto-detection uses your local Git config to determine which repo and branch to analyze.

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
| `-a, --agent` | Plain output (no colors, no emoji). Useful when piping to other tools or automated systems. |

## Local Security Toolkit — Free, No Account Required

Security features that run on your machine. Everything below works offline — **no API key, no sign-up, no telemetry, no usage limits.** Free forever for individuals and open source.

Every developer gets the same policies and the same deterministic output.

**Trust guarantees:** No code leaves your machine unless you explicitly use the remote API. Secrets are redacted in all output — logs, JSON, and human-readable formats. No data is collected or phoned home.

### Setup

```sh
rafter agent init --all                    # install all detected integrations
rafter agent init --with-claude-code       # or install specific ones
rafter agent init --local                  # write config to ./.rafter (not ~/.rafter)
rafter agent list                          # show detected integrations + status
rafter agent enable claude-code            # opt a single platform in
rafter agent disable gemini                # opt a single platform out
```

This command:
- Creates `~/.rafter/` config and audit log (or `./.rafter/` with `--local` for ephemeral / containerized / benchmark setups)
- Auto-detects Claude Code, Codex CLI, OpenClaw, Gemini, Cursor, Windsurf, Continue.dev, and Aider
- With `--with-*` or `--all`: installs Rafter skills/extensions to opted-in agents
- With `--with-gitleaks` or `--all`: downloads [Gitleaks](https://github.com/gitleaks/gitleaks) for enhanced secret scanning (falls back to built-in 21-pattern regex scanner)

Use `rafter agent list/enable/disable` for granular per-component control after the initial install — toggle any platform on or off without re-running `init`.

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
    rev: v0.7.1
    hooks:
      - id: rafter-scan-node
```

Requires `rafter` in PATH (install via `npm i -g @rafter-security/cli` or `pip install rafter-cli`).

### Policy Enforcement

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

### Skills — Install, Audit, Manage

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

### Audit Log

Every security-relevant event is logged to `~/.rafter/audit.jsonl` in JSON-lines format. Each entry carries a `prevHash` forming a SHA-256 chain, plus the `cwd` and enclosing `gitRepo` where the event was recorded — so tampering, truncation, and out-of-context replays are all detectable.

```sh
rafter agent audit                           # last 10 entries
rafter agent audit --last 20                 # last 20
rafter agent audit --event secret_detected   # filter by type
rafter agent audit --since 2026-02-01        # filter by date
rafter agent audit --verify                  # verify hash chain (exit 1 if tampered)
```

Event types: `command_intercepted`, `secret_detected`, `content_sanitized`, `policy_override`, `scan_executed`, `config_changed`.

Point the log at a repo-local path by setting `agent.audit.logPath` in `.rafter.yml` (e.g. `.rafter/audit.jsonl`) so every contributor can verify their own chain independently. Retention pruning rewrites the log atomically and re-seals the chain, preserving a sidecar manifest (`audit.jsonl.retention.log`) that records the hashes of pruned entries — verify still passes after legitimate cleanup, and fails on forgery.

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

### Custom Rules

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
rafter ci init --with-remote            # include remote security audit job
```

#### GitHub Action

Use as a reusable action in any GitHub Actions workflow:

```yaml
- uses: raftersecurity/rafter-cli@v1
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
    rev: v0.7.1
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

### Supported Platforms

| Platform | Integration | Detection | Config installed to |
|-------|-------------|-----------|-------------------|
| Claude Code | Hooks + Skills | `~/.claude` | `~/.claude/skills/rafter/` and `rafter-agent-security/` |
| Codex CLI | Skills | `~/.codex` | `~/.agents/skills/rafter/` and `rafter-agent-security/` |
| OpenClaw | Skills | `~/.openclaw` | `~/.openclaw/skills/rafter-security.md` |
| Gemini CLI | MCP server | `~/.gemini` | `~/.gemini/settings.json` |
| Cursor | MCP server | `~/.cursor` | `~/.cursor/mcp.json` |
| Windsurf | MCP server | `~/.codeium/windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | MCP server | `~/.continue` | `~/.continue/config.json` |
| Aider | MCP server | `~/.aider.conf.yml` | `~/.aider.conf.yml` |

`rafter agent init` auto-detects which platforms are installed. Use `--with-*` flags or `--all` to install integrations.

**Skill-based platforms** (Claude Code, Codex, OpenClaw) get the full Rafter skill set:

- **`rafter`** — CYOA router for detection (remote + local scanning, audit log, policy).
- **`rafter-code-review`** — Structured OWASP / MITRE / ASVS walkthrough during PR review or refactoring.
- **`rafter-secure-design`** — Shift-left threat modeling at feature kickoff (auth, data, API, ingestion, deployment, dependencies).
- **`rafter-skill-review`** — Guided review of third-party skills before install.

Install, remove, or audit them at any time with `rafter skill list/install/uninstall/review`.

**MCP-based platforms** (Gemini, Cursor, Windsurf, Continue.dev, Aider) connect to the Rafter MCP server (`rafter mcp serve`), which exposes `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools. See individual setup recipes in [`recipes/`](recipes/).

---

## Exit Codes (Stable Contract)

Exit codes are part of Rafter's output contract — CI pipelines and orchestrators can rely on these semantics across versions.

### Local Secret Scan (`rafter scan local` / `rafter agent scan`)

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Clean — no secrets detected | Proceed |
| 1 | Findings — one or more secrets detected | Stop / review |
| 2 | Runtime error — path not found, invalid ref | Fix input and retry |

### Remote Commands (`rafter run` / `rafter get` / `rafter usage`)

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

## Badges

Show that your project is protected by Rafter. Add one of these badges to your README:

[![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/raftercli/rafter) [![Rafter policy: enforced](https://img.shields.io/badge/rafter_policy-enforced-2ea44f)](https://github.com/raftercli/rafter)

**Markdown (copy-paste):**

```markdown
[![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/raftercli/rafter)
```

```markdown
[![Rafter policy: enforced](https://img.shields.io/badge/rafter_policy-enforced-2ea44f)](https://github.com/raftercli/rafter)
```

More badge variants (HTML, reStructuredText) available in [`badges/`](badges/).

## License

[MIT](LICENSE)
