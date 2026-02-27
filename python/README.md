# rafter-cli (Python)

Python CLI for [Rafter](https://rafter.so) — zero-setup security for AI builders. Full feature parity with the Node.js package.

**Backend scanning** — Remote SAST/SCA via Rafter API. Trigger scans, retrieve structured vulnerability reports, pipe to any tool.

**Agent security** — Local-first protection for autonomous AI agents. Secret scanning (21+ patterns, Gitleaks), command interception with risk-tiered approval, pre-commit hooks, pretool hooks, and full audit logging. Works with Claude Code, Codex CLI, and OpenClaw. No API key required.

**MCP server** — Expose Rafter security tools to any MCP-compatible client (Cursor, Windsurf, Claude Desktop, Cline) over stdio.

## Installation

```bash
pip install rafter-cli
```

Requires Python 3.10+.

## Quick Start

### Backend Scanning

```bash
export RAFTER_API_KEY="your-key"   # or add to .env file

rafter run                                    # scan current repo (auto-detected)
rafter scan --repo myorg/myrepo --branch main # scan specific repo
rafter get SCAN_ID                            # retrieve results
rafter get SCAN_ID --interactive              # poll until complete
rafter usage                                  # check quota
```

**Important**: The scanner analyzes the **remote repository** on GitHub, not your local files.

### Agent Security

```bash
rafter agent init                # initialize + auto-detect agents
rafter scan local .              # scan for secrets
rafter scan local --diff HEAD~1  # scan changed files
rafter agent exec "git commit"   # execute with risk assessment
rafter agent audit               # view security logs
rafter agent config show         # view configuration
```

### Pretool Hooks (Claude Code)

```bash
rafter agent init --claude-code  # install PreToolUse hooks
rafter hook pretool              # hook handler (reads stdin, writes decision)
rafter policy export --format claude  # export hook config
```

### MCP Server

```bash
rafter mcp serve                 # start MCP server over stdio
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

**Tools:** `scan_secrets`, `evaluate_command`, `read_audit_log`, `get_config`
**Resources:** `rafter://config`, `rafter://policy`

## Commands

### `rafter run [options]`

Alias: `rafter scan`

Trigger a new security scan for your repository.

- `-r, --repo <repo>` — org/repo (default: auto-detected from git remote)
- `-b, --branch <branch>` — branch (default: current branch or 'main')
- `-k, --api-key <key>` — API key (or `RAFTER_API_KEY` env var)
- `-f, --format <format>` — `json` or `md` (default: `md`)
- `--skip-interactive` — don't wait for scan completion
- `--quiet` — suppress status messages

### `rafter get <scan-id> [options]`

Retrieve results from a scan.

- `-k, --api-key <key>` — API key
- `-f, --format <format>` — `json` or `md` (default: `md`)
- `--interactive` — poll until scan completes
- `--quiet` — suppress status messages

### `rafter usage [options]`

Check API quota and usage.

- `-k, --api-key <key>` — API key

### `rafter mcp serve [options]`

Start MCP server over stdio transport.

- `--transport <type>` — Transport type (default: `stdio`)

### `rafter hook pretool`

PreToolUse hook handler. Reads tool input JSON from stdin, writes decision to stdout.

### `rafter policy export [options]`

Export Rafter policy for agent platforms.

- `--format <type>` — Target format: `claude` or `codex`
- `--output <path>` — Write to file instead of stdout

## Piping and Automation

```bash
# Filter critical vulnerabilities
rafter get SCAN_ID --format json | jq '.vulnerabilities[] | select(.level=="critical")'

# CI gate
if rafter get SCAN_ID --format json | jq -e '.vulnerabilities | length > 0'; then
    echo "Vulnerabilities found!" && exit 1
fi
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / secrets found |
| 2 | Scan not found |
| 3 | Quota exhausted |

## Documentation

Full docs at [docs.rafter.so](https://docs.rafter.so).
