# rafter-cli (Python)

Python CLI for [Rafter](https://rafter.so) — trigger and retrieve remote SAST/SCA security scans via the Rafter API.

> **Note**: This package provides **backend scanning only**. For the full feature set—including agent security (secret scanning, command interception, pre-commit hooks, skill auditing)—install the [Node.js package](https://www.npmjs.com/package/@rafter-security/cli): `npm install -g @rafter-security/cli`

## Installation

```bash
pip install rafter-cli
```

Requires Python 3.10+.

## Quick Start

```bash
export RAFTER_API_KEY="your-key"   # or add to .env file

rafter run                                    # scan current repo (auto-detected)
rafter scan --repo myorg/myrepo --branch main # scan specific repo
rafter get SCAN_ID                            # retrieve results
rafter get SCAN_ID --interactive              # poll until complete
rafter usage                                  # check quota
```

**Important**: The scanner analyzes the **remote repository** on GitHub, not your local files. Auto-detection uses your local Git configuration to determine which repo and branch to scan.

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

## Piping and Automation

The CLI follows UNIX principles: scan data to stdout, status to stderr, no file writing.

```bash
# Filter critical vulnerabilities
rafter get SCAN_ID --format json | jq '.vulnerabilities[] | select(.level=="critical")'

# Count vulnerabilities
rafter get SCAN_ID --format json | jq '.vulnerabilities | length'

# CSV export
rafter get SCAN_ID --format json --quiet | jq -r '.vulnerabilities[] | [.level, .rule_id, .file, .line] | @csv'

# CI gate
if rafter get SCAN_ID --format json | jq -e '.vulnerabilities | length > 0'; then
    echo "Vulnerabilities found!" && exit 1
fi

# Save to file
rafter get SCAN_ID > scan_results.json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Scan not found |
| 3 | Quota exhausted |

## Configuration

- **API key**: `--api-key` flag, `RAFTER_API_KEY` env var, or `.env` file
- **Git auto-detection**: works in CI (`GITHUB_REPOSITORY`, `GITHUB_REF_NAME`, `CI_REPOSITORY`, `CI_COMMIT_BRANCH`)
- **Remote scanning**: analyzes the remote repository, not local files

## Documentation

Full docs at [docs.rafter.so](https://docs.rafter.so).
