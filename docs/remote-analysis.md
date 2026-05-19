# Remote Code Analysis

[← Back to README](../README.md)

Agentic security audits backed by a full SAST/SCA toolchain, via the Rafter API. The analysis engine examines your codebase the way a professional cybersecurity auditor would — following data flows across files, reasoning about authentication and authorization logic, and identifying vulnerabilities that pattern-matching alone cannot catch — then validates and enriches findings with industry-standard static analysis, dependency scanning, and secret detection. Runs against the **remote repository** on GitHub, not local files. Your code is deleted immediately after analysis completes. Auto-detection uses your local Git config to determine which repo and branch to analyze.

```sh
export RAFTER_API_KEY="your-key"   # or use .env file

rafter run                                    # scan current repo (auto-detected)
rafter run --repo myorg/myrepo --branch main  # scan specific repo
rafter run --mode plus                        # default fast; plus adds agentic deep-dives
rafter get SCAN_ID                            # retrieve results
rafter get SCAN_ID --interactive              # poll until complete
rafter usage                                  # check quota
```

`rafter scan --repo <org/repo>` is an explicit alias for `rafter run`.

## Flags (`rafter run`)

| Flag | Description |
|------|-------------|
| `-r, --repo <repo>` | `org/repo` (default: current repo from git config) |
| `-b, --branch <branch>` | Branch (default: current else `main`) |
| `-k, --api-key <key>` | API key, overrides `RAFTER_API_KEY` |
| `-f, --format <fmt>` | `json` or `md` (default `md`) |
| `-m, --mode <mode>` | `fast` (default) or `plus` |
| `--github-token <tok>` | GitHub PAT for private repos (or `RAFTER_GITHUB_TOKEN`) |
| `--skip-interactive` | Do not wait for the scan to complete |
| `--quiet` | Suppress status messages |

## Piping and automation

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

## API key setup

1. Sign up at [rafter.so](https://rafter.so)
2. Dashboard → Settings → API Keys
3. `export RAFTER_API_KEY="your-key"` or add to `.env`

## See also

- [README](../README.md) — top-level overview
- [docs/local-toolkit.md](local-toolkit.md) — offline secret scanning and policy enforcement
- [docs/exit-codes.md](exit-codes.md) — remote exit-code contract
