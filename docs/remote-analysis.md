# Remote Code Analysis

Agentic security audits backed by a full SAST/SCA toolchain, via the Rafter API.

The analysis engine examines your codebase the way a professional cybersecurity auditor
would — following data flows across files, reasoning about authentication and authorization
logic, and identifying vulnerabilities that pattern-matching alone cannot catch — then
validates and enriches findings with industry-standard static analysis, dependency scanning,
and secret detection.

Runs against the **remote repository** on GitHub. Your code is deleted immediately after
analysis completes.

## Commands

```sh
export RAFTER_API_KEY="your-key"   # or use .env file

rafter run                                    # scan current repo (auto-detected)
rafter scan --repo myorg/myrepo --branch main # scan specific repo
rafter get SCAN_ID                            # retrieve results
rafter get SCAN_ID --interactive              # poll until complete
rafter usage                                  # check quota
```

## Piping and automation

```sh
# Filter high-severity vulnerabilities
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

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success — scan completed or results retrieved |
| 1 | General error |
| 2 | Scan not found |
| 3 | Quota exhausted |
| 4 | Insufficient scope / forbidden |
