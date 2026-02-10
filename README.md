# Rafter CLI

Multi-language CLI for Rafter.

## Overview
This CLI allows you to trigger and retrieve security scans for your repositories via the Rafter public API. It is available for both Python (pip) and Node.js (npm, pnpm, yarn).

The CLI follows UNIX principles for automation-friendly operation:
- **Scan data** is output to **stdout** for easy piping
- **Status messages** are output to **stderr** 
- **Exit codes** provide predictable failure modes
- **No file writing** - pure stdout output for maximum pipe-friendliness

**Important**: The scanner analyzes the **remote repository** (e.g., on GitHub), not your local files. Auto-detection uses your local Git configuration to determine which remote repository and branch to scan.

## Installation

### Python (pip)
```sh
pip install rafter-cli
```

### Node.js (npm, pnpm, yarn)
```sh
npm install -g @rafter-security/cli
# or
yarn global add @rafter-security/cli
# or
pnpm add -g @rafter-security/cli
```

## Rafter Security Audits

Analyze remote repositories for vulnerabilities. Requires a [Rafter API key](https://rafter.so). See [docs.rafter.so](https://docs.rafter.so) for full documentation.

### Basic Usage
```sh
# Run a scan and wait for completion (scans remote repository)
rafter run --repo myorg/myrepo --branch main

# Get existing scan results
rafter get SCAN_ID

# Check API usage
rafter usage
```

### Piping and Automation
```sh
# Pipe JSON output to jq for filtering
rafter get SCAN_ID | jq '.vulnerabilities[] | select(.level=="critical")'

# Count total vulnerabilities
rafter get SCAN_ID | jq '.vulnerabilities | length'

# Save output to file using shell redirection
rafter get SCAN_ID > scan_results.json

# Process scan results in scripts
if rafter get SCAN_ID --format json | jq -e '.vulnerabilities | length > 0'; then
    echo "Vulnerabilities found!"
fi
```

### Advanced Piping Examples
```sh
# Extract all file paths with vulnerabilities
rafter get SCAN_ID | jq -r '.vulnerabilities[].file' | sort | uniq

# Create a summary report
rafter get SCAN_ID | jq '{
    scan_id: .scan_id,
    total_vulnerabilities: (.vulnerabilities | length),
    critical_count: (.vulnerabilities | map(select(.level=="critical")) | length),
    high_count: (.vulnerabilities | map(select(.level=="high")) | length)
}'

# Filter and format for CSV output
rafter get SCAN_ID | jq -r '.vulnerabilities[] | [.level, .rule_id, .file, .line] | @csv'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (API failure, network issues, etc.) |
| 2 | Scan not found |
| 3 | Quota exhausted |

## Documentation
See `shared-docs/CLI_SPEC.md` for full CLI flag and command documentation. 