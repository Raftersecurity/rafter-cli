# Rafter CLI Command Spec

## Overview

The Rafter CLI follows UNIX principles for automation-friendly operation:

- **Scan data** is output to **stdout** for easy piping
- **Status messages** are output to **stderr** 
- **Exit codes** provide predictable failure modes
- **No file writing** - pure stdout output for maximum pipe-friendliness

**Important**: The scanner analyzes the **remote repository** (e.g., on GitHub), not your local files. Auto-detection uses your local Git configuration to determine which remote repository and branch to scan.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (API failure, network issues, etc.) |
| 2 | Scan not found |
| 3 | Quota exhausted |

## Commands

### rafter run [OPTIONS]
- `-k, --api-key TEXT` - API key or RAFTER_API_KEY env var
- `-r, --repo TEXT` - org/repo (default: current repo)
- `-b, --branch TEXT` - branch (default: current branch or 'main')
- `-f, --format [json|md]` - output format (default: md)
- `--skip-interactive` - fire-and-forget mode
- `--quiet` - suppress status messages
- `-h, --help`

### rafter get SCAN_ID [OPTIONS]
- `-k, --api-key TEXT` - API key or RAFTER_API_KEY env var
- `-f, --format [json|md]` - output format (default: md)
- `--interactive` - poll until scan completes
- `--quiet` - suppress status messages
- `-h, --help`

### rafter usage [OPTIONS]
- `-k, --api-key TEXT` - API key or RAFTER_API_KEY env var
- `-h, --help`

## Usage Examples

### Basic Usage (stdout output)
```bash
# Get scan results as JSON to stdout
rafter get 8c2e1234-5678-9abc-def0-123456789abc

# Get scan results as Markdown to stdout  
rafter get 8c2e1234-5678-9abc-def0-123456789abc --format md

# Pipe to jq for filtering
rafter get 8c2e1234-5678-9abc-def0-123456789abc | jq '.vulnerabilities[] | select(.level=="critical")'

# Run new scan and wait for completion (scans remote repository)
rafter run --repo myorg/myrepo --branch main
```

### Piping and Automation
```bash
# Filter vulnerabilities by severity
rafter get 8c2e1234-5678-9abc-def0-123456789abc | jq '.vulnerabilities[] | select(.level=="high" or .level=="critical")'

# Count total vulnerabilities
rafter get 8c2e1234-5678-9abc-def0-123456789abc | jq '.vulnerabilities | length'

# Save output to file using shell redirection
rafter get 8c2e1234-5678-9abc-def0-123456789abc > scan_results.json

# Process scan results in scripts
if rafter get 8c2e1234-5678-9abc-def0-123456789abc --format json | jq -e '.vulnerabilities | length > 0'; then
    echo "Vulnerabilities found!"
fi
```

### Quiet Mode for Scripts
```bash
# Get just the scan data, no status messages
rafter get 8c2e1234-5678-9abc-def0-123456789abc --quiet | jq '.scan_id'

# Run scan quietly and capture output
scan_data=$(rafter run --repo myorg/myrepo --branch main --quiet)
```

### Error Handling
```bash
# Check for specific error conditions
if rafter get invalid-scan-id; then
    echo "Scan found"
else
    case $? in
        2) echo "Scan not found" ;;
        3) echo "Quota exhausted" ;;
        *) echo "Other error" ;;
    esac
fi
```

### Advanced Piping Examples
```bash
# Extract all file paths with vulnerabilities
rafter get 8c2e1234-5678-9abc-def0-123456789abc | jq -r '.vulnerabilities[].file' | sort | uniq

# Create a summary report
rafter get 8c2e1234-5678-9abc-def0-123456789abc | jq '{
    scan_id: .scan_id,
    total_vulnerabilities: (.vulnerabilities | length),
    critical_count: (.vulnerabilities | map(select(.level=="critical")) | length),
    high_count: (.vulnerabilities | map(select(.level=="high")) | length)
}'

# Filter and format for CSV output
rafter get 8c2e1234-5678-9abc-def0-123456789abc | jq -r '.vulnerabilities[] | [.level, .rule_id, .file, .line] | @csv'
```

## Notes

- API key can be provided as a flag, env var, or .env file
- Git repository auto-detection works in CI environments (GITHUB_REPOSITORY, CI_REPOSITORY, etc.)
- **The scanner analyzes the remote repository, not your local files**
- Auto-detection uses your local Git configuration to determine which remote repository and branch to scan
- All scan data is output to stdout for maximum pipe-friendliness
- Status messages (progress, completion notices, errors) go to stderr
- The `--quiet` flag suppresses all stderr output while preserving stdout behavior
- Use shell redirection (`>`, `>>`) to save output to files when needed 