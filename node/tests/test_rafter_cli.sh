#!/bin/bash

# Set test values
API_KEY="REDACTED_API_KEY"
REPO="Rome-1/ridespy"
BRANCH="main"
SCAN_ID1="0f89007c-1e20-4cba-938e-ffc36c1dad16" # Existing scan (few-vulnerable repo)
SCAN_ID2="0f89007c-1e20-4cba-938e-ffc36c1dad16" # Existing scan (particularly vulnerable repo)

CLI="node ../dist/index.js"

echo "=== rafter version ==="
$CLI version



# echo "=== rafter --help ==="
# $CLI --help

# echo -e "\n=== rafter run --help ==="
# $CLI run --help

# echo -e "\n=== rafter get --help ==="
# $CLI get --help

# echo -e "\n=== rafter usage --help ==="
# $CLI usage --help

# echo -e "\n=== rafter usage ==="
# $CLI usage

# echo -e "\n=== rafter get (json to stdout) ==="
# $CLI get "$SCAN_ID1" --api-key "$API_KEY" --format json

# echo -e "\n=== rafter get (markdown to stdout) ==="
# $CLI get "$SCAN_ID1" --api-key "$API_KEY" --format md

# echo -e "\n=== rafter get (quiet mode) ==="
# $CLI get "$SCAN_ID1" --api-key "$API_KEY" --format json --quiet

# echo -e "\n=== rafter get (test invalid scan ID) ==="
# $CLI get "invalid-scan-id" --api-key "$API_KEY"
# echo "Exit code: $?"

# echo -e "\n=== rafter get (interactive mode) ==="
# $CLI get "$SCAN_ID2" --api-key "$API_KEY" --format md --interactive

# echo -e "\n=== rafter run (non-interactive, skip) ==="
# $CLI run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --skip-interactive

# echo -e "\n=== rafter run (interactive, default format) ==="
# $CLI run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY"

# echo -e "\n=== rafter run (interactive, markdown format) ==="
# $CLI run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --format md

# echo -e "\n=== Testing pipe functionality ==="
# echo "Piping JSON output to jq:"
# $CLI get "$SCAN_ID1" --api-key "$API_KEY" --format json | jq '.scan_id' 2>/dev/null

# echo -e "\n=== Testing shell redirection ==="
# echo "Saving output to file using shell redirection:"
# $CLI get "$SCAN_ID1" --api-key "$API_KEY" --format json > test_output.json
# echo "File created: test_output.json"
# ls -la test_output.json

# echo -e "\n=== Testing quiet mode with pipes ==="
# echo "Getting vulns ID quietly:"
# $CLI get "$SCAN_ID2" --format json --quiet | jq -r '.vulnerabilities[] | [.level, .rule_id, .file, .line] | @csv' 2>/dev/null

# echo -e "\n=== Done! ==="