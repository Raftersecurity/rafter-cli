#!/bin/bash

# Test values
API_KEY="RFxpk-70ea0847a32231461dd843fa2734b4c7c719d9f43b4814e374f649b93d36f347"
REPO="Rome-1/ridespy"
BRANCH="main"
SCAN_ID1="0f89007c-1e20-4cba-938e-ffc36c1dad16" # Existing scan (few-vulnerable repo)
SCAN_ID2="0f89007c-1e20-4cba-938e-ffc36c1dad16" # Existing scan (particularly vulnerable repo)

cd "$(dirname "$0")"

echo "=== rafter --help ==="
poetry run rafter --help

echo -e "\n=== rafter usage ==="
poetry run rafter usage --api-key "$API_KEY"

echo -e "\n=== rafter get (json to stdout) ==="
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format json

echo -e "\n=== rafter get (markdown to stdout) ==="
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format md

echo -e "\n=== rafter get (quiet mode) ==="
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format json --quiet

echo -e "\n=== rafter get (test invalid scan ID) ==="
poetry run rafter get "invalid-scan-id" --api-key "$API_KEY"
echo "Exit code: $?"

echo -e "\n=== rafter get (interactive mode) ==="
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format md --interactive

# echo -e "\n=== rafter run (non-interactive, skip) ==="
# poetry run rafter run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --skip-interactive

# echo -e "\n=== rafter run (interactive, default format) ==="
# poetry run rafter run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY"

# echo -e "\n=== rafter run (interactive, markdown format) ==="
# poetry run rafter run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --format md

echo -e "\n=== Testing pipe functionality ==="
echo "Piping JSON output to jq:"
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format json | jq '.scan_id' 2>/dev/null

echo -e "\n=== Testing shell redirection ==="
echo "Saving output to file using shell redirection:"
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format json > test_output.json
echo "File created: test_output.json"
ls -la test_output.json

echo -e "\n=== Testing quiet mode with pipes ==="
echo "Getting vulns quietly:"
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format json --quiet | jq -r '.vulnerabilities[] | [.level, .rule_id, .file, .line] | @csv' 2>/dev/null

echo -e "\n=== Done! ===" 