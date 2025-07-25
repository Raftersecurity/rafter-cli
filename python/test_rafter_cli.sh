#!/bin/bash

# Test values
API_KEY="RFxpk-70ea0847a32231461dd843fa2734b4c7c719d9f43b4814e374f649b93d36f347"
REPO="Rome-1/ridespy"
BRANCH="main"
SCAN_ID1="16d3a53a-6b2e-4ad4-8ab8-b8135e7a6ffd" # Existing scan (few-vulnerable repo)
SCAN_ID2="13d380dc-4ac7-4451-a840-51de405f6925" # Existing scan (particularly vulnerable repo)

cd "$(dirname "$0")"

echo "=== rafter --help ==="
poetry run rafter --help

echo -e "\n=== rafter usage ==="
poetry run rafter usage --api-key "$API_KEY"

# echo -e "\n=== rafter run (non-interactive, skip) ==="
# poetry run rafter run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --skip-interactive

# echo -e "\n=== rafter run (interactive, default format) ==="
# poetry run rafter run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY"

# echo -e "\n=== rafter run (interactive, markdown format, save to file) ==="
# poetry run rafter run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --format md --save ./ --save-name "test_scan_md"

echo -e "\n=== rafter get (json, save to file) ==="
poetry run rafter get "$SCAN_ID2" --api-key "$API_KEY" --format json --save-path ./ --save-name "test_get_json"

echo -e "\n=== rafter get (markdown, interactive) ==="
poetry run rafter get "$SCAN_ID3" --api-key "$API_KEY" --format md --interactive

echo -e "\n=== rafter get (json, non-interactive) ==="
poetry run rafter get "$SCAN_ID3" --api-key "$API_KEY" --format json

echo -e "\n=== Done! ===" 