#!/bin/bash

# Set test values
API_KEY="API KEY"
REPO="org/repo"
BRANCH="main"
SCAN_ID1="demo-scan-id" # Existing scan (few-vulnerable repo)
SCAN_ID2="demo-scan-id-2" # Existing scan (particularly vulnerable repo)

CLI="node ../dist/index.js"

echo "=== rafter --help ==="
$CLI --help

echo -e "\n=== rafter run --help ==="
$CLI run --help

echo -e "\n=== rafter get --help ==="
$CLI get --help

echo -e "\n=== rafter usage --help ==="
$CLI usage --help

echo -e "\n=== rafter usage ==="
$CLI usage --api-key "$API_KEY"

echo -e "\n=== rafter run (non-interactive, skip) ==="
$CLI run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --skip-interactive

echo -e "\n=== rafter run (interactive, default format) ==="
$CLI run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY"

echo -e "\n=== rafter run (interactive, markdown format, save to file) ==="
$CLI run --repo "$REPO" --branch "$BRANCH" --api-key "$API_KEY" --format md --save-path ./ --save-name "test_scan_md"

echo -e "\n=== rafter get (json, save to file) ==="
$CLI get "$SCAN_ID1" --api-key "$API_KEY" --format json --save-path ./ --save-name "test_get_json"

echo -e "\n=== rafter get (markdown, interactive) ==="
$CLI get "$SCAN_ID2" --api-key "$API_KEY" --format md --interactive

echo -e "\n=== rafter get (json, non-interactive) ==="
$CLI get "$SCAN_ID2" --api-key "$API_KEY" --format json

echo -e "\n=== Done! ==="