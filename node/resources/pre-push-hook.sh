#!/bin/bash
# Rafter Security Pre-Push Hook
# Scans commits being pushed for secrets

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if rafter is installed
if ! command -v rafter &> /dev/null; then
    echo -e "${YELLOW}⚠️  Warning: rafter CLI not found in PATH${NC}"
    echo "   Install: npm install -g @rafter-security/cli"
    echo "   Skipping secret scan..."
    exit 0
fi

ZERO_SHA="0000000000000000000000000000000000000000"
FOUND_SECRETS=0

while read local_ref local_sha remote_ref remote_sha; do
    # Skip branch deletions
    if [ "$local_sha" = "$ZERO_SHA" ]; then
        continue
    fi

    if [ "$remote_sha" = "$ZERO_SHA" ]; then
        # New branch — scan all commits on this branch not on any remote branch
        ref_arg=$(git rev-list --max-parents=0 "$local_sha" 2>/dev/null | head -1)
        if [ -z "$ref_arg" ]; then
            ref_arg="$local_sha^"
        fi
    else
        # Existing branch — scan only new commits
        ref_arg="$remote_sha"
    fi

    echo "🔍 Rafter: Scanning commits being pushed ($local_ref)..."

    rafter scan local --diff "$ref_arg" --quiet
    EXIT_CODE=$?

    if [ $EXIT_CODE -ne 0 ]; then
        FOUND_SECRETS=1
    fi
done

if [ $FOUND_SECRETS -ne 0 ]; then
    echo -e "${RED}❌ Push blocked: Secrets detected in commits being pushed${NC}"
    echo ""
    echo "   Run: rafter scan local --diff <remote-sha>"
    echo "   To see details and remediate."
    echo ""
    echo "   To bypass (NOT recommended): git push --no-verify"
    exit 1
fi

echo -e "${GREEN}✓ No secrets detected${NC}"
exit 0
