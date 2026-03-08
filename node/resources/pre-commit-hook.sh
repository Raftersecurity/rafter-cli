#!/bin/bash
# Rafter Security Pre-Commit Hook
# Scans staged files for secrets before allowing commits

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

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    # No files staged
    exit 0
fi

echo "🔍 Rafter: Scanning staged files for secrets..."

# Scan staged files
rafter scan local --staged --quiet

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${RED}❌ Commit blocked: Secrets detected in staged files${NC}"
    echo ""
    echo "   Run: rafter scan local --staged"
    echo "   To see details and remediate."
    echo ""
    echo "   To bypass (NOT recommended): git commit --no-verify"
    exit 1
fi

echo -e "${GREEN}✓ No secrets detected${NC}"
exit 0
