#!/bin/bash
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

command -v asciidoctor >/dev/null 2>&1 || {
    echo "asciidoctor must be installed -> https://github.com/asciidoctor/asciidoctor"
    exit 1
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Find all .adoc files
mapfile -t ADOC_FILES < <(find . -name "*.adoc" -type f | grep -v ".git")

if [ ${#ADOC_FILES[@]} -eq 0 ]; then
    echo -e "${YELLOW}No AsciiDoc files found.${NC}"
    exit 0
fi

# Check each file with asciidoctor
EXIT_CODE=0
TOTAL_FILES=0
FAILED_FILES=0

for file in "${ADOC_FILES[@]}"; do
    TOTAL_FILES=$((TOTAL_FILES + 1))
    echo "Checking: $file"

    # Run asciidoctor in safe mode to check for issues
    # Using --safe-mode=unsafe to allow includes but capture warnings
    # Redirect output to /dev/null, but capture stderr for warnings
    if ! asciidoctor --safe-mode=unsafe --no-header-footer -o /dev/null "$file" 2>&1; then
        echo -e "${RED}✗ $file has errors${NC}"
        FAILED_FILES=$((FAILED_FILES + 1))
        EXIT_CODE=1
    else
        # Check for warnings by running again and capturing stderr
        WARNINGS=$(asciidoctor --safe-mode=unsafe --no-header-footer -o /dev/null "$file" 2>&1 || true)
        if [ -n "$WARNINGS" ]; then
            echo -e "${YELLOW}⚠ $file has warnings:${NC}"
            echo "$WARNINGS"
            FAILED_FILES=$((FAILED_FILES + 1))
            EXIT_CODE=1
        else
            echo -e "${GREEN}✓ $file is valid${NC}"
        fi
    fi
    echo
done

echo "=========================================="
echo "AsciiDoc Linter Summary:"
echo "Total files checked: $TOTAL_FILES"
echo "Files with issues: $FAILED_FILES"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All AsciiDoc files are valid!${NC}"
else
    echo -e "${RED}Some AsciiDoc files have issues that need to be fixed.${NC}"
fi

exit $EXIT_CODE
