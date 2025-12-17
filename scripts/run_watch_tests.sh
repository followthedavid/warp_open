#!/bin/bash
# Warp_Open Watch Mode Tests
# Automatically runs tests when source files change

echo "══════════════════════════════════════════"
echo "  Warp_Open Watch Mode"
echo "  Press Ctrl+C to exit"
echo "══════════════════════════════════════════"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if fswatch is installed
if ! command -v fswatch &> /dev/null; then
    echo "${YELLOW}Installing fswatch...${NC}"
    brew install fswatch
fi

echo "${GREEN}Watching for file changes in src/ and src-tauri/src/${NC}"
echo ""

# Watch for changes and run smoke tests
fswatch -o src/ src-tauri/src/ | while read change; do
    clear
    echo "${YELLOW}[File changed - running smoke tests]${NC}"
    echo ""
    ./scripts/run_smoke_tests.sh
    echo ""
    echo "${GREEN}Watching for next change...${NC}"
done
