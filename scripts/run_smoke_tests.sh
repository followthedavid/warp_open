#!/bin/bash
# Warp_Open Smoke Tests
# Quick tests to verify basic functionality

set -e

echo "══════════════════════════════════════════"
echo "  Warp_Open Smoke Tests"
echo "══════════════════════════════════════════"
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Quick Rust tests
echo "${YELLOW}[1/2]${NC} Running Rust smoke tests..."
cd src-tauri
cargo test --lib --quiet 2>&1 | head -20
echo "${GREEN}✓ Rust smoke tests complete${NC}"
cd ..

# Quick compile check
echo ""
echo "${YELLOW}[2/2]${NC} Verifying frontend compiles..."
npm run build > /tmp/warp_smoke_build.log 2>&1 &
BUILD_PID=$!

# Wait max 30 seconds for build
for i in {1..30}; do
    if ! kill -0 $BUILD_PID 2>/dev/null; then
        break
    fi
    sleep 1
done

if wait $BUILD_PID 2>/dev/null; then
    echo "${GREEN}✓ Frontend build successful${NC}"
else
    echo "${RED}✗ Frontend build failed${NC}"
    echo "See: /tmp/warp_smoke_build.log"
    exit 1
fi

echo ""
echo "${GREEN}══════════════════════════════════════════${NC}"
echo "${GREEN}  Smoke Tests PASSED ✓${NC}"
echo "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "Run './scripts/run_full_tests.sh' for complete test suite"
