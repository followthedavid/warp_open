#!/bin/bash
# Warp_Open Full Test Suite Runner
# Runs all tests: Rust backend + Playwright UI

set -e

echo "════════════════════════════════════════════════════════"
echo "  Warp_Open Full Test Suite"
echo "════════════════════════════════════════════════════════"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
RUST_TESTS_PASSED=false
UI_TESTS_PASSED=false

# Kill any leftover processes
echo "${YELLOW}[Cleanup]${NC} Killing leftover processes..."
pkill -9 -f "tauri|vite|warp_tauri|Warp_Open" >/dev/null 2>&1 || true
sleep 2

# Step 1: Rust tests
echo ""
echo "${YELLOW}[1/3]${NC} Running Rust backend tests..."
echo "────────────────────────────────────────────────────────"
cd src-tauri
if cargo test --tests 2>&1 | tee /tmp/warp_rust_tests.log; then
    echo "${GREEN}✓ Rust tests passed${NC}"
    RUST_TESTS_PASSED=true
else
    echo "${RED}✗ Rust tests failed${NC}"
    echo "See: /tmp/warp_rust_tests.log"
fi
cd ..

# Step 2: Start dev server
echo ""
echo "${YELLOW}[2/3]${NC} Starting Warp_Open dev server..."
echo "────────────────────────────────────────────────────────"
npm run tauri:dev > /tmp/warp_test_server.log 2>&1 &
DEV_PID=$!
echo "Dev server PID: $DEV_PID"

# Wait for server to be ready
echo "Waiting for server to start..."
sleep 10

# Check if Vite is responding
if curl -s http://localhost:5173 > /dev/null; then
    echo "${GREEN}✓ Dev server ready${NC}"
else
    echo "${RED}✗ Dev server failed to start${NC}"
    echo "See: /tmp/warp_test_server.log"
    kill $DEV_PID 2>/dev/null || true
    exit 1
fi

# Step 3: Playwright UI tests
echo ""
echo "${YELLOW}[3/3]${NC} Running Playwright UI tests..."
echo "────────────────────────────────────────────────────────"
if npx playwright test tests/ui/warp_tabs.spec.ts 2>&1 | tee /tmp/warp_ui_tests.log; then
    echo "${GREEN}✓ UI tests passed${NC}"
    UI_TESTS_PASSED=true
else
    echo "${RED}✗ UI tests failed${NC}"
    echo "See: /tmp/warp_ui_tests.log"
fi

# Cleanup
echo ""
echo "${YELLOW}[Cleanup]${NC} Stopping dev server..."
kill $DEV_PID 2>/dev/null || true
sleep 2
pkill -9 -f "tauri|vite|Warp_Open" >/dev/null 2>&1 || true

# Final report
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Test Results Summary"
echo "════════════════════════════════════════════════════════"
echo ""
if [ "$RUST_TESTS_PASSED" = true ]; then
    echo "${GREEN}✓${NC} Rust Backend Tests: PASSED"
else
    echo "${RED}✗${NC} Rust Backend Tests: FAILED"
fi

if [ "$UI_TESTS_PASSED" = true ]; then
    echo "${GREEN}✓${NC} Playwright UI Tests: PASSED"
else
    echo "${RED}✗${NC} Playwright UI Tests: FAILED"
fi

echo ""
echo "Logs:"
echo "  - Rust tests: /tmp/warp_rust_tests.log"
echo "  - UI tests: /tmp/warp_ui_tests.log"
echo "  - Dev server: /tmp/warp_test_server.log"
echo ""

# Exit with error if any test failed
if [ "$RUST_TESTS_PASSED" = true ] && [ "$UI_TESTS_PASSED" = true ]; then
    echo "${GREEN}════════════════════════════════════════════════════════${NC}"
    echo "${GREEN}  ALL TESTS PASSED ✓${NC}"
    echo "${GREEN}════════════════════════════════════════════════════════${NC}"
    exit 0
else
    echo "${RED}════════════════════════════════════════════════════════${NC}"
    echo "${RED}  SOME TESTS FAILED ✗${NC}"
    echo "${RED}════════════════════════════════════════════════════════${NC}"
    exit 1
fi
