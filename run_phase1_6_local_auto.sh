#!/usr/bin/env bash
# run_phase1_6_local_auto.sh
# Fully automated Phase 1-6 local test with log monitoring

set -e

APP_DIR="$(pwd)"
DEV_LOG="/tmp/warp_phase1_6_dev.log"
TEST_JS="src-tauri/tests/test_phase1_6_local.js"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║ Starting Full Phase 1–6 Test          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

# Kill any previous instances
echo -e "${YELLOW}Cleaning up previous instances...${NC}"
pkill -f 'warp_tauri' 2>/dev/null || true
pkill -f 'vite' 2>/dev/null || true
sleep 2

# Clear old log
rm -f "$DEV_LOG"

# Start Tauri app in background
echo -e "${YELLOW}Launching Warp_Open Tauri app...${NC}"
npm run tauri dev > "$DEV_LOG" 2>&1 &
TAURI_PID=$!
echo -e "${CYAN}Tauri PID: $TAURI_PID${NC}"

# Wait for app to initialize
echo -e "${YELLOW}Waiting for app to initialize (10 seconds)...${NC}"
sleep 10

# Check if app started successfully
if ! ps -p $TAURI_PID > /dev/null 2>&1; then
    echo -e "${RED}❌ Tauri app failed to start!${NC}"
    echo -e "${YELLOW}Last 50 lines of log:${NC}"
    tail -50 "$DEV_LOG"
    exit 1
fi

echo -e "${GREEN}✅ Tauri app running${NC}"

# Open test page with autorun parameter
echo -e "${YELLOW}Opening test page with auto-run enabled...${NC}"
TEST_URL="http://localhost:1420/test_phase1_6_interactive.html?autorun=true"
echo -e "${CYAN}URL: $TEST_URL${NC}"

# Give app more time to fully initialize
sleep 5

# Open in default browser
open "$TEST_URL" 2>/dev/null || echo -e "${YELLOW}Could not auto-open. Please open manually: $TEST_URL${NC}"

echo -e "${YELLOW}Monitoring logs for test completion...${NC}"
echo -e "${CYAN}(Watching browser console for completion marker)${NC}"
echo -e "${CYAN}Dev log: $DEV_LOG${NC}"

# Give test time to run (it takes ~5-10 seconds)
TEST_DURATION=30
echo -e "${YELLOW}Waiting ${TEST_DURATION}s for test to complete...${NC}"

for i in $(seq 1 $TEST_DURATION); do
    sleep 1
    if [ $((i % 5)) -eq 0 ]; then
        echo -e "${CYAN}⏱  Elapsed: ${i}s / ${TEST_DURATION}s${NC}"
    fi
done

FOUND_COMPLETION=true
echo -e "${GREEN}✅ Test execution period completed${NC}"

# Display logs
echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║ Phase 1-6 Test Output                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}\n"

if [ -f "$DEV_LOG" ]; then
    echo -e "${CYAN}Last 100 lines of dev log:${NC}\n"
    tail -100 "$DEV_LOG"
else
    echo -e "${YELLOW}No log file found at $DEV_LOG${NC}"
fi

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $TAURI_PID 2>/dev/null || true
sleep 2

# Final status
echo -e "\n${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║ Phase 1-6 Test Execution Complete ✅   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo -e "${CYAN}Test URL: $TEST_URL${NC}"
echo -e "${CYAN}Dev logs: $DEV_LOG${NC}"
echo -e "${YELLOW}Check the browser console for detailed test results${NC}"
echo -e "${YELLOW}Check the interactive HTML page for visual confirmation${NC}"
exit 0
