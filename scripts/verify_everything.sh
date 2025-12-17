#!/bin/bash

set -e

echo "══════════════════════════════════════════════"
echo "      WARP_OPEN ─ FULL SYSTEM VERIFICATION"
echo "══════════════════════════════════════════════"

REPORT="/tmp/warp_status_report.txt"
SCREEN_DIR="/tmp/warp_status_screenshots"
LOG_DIR="/tmp/warp_status_logs"

mkdir -p "$SCREEN_DIR"
mkdir -p "$LOG_DIR"

echo "⏳ Killing old dev servers..."
pkill -f "tauri" || true
pkill -f "vite" || true
sleep 1

echo "⏳ Clearing previous test artifacts..."
rm -rf test-results || true
rm -f "$REPORT"

echo -e "\n🟦 Phase 1 ─ Installing Dependencies" | tee -a "$REPORT"
npm install || { echo "❌ npm install failed"; exit 1; }

echo -e "\n🟦 Phase 2 ─ Running Rust Backend Tests" | tee -a "$REPORT"
cd src-tauri
cargo test --tests 2>&1 | tee -a "$REPORT"
cd ..

echo -e "\n🟦 Phase 3 ─ Launch Dev Server in Background" | tee -a "$REPORT"
npm run tauri:dev > "$LOG_DIR/dev_server.log" 2>&1 &
DEV_PID=$!

echo "   Dev server PID: $DEV_PID"
sleep 10

echo -e "\n🟦 Phase 4 ─ Automated UI Smoke Test" | tee -a "$REPORT"
npx playwright test tests/ui/warp_tabs.spec.ts 2>&1 | tee -a "$REPORT"

echo -e "\n🟩 Phase 5 ─ Summaries" | tee -a "$REPORT"
echo "Screenshots: $SCREEN_DIR" | tee -a "$REPORT"
echo "Logs:        $LOG_DIR" | tee -a "$REPORT"

# Kill dev server
kill $DEV_PID 2>/dev/null || true
sleep 1
pkill -9 -f "tauri|vite" >/dev/null 2>&1 || true

echo -e "\n══════════════════════════════════════════════"
echo "      DONE! Full report saved at:"
echo "      $REPORT"
echo "══════════════════════════════════════════════"
