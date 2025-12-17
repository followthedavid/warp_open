#!/usr/bin/env bash
# run_phase1_6_auto_live.sh
# Fully automated end-to-end Phase 1–6 test runner with live Phase 6 dashboard

set -euo pipefail

APP_DIR="/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri"
LOG_FILE="/tmp/warp_phase1_6_auto_live.log"
HTML_TESTER="$APP_DIR/public/test_phase1_6_auto.html"

echo "╔════════════════════════════════════════════════╗"
echo "║ Starting Full Phase 1–6 Auto Test w/ Live Monitor ║"
echo "╚════════════════════════════════════════════════╝"

# Cleanup
echo "Cleaning up previous instances..."
pkill -f 'warp-tauri' >/dev/null 2>&1 || true
pkill -f 'npm run tauri' >/dev/null 2>&1 || true
sleep 2
rm -f "$LOG_FILE"

# Start Tauri app
echo "Launching Warp_Open Tauri app..."
cd "$APP_DIR"
npm run tauri dev > "$LOG_FILE" 2>&1 &
APP_PID=$!
echo "Tauri PID: $APP_PID"
echo "Waiting for app to initialize (15 seconds)..."
sleep 15

# Check if still running
if ! ps -p $APP_PID > /dev/null 2>&1; then
    echo "❌ Tauri app failed to start!"
    echo "Last 50 lines of log:"
    tail -50 "$LOG_FILE"
    exit 1
fi

echo "✅ Tauri app running."
echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║ Interactive Test Page Available               ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Manual testing:"
echo "  Open: http://localhost:1420/test_phase1_6_auto.html"
echo ""
echo "Auto-run testing:"
echo "  Open: http://localhost:1420/test_phase1_6_auto.html?autorun=true"
echo ""
echo "Opening auto-run page in 5 seconds..."
sleep 5

# Open in default browser with autorun parameter
if command -v open >/dev/null 2>&1; then
    open "http://localhost:1420/test_phase1_6_auto.html?autorun=true"
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://localhost:1420/test_phase1_6_auto.html?autorun=true"
else
    echo "⚠️ Could not auto-open browser. Please open manually:"
    echo "   http://localhost:1420/test_phase1_6_auto.html?autorun=true"
fi

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║ Monitoring Mode                                ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Logs are being written to: $LOG_FILE"
echo "Press Ctrl+C to stop monitoring and clean up"
echo ""
echo "Waiting 30 seconds for tests to complete..."
echo "------------------------------------------------------------"

# Monitor for test completion
ELAPSED=0
MAX_WAIT=30
while [ $ELAPSED -lt $MAX_WAIT ]; do
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo "⏱  Elapsed: ${ELAPSED}s / ${MAX_WAIT}s"
    
    # Check if test completion marker appears in log
    if grep -q "All phases complete" "$LOG_FILE" 2>/dev/null; then
        echo "✅ Test completion detected!"
        break
    fi
done

echo ""
echo "------------------------------------------------------------"
echo "Last 50 lines of dev log:"
echo "------------------------------------------------------------"
tail -50 "$LOG_FILE"
echo "------------------------------------------------------------"
echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║ Phase 1-6 Test Execution Complete ✅           ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Full logs available at: $LOG_FILE"
echo "Interactive tester: http://localhost:1420/test_phase1_6_auto.html"
echo ""
echo "Press Enter to stop the Tauri app and exit..."
read -r

# Cleanup
echo "Stopping Tauri app..."
kill $APP_PID 2>/dev/null || true
sleep 2
echo "Done!"
