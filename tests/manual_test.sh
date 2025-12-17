#!/bin/bash
# Manual test helper - monitors app logs and validates results

TEST_DIR="/tmp/warp_open_tests"
LOG_FILE="$TEST_DIR/manual_test.log"

mkdir -p "$TEST_DIR"

echo "🧪 Manual Test Helper for Warp_Open"
echo ""
echo "Instructions:"
echo "1. I will launch the app and tail its console logs"
echo "2. In the app, send this message: 'read my zshrc file'"
echo "3. This script will monitor for duplicate tool calls"
echo ""
echo "Press Enter to start..."
read

# Clear old logs
rm -f "$LOG_FILE"
touch "$LOG_FILE"

# Launch app and redirect to log file
/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src-tauri/target/release/Warp_Open > "$LOG_FILE" 2>&1 &
APP_PID=$!

echo "✓ App launched (PID: $APP_PID)"
echo "✓ Monitoring logs at: $LOG_FILE"
echo ""
echo "Now send your test message in the app..."
echo "Press Ctrl+C when done to see results"
echo ""

# Monitor logs in real-time
tail -f "$LOG_FILE" &
TAIL_PID=$!

# Wait for user to ctrl+c
trap "kill $TAIL_PID 2>/dev/null; kill $APP_PID 2>/dev/null; analyze_results" EXIT

wait $TAIL_PID

analyze_results() {
    echo ""
    echo "📊 Analyzing results..."
    echo ""
    
    local tool_detections=$(grep -c "Detected tool JSON.*read_file" "$LOG_FILE" 2>/dev/null || echo "0")
    local tool_executions=$(grep -c "Tool executed: read_file" "$LOG_FILE" 2>/dev/null || echo "0")
    local duplicate_skips=$(grep -c "Tool already executed, skipping duplicate" "$LOG_FILE" 2>/dev/null || echo "0")
    
    echo "Tool JSON detections: $tool_detections"
    echo "Tool executions: $tool_executions"
    echo "Duplicate skips: $duplicate_skips"
    echo ""
    
    if [ "$tool_executions" -eq 1 ]; then
        echo "✅ PASS: Tool executed exactly once"
    else
        echo "❌ FAIL: Expected 1 execution, got $tool_executions"
    fi
    
    if [ "$duplicate_skips" -gt 0 ]; then
        echo "✅ PASS: Duplicate prevention working ($duplicate_skips duplicates caught)"
    fi
    
    echo ""
    echo "Full log saved to: $LOG_FILE"
}
