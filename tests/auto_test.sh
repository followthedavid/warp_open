#!/bin/bash
# Fully automated E2E test for Warp_Open

set -e

APP_PATH="/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src-tauri/target/release/Warp_Open"
STATE_FILE="/tmp/warp_ui_state.json"

echo "🧪 Warp_Open Automated E2E Test"
echo ""

# Clean up old state
rm -f "$STATE_FILE"

# Stop any running instances to start fresh
echo "0. Stopping any running instances..."
pkill -f "Warp_Open" 2>/dev/null || true
sleep 1

# Clear localStorage by removing the app's data
# Tauri on macOS stores WebView data in ~/Library/WebKit/
rm -rf "$HOME/Library/WebKit/com.warp.open" 2>/dev/null || true
rm -rf "$HOME/Library/WebKit/Warp_Open" 2>/dev/null || true

echo "1. Launching app with test mode enabled..."
WARP_OPEN_TEST_MODE=1 WARP_OPEN_WS_PORT=9223 "$APP_PATH" > /tmp/warp_test_app.log 2>&1 &
APP_PID=$!
sleep 2

# Wait for app to be ready (state file appears)
echo "2. Waiting for app to be ready..."
for i in {1..30}; do
    if [ -f "$STATE_FILE" ]; then
        echo "   ✓ App ready (state file detected)"
        break
    fi
    sleep 0.5
done

if [ ! -f "$STATE_FILE" ]; then
    echo "   ✗ App failed to start (no state file after 15s)"
    kill $APP_PID 2>/dev/null || true
    exit 1
fi

# Send test message via WebSocket
echo "3. Sending test message: 'read my zshrc file'"
WARP_OPEN_WS_PORT=9223 node tests/send_message_ws.mjs "read my zshrc file" || {
    echo "   ✗ Failed to send message via WebSocket"
    kill $APP_PID 2>/dev/null || true
    exit 1
}

echo "   ✓ Message sent, waiting for response..."
sleep 1

# Wait for response (watch for state changes)
echo "4. Waiting for AI response..."
initial_count=$(jq -r '.messageCount // 0' "$STATE_FILE" 2>/dev/null || echo "0")

# Wait up to 30 seconds for response
for i in {1..60}; do
    sleep 0.5
    current_count=$(jq -r '.messageCount // 0' "$STATE_FILE" 2>/dev/null || echo "0")
    is_thinking=$(jq -r '.isThinking' "$STATE_FILE" 2>/dev/null || echo "true")
    tool_calls=$(jq -r '.toolCallCount // 0' "$STATE_FILE" 2>/dev/null || echo "0")
    
    # Debug: show progress every 5 iterations
    if [ $((i % 10)) -eq 0 ]; then
        echo "   [$(($i/2))s] Messages: $current_count, Tools: $tool_calls, Thinking: $is_thinking"
    fi
    
    # Success conditions:
    # - We have at least 1 tool call, OR
    # - Message count increased significantly (>= 3 new messages = user + tool + result + AI response)
    if [ "$tool_calls" -ge 1 ] || [ "$current_count" -ge $((initial_count + 3)) ]; then
        if [ "$is_thinking" = "false" ]; then
            echo "   ✓ Response complete"
            break
        fi
    fi
done

# Analyze results
echo "5. Analyzing results..."
echo ""

tool_calls=$(jq -r '.toolCallCount // 0' "$STATE_FILE")
tool_results=$(jq -r '.toolResultCount // 0' "$STATE_FILE")
is_thinking=$(jq -r '.isThinking' "$STATE_FILE")

echo "   Tool calls: $tool_calls"
echo "   Tool results: $tool_results"
echo "   Is thinking: $is_thinking"
echo ""

FAILED=0

# Check for duplicates
if [ "$tool_calls" -eq 1 ] && [ "$tool_results" -eq 1 ]; then
    echo "✅ PASS: No duplicate execution"
else
    echo "❌ FAIL: Duplicate execution detected (expected 1/1, got $tool_calls/$tool_results)"
    FAILED=1
fi

# Check for infinite thinking
if [ "$is_thinking" = "false" ]; then
    echo "✅ PASS: Thinking indicator stopped"
else
    echo "❌ FAIL: Infinite thinking bug"
    FAILED=1
fi

# Cleanup
echo ""
echo "6. Cleaning up..."
kill $APP_PID 2>/dev/null || true
sleep 1

if [ $FAILED -eq 0 ]; then
    echo ""
    echo "🎉 All tests PASSED!"
    exit 0
else
    echo ""
    echo "💥 Tests FAILED"
    echo "View state: cat $STATE_FILE"
    echo "View logs: cat /tmp/warp_test.log"
    exit 1
fi
