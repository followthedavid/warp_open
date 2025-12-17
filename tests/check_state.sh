#!/bin/bash
# Check Warp_Open UI state from exported JSON

STATE_FILE="/tmp/warp_ui_state.json"

if [ ! -f "$STATE_FILE" ]; then
    echo "❌ No state file found at $STATE_FILE"
    echo "Make sure the app is running and test mode is enabled"
    exit 1
fi

echo "📊 Warp_Open UI State Check"
echo ""

tool_calls=$(jq -r '.toolCallCount // 0' "$STATE_FILE")
tool_results=$(jq -r '.toolResultCount // 0' "$STATE_FILE")
is_thinking=$(jq -r '.isThinking' "$STATE_FILE")
message_count=$(jq -r '.messageCount' "$STATE_FILE")

echo "Messages: $message_count"
echo "Tool calls: $tool_calls"
echo "Tool results: $tool_results"
echo "Is thinking: $is_thinking"
echo ""

# Check for duplicate execution
if [ "$tool_calls" -eq 1 ] && [ "$tool_results" -eq 1 ]; then
    echo "✅ PASS: Tool executed exactly once (no duplicates)"
elif [ "$tool_calls" -gt 1 ] || [ "$tool_results" -gt 1 ]; then
    echo "❌ FAIL: Duplicate execution detected"
    echo "   Expected: 1 tool call, 1 result"
    echo "   Got: $tool_calls tool calls, $tool_results results"
else
    echo "ℹ️  No tool execution detected yet"
fi

# Check for infinite thinking
if [ "$is_thinking" = "true" ]; then
    echo "❌ FAIL: Infinite thinking bug - thinking indicator still active"
elif [ "$is_thinking" = "false" ] && [ "$tool_calls" -gt 0 ]; then
    echo "✅ PASS: Thinking indicator properly stopped"
fi

echo ""
echo "Full state:"
jq '.' "$STATE_FILE"
