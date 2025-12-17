#!/bin/bash
# Automated E2E tests for Warp_Open AI tool calling
# Uses screenshot OCR to verify UI state

set -e

TEST_DIR="/tmp/warp_open_tests"
RESULTS_FILE="$TEST_DIR/results.json"
APP_PATH="/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src-tauri/target/release/Warp_Open"

mkdir -p "$TEST_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')]${NC} $1"
}

# Launch app
launch_app() {
    log "Launching Warp_Open..."
    "$APP_PATH" > "$TEST_DIR/app.log" 2>&1 &
    APP_PID=$!
    sleep 3
    
    if ! kill -0 $APP_PID 2>/dev/null; then
        error "App failed to launch"
        exit 1
    fi
    
    log "App launched (PID: $APP_PID)"
}

# Kill app
kill_app() {
    if [ ! -z "$APP_PID" ]; then
        log "Killing app (PID: $APP_PID)..."
        kill $APP_PID 2>/dev/null || true
        sleep 1
    fi
}

# Take screenshot
screenshot() {
    local name=$1
    local output="$TEST_DIR/screenshot_${name}_$(date +%s).png"
    screencapture -x -o "$output"
    echo "$output"
}

# Send text input via AppleScript
send_input() {
    local text=$1
    osascript <<EOF
tell application "Warp_Open"
    activate
end tell

delay 0.5

tell application "System Events"
    keystroke "$text"
    delay 0.2
    key code 36  -- Enter key
end tell
EOF
}

# Wait for AI response (checks for thinking indicator to disappear)
wait_for_response() {
    local timeout=15
    local elapsed=0
    
    log "Waiting for AI response..."
    
    while [ $elapsed -lt $timeout ]; do
        sleep 1
        elapsed=$((elapsed + 1))
        
        # Take screenshot and check if thinking indicator is present
        local screenshot=$(screenshot "check_$elapsed")
        
        # Use tesseract OCR to read screen text
        if command -v tesseract &> /dev/null; then
            local text=$(tesseract "$screenshot" stdout 2>/dev/null | tr '[:upper:]' '[:lower:]')
            
            # If we see "thinking" bubbles, keep waiting
            if echo "$text" | grep -q "thinking\|..."; then
                continue
            else
                log "Response complete"
                return 0
            fi
        fi
    done
    
    warn "Timeout waiting for response"
    return 1
}

# Count occurrences of pattern in log
count_in_log() {
    local pattern=$1
    grep -c "$pattern" "$TEST_DIR/app.log" 2>/dev/null || echo "0"
}

# Test: Read file
test_read_file() {
    log "Test: Read file tool call"
    
    local test_start=$(date +%s)
    
    send_input "read my zshrc file"
    
    if wait_for_response; then
        sleep 2  # Let UI settle
        
        local screenshot=$(screenshot "test_read_file")
        
        # Check app logs for tool execution
        local tool_calls=$(count_in_log "Detected tool JSON.*read_file")
        local tool_results=$(count_in_log "Tool executed: read_file")
        
        log "Tool calls detected: $tool_calls"
        log "Tool results: $tool_results"
        
        if [ "$tool_calls" -eq 1 ] && [ "$tool_results" -eq 1 ]; then
            log "✅ PASS: Read file test"
            echo "{\"test\": \"read_file\", \"passed\": true, \"tool_calls\": $tool_calls, \"screenshot\": \"$screenshot\"}" >> "$RESULTS_FILE"
            return 0
        else
            error "❌ FAIL: Expected 1 tool call and 1 result, got $tool_calls calls and $tool_results results"
            echo "{\"test\": \"read_file\", \"passed\": false, \"tool_calls\": $tool_calls, \"tool_results\": $tool_results, \"screenshot\": \"$screenshot\"}" >> "$RESULTS_FILE"
            return 1
        fi
    else
        error "❌ FAIL: Timeout waiting for response"
        local screenshot=$(screenshot "test_read_file_timeout")
        echo "{\"test\": \"read_file\", \"passed\": false, \"error\": \"timeout\", \"screenshot\": \"$screenshot\"}" >> "$RESULTS_FILE"
        return 1
    fi
}

# Test: Write file
test_write_file() {
    log "Test: Write file tool call"
    
    local test_file="/tmp/warp_test_$(date +%s).txt"
    local test_content="hello world from test"
    
    send_input "write \\\"$test_content\\\" to $test_file"
    
    if wait_for_response; then
        sleep 2
        
        local screenshot=$(screenshot "test_write_file")
        
        # Check if file was created
        if [ -f "$test_file" ]; then
            local content=$(cat "$test_file")
            if echo "$content" | grep -q "$test_content"; then
                log "✅ PASS: Write file test"
                echo "{\"test\": \"write_file\", \"passed\": true, \"screenshot\": \"$screenshot\"}" >> "$RESULTS_FILE"
                rm "$test_file"
                return 0
            else
                error "❌ FAIL: File content incorrect"
                echo "{\"test\": \"write_file\", \"passed\": false, \"error\": \"wrong_content\", \"screenshot\": \"$screenshot\"}" >> "$RESULTS_FILE"
                return 1
            fi
        else
            error "❌ FAIL: File was not created"
            echo "{\"test\": \"write_file\", \"passed\": false, \"error\": \"file_not_created\", \"screenshot\": \"$screenshot\"}" >> "$RESULTS_FILE"
            return 1
        fi
    else
        error "❌ FAIL: Timeout"
        return 1
    fi
}

# Main
main() {
    log "🧪 Starting Warp_Open E2E Tests"
    
    # Clear previous results
    echo "" > "$RESULTS_FILE"
    
    # Clean logs
    rm -f "$TEST_DIR/app.log"
    
    # Launch app
    launch_app
    
    # Run tests
    passed=0
    failed=0
    
    if test_read_file; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
    
    sleep 2
    
    # Cleanup
    kill_app
    
    # Report
    log ""
    log "📊 Results: $passed passed, $failed failed"
    
    if [ $failed -gt 0 ]; then
        error "Some tests failed. See logs and screenshots in $TEST_DIR"
        exit 1
    else
        log "All tests passed!"
        exit 0
    fi
}

trap kill_app EXIT

main
