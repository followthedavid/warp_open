# Warp_Open Automated Testing

Automated E2E tests for verifying AI tool calling behavior.

## Quick Start

```bash
# Build the app first
npm run tauri build

# Run automated tests
./tests/test_ai_tools.sh
```

## What It Tests

1. **Read File Tool Call**
   - Sends: "read my zshrc file"
   - Verifies: Tool called exactly once, result returned, no duplicates
   - Checks console logs for duplicate execution

2. **Write File Tool Call**
   - Sends: "write 'hello world' to /tmp/test.txt"
   - Verifies: File created, correct content, single execution

## How It Works

The test script:
1. Launches Warp_Open headlessly
2. Uses AppleScript to send keyboard input
3. Captures app console logs
4. Takes screenshots at each stage
5. Verifies log patterns match expected behavior
6. Reports pass/fail with evidence

## Test Output

Results saved to `/tmp/warp_open_tests/`:
- `results.json` - Test outcomes
- `app.log` - Console output from the app
- `screenshot_*.png` - UI screenshots at each stage

## Usage Examples

```bash
# Run all tests
./tests/test_ai_tools.sh

# View test results
cat /tmp/warp_open_tests/results.json

# View app logs
cat /tmp/warp_open_tests/app.log

# View screenshots
open /tmp/warp_open_tests/
```

## Debugging Failed Tests

If tests fail:

1. Check `/tmp/warp_open_tests/app.log` for errors
2. View screenshots to see UI state
3. Look for patterns like:
   - Multiple "Detected tool JSON" lines → duplication bug
   - No "Tool executed" line → tool not running
   - Thinking bubbles in final screenshot → infinite thinking

## Adding New Tests

Add test functions to `test_ai_tools.sh`:

```bash
test_my_feature() {
    log "Test: My feature"
    
    send_input "test prompt"
    
    if wait_for_response; then
        # Add verification logic
        local result=$(count_in_log "expected pattern")
        
        if [ "$result" -eq 1 ]; then
            log "✅ PASS"
            return 0
        fi
    fi
    
    error "❌ FAIL"
    return 1
}
```

Then add to the main test sequence in `main()`.

## CI/CD Integration

This script exits with code 0 on success, 1 on failure, making it suitable for CI:

```bash
#!/bin/bash
npm run tauri build && ./tests/test_ai_tools.sh || exit 1
```

## Requirements

- macOS (uses `screencapture` and AppleScript)
- Bash 4+
- Optional: `tesseract` for OCR-based verification (brew install tesseract)
