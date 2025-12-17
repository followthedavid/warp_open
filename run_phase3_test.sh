#!/bin/bash
# Phase 3: Full Autonomy Test Runner
# Tests auto-batch creation, auto-approval, dependencies, and rollback

echo "🚀 Phase 3 Full Autonomy Test"
echo "============================="
echo ""

# Wait for app to be ready
sleep 2

# Run Phase 3 test via AppleScript
osascript <<EOF
tell application "System Events"
    tell process "warp-tauri"
        # Open DevTools if not already open
        keystroke "i" using {command down, option down}
        delay 1
        
        # Run test in console
        keystroke "await window.__TAURI__.invoke('test_phase3_workflow')"
        keystroke return
        delay 2
    end tell
end tell
EOF

echo ""
echo "✅ Phase 3 test completed!"
echo "Check the DevTools console for detailed results"
