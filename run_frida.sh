#!/bin/bash
# Frida SSL Unpinning Test Script
# This will prompt for your password

echo "=========================================="
echo "ChatGPT Frida SSL Unpinning Test"
echo "=========================================="
echo ""

# Check if ChatGPT is running
if ! pgrep ChatGPT > /dev/null; then
    echo "ERROR: ChatGPT is not running"
    echo "Please start ChatGPT Desktop first"
    exit 1
fi

echo "✓ ChatGPT is running (PID: $(pgrep ChatGPT))"
echo ""
echo "Starting Frida with SSL unpinning..."
echo "This will prompt for your password."
echo ""
echo "After Frida attaches, send a test message:"
echo "  - Either manually in ChatGPT"
echo "  - Or run: node desktop_automation.cjs --app ChatGPT --prompt 'Test'"
echo ""
echo "Watch for [RESPONSE INTERCEPTED] in the output below."
echo "Full responses will be saved to /tmp/chatgpt_frida_response.txt"
echo ""
echo "Press Ctrl+C to stop when done."
echo ""
echo "=========================================="
echo ""

# Run Frida (will prompt for password)
sudo /Users/davidquinton/.local/bin/frida -n ChatGPT -l frida_ssl_unpin_chatgpt.js
