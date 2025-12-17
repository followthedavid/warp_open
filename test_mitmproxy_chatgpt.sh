#!/bin/bash
# test_mitmproxy_chatgpt.sh
# Automated test script for ChatGPT Desktop traffic interception

set -e

echo "=========================================="
echo "ChatGPT mitmproxy Interception Test"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Step 1: Get network service
echo "[1/7] Detecting network service..."
SERVICES=$(networksetup -listallnetworkservices | grep -v "^An asterisk")
WIFI_SERVICE=$(echo "$SERVICES" | grep -i "wi-fi" | head -n1)
ETHERNET_SERVICE=$(echo "$SERVICES" | grep -i "ethernet" | head -n1)

if [ -n "$WIFI_SERVICE" ]; then
    NETWORK_SERVICE="$WIFI_SERVICE"
    echo "  Using: $NETWORK_SERVICE"
elif [ -n "$ETHERNET_SERVICE" ]; then
    NETWORK_SERVICE="$ETHERNET_SERVICE"
    echo "  Using: $NETWORK_SERVICE"
else
    echo -e "${RED}  ERROR: No active network service found${NC}"
    exit 1
fi

# Step 2: Check if mitmproxy is running
echo ""
echo "[2/7] Checking mitmproxy status..."
if lsof -i :8080 | grep -q LISTEN; then
    echo -e "  ${GREEN}✓${NC} mitmproxy is running on port 8080"
else
    echo -e "  ${RED}✗${NC} mitmproxy is NOT running"
    echo "  Starting mitmdump..."
    mitmdump -s mitm_chatgpt_intercept.py --set ssl_insecure=true &
    MITM_PID=$!
    echo "  Started mitmdump (PID: $MITM_PID)"
    sleep 2
fi

# Step 3: Configure system proxy
echo ""
echo "[3/7] Configuring system proxy..."
networksetup -setwebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
networksetup -setsecurewebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
networksetup -setwebproxystate "$NETWORK_SERVICE" on
networksetup -setsecurewebproxystate "$NETWORK_SERVICE" on
echo -e "  ${GREEN}✓${NC} Proxy configured: localhost:8080"

# Step 4: Test basic proxy connectivity
echo ""
echo "[4/7] Testing basic HTTP proxy..."
if curl -x http://localhost:8080 -s http://httpbin.org/get > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} HTTP proxy working"
else
    echo -e "  ${YELLOW}⚠${NC} HTTP proxy test failed (non-critical)"
fi

echo ""
echo "[5/7] Testing HTTPS proxy..."
if curl -x http://localhost:8080 -s https://httpbin.org/get > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} HTTPS proxy working"
else
    echo -e "  ${YELLOW}⚠${NC} HTTPS proxy test failed (cert may not be trusted)"
fi

# Step 6: Check if ChatGPT is running
echo ""
echo "[6/7] Checking ChatGPT Desktop status..."
if pgrep -x ChatGPT > /dev/null; then
    echo -e "  ${GREEN}✓${NC} ChatGPT is running"
    CHATGPT_RUNNING=1
else
    echo -e "  ${YELLOW}⚠${NC} ChatGPT is NOT running"
    echo "  Please start ChatGPT Desktop manually for full testing"
    CHATGPT_RUNNING=0
fi

# Step 7: Test ChatGPT interception
echo ""
echo "[7/7] Testing ChatGPT traffic interception..."

# Clear previous response file
rm -f /tmp/chatgpt_last_response.txt

if [ $CHATGPT_RUNNING -eq 1 ]; then
    echo "  Sending test message to ChatGPT..."
    echo "  (This will use desktop_automation.cjs)"

    # Monitor mitmproxy output for ChatGPT traffic
    echo "  Monitoring for ChatGPT traffic..."

    # Send message via automation
    if node desktop_automation.cjs --app ChatGPT --prompt "Respond with exactly: INTERCEPTION_TEST_SUCCESS" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Message sent successfully"
    else
        echo -e "  ${YELLOW}⚠${NC} Message send may have failed"
    fi

    # Wait a moment for response to be captured
    sleep 2

    # Check if response was captured
    if [ -f /tmp/chatgpt_last_response.txt ]; then
        RESPONSE=$(cat /tmp/chatgpt_last_response.txt)
        if [[ "$RESPONSE" == *"INTERCEPTION_TEST_SUCCESS"* ]]; then
            echo -e "  ${GREEN}✓✓✓ SUCCESS! ChatGPT response intercepted!${NC}"
            echo "  Response: $RESPONSE"
        else
            echo -e "  ${YELLOW}⚠${NC} Response file exists but doesn't match expected content"
            echo "  Response: $RESPONSE"
        fi
    else
        echo -e "  ${RED}✗${NC} No response captured in /tmp/chatgpt_last_response.txt"
        echo "  This suggests:"
        echo "    - ChatGPT may use certificate pinning"
        echo "    - Traffic may bypass the proxy"
        echo "    - Response may use WebRTC instead of HTTP"
    fi
else
    echo "  Skipping ChatGPT test (app not running)"
fi

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo ""

# Check mitmproxy logs for any OpenAI traffic
if lsof -i :8080 | grep -q LISTEN; then
    echo "Checking mitmproxy logs for OpenAI/ChatGPT traffic..."
    # Note: This would need to check actual mitmproxy logs
    # For now, just indicate where to check
    echo "  → Review mitmdump output above for [REQUEST]/[RESPONSE] entries"
    echo "  → Look for 'openai' or 'chatgpt' domains"
fi

echo ""
echo "Next Steps:"
echo "1. Review mitmdump console output for captured traffic"
echo "2. Check /tmp/chatgpt_last_response.txt for extracted responses"
echo "3. If no traffic captured, likely causes:"
echo "   - Certificate pinning (most likely)"
echo "   - WebRTC bypass"
echo "   - App ignoring system proxy"
echo ""
echo "Alternative approaches if blocked:"
echo "   - Try: sudo frida -n ChatGPT -l frida_chatgpt_recon.js"
echo "   - Try: Memory dumping with lldb"
echo "   - Try: Network packet capture with tcpdump/Wireshark"
echo ""

# Cleanup prompt
echo "Proxy is still configured. To disable:"
echo "  networksetup -setwebproxystate \"$NETWORK_SERVICE\" off"
echo "  networksetup -setsecurewebproxystate \"$NETWORK_SERVICE\" off"
echo ""

echo "To stop mitmproxy:"
echo "  pkill -f mitmdump"
echo ""
