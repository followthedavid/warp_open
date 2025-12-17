# mitmproxy Setup Guide for ChatGPT Desktop Interception

## Status
- mitmproxy installed: ✅ Version 12.2.1
- Certificates generated: ✅ Located in ~/.mitmproxy/
- Intercept script created: ✅ mitm_chatgpt_intercept.py
- Proxy running: ✅ Listening on port 8080

## Setup Steps

### 1. Install mitmproxy CA Certificate

To intercept HTTPS traffic, macOS needs to trust the mitmproxy certificate:

```bash
# Open the certificate in Keychain Access
open ~/.mitmproxy/mitmproxy-ca-cert.pem
```

**In Keychain Access:**
1. Find "mitmproxy" certificate
2. Double-click to open
3. Expand "Trust" section
4. Set "When using this certificate" to "Always Trust"
5. Close window (requires password)

### 2. Configure System Proxy

**Manual Configuration:**
1. System Settings → Network
2. Select your active connection (Wi-Fi/Ethernet)
3. Click "Details..."
4. Go to "Proxies" tab
5. Enable "Web Proxy (HTTP)" → localhost:8080
6. Enable "Secure Web Proxy (HTTPS)" → localhost:8080
7. Click "OK"

**Command-line (faster):**
```bash
# Get your network service name
networksetup -listallnetworkservices

# Set proxy (replace "Wi-Fi" with your service name)
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setwebproxystate "Wi-Fi" on
networksetup -setsecurewebproxystate "Wi-Fi" on
```

### 3. Start mitmproxy with Intercept Script

```bash
# Already running in background (PID check with lsof -i :8080)
mitmdump -s mitm_chatgpt_intercept.py --set ssl_insecure=true

# Or start interactively with UI
mitmproxy -s mitm_chatgpt_intercept.py --set ssl_insecure=true
```

### 4. Test Basic Proxy Functionality

```bash
# Test that proxy is working with a simple HTTP request
curl -x http://localhost:8080 http://httpbin.org/get

# Test HTTPS with mitmproxy cert (should work if cert is trusted)
curl -x http://localhost:8080 https://httpbin.org/get
```

### 5. Test ChatGPT Traffic Interception

1. Ensure ChatGPT Desktop is running
2. Send a message via automation:
   ```bash
   node desktop_automation.cjs --app ChatGPT --prompt "Test interception"
   ```
3. Check mitmproxy output for captured traffic
4. Check `/tmp/chatgpt_last_response.txt` for extracted response

## Expected Traffic Patterns

Based on discovery, ChatGPT Desktop communicates with:
- **Host**: 104.18.39.21:443 (Cloudflare/OpenAI)
- **Domains**: *.openai.com, *.chatgpt.com
- **Protocols**: HTTPS + WebRTC
- **Content-Type**: application/json or text/event-stream (SSE)

## Intercept Script Details

**File**: `mitm_chatgpt_intercept.py`

**What it captures:**
- All requests to openai.com/chatgpt.com domains
- JSON responses (format: choices[].message.content)
- SSE streaming responses (format: data: {delta: {content: "..."}})
- Conversation IDs from requests
- Saves last response to `/tmp/chatgpt_last_response.txt`

**Logging:**
- [REQUEST] method + URL
- [CONV_ID] conversation identifier
- [RESPONSE] status code
- [CHATGPT RESPONSE FOUND] extracted message
- [SAVED] confirmation of file write

## Potential Blockers

### 1. Certificate Pinning
ChatGPT Desktop may use certificate pinning, which means:
- App only trusts OpenAI's official certificates
- Even if system trusts mitmproxy cert, app will reject it
- Connection will fail or bypass proxy

**Symptoms:**
- App shows connection errors
- mitmproxy shows SSL handshake failures
- No traffic appears in mitmproxy

**Workarounds:**
- Use Frida to disable certificate pinning
- Patch app binary to remove pinning (advanced)
- Use alternative interception method (memory/Frida)

### 2. WebRTC Traffic
LiveKitWebRTC may bypass HTTP proxy:
- Uses UDP for peer-to-peer connections
- Doesn't go through HTTP proxy settings
- Requires network-level interception (Wireshark/tcpdump)

**Solution:**
- Focus on HTTP API calls (initial setup, message submission)
- WebRTC might only be for voice/video features

### 3. System Proxy Bypass
Some apps ignore system proxy settings:
- Native apps can make direct connections
- Requires forcing proxy via pf (packet filter) or proxychains

## Cleanup (When Done Testing)

```bash
# Stop mitmproxy
pkill -f mitmdump

# Disable system proxy
networksetup -setwebproxystate "Wi-Fi" off
networksetup -setsecurewebproxystate "Wi-Fi" off

# Optional: Remove certificate from Keychain
# (Search for "mitmproxy" in Keychain Access and delete)
```

## Monitoring Commands

```bash
# Check if proxy is running
lsof -i :8080

# View live mitmproxy output
tail -f /tmp/mitmproxy_output.log

# Check for captured responses
cat /tmp/chatgpt_last_response.txt

# Monitor ChatGPT connections
lsof -i -n | grep ChatGPT
```

## Next Steps if This Fails

If mitmproxy cannot intercept ChatGPT traffic due to certificate pinning or WebRTC:

1. **Frida with elevated permissions**
   - `sudo frida -n ChatGPT -l frida_chatgpt_recon.js`
   - Hook Swift methods to intercept responses before rendering
   - Bypass certificate pinning programmatically

2. **Memory dumping with lldb**
   - Attach debugger to ChatGPT process
   - Search memory for response strings
   - Extract data structures

3. **Network-level packet capture**
   - Use Wireshark/tcpdump to capture all traffic
   - May be encrypted, but can analyze patterns
   - Identify alternative endpoints

4. **Binary patching**
   - Use Hopper/Ghidra to analyze app binary
   - Find and patch certificate pinning code
   - Repackage app (requires disabling code signing)

## Testing Checklist

- [ ] mitmproxy certificate installed and trusted
- [ ] System proxy configured (localhost:8080)
- [ ] mitmdump running with intercept script
- [ ] Basic curl test through proxy works
- [ ] ChatGPT Desktop launches without errors
- [ ] Send test message via automation
- [ ] Check mitmproxy logs for ChatGPT traffic
- [ ] Verify response extraction to /tmp file
- [ ] Document results (success or blocker)

## Success Criteria

✅ **Full Success**: ChatGPT responses appear in mitmproxy and are saved to /tmp/chatgpt_last_response.txt

⚠️ **Partial Success**: See some ChatGPT traffic but responses are encrypted/incomplete

❌ **Blocked**: No ChatGPT traffic in mitmproxy, or SSL errors indicate certificate pinning

---

**Created**: 2025-12-11
**Status**: Ready for testing
**Next Action**: Configure system proxy and test with ChatGPT Desktop
