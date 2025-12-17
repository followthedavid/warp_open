# Warp Phase 1-6 WebSocket Live Automation

**Version**: 2.0.0  
**Status**: Production Ready with Live Streaming  
**Date**: November 24, 2025

## 🎯 Overview

Complete Warp Phase 1-6 automation system with real-time WebSocket event streaming, parallel execution, and live visual dashboard. This extends the base automation package with full observability and multi-client monitoring capabilities.

## 📦 What's New

### WebSocket Architecture
- **Real-time event streaming** from all automation components
- **Multi-client support** - multiple dashboards can connect simultaneously
- **Event history** - new clients receive last 50 events on connect
- **Auto-reconnect** - clients automatically reconnect if disconnected
- **Heartbeat** - periodic keep-alive messages every 30 seconds

### Live Parallel Dashboard
- **6 phase panels** - one for each Phase 1-6 with independent logs
- **System alerts panel** - centralized monitoring and safety alerts
- **Live statistics** - total events, success/warn/error counts, uptime
- **Color-coded events** - green (success), yellow (warn), red (error), cyan (info)
- **Auto-scroll** - keeps newest events visible
- **Export logs** - download complete event history as JSON

### Parallel Execution
- All phases run simultaneously for maximum throughput
- Independent logging per phase
- Coordinated via WebSocket event bus
- Human oversight preserved for critical operations

## 🚀 Quick Start

### 1. Launch Everything (One Command)

```bash
cd /path/to/warp_phase1_6_bundle
./scripts/launch_parallel_automation.sh
```

This single script will:
1. Start WebSocket server on port 9000
2. Open live dashboard in browser
3. Start Python ML safety predictor
4. Start JavaScript alert store
5. Simulate Phase 1-6 test events
6. Stream all logs in real-time

### 2. Manual Launch (Step by Step)

**Terminal 1: Start WebSocket Server**
```bash
python3 scripts/warp_phase1_6_event_server.py --port 9000
```

**Terminal 2: Open Dashboard**
```bash
open dashboard/parallel_dashboard.html
```

**Terminal 3: Start Automation Components**
```bash
# Python ML predictor
python3 automation/python/phase6_safety_ml.py

# JavaScript alert store (if Node.js available)
node automation/js/alertStore_automation.js
```

## 📡 WebSocket Event Format

All components emit events in this JSON format:

```json
{
  "phase": 1-6 | "system" | "alert",
  "event": "Human-readable event description",
  "type": "success" | "warn" | "error" | "info",
  "timestamp": "2025-11-24T07:30:00.000Z"
}
```

### Example Events

**Phase Event (Success)**
```json
{
  "phase": 3,
  "event": "Dependency batch completed successfully",
  "type": "success",
  "timestamp": "2025-11-24T07:30:15.123Z"
}
```

**System Alert (Warning)**
```json
{
  "phase": "alert",
  "event": "Plan #12 requires manual review - safety score 75%",
  "type": "warn",
  "timestamp": "2025-11-24T07:30:20.456Z"
}
```

**Error Event**
```json
{
  "phase": 5,
  "event": "Monitoring connection timeout - retrying",
  "type": "error",
  "timestamp": "2025-11-24T07:30:25.789Z"
}
```

## 🔧 Integration Guide

### Python Integration

```python
import asyncio
import websockets
import json
from datetime import datetime

async def send_phase_event(phase, event, event_type="success"):
    """Send event to WebSocket server"""
    uri = "ws://localhost:9000"
    
    async with websockets.connect(uri) as ws:
        data = {
            "phase": phase,
            "event": event,
            "type": event_type,
            "timestamp": datetime.now().isoformat()
        }
        await ws.send(json.dumps(data))

# Usage
asyncio.run(send_phase_event(6, "Plan auto-approved", "success"))
```

### JavaScript/Node.js Integration

```javascript
const WebSocket = require('ws');

function sendPhaseEvent(phase, event, type = 'success') {
    const ws = new WebSocket('ws://localhost:9000');
    
    ws.on('open', () => {
        const data = {
            phase,
            event,
            type,
            timestamp: new Date().toISOString()
        };
        ws.send(JSON.stringify(data));
        ws.close();
    });
}

// Usage
sendPhaseEvent(2, 'Agent assigned to plan', 'success');
```

### Rust Integration (Tauri)

```rust
use serde_json::json;
use std::net::TcpStream;
use tungstenite::{connect, Message};

fn send_phase_event(phase: u32, event: &str, event_type: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (mut socket, _) = connect("ws://localhost:9000")?;
    
    let data = json!({
        "phase": phase,
        "event": event,
        "type": event_type,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    socket.write_message(Message::Text(data.to_string()))?;
    socket.close(None)?;
    
    Ok(())
}

// Usage
send_phase_event(6, "Scheduler tick completed", "success")?;
```

## 📊 Dashboard Features

### Connection Status
- **Green**: Connected to WebSocket server
- **Red (blinking)**: Disconnected, attempting reconnection

### Statistics Panel
- **Total Events**: Cumulative count of all events
- **Success**: Count of successful operations (green)
- **Warnings**: Count of warning events (yellow)
- **Errors**: Count of error events (red)
- **Uptime**: Dashboard uptime in MM:SS format

### Phase Panels (1-6)
Each phase has:
- **Status badge**: IDLE → RUNNING → ACTIVE/WARNING/ERROR
- **Event log**: Scrollable list of phase-specific events
- **Auto-scroll**: Keeps latest events visible
- **Color-coding**: Visual distinction by event type

### System Alerts Panel
- Centralized view of all system-level events
- Safety alerts from ML predictor
- Scheduler decisions (auto-approval, manual review)
- Agent assignment notifications
- Batch failure alerts

### Controls
- **Clear All Logs**: Reset all event logs and statistics
- **Export Logs**: Download complete event history as JSON
- **Auto-Scroll**: Toggle automatic scrolling (ON/OFF)
- **Reconnect**: Manual WebSocket reconnection

## 🛡️ Safety & Human Oversight

All automation maintains human-in-the-loop safety:

### Auto-Approval Thresholds
- **≥80%**: Automatically approved, event logged
- **50-79%**: Manual review required, alert generated
- **<50%**: Blocked, critical alert sent

### Alert Escalation
1. **INFO**: Routine operational events (cyan)
2. **SUCCESS**: Successful completions (green)
3. **WARN**: Attention needed, non-critical (yellow)
4. **ERROR**: Failures requiring intervention (red)

### Audit Trail
- All events timestamped and logged
- Complete event history exportable
- WebSocket server maintains last 1000 events
- Dashboard logs persist until cleared

## 🔍 Troubleshooting

### WebSocket Server Won't Start

**Symptom**: `Address already in use` error

**Solution**:
```bash
# Find process using port 9000
lsof -ti:9000

# Kill the process
kill -9 $(lsof -ti:9000)

# Restart server
python3 scripts/warp_phase1_6_event_server.py
```

### Dashboard Shows "DISCONNECTED"

**Causes**:
1. WebSocket server not running
2. Port 9000 blocked by firewall
3. Browser WebSocket support disabled

**Solutions**:
```bash
# Verify server is running
ps aux | grep warp_phase1_6_event_server

# Test WebSocket connection
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:9000

# Check firewall (macOS)
sudo pfctl -s rules | grep 9000
```

### No Events Appearing

**Check**:
1. Components are running and emitting events
2. WebSocket server is receiving events (check terminal output)
3. Dashboard is connected (status should be green)
4. Browser console for JavaScript errors (F12)

**Debug**:
```bash
# Tail WebSocket server log
tail -f /tmp/warp_phase1_6_logs/websocket_server.log

# Send test event
python3 -c "
import asyncio, websockets, json
async def test():
    async with websockets.connect('ws://localhost:9000') as ws:
        await ws.send(json.dumps({'phase': 1, 'event': 'Test event', 'type': 'info'}))
asyncio.run(test())
"
```

### Python Dependencies Missing

```bash
# Install all required packages
pip3 install websockets pandas numpy scikit-learn joblib

# Verify installation
python3 -c "import websockets; print('✓ websockets')"
python3 -c "import pandas; print('✓ pandas')"
python3 -c "import sklearn; print('✓ scikit-learn')"
```

## 📦 Deployment

### Standalone Deployment

```bash
# 1. Extract bundle
tar -xzf warp_phase1_6_automation_bundle.tar.gz
cd warp_phase1_6_bundle

# 2. Install dependencies
pip3 install -r requirements.txt  # if available
# OR
pip3 install websockets pandas numpy scikit-learn joblib

# 3. Launch
./scripts/launch_parallel_automation.sh
```

### Production Deployment

**Option 1: systemd Service (Linux)**

```ini
[Unit]
Description=Warp Phase 1-6 WebSocket Server
After=network.target

[Service]
Type=simple
User=warp
WorkingDirectory=/opt/warp_phase1_6_bundle
ExecStart=/usr/bin/python3 scripts/warp_phase1_6_event_server.py --port 9000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable warp-websocket
sudo systemctl start warp-websocket
```

**Option 2: Docker Container**

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install websockets pandas numpy scikit-learn joblib

EXPOSE 9000

CMD ["python3", "scripts/warp_phase1_6_event_server.py", "--port", "9000"]
```

```bash
docker build -t warp-phase1-6 .
docker run -d -p 9000:9000 --name warp-automation warp-phase1-6
```

**Option 3: launchd (macOS)**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.warp.phase1-6.websocket</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>/path/to/scripts/warp_phase1_6_event_server.py</string>
        <string>--port</string>
        <string>9000</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.warp.phase1-6.websocket.plist
```

## 📈 Performance Tuning

### WebSocket Server

**Max Clients**: Default unlimited, can be limited:
```python
MAX_CLIENTS = 100  # Add to warp_phase1_6_event_server.py
```

**Event History Size**: Default 1000 events:
```python
MAX_LOG_SIZE = 5000  # Increase for longer history
```

**Heartbeat Interval**: Default 30 seconds:
```python
await asyncio.sleep(10)  # More frequent heartbeats
```

### Dashboard

**Max Log Entries**: Default 100 per phase:
```javascript
const MAX_LOG_ENTRIES = 200;  // Increase for more history
```

**Reconnect Delay**: Default 3 seconds:
```javascript
setTimeout(connectWebSocket, 1000);  // Faster reconnect
```

## 🔐 Security Considerations

### Production Checklist

- [ ] Change WebSocket port from default 9000
- [ ] Enable TLS/WSS for encrypted connections
- [ ] Implement authentication for WebSocket connections
- [ ] Restrict WebSocket server to localhost in production
- [ ] Use reverse proxy (nginx) for external access
- [ ] Enable CORS restrictions
- [ ] Sanitize event messages to prevent XSS
- [ ] Rate limit event submissions
- [ ] Monitor for malicious event patterns

### TLS/WSS Example

```python
import ssl

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain('cert.pem', 'key.pem')

async with websockets.serve(handler, "0.0.0.0", 9000, ssl=ssl_context):
    await asyncio.Future()
```

## 📚 Additional Resources

- **Base Automation README**: `automation/README.md`
- **Verification Report**: `automation/VERIFICATION.md`
- **Completion Summary**: `automation/COMPLETION_SUMMARY.txt`
- **Tauri Integration**: `automation/rust/tauri_commands_example.rs`
- **API Reference**: See base automation README

## 🎉 Summary

This WebSocket integration provides:
- ✅ Real-time event streaming from all components
- ✅ Live visual dashboard with 6 phase panels
- ✅ Parallel execution for maximum throughput
- ✅ Human oversight preserved for safety
- ✅ Multi-client support
- ✅ Auto-reconnect and heartbeat
- ✅ Complete audit trail
- ✅ Export and analysis tools
- ✅ Production-ready deployment options

**Warp Phase 1-6 is now fully observable, autonomous, and production-ready!**

---

*Warp Phase 1-6 WebSocket Live Automation v2.0.0*  
*Built with safety, observability, and real-time monitoring*
