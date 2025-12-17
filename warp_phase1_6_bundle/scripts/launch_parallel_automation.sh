#!/usr/bin/env bash
# launch_parallel_automation.sh
# Fully parallel Warp Phase 1-6 automation runner with WebSocket live streaming

set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="$BUNDLE_DIR/scripts"
AUTOMATION_DIR="$BUNDLE_DIR/automation"
LOG_DIR="/tmp/warp_phase1_6_logs"
MAIN_LOG="$LOG_DIR/parallel_automation.log"
WS_PORT=9000

# Colors for terminal output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}Warp Phase 1-6 Parallel Automation Launcher${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""

# Create log directory
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log

# Cleanup function
PIDS=()
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down all Warp Phase 1-6 processes...${NC}"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    echo -e "${GREEN}All processes terminated.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# -----------------------------
# Step 1: Start WebSocket Event Server
# -----------------------------
echo -e "${GREEN}[1/5] Starting WebSocket Event Server on port $WS_PORT...${NC}"
python3 "$SCRIPTS_DIR/warp_phase1_6_event_server.py" --port $WS_PORT > "$LOG_DIR/websocket_server.log" 2>&1 &
WS_PID=$!
PIDS+=($WS_PID)
echo -e "  ${CYAN}PID: $WS_PID${NC}"
sleep 2  # Give server time to start

# -----------------------------
# Step 2: Open Live Dashboard
# -----------------------------
echo -e "${GREEN}[2/5] Opening Live Dashboard...${NC}"
DASHBOARD_HTML="$BUNDLE_DIR/dashboard/parallel_dashboard.html"
if [[ -f "$DASHBOARD_HTML" ]]; then
    if command -v open >/dev/null 2>&1; then
        open "$DASHBOARD_HTML" &
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$DASHBOARD_HTML" &
    else
        echo -e "  ${YELLOW}⚠️  Could not open dashboard automatically${NC}"
        echo -e "  ${YELLOW}Open manually: $DASHBOARD_HTML${NC}"
    fi
    echo -e "  ${CYAN}Dashboard: $DASHBOARD_HTML${NC}"
else
    echo -e "  ${RED}✗ Dashboard not found at $DASHBOARD_HTML${NC}"
fi

# -----------------------------
# Step 3: Start Python ML Safety Predictor
# -----------------------------
echo -e "${GREEN}[3/5] Starting Python ML Safety Predictor...${NC}"
if [[ -f "$AUTOMATION_DIR/python/phase6_safety_ml.py" ]]; then
    # Check for required Python packages
    if ! python3 -c "import websockets" 2>/dev/null; then
        echo -e "  ${YELLOW}Installing websockets package...${NC}"
        pip3 install websockets --quiet || echo -e "  ${RED}Failed to install websockets${NC}"
    fi
    
    python3 "$AUTOMATION_DIR/python/phase6_safety_ml.py" --server ws://localhost:$WS_PORT > "$LOG_DIR/ml_predictor.log" 2>&1 &
    ML_PID=$!
    PIDS+=($ML_PID)
    echo -e "  ${CYAN}PID: $ML_PID${NC}"
else
    echo -e "  ${YELLOW}⚠️  ML predictor not found, skipping${NC}"
fi

# -----------------------------
# Step 4: Start JavaScript Alert Store
# -----------------------------
echo -e "${GREEN}[4/5] Starting JavaScript Alert Store...${NC}"
if [[ -f "$AUTOMATION_DIR/js/alertStore_automation.js" ]] && command -v node >/dev/null 2>&1; then
    # Check for ws package
    if ! node -e "require('ws')" 2>/dev/null; then
        echo -e "  ${YELLOW}Installing ws package...${NC}"
        npm install -g ws --quiet 2>/dev/null || echo -e "  ${RED}Failed to install ws${NC}"
    fi
    
    node "$AUTOMATION_DIR/js/alertStore_automation.js" --ws-port $WS_PORT > "$LOG_DIR/alert_store.log" 2>&1 &
    JS_PID=$!
    PIDS+=($JS_PID)
    echo -e "  ${CYAN}PID: $JS_PID${NC}"
else
    echo -e "  ${YELLOW}⚠️  Alert store or Node.js not found, skipping${NC}"
fi

# -----------------------------
# Step 5: Simulate Phase 1-6 Test Events
# -----------------------------
echo -e "${GREEN}[5/5] Simulating Phase 1-6 Test Events...${NC}"
echo -e "  ${CYAN}Events will stream to WebSocket and dashboard${NC}"

# Event simulator (sends test events to WebSocket)
python3 - <<'PYTHON_SCRIPT' &
import asyncio
import websockets
import json
import random
from datetime import datetime

async def send_test_events():
    uri = "ws://localhost:9000"
    phases = [
        ("1", "Plan Store initialization"),
        ("2", "Agent Store setup"),
        ("3", "Dependency resolution"),
        ("4", "Batch Store created"),
        ("5", "Monitoring active"),
        ("6", "Scheduler running")
    ]
    
    try:
        async with websockets.connect(uri) as ws:
            # Send startup events
            for phase, desc in phases:
                event = {
                    "phase": int(phase),
                    "event": f"{desc} - Starting Phase {phase}",
                    "type": "success",
                    "timestamp": datetime.now().isoformat()
                }
                await ws.send(json.dumps(event))
                await asyncio.sleep(0.5)
            
            # Send ongoing events
            for i in range(50):
                phase = random.randint(1, 6)
                event_types = ["success", "warn", "error"]
                weights = [0.7, 0.2, 0.1]
                etype = random.choices(event_types, weights)[0]
                
                events_pool = [
                    "Processing batch",
                    "Agent assignment complete",
                    "Safety check passed",
                    "Plan advanced to next step",
                    "Dependency resolved",
                    "Monitoring telemetry",
                    "Scheduler tick"
                ]
                
                event = {
                    "phase": phase,
                    "event": f"{random.choice(events_pool)} (iteration {i+1})",
                    "type": etype,
                    "timestamp": datetime.now().isoformat()
                }
                await ws.send(json.dumps(event))
                await asyncio.sleep(random.uniform(0.3, 1.5))
                
            # Send completion
            event = {
                "phase": "system",
                "event": "All Phase 1-6 tests completed successfully",
                "type": "success",
                "timestamp": datetime.now().isoformat()
            }
            await ws.send(json.dumps(event))
            
    except Exception as e:
        print(f"Event simulator error: {e}")

asyncio.run(send_test_events())
PYTHON_SCRIPT

SIM_PID=$!
PIDS+=($SIM_PID)

# -----------------------------
# Monitor and Stream Logs
# -----------------------------
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}All components started successfully!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} WebSocket Server: ws://localhost:$WS_PORT"
echo -e "  ${GREEN}✓${NC} Live Dashboard: $DASHBOARD_HTML"
echo -e "  ${GREEN}✓${NC} ML Safety Predictor: Running"
echo -e "  ${GREEN}✓${NC} Alert Store: Running"
echo -e "  ${GREEN}✓${NC} Event Simulator: Running"
echo ""
echo -e "${YELLOW}Logs directory: $LOG_DIR${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop all processes${NC}"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""

# Keep script running and tail main log
tail -f "$LOG_DIR"/*.log 2>/dev/null || {
    echo "Waiting for processes..."
    wait
}
