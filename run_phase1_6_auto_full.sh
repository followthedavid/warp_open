#!/usr/bin/env bash
# run_phase1_6_auto_full.sh
# Fully automated Phase 1–6 runner with live dashboard auto-start

set -euo pipefail

APP_DIR="/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri"
LOG_FILE="/tmp/warp_phase1_6_auto.log"
HTML_DASH="/tmp/warp_phase1_6_live.html"

echo "╔════════════════════════════════════════╗"
echo "║ Starting Full Phase 1–6 Auto Test     ║"
echo "╚════════════════════════════════════════╝"

# Cleanup previous runs
echo "Cleaning up previous instances..."
pkill -f 'Warp_Open' >/dev/null 2>&1 || true
sleep 1
rm -f "$LOG_FILE" "$HTML_DASH"

# Launch Tauri app
echo "Launching Warp_Open Tauri app..."
cd "$APP_DIR"
npm run tauri dev > "$LOG_FILE" 2>&1 &
APP_PID=$!
echo "Tauri PID: $APP_PID"

# Wait for app initialization
echo "Waiting 10 seconds for app startup..."
sleep 10
echo "✅ Tauri app running."

# Create live dashboard with auto-start Phase 1–6 test
cat <<'EOF' > "$HTML_DASH"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Warp Phase 6 Live Monitor</title>
<style>
body { background:black; color:#0f0; font-family: monospace; padding:10px;}
#log { white-space: pre; height:80vh; overflow-y:auto; border:1px solid #0f0; padding:8px;}
</style>
</head>
<body>
<h2>Warp Phase 6 Live Events</h2>
<div id="log">Connecting to Tauri events...</div>
<script type="module">
const logDiv = document.getElementById('log');
function appendLog(msg) {
    logDiv.textContent += msg + "\n";
    logDiv.scrollTop = logDiv.scrollHeight;
}
import { listen } from '@tauri-apps/api/event'
listen('phase1_6_log', event => appendLog(event.payload));

// Auto-start the full Phase 1–6 test
window.addEventListener('DOMContentLoaded', async () => {
    appendLog("Auto-starting full Phase 1–6 test...");
    try {
        await window.__TAURI__.tauri.invoke("run_phase1_6_auto");
    } catch (e) {
        appendLog("Error invoking backend: " + e);
    }
});
</script>
</body>
</html>
EOF

echo "Live dashboard created at $HTML_DASH"

# Open the dashboard in default browser or Tauri WebView
if command -v open >/dev/null; then
    open "$HTML_DASH"
elif command -v xdg-open >/dev/null; then
    xdg-open "$HTML_DASH"
else
    echo "⚠️ Could not open dashboard automatically. Open manually: $HTML_DASH"
fi

# Tail logs in real-time
echo "Monitoring logs..."
tail -f "$LOG_FILE"
