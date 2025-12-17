#!/usr/bin/env bash
# run_phase1_6_auto_live.sh
# Fully automated Phase 1–6 runner with live dashboard

set -euo pipefail

APP_DIR="${APP_DIR:-$(pwd)/src-tauri}"
LOG_FILE="/tmp/warp_phase1_6_auto_live.log"
HTML_DASH="/tmp/warp_phase1_6_live.html"
DB_PATH="${DB_PATH:-$(pwd)/phase1_6_test.db}"

echo "╔════════════════════════════════════════╗"
echo "║ Warp Phase 1–6 Automated Test Runner  ║"
echo "╚════════════════════════════════════════╝"

# Cleanup previous instances
echo "Cleaning up previous instances..."
pkill -f 'Warp_Open' >/dev/null 2>&1 || true
rm -f "$LOG_FILE"
sleep 1

# Generate database if it doesn't exist
if [[ ! -f "$DB_PATH" ]]; then
    echo "Generating Phase 1–6 test database..."
    python3 "$(dirname "$0")/generate_phase1_6_db.py"
fi

echo "✅ Test database ready at: $DB_PATH"

# Copy dashboard HTML to temp location
BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$BUNDLE_DIR/batch6_dashboard/index.html" "$HTML_DASH"
echo "✅ Dashboard copied to: $HTML_DASH"

# Check if Tauri app exists
if [[ -d "$APP_DIR" ]]; then
    echo "Launching Warp_Open Tauri app..."
    cd "$APP_DIR"
    npm run tauri dev > "$LOG_FILE" 2>&1 &
    APP_PID=$!
    echo "Tauri PID: $APP_PID"
    
    # Wait for app initialization
    echo "Waiting 10 seconds for app startup..."
    sleep 10
    echo "✅ Tauri app running"
    
    echo "Opening dashboard..."
    if command -v open >/dev/null 2>&1; then
        open "$HTML_DASH"
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$HTML_DASH"
    else
        echo "⚠️ Please open $HTML_DASH manually in your browser"
    fi
    
    echo ""
    echo "Dashboard is available at: $HTML_DASH"
    echo "Logs are being written to: $LOG_FILE"
    echo ""
    echo "Tailing logs (press Ctrl+C to stop)..."
    tail -f "$LOG_FILE"
else
    echo "⚠️ Tauri app directory not found at: $APP_DIR"
    echo "Opening dashboard in standalone mode..."
    
    if command -v open >/dev/null 2>&1; then
        open "$HTML_DASH"
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$HTML_DASH"
    fi
    
    echo ""
    echo "Dashboard opened at: $HTML_DASH"
    echo "Running in standalone simulation mode."
    echo ""
    echo "To use with Tauri, set APP_DIR environment variable:"
    echo "export APP_DIR=/path/to/warp_tauri/src-tauri"
fi
