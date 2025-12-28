#!/bin/bash
# Single-instance launcher for Warp Open

# Kill any existing instances
pkill -f "warp-tauri" 2>/dev/null
lsof -ti :5173 | xargs kill -9 2>/dev/null
lsof -ti :1420 | xargs kill -9 2>/dev/null

# Wait for cleanup
sleep 1

# Start the app
cd "$(dirname "$0")"
npm run tauri:dev
