#!/bin/bash
# Quick Start Script for Warp AI Terminal

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "🚀 Starting Warp AI Terminal..."
echo ""

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "⚠️  Ollama is not running!"
    echo "   Start it in another terminal with: ollama serve"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ Ollama is running"
    
    # Check if model is available
    if curl -s http://localhost:11434/api/tags | grep -q "deepseek-coder:6.7b"; then
        echo "✅ Model deepseek-coder:6.7b is available"
    else
        echo "⚠️  Recommended model not found"
        echo "   Download it with: ollama pull deepseek-coder:6.7b"
    fi
fi

echo ""
echo "🏗️  Starting Tauri development server..."
echo "   This may take a moment on first run..."
echo ""

npm run tauri:dev
