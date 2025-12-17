#!/bin/bash

# Warp_Open with Ollama - Quick Start Script
# This script ensures Ollama is running and starts your app

set -e

echo "🚀 Starting Warp_Open with Ollama Integration"
echo "=============================================="
echo ""

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "❌ Ollama not found. Please install it first:"
    echo "   brew install ollama"
    exit 1
fi

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags &> /dev/null; then
    echo "⚠️  Ollama is not running. Starting it now..."
    echo ""

    # Start Ollama in background
    ollama serve &
    OLLAMA_PID=$!

    # Wait for Ollama to start
    echo "   Waiting for Ollama to start..."
    for i in {1..30}; do
        if curl -s http://localhost:11434/api/tags &> /dev/null; then
            echo "   ✅ Ollama started successfully (PID: $OLLAMA_PID)"
            break
        fi
        sleep 1
    done
else
    echo "✅ Ollama is already running"
fi

# Check available models
echo ""
echo "📦 Available models:"
ollama list | grep -E "deepseek-coder|llama3|qwen" || echo "   (No models found - will use default)"

echo ""
echo "🎨 Starting Warp_Open app..."
echo ""

# Change to the app directory
cd "$(dirname "$0")"

# Start the app
npm run tauri:dev

# Note: If you started Ollama, you might want to stop it manually later with:
# kill $OLLAMA_PID
