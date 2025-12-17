# Warp_Open - Build & Run Guide

## Quick Start

### Run the built app
```bash
/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src-tauri/target/release/Warp_Open
```

### Run in background with logging
```bash
/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src-tauri/target/release/Warp_Open > /tmp/warp_open.log 2>&1 &
```

### Check logs
```bash
tail -f /tmp/warp_open.log
```

## Development

### Frontend changes only (TypeScript/Vue)
```bash
npm run build
# Then restart the app
```

### Backend changes only (Rust)
```bash
cargo build --manifest-path=src-tauri/Cargo.toml --release
# Then restart the app
```

### Full rebuild
```bash
npm run tauri build
```

### Dev mode with hot reload
```bash
npm run tauri dev
```

## Current Configuration

- **AI Model**: qwen2.5:3b via Ollama (localhost:11434)
- **Bundling**: Disabled (`tauri.conf.json`: `bundle.active: false`)
- **Product Name**: Warp_Open
- **Binary Location**: `src-tauri/target/release/Warp_Open`

## Recent Fixes

### AI Tool Calling & Follow-up (2025-01-17)
- **Problem 1**: AI was generating multiple JSON tool calls concatenated with `>` symbols
  - **Solution**: Updated system prompt, added brace-counting JSON parser, Ollama parameters (temp: 0.1, stop sequences, limited output)
  
- **Problem 2**: AI executed tools but didn't answer the original question
  - **Solution**: After tool execution, automatically trigger new AI query with full conversation history to interpret results
  
- **Problem 3**: Tool calls and results were hard to distinguish visually
  - **Solution**: Added visual indicators (🔧 for tool calls, 📋 for results), color-coded borders, formatted JSON display

- **Problem 4**: Tilde (~) not expanding to home directory
  - **Solution**: Added shellexpand crate to read_file and write_file commands

### App Bundling (2025-01-17)
- Enabled macOS app bundling (creates .dmg installer)
- Installed to /Applications/Warp_Open.app
- Can be launched via Spotlight or Dock

## Prerequisites

- Ollama installed and running: `ollama serve`
- Model pulled: `ollama pull qwen2.5:3b`

## Troubleshooting

### App won't start
```bash
# Check if already running
ps aux | grep Warp_Open | grep -v grep
# Kill if needed
pkill -f Warp_Open
```

### AI not responding
```bash
# Check Ollama status
curl http://localhost:11434/api/tags
# Start Ollama if needed
ollama serve
```

### Frontend changes not reflected
```bash
# Rebuild frontend
npm run build
# Ensure binary is loading from correct dist directory
ls -la dist/
```
