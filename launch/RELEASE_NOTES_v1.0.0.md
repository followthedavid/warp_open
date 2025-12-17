# Warp_Open v1.0.0 - Initial Release

**The open-source Warp Terminal clone with Claude Code AI capabilities**

## Highlights

- **Warp-style command blocks** - Output organized in collapsible blocks, not endless scroll
- **Agentic AI assistant** - Reads, writes, and executes code locally via Ollama
- **Plugin API v2** - Build custom extensions with full TypeScript support
- **100% local** - Your code never leaves your machine

## Features

### Terminal Core
- Command block interface with OSC 133 shell integration
- WebGL-accelerated rendering via xterm.js
- 60 FPS performance, 100k lines in 23ms
- Keyboard navigation and search

### AI Assistant
- Tool use: Read, Write, Edit, Bash, Grep, Glob
- Context-aware code generation
- Multi-file project understanding
- Ollama integration (qwen2.5-coder, llama, etc.)

### Official Plugins
- **Git Insights** - Real-time repo status in sidebar
- **Command Linter** - Protect against dangerous commands
- **Session Annotator** - Tag and annotate commands for docs
- **Command Timer** - Track execution times with stats

### Maintainer Tools
- **Notification Agent** - Real-time alerts for stars, issues, PRs
- **Auto-Tagger** - Automatically label GitHub issues
- **Response Suggester** - AI-powered response drafts
- **Metrics Dashboard** - ASCII dashboard of project health

## Tech Stack
- **Backend:** Tauri + Rust (~10MB binary)
- **Frontend:** Vue 3 + TypeScript
- **Terminal:** xterm.js + WebGL
- **AI:** Ollama (local LLM)
- **Build:** Vite

## Getting Started

```bash
# Clone
git clone https://github.com/followthedavid/warp_open.git
cd warp_open

# Install dependencies
npm install

# Run in dev mode
npm run tauri:dev
```

### Set up AI
```bash
brew install ollama
ollama serve
ollama pull qwen2.5-coder:7b
```

## Documentation
- [Getting Started Guide](./docs/GETTING_STARTED.md)
- [Plugin Development Guide](./docs/PLUGIN_DEV_GUIDE.md)

## What's Next
- SSH integration
- Windows/Linux binaries
- Plugin marketplace
- More AI model support

## License
MIT

---

Built with Tauri, Vue 3, and Claude Code assistance.
