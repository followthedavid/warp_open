# Warp_Open

**A local-first, open-source terminal that combines Warp's modern UX with Claude Code's agentic AI capabilities.**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](./CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-53%20passing-brightgreen.svg)](./package.json)

---

## Why Warp_Open?

| Feature | Warp_Open | Warp | iTerm2/Terminal |
|---------|-----------|------|-----------------|
| **Local-first** | No cloud required | Cloud features | Local |
| **AI Assistant** | Ollama (free, local) | Paid API | None |
| **Command Blocks** | Full support | Full support | None |
| **Notebooks** | Full support | Partial | None |
| **Plugin System** | Extensible (v2 API) | Limited | None |
| **Open Source** | MIT License | Proprietary | Open Source |
| **Privacy** | 100% local | Cloud telemetry | Local |

---

## Features

### Terminal Experience

- **Command Blocks** - Group commands with collapsible output (OSC 133 + heuristics)
- **Split Panes** - Horizontal/vertical splits with drag-to-resize
- **Multi-Tab** - Full tab management with reordering
- **Session Recovery** - Auto-save and crash recovery
- **Terminal Recording** - Record and replay terminal sessions

### AI-Powered

- **Agent Mode** - Autonomous AI with tool execution (Read/Write/Edit/Bash/Grep/Glob)
- **AI Command Search** - Natural language to shell commands
- **Context-Aware** - Understands your working directory and recent output
- **100% Local** - Uses Ollama, no API keys required

### Workflows & Automation

- **Workflows/Snippets** - 15+ built-in workflows, create custom templates
- **Notebook Mode** - Jupyter-style execution with markdown cells
- **Export** - Export to JSON, Markdown, or shell scripts
- **Snapshots** - Save/restore workspace state with tags

### Developer Experience

- **Plugin System** - Extensible API v2 with permissions
- **Global Search** - Regex search across tabs and output
- **Analytics** - Command frequency and session metrics
- **107KB Documentation** - Complete rebuild from scratch possible

---

## Quick Start

### Prerequisites

- Node.js 18+
- Rust (latest stable)
- [Ollama](https://ollama.ai/) (for AI features)

### Installation

```bash
# Clone the repository
git clone https://github.com/warp-open/warp_open.git
cd warp_open/warp_tauri

# Install dependencies
npm install

# Start development mode
npm run tauri dev
```

### Production Build

```bash
npm run tauri build

# Output:
# macOS: src-tauri/target/release/bundle/macos/Warp_Open.app
# Linux: src-tauri/target/release/bundle/deb/*.deb
# Windows: src-tauri/target/release/bundle/msi/*.msi
```

### Setup Ollama (for AI features)

```bash
# Install Ollama
brew install ollama  # macOS
# or visit https://ollama.ai for other platforms

# Start Ollama
ollama serve

# Pull a coding model
ollama pull qwen2.5-coder:7b
```

---

## Keyboard Shortcuts

### Tabs & Panes

| Shortcut | Action |
|----------|--------|
| `Cmd+T` | New terminal tab |
| `Cmd+W` | Close current tab |
| `Cmd+1-9` | Jump to tab by number |
| `Cmd+Shift+D` | Split vertically |
| `Cmd+Shift+E` | Split horizontally |
| `Alt+Arrow` | Navigate between panes |

### Features

| Shortcut | Action |
|----------|--------|
| `Cmd+Shift+P` | Command Palette |
| `Cmd+Shift+F` | Global Search |
| `Cmd+Shift+A` | Toggle AI overlay |
| `Cmd+Shift+R` | Start/Stop Recording |
| `Cmd+/` | Keyboard shortcuts help |
| `Cmd+B` | Toggle sidebar |

---

## Architecture

```
Frontend (Vue 3 + TypeScript)
├── Composables (15+)
│   ├── usePty.ts          - PTY management
│   ├── useBlocks.ts       - Command grouping
│   ├── useNotebook.ts     - Notebook cells
│   ├── useTools.ts        - AI tool framework
│   ├── useAgentMode.ts    - Agentic AI loop
│   └── ...
├── Components (20+)
│   ├── TerminalPane.vue   - Terminal + AI overlay
│   ├── BlockList.vue      - Command blocks
│   ├── NotebookPanel.vue  - Notebook mode
│   ├── AgentPanel.vue     - AI assistant
│   └── ...
│
Backend (Rust + Tauri)
├── commands.rs            - PTY commands
├── ollama.rs              - LLM integration
├── session.rs             - Persistence
└── policy_store.rs        - Security policies
```

---

## Plugin System (API v2)

Warp_Open supports plugins for extending functionality:

```typescript
const MyPlugin: WarpPlugin = {
  name: 'My Plugin',
  version: '1.0.0',
  apiVersion: '2.0',
  pluginType: 'ui',

  init(context) {
    context.subscribe('command', (event) => {
      context.log.info(`Command: ${event.data.command}`);
    });
  },

  render(container, state) {
    container.innerHTML = '<div>Hello from plugin!</div>';
  },

  destroy() {
    console.log('Plugin destroyed');
  }
};
```

See [PLUGINS.md](./PLUGINS.md) for full documentation.

---

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](./docs/ARCHITECTURE.md) | System design and patterns |
| [BUILD_FROM_SCRATCH.md](./docs/BUILD_FROM_SCRATCH.md) | Complete rebuild guide |
| [COMPOSABLES_REFERENCE.md](./docs/COMPOSABLES_REFERENCE.md) | All Vue composables |
| [COMPONENTS_REFERENCE.md](./docs/COMPONENTS_REFERENCE.md) | All Vue components |
| [RUST_BACKEND.md](./docs/RUST_BACKEND.md) | All Rust commands |
| [DATA_STRUCTURES.md](./docs/DATA_STRUCTURES.md) | All TypeScript types |
| [PLUGINS.md](./PLUGINS.md) | Plugin API documentation |
| [V2_ROADMAP.md](./V2_ROADMAP.md) | Future features |
| [CHANGELOG.md](./CHANGELOG.md) | Version history |

---

## Technology Stack

**Frontend:**
- Vue 3 (Composition API)
- TypeScript
- Vite
- xterm.js + WebGL
- Monaco Editor

**Backend:**
- Tauri 1.x
- Rust
- portable-pty
- reqwest

**AI:**
- Ollama (local LLM)
- No cloud dependencies

---

## Performance

| Metric | Value |
|--------|-------|
| Cold start | < 1.5s |
| Core bundle (gzipped) | 63 KB |
| Terminal render | 60 FPS (WebGL) |
| 100k lines | 23ms render |
| Memory (base) | ~80 MB |
| Memory (10 tabs) | ~250 MB |

---

## Security

- **Local-first** - No data leaves your machine
- **XSS Protection** - DOMPurify sanitization
- **Plugin Sandboxing** - Permission-based API
- **PTY Isolation** - Each pane has its own PTY
- **Crash Recovery** - Panic logs with context

See [SECURITY_AUDIT.md](./SECURITY_AUDIT.md) for the full security audit.

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

```bash
# Run tests
npm test

# Run linter
npm run lint

# Build for development
npm run tauri dev
```

---

## License

MIT License - see [LICENSE](./LICENSE)

---

## Acknowledgments

- [Tauri](https://tauri.app/) - Desktop framework
- [xterm.js](https://xtermjs.org/) - Terminal emulation
- [Ollama](https://ollama.ai/) - Local LLM inference
- [Warp](https://warp.dev/) - Inspiration for terminal UX
- [Claude Code](https://claude.ai/) - Inspiration for agentic AI

---

## Links

- [GitHub Repository](https://github.com/warp-open/warp_open)
- [Documentation](./docs/README.md)
- [Changelog](./CHANGELOG.md)
- [Roadmap](./V2_ROADMAP.md)
