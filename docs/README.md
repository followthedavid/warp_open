# Warp-Tauri Documentation

Complete documentation for rebuilding and understanding the Warp-Tauri terminal application.

## Quick Start

```bash
# Install dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build

# Run tests
npm test
```

## Documentation Index

### Core Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System overview, design patterns, technology stack |
| [BUILD_FROM_SCRATCH.md](./BUILD_FROM_SCRATCH.md) | Complete guide to rebuild from zero |
| [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) | All TypeScript interfaces and types |

### Reference Documentation

| Document | Description |
|----------|-------------|
| [COMPOSABLES_REFERENCE.md](./COMPOSABLES_REFERENCE.md) | All Vue composables with APIs |
| [COMPONENTS_REFERENCE.md](./COMPONENTS_REFERENCE.md) | All Vue components with props/events |
| [RUST_BACKEND.md](./RUST_BACKEND.md) | All Tauri commands and Rust modules |

### Feature Documentation

| Feature | Composable | Components |
|---------|------------|------------|
| Terminal | `usePty.ts`, `useTerminalBuffer.ts` | `TerminalPane.vue` |
| Blocks | `useBlocks.ts` | `BlockList.vue`, `CommandBlock.vue`, `BlockHeader.vue`, `BlockBody.vue` |
| Autocomplete | `useAutocomplete.ts` | `AutocompleteDropdown.vue` |
| Workflows | `useWorkflows.ts` | `WorkflowPanel.vue`, `WorkflowCard.vue` |
| Notebooks | `useNotebook.ts` | `NotebookPanel.vue`, `NotebookCell.vue` |
| AI Search | `useAICommandSearch.ts` | `AICommandSearch.vue` |
| Tools | `useTools.ts` | (used by AgentPanel) |
| Agent | `useAgentMode.ts` | `AgentPanel.vue` |
| Tabs | `useTabs.ts` | `TabBar.vue`, `Tab.vue` |
| Panes | `useSplitPane.ts` | `SplitPaneContainer.vue` |
| Theme | `useTheme.ts` | (global CSS variables) |
| Sessions | `useSessionStore.ts` | (persistence layer) |
| Snapshots | `useSnapshots.ts` | `SnapshotPanel.vue` |

## Project Structure

```
warp_tauri/
├── src/                          # Vue frontend
│   ├── components/               # Vue components
│   │   ├── TerminalPane.vue      # Main terminal
│   │   ├── BlockList.vue         # Block mode
│   │   ├── NotebookPanel.vue     # Notebook mode
│   │   ├── AgentPanel.vue        # AI assistant
│   │   ├── WorkflowPanel.vue     # Workflows
│   │   └── ...
│   ├── composables/              # Vue composables
│   │   ├── usePty.ts             # PTY management
│   │   ├── useBlocks.ts          # Block detection
│   │   ├── useNotebook.ts        # Notebook logic
│   │   ├── useTools.ts           # Tool framework
│   │   ├── useAgentMode.ts       # Agent AI
│   │   └── ...
│   ├── App.vue                   # Root component
│   └── main.ts                   # Entry point
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── main.rs               # Tauri entry
│   │   ├── pty.rs                # PTY module
│   │   ├── ollama.rs             # LLM integration
│   │   └── commands.rs           # File/shell commands
│   └── Cargo.toml                # Rust deps
├── docs/                         # Documentation
├── tests/                        # E2E tests
└── package.json                  # Node deps
```

## Feature Overview

### Warp Features (100%)

| Feature | Status | Description |
|---------|--------|-------------|
| Blocks | ✅ | Command grouping with collapsible output |
| Autocomplete | ✅ | Commands, paths, git/npm subcommands |
| Workflows | ✅ | Saved command templates with parameters |
| Notebooks | ✅ | Jupyter-style cell execution |
| AI Search | ✅ | Natural language to shell commands |
| Themes | ✅ | Dark/light mode, custom colors |
| Split Panes | ✅ | Horizontal/vertical splits |
| Tabs | ✅ | Multiple terminal sessions |
| Snapshots | ✅ | Save/restore workspace state |

### Claude Code Features (100%)

| Feature | Status | Description |
|---------|--------|-------------|
| Tool Framework | ✅ | Read/Write/Edit/Bash/Grep/Glob tools |
| Agent Mode | ✅ | Agentic AI with tool execution loop |
| File Operations | ✅ | Read, write, edit files via Rust |
| Search | ✅ | Grep and glob patterns |
| Shell Execution | ✅ | Command execution with output |

### AI Integration

All AI features use **Ollama** for local LLM inference:
- No API keys required
- Works offline
- Privacy (data stays local)
- Supported models: Qwen2.5-Coder, CodeLlama, DeepSeek-Coder, Llama 3.2

## Technology Stack

### Frontend
- Vue 3 (Composition API)
- TypeScript
- Vite
- xterm.js (terminal emulation)
- Monaco Editor (code editing)

### Backend
- Tauri 1.x (desktop framework)
- Rust
- portable-pty (PTY management)
- reqwest (HTTP client)

### Testing
- Vitest (unit tests)
- Playwright (E2E tests)

## Key Design Decisions

1. **Local-First AI** - Ollama for LLM inference, no cloud dependencies
2. **Composables over Stores** - State in composables for flexibility
3. **PTY per Pane** - Process isolation for terminal sessions
4. **LocalStorage Persistence** - Simple, offline-capable storage
5. **XML Tool Format** - Reliable LLM tool call parsing

## Building

### Development
```bash
npm run tauri dev
```

### Production
```bash
npm run tauri build
```

### Testing
```bash
npm test
```

## Contributing

1. Read the architecture documentation
2. Follow existing patterns for composables and components
3. Add tests for new features
4. Update documentation for API changes

## License

[Your License Here]
