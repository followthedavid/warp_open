# Warp-Tauri Architecture Documentation

## Overview

Warp-Tauri is a modern terminal emulator that combines the best features of Warp terminal and Claude Code, running entirely locally without external API dependencies. It uses a Tauri (Rust) backend with a Vue 3 frontend.

## Technology Stack

### Frontend
- **Vue 3** (Composition API) - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool and dev server
- **xterm.js** - Terminal emulation
- **Monaco Editor** - Code editing
- **Vitest** - Unit testing

### Backend
- **Tauri 1.x** - Desktop application framework
- **Rust** - Backend language
- **portable-pty** - PTY (pseudo-terminal) management
- **reqwest** - HTTP client for Ollama
- **serde** - Serialization

### AI Integration
- **Ollama** - Local LLM runtime (no API keys required)
- Supported models: Qwen2.5-Coder, CodeLlama, DeepSeek-Coder, Llama 3.2

## Project Structure

```
warp_tauri/
├── src/                          # Vue frontend
│   ├── components/               # Vue components
│   ├── composables/              # Vue composables (state/logic)
│   ├── stores/                   # Pinia stores (if used)
│   ├── assets/                   # Static assets
│   ├── App.vue                   # Root component
│   └── main.ts                   # Entry point
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── main.rs              # Tauri entry point
│   │   ├── commands.rs          # Tauri commands
│   │   ├── pty.rs               # PTY management
│   │   ├── ollama.rs            # LLM integration
│   │   └── ...                  # Other modules
│   ├── Cargo.toml               # Rust dependencies
│   └── tauri.conf.json          # Tauri configuration
├── docs/                         # Documentation
├── tests/                        # E2E tests
└── package.json                  # Node dependencies
```

## Core Architecture Patterns

### 1. Composables Pattern
All state management and business logic is encapsulated in Vue composables (`use*.ts` files). This provides:
- Reusable, testable logic
- Reactive state management
- Clean separation of concerns

### 2. Command Pattern (Tauri)
Frontend-backend communication uses Tauri's invoke pattern:
```typescript
// Frontend
const result = await invoke<ReturnType>('command_name', { param1, param2 })

// Backend (Rust)
#[tauri::command]
pub fn command_name(param1: String, param2: i32) -> Result<ReturnType, String> {
    // Implementation
}
```

### 3. Event-Driven PTY
Terminal I/O uses Tauri events for real-time streaming:
```
Frontend → invoke('write_to_pty') → Backend
Backend → emit('pty-output') → Frontend
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         Vue Frontend                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Components  │──│  Composables │──│    Stores    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                  │                                     │
│         └──────────────────┴─────────────────────────────────┐  │
│                                                               │  │
│  ┌────────────────────────────────────────────────────────┐  │  │
│  │                    Tauri Bridge                         │  │  │
│  │        invoke() / emit() / listen()                     │  │  │
│  └────────────────────────────────────────────────────────┘  │  │
└──────────────────────────────────────────────────────────────┼──┘
                                                               │
┌──────────────────────────────────────────────────────────────┼──┐
│                        Rust Backend                          │  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │  │
│  │   Commands   │  │     PTY      │  │    Ollama    │       │  │
│  └──────────────┘  └──────────────┘  └──────────────┘       │  │
│         │                  │                  │               │  │
│  ┌──────┴──────────────────┴──────────────────┴──────────┐  │  │
│  │                   System Resources                      │  │  │
│  │         Files / Shell / Network / LLM                   │  │  │
│  └─────────────────────────────────────────────────────────┘  │  │
└───────────────────────────────────────────────────────────────┘  │
```

## Feature Modules

### Terminal Core
- **usePty.ts** - PTY creation, I/O, lifecycle
- **useTerminalBuffer.ts** - Output buffering, search, virtual scrolling
- **TerminalPane.vue** - xterm.js integration

### Warp Features
- **useBlocks.ts** - Command grouping with output
- **useAutocomplete.ts** - Command suggestions
- **useWorkflows.ts** - Saved command workflows
- **useNotebook.ts** - Jupyter-style notebooks
- **useAICommandSearch.ts** - Natural language → commands

### Claude Code Features
- **useTools.ts** - File/shell tool execution
- **useAgentMode.ts** - Agentic AI with tool loop

### UI Management
- **useTabs.ts** - Tab management
- **useSplitPane.ts** - Pane splitting
- **useTheme.ts** - Theming
- **useSnapshots.ts** - Workspace snapshots
- **useSessionStore.ts** - Session persistence

## Key Design Decisions

### 1. Local-First AI
All AI features use Ollama for local LLM inference. This ensures:
- No API costs
- Privacy (data never leaves machine)
- Works offline
- No rate limits

### 2. Composables over Stores
We prefer composables over Pinia stores because:
- More flexible composition
- Easier testing
- Better TypeScript inference
- Simpler mental model

### 3. PTY per Pane
Each terminal pane has its own PTY process. This provides:
- Process isolation
- Independent working directories
- Clean process cleanup

### 4. LocalStorage Persistence
User data (sessions, snapshots, workflows) uses localStorage:
- Simple implementation
- Works offline
- No database setup
- Sufficient for single-user app

### 5. XML Tool Format
AI tool calls use XML format for reliability:
```xml
<tool name="Read">
  <param name="path">/path/to/file</param>
</tool>
```
This format is more reliably generated by LLMs than JSON.

## Security Considerations

### Sandbox
Tauri runs with restricted permissions. The `tauri.conf.json` allowlist controls:
- File system access
- Shell execution
- Network access

### Input Validation
All Tauri commands validate inputs before execution.

### No Remote Code
The app doesn't download or execute remote code.

## Performance Optimizations

### Virtual Scrolling
Terminal buffer uses virtual scrolling for large outputs (100k+ lines).

### Debounced Updates
UI updates are debounced to prevent excessive re-renders.

### Code Splitting
Monaco editor and other large dependencies are lazily loaded.

### Buffer Limits
Terminal buffers are capped to prevent memory exhaustion.

## Testing Strategy

### Unit Tests (Vitest)
- All composables have unit tests
- Mock Tauri invoke for isolation
- Test reactive state changes

### E2E Tests (Playwright)
- Full application flows
- Real terminal interaction
- Snapshot testing

## Deployment

### Development
```bash
npm install
npm run tauri dev
```

### Production Build
```bash
npm run tauri build
```

Produces platform-specific installers in `src-tauri/target/release/bundle/`.
