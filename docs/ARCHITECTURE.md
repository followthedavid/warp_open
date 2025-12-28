# Warp_Open Architecture Documentation

## Overview

Warp_Open is a local-first, AI-powered terminal that achieves **100% feature parity** with Warp Terminal and Claude Code without requiring external API calls. All AI inference runs locally via Ollama.

---

## Technology Stack

### Backend (Rust + Tauri)
- **Tauri 1.5** - Desktop application framework
- **tokio** - Async runtime
- **rusqlite** - SQLite database for session persistence
- **ssh2** - SSH client library
- **reqwest** - HTTP client for Ollama
- **serde** - Serialization
- **html2text** - Web content extraction

### Frontend (Vue 3 + TypeScript)
- **Vue 3.3** - Reactive UI framework
- **xterm.js 5.3** - Terminal emulation with WebGL
- **Monaco Editor** - Code editing
- **Vite** - Build tooling
- **Composition API** - All composables use Vue 3 Composition API

### AI Stack (Local-Only)
- **Ollama** - LLM inference server
- **Models**: llama3.1:8b, qwen2.5:3b, deepseek-coder:6.7b
- **Embeddings**: nomic-embed-text (semantic search)
- **Vision**: llava, bakllava (image understanding)
- **Voice**: Web Speech API / whisper.cpp

---

## Directory Structure

```
warp_tauri/
├── src/                          # Vue frontend
│   ├── components/               # 51+ Vue components
│   │   ├── TerminalPane.vue      # Main terminal UI
│   │   ├── AIChat.vue            # AI conversation panel
│   │   ├── AutocompleteDropdown  # Tab completion UI
│   │   ├── CommandPalette.vue    # Cmd+K palette
│   │   └── ...
│   ├── composables/              # 50+ Vue composables
│   │   ├── useAI.ts              # AI interaction
│   │   ├── usePlanningMode.ts    # Planning mode
│   │   ├── useHooks.ts           # PreToolUse/PostToolUse
│   │   ├── useSubAgents.ts       # Sub-agent delegation
│   │   ├── useCodebaseEmbeddings.ts  # Semantic search
│   │   ├── useBackgroundTasks.ts # Background processes
│   │   ├── useVoiceInput.ts      # Speech-to-text
│   │   ├── useImageUnderstanding.ts  # Vision AI
│   │   ├── useNextCommandPrediction.ts  # Command suggestions
│   │   ├── useMCPServers.ts      # MCP protocol support
│   │   ├── useSecretRedaction.ts # Secret masking
│   │   ├── useSlashCommands.ts   # Slash command system
│   │   └── ...
│   └── App.vue                   # Main application
├── src-tauri/                    # Rust backend
│   └── src/
│       ├── main.rs               # Tauri entry point
│       ├── commands.rs           # 4000+ lines of Tauri commands
│       ├── conversation.rs       # Conversation state + CLAUDE.md
│       ├── pty.rs                # PTY management
│       ├── ssh_session.rs        # SSH client
│       ├── ollama.rs             # Ollama integration
│       └── scaffolding/          # 13 modules for LLM enhancement
│           ├── mod.rs            # Module registry
│           ├── json_repair.rs    # JSON fixing
│           ├── tool_parser.rs    # Tool call extraction
│           ├── self_correction.rs # Error recovery
│           └── ...
└── docs/                         # Documentation
    ├── ARCHITECTURE.md           # This file
    ├── FEATURES.md               # Feature list
    └── PARITY_PLAN.md            # Parity roadmap
```

---

## Core Systems

### 1. Terminal Emulation
- **xterm.js** with WebGL rendering for 60fps performance
- OSC 133 shell integration for command blocks
- ANSI/VT100 full compatibility
- Unicode and emoji support

### 2. PTY Management (`pty.rs`)
- Manages pseudo-terminals for shell interaction
- Background process support
- Session persistence and crash recovery
- Cross-platform (macOS, Linux, Windows)

### 3. AI Tool System
Seven core tools for agentic AI:

| Tool | Description |
|------|-------------|
| `glob_files` | Find files by pattern |
| `grep_files` | Search content in files |
| `read_file` | Read file contents |
| `write_file` | Create/overwrite files |
| `edit_file` | Surgical string replacement |
| `execute_shell` | Run shell commands |
| `web_fetch` | Fetch web page content |

### 4. Scaffolding System (13 Modules)
Enhances local LLM reliability:

1. **json_repair** - Fix malformed JSON from LLM
2. **tool_parser** - Extract tool calls from responses
3. **self_correction** - Retry on errors with feedback
4. **context_manager** - Manage conversation context
5. **prompt_templates** - System prompts for tools
6. **validation** - Validate tool arguments
7. **rate_limiter** - Prevent API abuse
8. **cache** - Response caching
9. **streaming** - SSE streaming handler
10. **error_recovery** - Graceful error handling
11. **model_router** - Select best model for task
12. **memory** - Long-term memory storage
13. **metrics** - Performance monitoring

### 5. Conversation Management (`conversation.rs`)
- Per-tab conversation history
- Project context loading (CLAUDE.md)
- SQLite persistence
- Context window management
- Automatic summarization

### 6. Slash Commands (`useSlashCommands.ts`)
30+ built-in commands:

| Category | Commands |
|----------|----------|
| System | `/compact`, `/context`, `/model`, `/reset`, `/resume` |
| Git | `/catchup`, `/diff`, `/status`, `/commit` |
| Files | `/review`, `/explain`, `/fix`, `/test` |
| Project | `/init`, `/plan`, `/todo` |
| Debug | `/debug`, `/errors`, `/performance` |
| Help | `/help`, `/docs`, `/examples` |

### 7. Secret Redaction (`useSecretRedaction.ts`)
Automatically masks:
- AWS keys, GitHub tokens
- OpenAI/Anthropic API keys
- Database connection URLs
- JWT tokens, private keys
- Environment variables with secrets

### 8. Safety & Policy System
- Command classification (safe/warn/block)
- Dangerous command approval workflow
- Sandbox mode for untrusted contexts
- Audit logging

---

## Claude Code Parity Features

### Planning Mode (`usePlanningMode.ts`)
- Enter planning mode before complex tasks
- Step-by-step plan creation
- Plans saved to `~/.warp_open/plans/` as Markdown
- Plan approval workflow
- Progress tracking during execution

### Hooks System (`useHooks.ts`)
- **PreToolUse** hooks: Validate/block/transform before tool execution
- **PostToolUse** hooks: Log/audit after tool execution
- Built-in security hooks (block .env writes, warn on rm -rf)
- Custom hook registration
- Pattern matching with regex

### Sub-Agents (`useSubAgents.ts`)
Spawn specialized agents for task delegation:

| Agent | Purpose | Tools |
|-------|---------|-------|
| explore | Codebase exploration | glob, grep, read |
| review | Code review | read, grep |
| test | Generate tests | read, write, shell |
| document | Generate docs | read, write, edit |
| refactor | Refactor code | read, edit, grep |
| debug | Debug issues | read, grep, shell |
| research | Web research | web_fetch, shell |
| plan | Create plans | glob, grep, read |

### Codebase Embeddings (`useCodebaseEmbeddings.ts`)
- Semantic search using local nomic-embed-text
- Index entire codebase by file type
- Chunking with overlap
- Cosine similarity search
- Context retrieval for AI

### Background Tasks (`useBackgroundTasks.ts`)
- Run long processes without blocking AI
- Task queue with priorities
- Output streaming
- Task cancellation
- Status monitoring

---

## Warp Terminal Parity Features

### Voice Input (`useVoiceInput.ts`)
- Web Speech API for browser
- Whisper.cpp for local transcription
- Voice commands registration
- Audio level visualization
- Multi-language support

### Image Understanding (`useImageUnderstanding.ts`)
- Screenshot capture and analysis
- Clipboard image processing
- Code extraction from images (OCR)
- UI/diagram description
- LLaVA/BakLLaVA vision models

### Next Command Prediction (`useNextCommandPrediction.ts`)
- Pattern-based suggestions (git, npm, docker, etc.)
- Error recovery suggestions
- AI-powered predictions
- Command history learning
- Context-aware (project type, git status)

### MCP Server Support (`useMCPServers.ts`)
- Model Context Protocol compatibility
- Connect to external MCP servers
- stdio/HTTP/WebSocket transports
- Tool/Resource/Prompt discovery
- Built-in server configs (filesystem, GitHub, Postgres)

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     Vue Frontend                              │
├─────────────────────────────────────────────────────────────┤
│  TerminalPane.vue  │  AIChat.vue  │  Components              │
│         │                │               │                    │
│         └────────────────┴───────────────┘                    │
│                          │                                    │
│              Composables (useAI, useHooks, etc.)              │
│                          │                                    │
│                    Tauri invoke()                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     Rust Backend                              │
├─────────────────────────────────────────────────────────────┤
│  commands.rs  │  conversation.rs  │  pty.rs  │  ollama.rs    │
│       │               │                │           │          │
│       └───────────────┴────────────────┴───────────┘          │
│                          │                                    │
│                   Scaffolding System                          │
│                          │                                    │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   External Services                           │
├─────────────────────────────────────────────────────────────┤
│     Ollama (localhost:11434)  │  Shell (PTY)  │  MCP Servers  │
└─────────────────────────────────────────────────────────────┘
```

---

## Session Persistence

### SQLite Schema
```sql
-- Conversations
CREATE TABLE conversations (
  id TEXT PRIMARY KEY,
  tab_id TEXT,
  created_at INTEGER,
  updated_at INTEGER
);

-- Messages
CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT,
  role TEXT, -- 'user', 'assistant', 'system'
  content TEXT,
  timestamp INTEGER,
  FOREIGN KEY (conversation_id) REFERENCES conversations(id)
);

-- Tool Calls
CREATE TABLE tool_calls (
  id TEXT PRIMARY KEY,
  message_id TEXT,
  tool_name TEXT,
  arguments TEXT,
  result TEXT,
  FOREIGN KEY (message_id) REFERENCES messages(id)
);
```

---

## Configuration

### Project Context Files
Loaded in order of priority:
1. `CLAUDE.md`
2. `WARP.md`
3. `.claude/project.md`
4. `.warp/project.md`
5. `PROJECT.md`

### Settings Storage
- `localStorage` for frontend settings
- `~/.warp_open/` for persistent data:
  - `plans/` - Saved plans
  - `sessions/` - Session backups
  - `hooks.json` - Custom hooks
  - `mcp_servers.json` - MCP configs

---

## Performance Optimizations

1. **WebGL Terminal** - 60fps rendering
2. **Response Streaming** - SSE for real-time output
3. **Debounced Autocomplete** - 300ms delay
4. **Lazy Loading** - Components loaded on demand
5. **Embedding Cache** - Avoid re-indexing unchanged files
6. **Model Routing** - Use small models for simple tasks

---

## Security Considerations

1. **Local-Only AI** - No data leaves the machine
2. **Secret Redaction** - Auto-mask sensitive data
3. **Hook Validation** - Block dangerous operations
4. **Sandbox Mode** - Restricted permissions
5. **Audit Logging** - Track all tool executions
6. **File Pattern Exclusions** - Don't index secrets

---

## Testing

```bash
# Run all tests
npm test

# Run specific test suite
npm test -- --grep "AI Tools"

# E2E tests
npm run test:e2e
```

---

## Building

```bash
# Development
npm run tauri:dev

# Production build
npm run tauri:build

# Platform-specific
npm run tauri:build -- --target aarch64-apple-darwin
npm run tauri:build -- --target x86_64-unknown-linux-gnu
```

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

MIT License - See [LICENSE](../LICENSE)
