# Warp_Open Architecture

## Overview

Warp_Open is a modern terminal emulator built with:
- **Frontend**: Vue 3 + TypeScript
- **Backend**: Rust (Tauri framework)
- **Terminal**: xterm.js with WebGL acceleration

## Directory Structure

```
src/
├── components/          # Vue components
│   ├── TerminalPane.vue    # Terminal rendering & PTY integration
│   ├── LayoutRenderer.vue  # Split pane layouts
│   ├── TabBar.vue          # Tab management
│   ├── AIOverlay.vue       # AI assistant overlay
│   ├── GlobalSearch.vue    # Global search modal
│   ├── SnapshotsPanel.vue  # Workspace snapshots
│   ├── RecordingControls.vue # Recording UI
│   ├── PluginPanel.vue     # Plugin management
│   ├── PluginDevConsole.vue # Plugin developer tools
│   └── ...
│
├── composables/         # Vue composables (reactive state)
│   ├── useTabs.ts          # Tab/pane management
│   ├── useSnapshots.ts     # Workspace snapshots
│   ├── useRecording.ts     # Terminal recording
│   ├── useReplay.ts        # Recording playback
│   ├── useTerminalBuffer.ts # Large scrollback buffer
│   ├── useSessionStore.ts  # Session persistence
│   ├── useAnalytics.ts     # Usage analytics
│   ├── useAI.ts            # AI integration
│   ├── useToast.ts         # Toast notifications
│   ├── useTheme.ts         # Theme management
│   ├── usePreferences.js   # User preferences
│   └── useSecuritySettings.ts # Security controls
│
├── plugins/             # Plugin system
│   ├── types.ts            # Plugin interfaces
│   ├── PluginManager.ts    # Plugin lifecycle
│   └── index.ts            # Plugin exports
│
└── App.vue              # Main application entry
```

## Core Concepts

### 1. Terminal Management

**TerminalPane.vue** manages each terminal instance:
- Creates xterm.js Terminal with WebGL renderer
- Connects to Rust PTY via Tauri IPC
- Handles OSC sequences (CWD, clipboard, hyperlinks)
- Integrates with TerminalBuffer for large scrollback

**useTerminalBuffer.ts** provides:
- Line-based buffer abstraction (100k+ lines)
- Windowed rendering for performance
- Full-buffer search indexing
- Export/import for recordings

### 2. Layout System

**useTabs.ts** manages:
- Tab creation/deletion
- Pane splitting (horizontal/vertical)
- Active pane tracking
- Split ratios persistence

**LayoutRenderer.vue**:
- Recursive layout rendering
- Drag-to-resize splits
- Double-click to reset ratios

### 3. Session Management

**useSnapshots.ts**:
- Save complete workspace state
- Tag and search snapshots
- Export/import JSON
- Auto-snapshot on exit

**useSessionStore.ts**:
- Persists session for crash recovery
- Stores CWDs and layout
- Opt-in auto-recovery

### 4. Recording System

**useRecording.ts**:
- Captures PTY output/input
- Records terminal size changes
- Command boundary markers
- Export to gist-compatible JSON

**useReplay.ts**:
- Playback with speed control
- Seek to timestamps
- Jump to command boundaries

### 5. Plugin System

**Plugin Architecture**:
- Sandboxed execution environment
- Permission-based API access
- Read-only PTY access
- Event subscription model

**Permissions**:
- `read-output`: PTY output events
- `read-session`: Session metadata
- `read-commands`: Command history
- `write-clipboard`: Clipboard write (user confirmation)
- `render-panel`: Side panel rendering

## Data Flow

```
┌─────────────────┐
│   User Input    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  TerminalPane   │──► Recording System
└────────┬────────┘
         │
         ▼ (IPC)
┌─────────────────┐
│   Rust Backend  │
│   PTY Manager   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Shell       │
└─────────────────┘
```

## Performance Optimizations

1. **WebGL Renderer**: GPU-accelerated terminal rendering
2. **Batched Writes**: Throttled output for high-throughput
3. **Virtual Scrolling**: Line buffer with windowed rendering
4. **Event-Driven PTY**: Replaced polling with Tauri events
5. **Debounced Resize**: Reduces resize IPC calls

## Security Model

1. **PTY Isolation**: Each pane has isolated PTY
2. **Plugin Sandbox**: No direct PTY write access
3. **Clipboard Control**: OSC 52 read blocked
4. **Permission System**: Explicit grants for plugins
5. **Air-Gapped Mode**: Disable AI/network features

## State Persistence

| Feature | Storage | Key |
|---------|---------|-----|
| Preferences | localStorage | `warp-preferences` |
| Snapshots | localStorage | `warp_open_snapshots` |
| Sessions | localStorage | `warp_session_state` |
| Recordings | localStorage | `warp_recordings` |
| Plugin State | localStorage | `warp_plugin_states` |
| AI History | localStorage | `ai_conversation_*` |

## Testing

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report
```

Test files:
- `src/composables/*.test.ts` - Unit tests
- `src/__tests__/*.test.ts` - Integration tests

## Build & Development

```bash
npm run dev           # Development server
npm run build         # Production build
npm run tauri dev     # Tauri development
npm run tauri build   # Tauri production build
```

## Contributing

1. Follow existing patterns in composables
2. Add tests for new features
3. Update this document for architectural changes
4. Run `npm run build` before committing
