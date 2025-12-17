# Warp_Open v2.0 Roadmap

This roadmap outlines planned features for v2.0 and beyond. All v1.0 core functionality is complete - these are enhancement features.

## Priority Legend

- **P0** - Critical for v2.0
- **P1** - High priority
- **P2** - Medium priority
- **P3** - Nice to have

---

## 1. Collaboration Features

### Real-Time Terminal Sharing (P1)

**Goal:** Allow multiple users to view/interact with the same terminal session.

**Components:**
- WebSocket server for session sync
- User presence indicators
- Cursor tracking for multiple users
- Permission levels (view-only, interactive)

**Files to Create:**
```
src/composables/useCollaboration.ts
src/components/CollaborationPanel.vue
src/components/UserPresence.vue
src-tauri/src/collab.rs
```

**Technical Approach:**
- CRDT-based state synchronization
- WebSocket transport layer
- Optional peer-to-peer via WebRTC
- End-to-end encryption for privacy

**Estimated Complexity:** High

---

### Shared Workflows (P2)

**Goal:** Team-shareable workflow library.

**Features:**
- Workflow publishing to team library
- Version control for workflows
- Usage analytics across team
- Role-based access control

**Files to Modify:**
- `src/composables/useWorkflows.ts` - Add sync methods
- `src/components/WorkflowPanel.vue` - Add sharing UI

---

## 2. Remote Agents

### SSH Connection Support (P0)

**Goal:** Connect to remote servers with full feature parity.

**Features:**
- SSH key management
- Connection profiles
- Secure credential storage
- Remote file operations
- Agent mode over SSH

**Files to Create:**
```
src/composables/useSSH.ts
src/components/SSHConnectionModal.vue
src/components/SSHProfileManager.vue
src-tauri/src/ssh.rs
```

**Technical Approach:**
- Use `russh` or `ssh2` Rust crates
- Store credentials in system keychain
- Multiplex connections for efficiency
- Support jump hosts / bastion

**Estimated Complexity:** High

---

### Remote Agent Execution (P1)

**Goal:** Run agent mode tools on remote machines.

**Features:**
- Tool execution over SSH
- Remote file read/write/edit
- Remote search (grep/glob)
- Context sync between local and remote

**Architecture:**
```
Local Agent <-> SSH Tunnel <-> Remote Agent Runner
```

**Files to Create:**
```
src/composables/useRemoteAgent.ts
src-tauri/src/remote_tools.rs
```

---

### Container Support (P2)

**Goal:** Execute commands inside Docker/Podman containers.

**Features:**
- Container listing and selection
- Exec into running containers
- Container-aware file operations
- Image management

**Files to Create:**
```
src/composables/useContainers.ts
src/components/ContainerPanel.vue
src-tauri/src/containers.rs
```

---

## 3. Language Server Integration

### LSP Support (P0)

**Goal:** IDE-level code intelligence in the terminal.

**Features:**
- Go-to-definition for commands/scripts
- Hover documentation
- Autocomplete from language servers
- Error diagnostics inline

**Supported Languages (Initial):**
- Bash/Zsh (bash-language-server)
- Python (pylsp)
- TypeScript/JavaScript (tsserver)
- Rust (rust-analyzer)

**Files to Create:**
```
src/composables/useLSP.ts
src/components/LSPStatus.vue
src-tauri/src/lsp.rs
```

**Technical Approach:**
- Spawn LSP servers as child processes
- JSON-RPC communication
- Cache server state for performance
- Lazy initialization per language

**Estimated Complexity:** Medium-High

---

### Inline Code Editing (P1)

**Goal:** Edit scripts/configs with full IDE features.

**Features:**
- Monaco editor with LSP integration
- Inline editing in terminal context
- Auto-save and sync
- Git diff visualization

**Files to Modify:**
- Enhance existing Monaco integration
- Add `useInlineEditor.ts` composable

---

## 4. Plugin Ecosystem

### Plugin Marketplace (P2)

**Goal:** Discover and install community plugins.

**Features:**
- Browse available plugins
- One-click install
- Auto-updates
- Reviews and ratings
- Security scanning

**Architecture:**
```
Plugin Registry (GitHub/npm) -> Plugin Manager -> Sandboxed Execution
```

**Files to Create:**
```
src/composables/usePluginMarketplace.ts
src/components/PluginMarketplace.vue
```

---

### Plugin API v2 (P1)

**Goal:** More powerful, safer plugin capabilities.

**New APIs:**
- Custom toolbar buttons
- Custom keyboard shortcuts
- Custom themes
- Custom autocomplete providers
- File system watchers (sandboxed)

**Security Enhancements:**
- Capability-based permissions
- Resource usage limits
- Network access controls
- Audit logging

---

## 5. Cloud Features (Optional)

### Settings Sync (P3)

**Goal:** Sync preferences across devices.

**Synced Data:**
- Theme preferences
- Keyboard shortcuts
- Workflows
- Snapshots metadata
- Plugin list

**Privacy:**
- End-to-end encryption
- Local-first with optional sync
- Self-hosted option

**Backend Options:**
- iCloud (macOS)
- Google Drive
- Self-hosted (WebDAV)

---

### Cloud Backup (P3)

**Goal:** Backup terminal history and recordings.

**Features:**
- Encrypted cloud storage
- Selective backup (privacy controls)
- Versioning
- Cross-device restore

---

## 6. Platform Enhancements

### Windows Improvements (P1)

**Features:**
- ConPTY optimization
- PowerShell integration
- Windows Terminal compatibility
- WSL2 support

**Files to Create:**
```
src-tauri/src/windows_pty.rs
```

---

### Linux Improvements (P1)

**Features:**
- Wayland native support
- Better font rendering
- System tray integration
- Package manager detection

---

### Auto-Update (P0)

**Goal:** Seamless application updates.

**Features:**
- Background update checks
- Delta updates (small downloads)
- Rollback support
- Release channel selection (stable/beta)

**Technical:**
- Use Tauri's built-in updater
- Sign all releases
- Host updates on GitHub Releases

---

## 7. Performance & Scale

### Multi-Pane Performance (P1)

**Goal:** Handle 10+ simultaneous panes smoothly.

**Optimizations:**
- Per-pane render throttling
- Lazy pane initialization
- Memory pooling for buffers
- Offscreen pane suspension

---

### Large Output Handling (P1)

**Goal:** Handle 1M+ lines without degradation.

**Approach:**
- Virtual scrolling improvements
- Indexed search
- Memory-mapped output files
- Background processing

---

### Startup Time (P2)

**Goal:** < 500ms cold start.

**Optimizations:**
- Lazy module loading
- Precompiled assets
- Deferred plugin initialization
- Shell environment caching

---

## 8. AI Enhancements

### Multi-Model Support (P1)

**Goal:** Use multiple AI models for different tasks.

**Features:**
- Model routing based on task type
- Fallback chains
- Quality/speed tradeoffs
- Cost tracking (for API models)

**Supported Providers:**
- Ollama (local)
- LM Studio (local)
- OpenAI API (optional)
- Anthropic API (optional)

---

### Code Context Indexing (P1)

**Goal:** AI understands full project context.

**Features:**
- Project-wide file indexing
- Semantic code search
- Dependency graph awareness
- Git history context

**Technical:**
- Local embedding model
- SQLite vector store
- Incremental re-indexing

---

### Agent Memory (P2)

**Goal:** AI remembers across sessions.

**Features:**
- Persistent conversation history
- Learned preferences
- Project-specific knowledge
- User corrections

---

## Implementation Phases

### Phase 1: Infrastructure (v2.0-alpha)
- [ ] Auto-update system
- [ ] LSP foundation
- [ ] SSH connection support
- [ ] Windows/Linux improvements

### Phase 2: Core Features (v2.0-beta)
- [ ] Remote agent execution
- [ ] Full LSP integration
- [ ] Plugin API v2
- [ ] Multi-model AI

### Phase 3: Collaboration (v2.0-rc)
- [ ] Real-time sharing
- [ ] Shared workflows
- [ ] Settings sync

### Phase 4: Polish (v2.0)
- [ ] Performance optimization
- [ ] Plugin marketplace
- [ ] Cloud backup
- [ ] Code context indexing

---

## Contributing

Priority areas for community contribution:
1. Language server integrations
2. Platform-specific optimizations
3. Plugin development
4. Documentation translations

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## Timeline

This roadmap is intentionally timeline-free. Features will be implemented based on:
1. User demand
2. Contributor availability
3. Technical dependencies

Track progress in GitHub Issues and Projects.
