# Warp_Open Parity Implementation Plan

## Goal: 100% Feature Parity with Claude Code & Warp Terminal (No API Required)

Based on comprehensive analysis, these features are needed for full parity.

---

## Phase 1: Core Agent Features (HIGH PRIORITY)

### 1.1 CLAUDE.md Project Context File
**What:** A markdown file at project root that provides persistent context to the AI agent.
**Why:** Claude Code uses this as the "constitution" - project rules, coding standards, architecture notes.
**Implementation:**
- On startup, check for `CLAUDE.md`, `WARP.md`, or `.claude/project.md`
- Prepend contents to system prompt
- Watch for file changes and reload
- Add `/init` command to create template

**Files to modify:**
- `src-tauri/src/conversation.rs` - Load project context
- `src/composables/useAI.ts` - Project context state

### 1.2 Slash Commands System
**What:** Commands like `/clear`, `/compact`, `/pr`, `/plan`, `/catchup`
**Why:** Quick actions without natural language overhead
**Implementation:**
```
/clear      - Clear conversation history
/compact    - Summarize and compress context
/plan       - Enter planning mode
/pr         - Generate PR description from git diff
/catchup    - Summarize recent git changes
/context    - Show token usage estimate
/help       - List available commands
/model      - Switch AI model
/reset      - Reset agent state
```

**Files to modify:**
- `src/composables/useSlashCommands.ts` - Already exists, extend it
- `src-tauri/src/commands.rs` - Add backend handlers

### 1.3 Planning Mode with plan.md
**What:** Structured planning before execution, saved to file
**Why:** Keeps agent on track for complex tasks, allows user review
**Implementation:**
- `/plan` enters planning mode
- Agent creates `~/.warp_open/plans/[task-id].md`
- Shows plan for approval before execution
- Tracks progress with checkboxes

**Files to create:**
- `src-tauri/src/planning.rs` - Plan file management
- `src/components/PlanViewer.vue` - Plan display component

### 1.4 Background Tasks
**What:** Run long processes (dev servers, builds) without blocking agent
**Why:** Agent can continue working while npm run dev is running
**Implementation:**
- `Ctrl+B` to background current command
- Track background processes with PIDs
- Show status in sidebar
- Stream output to separate buffer

**Files to modify:**
- `src-tauri/src/pty.rs` - Background process registry
- `src/components/BackgroundTasks.vue` - New component

### 1.5 Resume/Continue Sessions
**What:** `--resume` flag to continue previous conversation
**Why:** Context preservation across sessions
**Implementation:**
- Save conversation state with unique IDs
- `/sessions` to list recent sessions
- Click to restore full context
- Auto-save every N messages

**Files to modify:**
- `src-tauri/src/session.rs` - Session serialization
- `src/composables/useSessionStore.ts` - Session management

---

## Phase 2: Advanced Agent Capabilities (HIGH PRIORITY)

### 2.1 Hooks System (PreToolUse, PostToolUse)
**What:** Validation rules that run before/after tool execution
**Why:** Safety guardrails, custom validation, logging
**Implementation:**
```rust
// hooks.json or .claude/hooks/
{
  "PreToolUse": [
    {
      "tool": "write_file",
      "pattern": "*.env",
      "action": "block",
      "message": "Cannot write to .env files"
    }
  ],
  "PostToolUse": [
    {
      "tool": "execute_shell",
      "action": "log"
    }
  ]
}
```

**Files to create:**
- `src-tauri/src/hooks.rs` - Hook execution engine
- `src/components/HooksEditor.vue` - Hook configuration UI

### 2.2 Sub-agents / Task Delegation
**What:** Spawn specialized agents for specific tasks
**Why:** Complex tasks benefit from delegation (research, code review, testing)
**Implementation:**
- `Task()` function in agent loop
- Sub-agent runs in separate context
- Returns result to parent agent
- Configurable sub-agent types: Explore, Review, Test, Document

**Files to modify:**
- `src-tauri/src/scaffolding/agent_loop.rs` - Add spawn_subagent
- `src-tauri/src/scaffolding/ollama_agent.rs` - Sub-agent execution

### 2.3 Codebase Indexing/Embeddings
**What:** Vector embeddings of codebase for semantic search
**Why:** Find relevant code without exact keyword matches
**Implementation:**
- On project open, index all source files
- Generate embeddings using local model (nomic-embed-text)
- Store in SQLite with vector extension
- Query embeddings before grep for context

**Files to create:**
- `src-tauri/src/embeddings.rs` - Embedding generation
- `src-tauri/src/vector_store.rs` - Vector similarity search

### 2.4 Git Diff Review in Chat
**What:** Show git diff inline, allow AI to comment on changes
**Why:** Code review workflow without leaving terminal
**Implementation:**
- `/diff` command shows staged/unstaged changes
- AI can annotate specific lines
- Suggest improvements inline
- `/commit` with AI-generated message

**Files to modify:**
- `src/composables/useGitAI.ts` - Git diff integration
- `src/components/DiffViewer.vue` - Inline diff display

### 2.5 Auto-PR Creation
**What:** Generate PR title, description, and create on GitHub
**Why:** Streamlined PR workflow
**Implementation:**
- `/pr` analyzes commits since branch point
- Generates title and description
- Uses `gh` CLI or GitHub API (local)
- Optionally creates draft PR

**Files to modify:**
- `src-tauri/src/git.rs` - New file for git operations
- `src/composables/useGitAI.ts` - PR generation

---

## Phase 3: Warp-Specific Features (MEDIUM PRIORITY)

### 3.1 Secret Redaction
**What:** Automatically hide API keys, passwords in terminal output
**Why:** Security - prevent accidental exposure
**Implementation:**
- Regex patterns for common secrets (AWS, GitHub, JWT, etc.)
- Replace with `[REDACTED]` in display
- Store original in memory for copy
- Configurable patterns

**Files to modify:**
- `src/composables/useTerminalBuffer.ts` - Add redaction filter
- `src/components/TerminalPane.vue` - Apply filter on render

### 3.2 Next Command Prediction
**What:** Proactively suggest next command based on context
**Why:** Anticipate user needs, faster workflow
**Implementation:**
- After command completion, analyze output
- Predict likely next action
- Show as ghost text or suggestion chip
- Tab to accept

**Files to modify:**
- `src/components/TerminalPane.vue` - Add prediction UI
- `src-tauri/src/commands.rs` - Add `predict_next_command`

### 3.3 Voice Input
**What:** Speak commands instead of typing
**Why:** Hands-free operation, accessibility
**Implementation:**
- Use Web Speech API (browser)
- Or whisper.cpp locally for offline
- Button to activate, transcribe to input
- Works for both terminal and chat

**Files to create:**
- `src/composables/useVoiceInput.ts` - Voice recognition
- `src/components/VoiceButton.vue` - Microphone UI

### 3.4 Image Understanding
**What:** Paste screenshots, have AI analyze them
**Why:** Debug UI issues, understand error dialogs
**Implementation:**
- Paste image into chat
- Convert to base64
- Send to vision-capable local model (llava, bakllava)
- Display image inline with response

**Files to modify:**
- `src/components/AIChatTab.vue` - Image paste handler
- `src-tauri/src/ollama.rs` - Vision model support

### 3.5 Multi-file Diff Preview
**What:** Show all file changes before applying edits
**Why:** Review before commit, catch mistakes
**Implementation:**
- Collect all pending edits
- Show unified diff view
- Allow accept/reject per file
- Apply all or selected

**Files to create:**
- `src/components/MultiFileDiff.vue` - Diff preview component

---

## Phase 4: MCP & Extensibility (HARD)

### 4.1 MCP Server Support
**What:** Model Context Protocol for secure tool execution
**Why:** Standardized way to extend agent capabilities
**Implementation:**
- Implement MCP client in Rust
- Support stdio and SSE transports
- Load MCP servers from config
- Expose MCP tools to agent

**Files to create:**
- `src-tauri/src/mcp/mod.rs` - MCP client implementation
- `src-tauri/src/mcp/transport.rs` - Transport layer

### 4.2 Custom Prompts/Rules
**What:** Save and reuse prompt templates
**Why:** Consistency, efficiency for repeated tasks
**Implementation:**
- `.claude/prompts/` directory
- YAML or markdown format
- Variable substitution
- `/prompt <name>` to use

**Files to create:**
- `src-tauri/src/prompts.rs` - Prompt template loading
- `src/components/PromptsLibrary.vue` - Prompt management UI

---

## Implementation Order (Recommended)

### Sprint 1: Foundation (Easy wins)
1. ✅ CLAUDE.md project context
2. ✅ Slash commands system
3. ✅ Secret redaction
4. ✅ Resume sessions

### Sprint 2: Planning & Context
5. Planning mode with plan.md
6. Git diff review
7. Auto-PR creation
8. Custom prompts

### Sprint 3: Advanced Agent
9. Hooks system
10. Sub-agents
11. Background tasks
12. Next command prediction

### Sprint 4: Intelligence
13. Codebase embeddings
14. Image understanding
15. Voice input
16. Multi-file diff preview

### Sprint 5: Extensibility
17. MCP server support

---

## Success Metrics

- [ ] Can load CLAUDE.md and use it for context
- [ ] All slash commands working
- [ ] Planning mode creates reviewable plans
- [ ] Can delegate tasks to sub-agents
- [ ] Secrets are redacted in output
- [ ] Voice input works offline
- [ ] Images can be analyzed
- [ ] MCP servers can be loaded
- [ ] PR workflow fully automated
- [ ] Codebase search uses semantic embeddings

---

## Technical Notes

### Local-Only Constraint
All features must work 100% offline using:
- Ollama for LLM inference
- whisper.cpp or Web Speech API for voice
- llava/bakllava for vision
- nomic-embed-text for embeddings
- SQLite for vector storage
- Local git CLI for version control

### No External APIs
- No OpenAI API
- No Anthropic API
- No cloud services
- All processing on local machine
