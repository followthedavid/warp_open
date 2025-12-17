# Warp_Open - Feature Summary

## Overview
Warp_Open is a terminal application built with Tauri, featuring AI-powered command execution and intelligent tool calling via Ollama.

## Current Features

### ✅ AI Assistant Integration
- **Local AI Model**: Uses Ollama (qwen2.5:3b) running on localhost:11434
- **Streaming Responses**: Real-time token-by-token output
- **Conversation History**: Full context preservation across messages
- **Multi-tab Support**: Separate AI conversations in different tabs

### ✅ Autonomous Tool Calling
- **Supported Tools**:
  - `execute_shell`: Run shell commands
  - `read_file`: Read file contents (with ~ expansion)
  - `write_file`: Write content to files (with ~ expansion)

- **Smart Detection**: Brace-counting JSON parser handles nested objects
- **Automatic Execution**: Tool calls execute immediately without manual approval
- **Follow-up Interpretation**: AI automatically analyzes tool results and answers the original question

### ✅ Visual Feedback
- **Tool Call Indicators**: 🔧 icon with orange border for tool execution
- **Result Display**: 📋 icon with blue border for tool results
- **Formatted Output**: Syntax-highlighted JSON for tool arguments
- **Clear Separation**: Distinct styling for user messages, AI responses, system messages, and tool operations

### ✅ Safety Features
- **Command Whitelist**: Predefined safe commands (ls, cat, grep, git, npm, etc.)
- **Blacklist Protection**: Dangerous commands blocked (rm -rf, sudo, dd, mkfs, etc.)
- **Manual Approval Queue**: Unsafe commands moved to batch queue for review
- **Tool Call Bypass**: Autonomous tool calls skip the safety queue

### ✅ Shell Integration
- **Direct Commands**: `/shell` prefix for immediate execution
- **Environment Loading**: Full PATH and shell configuration available
- **Multiple Shells**: sh, bash, zsh support

### ✅ macOS Integration
- **.app Bundle**: Professional macOS application package
- **DMG Installer**: Easy distribution via disk image
- **Applications Folder**: Installs to /Applications/Warp_Open.app
- **Spotlight Launch**: Can be opened via Spotlight or Dock

## Technical Architecture

### Frontend (Vue 3 + TypeScript)
- **Framework**: Vue 3 Composition API
- **Build Tool**: Vite
- **Components**:
  - `AIChatTab.vue`: Main chat interface
  - `MessageBubble.vue`: Individual message display with tool visualization
  - `InputArea.vue`: User input field
  - `BatchPanel.vue`: Command queue for manual approval

### Backend (Rust + Tauri)
- **Framework**: Tauri 1.x
- **Commands**:
  - `ai_query_stream`: Streaming AI responses from Ollama
  - `execute_shell`: Shell command execution
  - `read_file` / `write_file`: File operations
  - `create_pty` / `send_input`: PTY management (future use)

### AI Configuration
- **Model**: qwen2.5:3b (Qwen 2.5 3B parameter model)
- **Temperature**: 0.1 (more deterministic)
- **Stop Sequences**: `["\n\n", "Q:", "A:"]` (prevent rambling)
- **Max Tokens**: 200 (concise responses)

### System Prompt
```
When user asks you to run commands or read files, output this JSON format EXACTLY:
{"tool":"execute_shell","args":{"command":"ls ~/"}}

IMPORTANT RULES:
- Output ONLY ONE tool call per response
- DO NOT chain multiple tool calls with > or other separators
- DO NOT explain before or after the JSON
- DO NOT wrap in code blocks
- Just output the single raw JSON line

If the user's request requires multiple steps, output ONE tool call. 
Wait for the result before suggesting the next step.
```

## Recent Improvements (2025-01-17)

### 1. Fixed Multi-Tool Call Issue
- **Before**: AI generated `>{"tool":...}>{"tool":...}` causing shell redirection errors
- **After**: System prompt enforces ONE tool per response, parser strips leading `>`, proper JSON extraction with brace counting

### 2. Added AI Follow-up Responses
- **Before**: Tool executed and showed raw results, but AI didn't interpret them
- **After**: After tool execution, automatically triggers new AI query to analyze results and answer the original question

### 3. Enhanced Visual Feedback
- **Before**: Tool calls looked like regular AI messages
- **After**: 
  - Tool calls: Orange border, 🔧 icon, formatted JSON display
  - Tool results: Blue border, 📋 icon, extracted content only
  - Clear visual hierarchy

### 4. Fixed Path Expansion
- **Before**: `~/.zshrc` treated as literal path, file not found
- **After**: Added `shellexpand` crate, `~` properly expands to `/Users/username`

### 5. macOS App Bundling
- **Before**: Running from binary only
- **After**: Professional .app bundle installable via DMG to /Applications

## Usage Examples

### Basic AI Interaction
```
User: "list files in my home directory"
AI: {"tool":"execute_shell","args":{"command":"ls ~/"}}
System: [Tool executed: execute_shell] Result: Desktop Documents Downloads...
AI: "Your home directory contains the following folders: Desktop, Documents, Downloads..."
```

### File Reading
```
User: "check if my zshrc is loaded"
AI: {"tool":"read_file","args":{"path":"~/.zshrc"}}
System: [Tool executed: read_file] Result: export PATH=...
AI: "Yes, your .zshrc is loaded. I can see it contains PATH configurations for..."
```

### Direct Shell Commands
```
User: "/shell echo $PATH"
System: $ echo $PATH
AI: /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin...
```

## Future Enhancements (Remaining Tasks)

### Task 6: Verification Gate Integration
- Add JSON receipt generation for all commands
- Integrate with existing VG audit system
- Support crash recovery and session resumption

### Task 7: Error Handling & Documentation
- Comprehensive error categorization
- Detailed troubleshooting guide
- Developer documentation for extending tool calls

## Configuration Files

- `src-tauri/tauri.conf.json`: Tauri app configuration
- `src-tauri/Cargo.toml`: Rust dependencies
- `src/composables/useAITabs.ts`: AI logic and tool handling
- `src/components/MessageBubble.vue`: Message rendering and styling

## Dependencies

### Rust
- `tauri`: ^1.5
- `serde_json`: ^1.0
- `reqwest`: ^0.11 (with json, stream features)
- `futures-util`: ^0.3
- `shellexpand`: ^3.1
- `tokio`: ^1 (full features)

### Node
- `vite`: ^5.4
- `vue`: ^3.4
- `@tauri-apps/api`: ^1.5
- `@vitejs/plugin-vue`: Latest

## Performance Characteristics

- **Startup Time**: ~2-3 seconds
- **AI Response Latency**: 50-200ms first token (on M2 8GB)
- **Tool Execution**: Instant for shell commands, file I/O
- **Memory Usage**: ~100-150MB typical
- **Model Size**: ~2GB for qwen2.5:3b

## Known Limitations

1. Tool calls must be valid JSON on a single line
2. AI sometimes still generates explanatory text alongside tool calls
3. No multi-step planning - one tool call at a time
4. PTY/terminal features not yet implemented
5. No Blocks UI integration yet

## Contributing

To add a new tool:
1. Add Rust command in `src-tauri/src/commands.rs`
2. Register in `invoke_handler` in `main.rs`
3. Update `handleToolCall` switch statement in `useAITabs.ts`
4. Add to system prompt examples
5. Update visual indicators in `MessageBubble.vue` if needed

## License

MIT License - See LICENSE file for details
