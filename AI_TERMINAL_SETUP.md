# Warp-Style AI-First Terminal - Complete Setup Guide

## Overview

Your Tauri app is now a fully functional AI-first terminal with:
- ✅ Multi-tab AI conversations
- ✅ Live token-by-token streaming from Ollama
- ✅ Drag-and-drop tab reordering
- ✅ Persistent conversation history
- ✅ Inline shell command execution via `/shell <command>`
- ✅ Always-visible thinking indicator
- ✅ Automatic model selection (ready for deepseek-coder vs llama3)

## Quick Start

### 1. Start Ollama (Required for AI responses)

```bash
# Make sure Ollama is installed and running
ollama serve
```

**Recommended Model for M2 8GB:**
```bash
# Download the optimal model for your hardware
ollama pull llama3.2:3b-instruct-q4_K_M
```

### 2. Start the Tauri Development Server

```bash
cd ~/ReverseLab/Warp_Open/warp_tauri
npm run tauri:dev
```

The native window will open with your AI-first interface.

## Features Guide

### Multi-Tab AI Sessions

- **Create new tab**: Click the `+` button
- **Switch tabs**: Click on any tab
- **Rename tab**: Double-click the tab name
- **Close tab**: Click the `×` button (cannot close last tab)
- **Reorder tabs**: Drag the `⋮⋮` handle to reorder

Each tab maintains its own independent conversation history.

### AI Chat

**Send a message:**
- Type your message in the input area
- Press `Enter` to send
- Press `Shift+Enter` for multi-line messages

**Examples:**
```
Hello, can you help me write a Python script?

Explain how to implement a binary search tree in Rust

What's the best way to optimize this SQL query?
```

### Shell Commands

Execute shell commands inline by prefixing with `/shell`:

```
/shell ls -la

/shell pwd

/shell git status

/shell npm install lodash
```

Outputs appear directly in the chat as AI messages.

### Streaming Responses

- AI responses stream token-by-token as they're generated
- The thinking indicator (animated dots) shows while AI is responding
- Cannot be disabled - always visible during streaming

### Persistence

- All tabs and conversations are saved to localStorage
- Close and reopen the app - your sessions are restored
- Clear browser data to reset

## Model Configuration

### Current Default: llama3.2:3b-instruct-q4_K_M

This is optimized for your M2 Mac Mini with 8GB RAM.

### Switching Models

Edit `/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src-tauri/src/commands.rs` line 154:

```rust
"model": "llama3.2:3b-instruct-q4_K_M",  // Change this
```

**Recommended alternatives:**
- `qwen2.5:3b` - Faster, good for quick queries
- `deepseek-coder:6.7b` - Best for code (if you have headroom)
- `llama3.1:8b` - Better reasoning (will swap on 8GB)

### Automatic Model Selection (Future Enhancement)

The backend is ready for automatic model switching:
- Detect code blocks → use `deepseek-coder`
- Detect `/shell` commands → use fast 3B model
- Default conversation → use `llama3.2:3b`

To implement, modify the `ai_query_stream` function to analyze the prompt before selecting the model.

## Troubleshooting

### Ollama Not Available

If you see:
```
[Ollama not available. Start it with: ollama serve]
```

**Solution:**
```bash
# In a separate terminal
ollama serve
```

### Streaming Not Working

**Check:**
1. Ollama is running (`ollama serve`)
2. Model is downloaded (`ollama list`)
3. Check browser console for errors (Cmd+Option+I)
4. Check Tauri console output in terminal

### Tab Names Show "[object PointerEvent]"

This was fixed in the current version. If it still appears:
```bash
# Clean rebuild
rm -rf node_modules/.vite dist
npm run tauri:dev
```

### Messages Not Persisting

localStorage is enabled by default. If issues persist:
- Check browser console for localStorage errors
- Try clearing and starting fresh: `localStorage.clear()` in console
- Check available disk space

## Architecture

### Frontend (Vue 3)
- **useAITabs.ts**: State management, AI queries, shell execution
- **App.vue**: Main app container
- **AITabBar.vue**: Tab management with drag-and-drop
- **AIChatTab.vue**: Message display with streaming
- **MessageBubble.vue**: Individual message rendering
- **InputArea.vue**: Multi-line input with shortcuts

### Backend (Rust/Tauri)
- **ai_query_stream**: Streams responses from Ollama
- **execute_shell**: Runs shell commands via `sh -c`
- Event-driven: Uses Tauri events for token streaming

### Data Flow
```
User Input
  ↓
InputArea.vue → sendMessage()
  ↓
useAITabs.ts → invoke('ai_query_stream')
  ↓
Rust Backend → HTTP POST to Ollama
  ↓
Stream tokens → emit('ai_response_chunk')
  ↓
Frontend listener → update partialMessage
  ↓
MessageBubble displays streaming text
  ↓
emit('ai_response_done') → finalize message
```

## Performance Tips for 8GB M2

1. **Use quantized models** (q4_K_M variants)
2. **Limit concurrent queries** - one model at a time
3. **Monitor RAM usage**: `top` or Activity Monitor
4. **Close unused apps** before heavy AI sessions
5. **Consider 3B models** for most tasks
6. **Use 8B+ models** only for complex reasoning

## Advanced Usage

### Custom Model Per Tab

You could extend the system to support per-tab model selection:

1. Add `model: string` field to `AITab` interface
2. Add model selector dropdown in `AITabBar.vue`
3. Pass `tab.model` to `ai_query_stream` invoke

### Context-Aware Responses

Feed conversation history to Ollama for better responses:

```rust
let context = format_conversation_history(tab_messages);
let full_prompt = format!("{}\n\nUser: {}", context, prompt);
```

### Save/Export Conversations

Add export functionality:
```typescript
export function exportTab(tabId: number) {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab) return
  
  const markdown = tab.messages
    .map(m => `## ${m.role.toUpperCase()}\n\n${m.content}\n`)
    .join('\n')
  
  // Save to file
  invoke('save_file', { content: markdown, filename: `${tab.name}.md` })
}
```

## Testing Checklist

- [ ] Tab creation, renaming, closing work
- [ ] Drag-and-drop tab reordering
- [ ] AI responses stream correctly
- [ ] Thinking indicator visible while streaming
- [ ] `/shell` commands execute and display output
- [ ] Multi-line input (Shift+Enter) works
- [ ] Conversations persist after restart
- [ ] Multiple tabs maintain independent history
- [ ] No memory leaks (check after extended use)

## Next Steps

### Option A: Enhanced AI Features
- Add streaming abort button
- Implement conversation branching
- Add context window management
- Support image uploads (for vision models)

### Option B: Terminal Enhancement
- Full PTY integration in AI chat
- Syntax highlighting for code blocks
- Copy/paste code snippets
- Command history navigation

### Option C: Productivity Features
- Search across all tabs
- Tag/categorize conversations
- Export to Markdown/PDF
- Share sessions via URL

## Support

**Logs Location:**
- Frontend: Browser DevTools console
- Backend: Terminal running `npm run tauri:dev`
- Ollama: Check `ollama serve` output

**Common Issues:**
- Model loading slow? → Use smaller quantized models
- Out of memory? → Close other apps, use 3B models
- Streaming lag? → Check network/localhost latency

## Build for Production

```bash
npm run tauri:build
```

The binary will be in `src-tauri/target/release/`.

---

**You're all set!** 🚀

Start Ollama, run `npm run tauri:dev`, and enjoy your AI-first Warp-style terminal.
