# Warp AI Terminal - Quick Start

## ⚡ Launch in 3 Commands

```bash
# 1. Start Ollama (separate terminal)
ollama serve

# 2. Ensure model is available
ollama pull llama3.2:3b-instruct-q4_K_M

# 3. Start Tauri app
cd ~/ReverseLab/Warp_Open/warp_tauri && npm run tauri:dev
```

## 🎯 First 5 Minutes

### Test AI Chat
1. Type: `Hello, how are you?`
2. Press Enter
3. Watch tokens stream in real-time

### Test Multi-Tab
1. Click `+` to create new tab
2. Drag `⋮⋮` to reorder
3. Double-click tab name to rename

### Test Shell Commands
```
/shell pwd
/shell ls -la
/shell echo "Hello from shell"
```

### Test Persistence
1. Create a tab, add messages
2. Close app (`Cmd+Q`)
3. Reopen → history restored

## 📊 What You'll See

```
┌────────────────────────────────────────────┐
│ ⋮⋮ AI Assistant × │ ⋮⋮ AI 2 × │ +        │ ← Tab Bar
├────────────────────────────────────────────┤
│ System: Welcome to AI Assistant!          │
│                                            │
│ You: Hello, how are you?         [blue]   │
│                                            │
│ AI: I'm doing well! ...          [gray]   │ ← Streaming
│ • • •                    [animated dots]   │ ← Thinking
├────────────────────────────────────────────┤
│ [Type message or /shell command...]  Send │ ← Input
└────────────────────────────────────────────┘
```

## 🔥 Key Features

| Feature | Shortcut/Action |
|---------|----------------|
| **Send message** | Enter |
| **New line** | Shift+Enter |
| **New tab** | Click `+` |
| **Rename tab** | Double-click name |
| **Close tab** | Click `×` |
| **Reorder tabs** | Drag `⋮⋮` |
| **Shell command** | `/shell <cmd>` |
| **Thinking indicator** | Always visible |

## 🧪 Quick Tests

### ✅ Verification Checklist

- [ ] **Tab Management**
  - [ ] Create new tab
  - [ ] Rename tab
  - [ ] Close tab (keeps last one)
  - [ ] Drag to reorder

- [ ] **AI Features**
  - [ ] Send message
  - [ ] See streaming response
  - [ ] Thinking indicator appears
  - [ ] Multiple tabs work independently

- [ ] **Shell Integration**
  - [ ] `/shell pwd` works
  - [ ] Output displays inline
  - [ ] Errors shown clearly

- [ ] **Persistence**
  - [ ] Close & reopen app
  - [ ] Tabs restored
  - [ ] Messages preserved

## ✅ Verification & Testing

### Run Full Verification (Recommended)
```bash
./scripts/warp_full_auto.sh
```

This runs complete verification, auto-fixes issues, generates dashboard, and reruns tests.

### Quick Commands
| Command | Purpose |
|---------|----------|
| `./scripts/verify_everything.sh` | Full verification (Rust + UI tests) |
| `./scripts/auto_fix_tabs.sh` | Apply auto-fixes from report |
| `./scripts/warp_health_dev.sh` | Verify + fix + dashboard + dev server |
| `node scripts/dashboard.js` | Generate test dashboard |

### View Test Results
```bash
open /tmp/warp_status_dashboard.html
```

**Reports:**
- `/tmp/warp_status_report.txt` - Full test report
- `/tmp/warp_status_screenshots/` - UI test screenshots
- `playwright-report/` - Playwright HTML report

## 🚨 Troubleshooting

### "Ollama not available"
```bash
ollama serve
```

### Tab shows "[object PointerEvent]"
```bash
rm -rf node_modules/.vite dist
npm run tauri:dev
```

### Streaming not working
1. Check Ollama: `ollama list`
2. Check console: Cmd+Option+I
3. Verify model downloaded

### Port 5173 already in use
```bash
lsof -ti:5173 | xargs kill -9
npm run tauri:dev
```

### Tests Failing
1. Run auto-fix: `./scripts/auto_fix_tabs.sh`
2. Check report: `cat /tmp/warp_status_report.txt`
3. View dashboard: `open /tmp/warp_status_dashboard.html`

## 🎓 Example Prompts

**Coding Help:**
```
Write a Python function to parse CSV files

Explain how Rust ownership works

Debug this JavaScript error: [paste error]
```

**System Admin:**
```
/shell df -h

Show me disk usage in this directory

/shell ps aux | grep node
```

**General:**
```
What's the weather in San Francisco?

Explain quantum computing simply

Write a haiku about programming
```

## 📚 Full Documentation

See `AI_TERMINAL_SETUP.md` for:
- Architecture details
- Model configuration
- Performance tuning
- Advanced features
- Production build

## 🚀 You're Ready!

Your AI-first Warp-style terminal is fully operational. Start chatting!

---

**Quick Links:**
- Setup Guide: `AI_TERMINAL_SETUP.md`
- Composable: `src/composables/useAITabs.ts`
- Backend: `src-tauri/src/commands.rs`
