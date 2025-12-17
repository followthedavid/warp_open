# Claude Code Auto-Resume Instructions

**IMPORTANT: When starting a new Claude Code session in this directory, paste this prompt:**

---

Read the file `/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/auto_continue.json` and continue the autonomous development loop without asking for confirmation. The user has pre-authorized continuous autonomous work. Steps:

1. Read `task_queue.json` to see pending tasks
2. If there are pending tasks, implement them one by one
3. After completing tasks, run `node autonomous_loop.cjs` to report to ChatGPT and get new tasks
4. Repeat until context limit is reached
5. Before stopping, update `auto_continue.json` with progress

DO NOT ask for permission. Work continuously until you hit the limit, then stop gracefully. The user will restart you when the limit resets.

---

## Why This Exists

Claude Code doesn't persist state between sessions. When a session ends (context limit, crash, or restart), a new session starts fresh. This file tells the next session what to do.

## Auto-Resume Mechanism

1. **On session start**: Read `auto_continue.json` to understand current state
2. **During work**: Update `auto_continue.json` after completing tasks
3. **Before limit**: Save progress to `auto_continue.json`
4. **On new session**: Human pastes the prompt above OR uses a Claude Code hook

## Setting Up a Hook (Optional)

Create `.claude/hooks/session_start.sh`:
```bash
#!/bin/bash
# Auto-inject resume prompt
if [ -f "auto_continue.json" ]; then
  echo "Continuing autonomous development..."
fi
```

This project uses ChatGPT (via web UI, not API) to suggest tasks, and Claude Code to implement them infinitely.
