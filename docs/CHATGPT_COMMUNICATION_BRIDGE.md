# ChatGPT ↔ Claude Code Communication Bridge

Complete documentation for the autonomous development loop system that enables ChatGPT to direct Claude Code implementation tasks.

## Overview

This system creates a communication bridge between:
- **ChatGPT** (running in browser) - Acts as project manager, suggests tasks
- **Claude Code** (running in terminal) - Implements the suggested tasks
- **You** (optional) - Can monitor or intervene via phone/ChatGPT

The loop runs autonomously: ChatGPT suggests → Claude implements → ChatGPT reviews → repeat.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Your Phone/Browser                          │
│                              ChatGPT                                 │
│    (Project manager - suggests tasks, reviews completions)          │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ Playwright (headless browser)
                                  │ reads/writes to ChatGPT thread
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Communication Bridge Scripts                      │
│                                                                      │
│  ┌─────────────────────┐    ┌─────────────────────┐                │
│  │ chatgpt_thread_     │    │   autonomous_       │                │
│  │ manager.cjs         │◄───│   loop.cjs          │                │
│  │                     │    │                     │                │
│  │ - Launch browser    │    │ - Poll for tasks    │                │
│  │ - Read threads      │    │ - Report completion │                │
│  │ - Send messages     │    │ - Parse new tasks   │                │
│  │ - Watch for updates │    │ - Add to queue      │                │
│  └─────────────────────┘    └─────────────────────┘                │
│              │                        │                              │
│              └────────┬───────────────┘                              │
│                       │                                              │
│                       ▼                                              │
│           ┌─────────────────────┐                                   │
│           │   task_queue.json   │                                   │
│           │                     │                                   │
│           │ - pending tasks     │                                   │
│           │ - in progress       │                                   │
│           │ - completed         │                                   │
│           └─────────────────────┘                                   │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ Claude Code reads task_queue.json
                                  │ and implements tasks
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          Claude Code                                 │
│                                                                      │
│  - Reads pending tasks from task_queue.json                         │
│  - Implements each task (creates files, writes code)                │
│  - Marks tasks complete with results                                │
│  - auto_continue.json tracks session state                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Files Overview

### Core Scripts

| File | Purpose |
|------|---------|
| `autonomous_loop.cjs` | Main loop that reports to ChatGPT and fetches new tasks |
| `chatgpt_thread_manager.cjs` | Low-level ChatGPT browser automation |
| `chatgpt_bridge.cjs` | Interactive bridge for manual approval |
| `chatgpt_orchestrator.cjs` | Orchestrator with task parsing |
| `chatgpt_web_stealth.cjs` | Stealth browser setup to avoid detection |

### State Files

| File | Purpose |
|------|---------|
| `task_queue.json` | Queue of pending/completed tasks |
| `auto_continue.json` | Session state for Claude Code resumption |
| `~/.chatgpt-thread-state.json` | Thread tracking state |
| `~/.chatgpt-stealth-profile-chromium/` | Browser profile with login session |

---

## Script Documentation

### 1. chatgpt_thread_manager.cjs

Low-level ChatGPT browser automation using Playwright.

#### Functions

```javascript
// List recent ChatGPT conversations
async function listThreads(keepOpen = false): Promise<Thread[]>
// Returns: [{ id, title, url }, ...]

// Read all messages from a thread
async function readThread(threadId, keepOpen = false): Promise<ThreadData>
// Returns: { threadId, url, messages: [{ index, role, text }, ...] }

// Send a message to a thread (or start new)
async function sendToThread(threadId, message, keepOpen = false): Promise<Result>
// Returns: { threadId, response }

// Watch thread for new messages (blocking)
async function watchThread(threadId, callback): Promise<void>
// Calls callback({ type, parsed, raw, thread }) on new messages

// Parse user message for commands
function parseUserMessage(text): ParsedMessage
// Returns: { type: 'approve_all' | 'approve_items' | 'skip_items' | 'wait' | 'question' | 'activate' | 'unknown', ... }
```

#### Configuration

```javascript
const CONFIG = {
  userDataDir: '~/.chatgpt-stealth-profile-chromium',
  baseUrl: 'https://chatgpt.com',
  pollInterval: 5000,

  // Approval patterns (for phone input)
  approvalPatterns: {
    approveAll: /^(y|yes|go|ok|do it|approved?|confirm|yep|yup|k|👍)$/i,
    approveItems: /^(\d+[\s,]*)+$/,      // "1 2 3" or "1,2,3"
    skipItems: /^(no|skip|not?)\s*(\d+[\s,]*)+$/i,
    wait: /^(wait|hold|pause|stop|later)$/i,
    question: /^\?|^(what|how|why|which|explain)/i,
  },

  // Trigger phrases to activate terminal mode
  triggerPhrases: [
    'coding session', 'terminal mode', 'dev mode',
    'start terminal', 'activate terminal', '@terminal',
  ],
};
```

#### CLI Usage

```bash
# List recent threads
node chatgpt_thread_manager.cjs list

# Read a thread
node chatgpt_thread_manager.cjs read <thread_id>

# Send message to thread
node chatgpt_thread_manager.cjs send <thread_id> "message"

# Start new thread
node chatgpt_thread_manager.cjs new "initial message"

# Watch thread for updates
node chatgpt_thread_manager.cjs watch <thread_id>
```

---

### 2. autonomous_loop.cjs

Main autonomous development loop.

#### Flow

```
┌─────────────────────────────────────────────────────────┐
│                    autonomous_loop.cjs                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Check task_queue.json for newly completed tasks      │
│                          │                               │
│                          ▼                               │
│  2. If new completions:                                  │
│     - Build status report message                        │
│     - Send to ChatGPT via thread_manager                 │
│                          │                               │
│                          ▼                               │
│  3. Wait for ChatGPT response                            │
│                          │                               │
│                          ▼                               │
│  4. Parse response for new task suggestions              │
│     (numbered list format)                               │
│                          │                               │
│                          ▼                               │
│  5. Add new tasks to task_queue.json pending list        │
│                          │                               │
│                          ▼                               │
│  6. Sleep for pollInterval, goto 1                       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### Key Functions

```javascript
// Parse ChatGPT response for task suggestions
function parseTasksFromResponse(text): Task[]
// Looks for: "1. Task title" or "1) Task title" patterns

// Report completed tasks and get new suggestions
async function reportAndGetNewTasks(threadId, completedTasks): Result

// Add new tasks to queue (avoiding duplicates)
function addTasksToQueue(tasks): number

// Get tasks completed since last report
function getUnreportedCompletedTasks(lastReportedId): Task[]
```

#### Prompts

**Status Report (sent after tasks complete):**
```
I've completed the following tasks:

1. **Task Title**
   Result: Brief description of what was done

Based on what I've accomplished, please suggest the next 3-5 bullet-point tasks I should work on. Focus on:
- Improving the codebase quality
- Adding useful features
- Fixing any issues
- Performance improvements

Format each task as a numbered list with clear, actionable items.
```

**Initialize Session:**
```
I'm starting an autonomous coding session on the Warp Terminal Clone project (Tauri + Vue 3).

Project summary:
[Recent completed tasks]

Please suggest 3-5 specific, actionable tasks I should work on. Format as a numbered list.
```

#### CLI Usage

```bash
# Start autonomous loop (uses configured thread)
node autonomous_loop.cjs

# Use specific thread
node autonomous_loop.cjs --thread <thread_id>
```

---

### 3. task_queue.json

Central task queue shared between ChatGPT and Claude Code.

#### Structure

```json
{
  "description": "Task queue for autonomous development",
  "config": {
    "autoFetchFromChatGPT": true,
    "threadId": "693f18ee-0290-8329-956d-2f873f9308b4"
  },
  "pending": [
    {
      "id": "1765783214368",
      "priority": "medium",
      "title": "Task Title",
      "description": "Detailed description...",
      "createdAt": "2025-12-15T07:20:14.368Z"
    }
  ],
  "inProgress": [],
  "completed": [
    {
      "id": "31",
      "priority": "low",
      "title": "Completed Task",
      "completedAt": "2025-12-15T08:20:00Z",
      "result": "Description of what was accomplished"
    }
  ],
  "failed": []
}
```

#### Task Lifecycle

```
pending → inProgress → completed
                    → failed
```

---

### 4. auto_continue.json

Session state for Claude Code resumption.

#### Structure

```json
{
  "description": "Auto-continuation state for Claude Code sessions",
  "lastActivity": "2025-12-15T09:00:00Z",
  "currentState": "ready_for_new_tasks",
  "lastCompletedTask": "42",
  "resumePrompt": "Continue the autonomous development loop...",
  "autoResume": true,
  "completedSinceLastReport": [
    "Task 32: Description of what was done",
    "Task 33: Description..."
  ],
  "warpFeatureProgress": {
    "blocks": "100% - OSC 133 + prompt heuristics",
    "autocomplete": "100% - commands, paths, fuzzy search"
  },
  "claudeCodeFeatureProgress": {
    "toolUse": "100% - 8 tools with execution tracking"
  },
  "overallProgress": "100% - All features implemented"
}
```

---

### 5. chatgpt_bridge.cjs

Interactive bridge with approval workflow.

#### Modes

1. **Simple Mode** (default): Pattern matching for approvals
2. **Claude Mode** (`--claude`): Uses Claude API to interpret conversation

#### Approval Flow

```
ChatGPT proposes commands → User approves (y/1 2 3/skip) → Bridge executes → Posts results
```

#### Safety

Dangerous commands are blocked:
```javascript
const dangerousPatterns = [
  /rm\s+-rf\s+[\/~]/i,
  /sudo\s+rm/i,
  /mkfs/i,
  /dd\s+if=.*of=\/dev/i,
];
```

---

### 6. chatgpt_orchestrator.cjs

Full orchestrator with task proposal parsing.

#### Task Detection

Parses ChatGPT responses for:
- Numbered lists: `1. Do something` or `1) Do something`
- Code blocks: ` ```bash ... ``` `
- Action verbs: Create, Update, Add, Remove, Fix, Run, etc.

#### Approval Commands (from phone)

| Command | Action |
|---------|--------|
| `y`, `yes`, `go`, `ok`, `👍` | Approve all |
| `1 2 3` | Approve specific items |
| `skip 2` | Skip item 2 |
| `wait` | Hold off |
| `?` | Ask question |

---

## Setup Guide

### 1. First-Time Browser Login

```bash
# Launch browser for manual ChatGPT login
node chatgpt_web_stealth.cjs --login
```

This opens a browser where you log into ChatGPT. The session is saved to `~/.chatgpt-stealth-profile-chromium/`.

### 2. Find Your Thread ID

```bash
# List recent threads
node chatgpt_thread_manager.cjs list
```

Or get it from the ChatGPT URL: `https://chatgpt.com/c/[THREAD-ID]`

### 3. Start Autonomous Loop

```bash
# Using configured thread (in task_queue.json)
node autonomous_loop.cjs

# Or specify thread
node autonomous_loop.cjs --thread abc123-def456
```

### 4. Configure Thread (Optional)

Edit `task_queue.json`:
```json
{
  "config": {
    "threadId": "your-thread-id-here"
  }
}
```

---

## Communication Protocol

### ChatGPT → Claude Code

ChatGPT suggests tasks in numbered list format:

```
Based on the current state, here are the next tasks:

1. **Implement Feature X**
   Create a new composable for X functionality...

2. **Fix Bug Y**
   Update the component to handle edge case...

3. **Add Tests for Z**
   Write unit tests covering...
```

The autonomous loop parses this and adds to `task_queue.json`.

### Claude Code → ChatGPT

Claude reports completions:

```
I've completed the following tasks:

1. **Implement Feature X**
   Result: Created useFeatureX.ts with functions A, B, C. Added FeatureX.vue component.

Please suggest the next 3-5 tasks...
```

---

## Preventing Repeated Suggestions

### The Problem

ChatGPT may repeatedly suggest features that are already implemented because:
1. It loses context over long conversations
2. It doesn't know the full project state
3. Earlier completions scroll out of view

### Solutions Implemented

1. **CHATGPT_STATUS_UPDATE.md** - Comprehensive status file with:
   - All completed features
   - "DO NOT SUGGEST" list
   - Feature progress percentages

2. **auto_continue.json** - Tracks:
   - `completedSinceLastReport` array
   - `warpFeatureProgress` object
   - `claudeCodeFeatureProgress` object

3. **Project Summary in Prompts** - The status report includes recent completions

### How to Update ChatGPT

When ChatGPT suggests something already done:

1. Send the contents of `CHATGPT_STATUS_UPDATE.md` to the thread
2. Or manually respond: "This is already implemented. See Task X."
3. Claude Code will automatically push back on duplicate suggestions

---

## Troubleshooting

### Browser Won't Launch

```bash
# Check if profile exists
ls -la ~/.chatgpt-stealth-profile-chromium/

# Re-login if needed
node chatgpt_web_stealth.cjs --login
```

### Can't Find Thread

```bash
# List all threads
node chatgpt_thread_manager.cjs list

# Read specific thread to verify
node chatgpt_thread_manager.cjs read <thread_id>
```

### Messages Not Sending

1. Check if logged into ChatGPT
2. Verify thread ID is correct
3. Check for CAPTCHA (may need manual intervention)

### Tasks Not Being Parsed

Ensure ChatGPT uses numbered list format:
```
1. Task title here
2. Another task
```

Not bullet points or prose.

---

## Security Considerations

1. **Browser Session** - Stored locally, contains ChatGPT login
2. **Command Execution** - Dangerous patterns are blocked
3. **No Secrets** - Don't put API keys in ChatGPT messages
4. **Local Only** - All communication is local browser automation

---

## Best Practices

1. **Clear Task Titles** - Help ChatGPT understand what's done
2. **Detailed Results** - Include file names, function names
3. **Regular Status Updates** - Send CHATGPT_STATUS_UPDATE.md periodically
4. **Monitor the Loop** - Check for stuck states or repeated suggestions
5. **Version Control** - Commit frequently during autonomous sessions
