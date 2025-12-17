# Autonomous AI Developer - Integration Guide

## Overview

The Autonomous AI Developer is a self-improving system that continuously works on goals, learns from results, and maintains perpetual memory. It combines Claude Max for reasoning with Ollama for local execution.

## Features

✅ **Goal Management** - Add high-level goals with priority (critical, high, medium, low)
✅ **Autonomous Planning** - Generates multi-step execution plans using Claude Max
✅ **Safe Execution** - Sandboxed file operations with automatic rollback
✅ **Perpetual Memory** - Logs all actions, decisions, and learnings for future reference
✅ **Self-Reflection** - Automatically generates improvement tasks after completing goals
✅ **Real-time Dashboard** - Monitor goals, tasks, logs, and statistics live

## Setup

### 1. Configure Claude API

The autonomous developer requires Claude Max (Sonnet 4.5) for reasoning and plan generation.

**In your AI Chat settings:**
1. Click the settings icon in AIChatTab
2. Select "Claude Only" or "Auto" mode
3. Enter your Anthropic API key
4. The dashboard will show "Claude Connected" (purple dot) when ready

### 2. Access the Developer Dashboard

**Option A: From AI Chat Tab**
- Click the "👤 Developer" button in the chat interface

**Option B: Direct Navigation**
- Navigate to the Developer Dashboard view in your app

### 3. Verify Connection

Check the dashboard header for status indicators:
- **Running/Stopped** - Green dot = autonomous loop active
- **Claude Connected/Disconnected** - Purple = ready, Red = needs API key

## Usage

### Adding Goals

1. Click **"+ Add Goal"** in the dashboard
2. Enter a clear, specific description:
   - ✅ "Add user authentication with JWT tokens"
   - ✅ "Optimize database queries in the user service"
   - ✅ "Write unit tests for the payment module"
   - ❌ "Make the app better" (too vague)
3. Set priority based on urgency
4. Click **"Add Goal"**

### Starting the Autonomous Loop

1. Add one or more goals
2. Click **"▶ Start"** button
3. The system will:
   - Pick the highest priority pending goal
   - Generate an execution plan using Claude Max
   - Execute steps with safety checks
   - Log all actions to perpetual memory
   - Self-reflect and generate improvements
   - Move to the next goal

### Monitoring Progress

The dashboard provides real-time visibility:

**Current Task Card**
- Shows active goal being worked on
- Progress bar (when plan is executing)
- Status and priority indicators

**Goals Queue**
- Pending goals sorted by priority
- Remove goals with the × button

**Live Execution Logs**
- Real-time activity stream
- Color-coded by level (info, success, warning, error)
- Auto-scrolls to latest

**Recent Learnings**
- Success/failure indicators
- Lessons learned from each action
- Context for future reference

**Statistics**
- Total goals processed
- Completed vs failed
- Success rate percentage

**Recently Completed**
- History of finished goals
- Completion timestamps

### Stopping the Loop

Click **"⏹ Stop"** to pause autonomous operation:
- Current task will complete
- No new goals will be started
- All progress is saved
- Can resume anytime

## How It Works

### Plan Generation (Claude Max)

When a goal is selected, the system:
1. Queries perpetual memory for relevant past experience
2. Includes recent learnings in context
3. Sends prompt to Claude Max with full context
4. Claude generates a JSON plan with steps:
   - File operations (read/write)
   - Shell commands (with safety checks)
   - Git operations (with rollback)
   - Ollama queries (for local reasoning)
   - Claude queries (for complex reasoning)

### Step Execution

Each step:
- **Approval Gate** - High-risk operations require approval
- **Sandboxed** - File operations limited to allowed directories
- **Snapshot** - File state saved before modification
- **Rollback** - Auto-restore on failure
- **Logged** - All actions recorded to perpetual memory

### Self-Reflection

After completing a goal:
1. Reviews steps executed and their results
2. Queries past learnings from memory
3. Asks Claude to suggest 1-3 improvements
4. Automatically adds improvement goals (low priority)
5. Records the learning for future use

### Perpetual Memory

All operations are logged to `data/claude_perpetual_log.json`:
- **Goals** - What was attempted
- **Plans** - How it was approached
- **Steps** - What was executed
- **Reflections** - What was learned
- **Improvements** - What to do next
- **Errors** - What went wrong

This creates a **retrieval-augmented memory** that makes the AI smarter over time.

## Safety Features

🔒 **Directory Sandboxing**
File operations only allowed in:
- `src/`
- `tests/`
- `docs/`

🔒 **Command Blocking**
Dangerous commands are blocked:
- `rm`, `rmdir`, `del`
- `format`, `dd`
- `shutdown`, `reboot`
- `sudo`, `kill`

🔒 **Automatic Rollback**
- File snapshots before modifications
- Git rollback on failure
- Full plan rollback on error

🔒 **Approval Gates**
High-risk operations pause for manual approval

## File Locations

- **Goals & Learnings**: `data/ai_developer_goals.json`, `data/ai_developer_learnings.json`
- **Perpetual Log**: `data/claude_perpetual_log.json`
- **Archived Logs**: `data/archive/claude_log_*.json` (when log exceeds 10k entries)

## Example Workflows

### Example 1: Add a New Feature

**Goal**: "Implement dark mode toggle in settings"

**What happens**:
1. Claude generates plan with steps:
   - Read existing Settings component
   - Create dark mode state management
   - Write CSS variables for themes
   - Update components to support themes
   - Add toggle UI in settings
   - Write tests
2. System executes each step safely
3. Creates snapshots before file changes
4. Runs tests to verify
5. Self-reflects and suggests:
   - "Add dark mode preference persistence"
   - "Test dark mode in all components"
   - "Document dark mode usage"

### Example 2: Fix a Bug

**Goal**: "Fix memory leak in WebSocket connection handler"

**What happens**:
1. Claude reads the relevant files
2. Analyzes the code for issues
3. Generates fix plan:
   - Identify leak source
   - Add cleanup handlers
   - Test connection lifecycle
   - Update documentation
4. Executes fix with rollback safety
5. Verifies no regression
6. Suggests additional improvements

### Example 3: Refactoring

**Goal**: "Refactor authentication to use JWT instead of sessions"

**What happens**:
1. Claude creates comprehensive plan:
   - Audit current auth system
   - Create JWT utilities
   - Update login/logout endpoints
   - Migrate middleware
   - Update tests
   - Document migration
2. Each step executed with approval gates
3. Git commits created at checkpoints
4. Rollback if any step fails
5. Self-reflection generates tasks:
   - "Add JWT refresh token rotation"
   - "Implement token revocation"
   - "Add rate limiting"

## Tips for Best Results

✅ **Be Specific** - Clear goals get better plans
✅ **Set Priorities** - Critical tasks run first
✅ **Start Small** - Test with simple goals initially
✅ **Monitor Logs** - Watch for issues in real-time
✅ **Review Learnings** - See what the AI is learning
✅ **Check Claude Status** - Ensure API key is configured

## Troubleshooting

**Claude Disconnected**
- Verify API key in settings
- Check internet connection
- Ensure Anthropic API quota available

**Plan Generation Fails**
- Check Claude connection status
- Review error in Live Logs
- Try a more specific goal description

**Step Execution Fails**
- Check sandboxing restrictions
- Review rollback in logs
- Manual approval may be needed

**High Memory Usage**
- Logs auto-compress at 10k entries
- Check `data/archive/` for old logs
- Can manually clear logs if needed

## Advanced: Hands-Free Operation

For **fully autonomous operation**:
1. Add multiple goals with clear priorities
2. Start the system
3. Let it run continuously
4. It will:
   - Work through goals by priority
   - Generate improvement tasks
   - Learn from successes/failures
   - Build up perpetual memory
   - Self-improve over time

The system is designed to **operate indefinitely** with minimal supervision, getting smarter with each goal completed.

---

Built with Claude Max (Sonnet 4.5) + Ollama + Tauri + Vue 3
