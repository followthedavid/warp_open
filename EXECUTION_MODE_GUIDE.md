# Code Execution Mode - Usage Guide

## What is Execution Mode?

The enhanced AI Chat now supports **Code Execution Mode** - a conversational interface that can execute code changes, file operations, and terminal commands while you chat, similar to Claude Code or Warp Terminal.

## Features

✅ **Conversational Interface** - Chat naturally with the AI
✅ **Code Execution** - AI can write and modify files
✅ **Live Progress** - See execution steps in real-time
✅ **Inline Results** - Results displayed directly in chat
✅ **Follow-up Support** - Give additional instructions after execution

## How to Use

### 1. Enable Execution Mode

In the AI Chat tab header, check the **⚡ Code Execution** checkbox:

```
Model: deepseek-coder:6.7b | AI Mode: Local Only | [✓] ⚡ Code Execution
```

### 2. Chat and Execute

With execution mode enabled, you can:

**Ask conversational questions:**
```
You: "What is Vue 3 Composition API?"
AI: [Normal conversational response]
```

**Request code changes:**
```
You: "Add a dark mode toggle to the header"
AI: ⚡ Executing: Add dark mode toggle component to header

[Shows live execution steps:]
✓ Read src/App.vue
💭 Analyzing current header structure
✓ Write src/components/DarkModeToggle.vue
✓ Update src/App.vue

Task: Add dark mode toggle component to header
Status: completed
Steps: 4/4 completed
```

**Make file modifications:**
```
You: "Change the primary color to blue"
AI: [Analyzes files, updates CSS, shows results]
```

**Run commands:**
```
You: "Run the tests"
AI: [Executes npm test, shows output]
```

### 3. Execution Steps Display

When executing a task, you'll see:

- **⚡ Executing** header with task description
- **Live step indicators:**
  - ✓ Completed steps (green)
  - ⟳ Currently running (blue, animated)
  - ✗ Failed steps (red)
  - ○ Pending steps (gray)

- **Step types:**
  - 💭 Thinking - AI is analyzing
  - 📖 Reading files
  - 📝 Writing files
  - ⚙️ Running commands

- **Step content** - Shows file contents, code changes, or command output

### 4. Mixed Mode Usage

You can toggle execution mode on/off at any time:

- **Execution OFF** - Pure conversation, no code changes
- **Execution ON** - AI decides if your message needs action or just conversation

The AI automatically detects whether your message is:
- A question → Responds conversationally
- An action request → Executes the task

## Examples

### Example 1: Add a Feature
```
You: "Add a search bar to the terminal component"

AI: ⚡ Executing: Add search functionality to terminal component

Steps:
✓ Read src/components/TerminalTab.vue
💭 Planning search bar implementation
✓ Update template with search input
✓ Add search functionality to script
✓ Add search bar styles

Task completed! Search bar added with live filtering.
```

### Example 2: Fix a Bug
```
You: "The dark mode button isn't working"

AI: ⚡ Executing: Fix dark mode toggle functionality

Steps:
✓ Read src/components/DarkModeToggle.vue
💭 Identifying issue - missing event handler
✓ Update DarkModeToggle.vue with proper @click handler
✓ Update state management

Bug fixed! Dark mode toggle now properly switches themes.
```

### Example 3: Mixed Conversation
```
You: "How does Vue reactivity work?"
AI: [Conversational explanation - no execution]

You: "Great! Now add reactive state to track window size"
AI: ⚡ Executing: Add reactive window size tracking
[Shows execution steps...]
```

## Browser vs Tauri Mode

### Browser Mode (Current)
- Task parsing works (AI identifies actionable tasks)
- Execution plan generation works
- **File operations** show placeholder messages
- **Commands** show placeholder messages

### Tauri Mode (Desktop App)
- Full file system access
- Real file read/write operations
- Terminal command execution
- Complete functionality

## Tips

1. **Be specific** - "Add a button to the header" is better than "improve the UI"
2. **One task at a time** - Let one task finish before starting another
3. **Review changes** - Check the execution steps to see what was modified
4. **Iterate** - Give follow-up instructions to refine the result
5. **Toggle off** - Disable execution mode for pure conversation

## Technical Details

- **Task Parser**: Uses Ollama (deepseek-coder:6.7b) to identify actionable requests
- **Plan Generator**: Creates step-by-step execution plans
- **Executor**: Runs each step sequentially with live updates
- **Progress Tracking**: Real-time step status updates in the UI

## Troubleshooting

**Q: Execution mode is enabled but nothing happens**
A: Make sure Ollama is running (`./start_with_ollama.sh`)

**Q: AI responds conversationally instead of executing**
A: Try being more explicit: "Create a file..." instead of "I need a file..."

**Q: Steps show as completed but files aren't changed**
A: In browser mode, file operations are simulated. Use the Tauri desktop app for real file changes.

**Q: Task failed with an error**
A: Check the error message in the execution steps. Common issues:
  - File not found
  - Permission denied (Tauri mode)
  - Invalid code generated

## Next Steps

1. Try executing a simple task to test the feature
2. Experiment with different types of requests
3. Combine conversation with execution for iterative development
4. Use the Developer Dashboard for autonomous long-running tasks

Enjoy your enhanced AI coding assistant! 🚀
