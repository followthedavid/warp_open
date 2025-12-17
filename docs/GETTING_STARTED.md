# Getting Started with Warp_Open

Welcome to Warp_Open! This guide will get you up and running in under 5 minutes.

## Table of Contents

1. [What is Warp_Open?](#what-is-warp_open)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Quick Tour](#quick-tour)
5. [Your First Commands](#your-first-commands)
6. [Using the AI Assistant](#using-the-ai-assistant)
7. [Customization](#customization)
8. [Next Steps](#next-steps)

---

## What is Warp_Open?

Warp_Open is a **local-first terminal** that combines:
- **Warp's modern UX** – Command blocks, notebooks, sleek interface
- **Agentic AI** – AI that can read, write, and execute on your behalf
- **Plugin System** – Extend functionality with v2 API

Everything runs locally. No cloud. No telemetry. No API keys required.

---

## System Requirements

| Platform | Requirements |
|----------|-------------|
| **macOS** | 10.15+ (Catalina or later) |
| **Linux** | Ubuntu 20.04+, Fedora 34+, or equivalent |
| **Windows** | Windows 10+ (experimental) |

**Dependencies:**
- Node.js 18+
- Rust 1.70+ (for building)
- Ollama (for AI features)

---

## Installation

### Option 1: Pre-built Binary (Recommended)

```bash
# macOS
brew install warp-open/tap/warp-open

# Linux (Debian/Ubuntu)
curl -fsSL https://warp-open.dev/install.sh | sh

# Windows
winget install warp-open
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/warp-open/warp_open.git
cd warp_open

# Install dependencies
npm install

# Run in development mode
npm run tauri:dev

# Or build for production
npm run tauri:build
```

### Install Ollama (for AI features)

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama
ollama serve

# Pull a coding model
ollama pull qwen2.5-coder:7b
```

---

## Quick Tour

### The Interface

```
┌─────────────────────────────────────────────────┐
│ [Tab 1] [Tab 2] [+]                    [AI] [⚙] │  <- Tab bar
├─────────────────────────────────────────────────┤
│                                                 │
│  $ ls -la                                       │  <- Command input
│  ┌─────────────────────────────────────────┐   │
│  │ total 48                                 │   │  <- Command block
│  │ drwxr-xr-x  12 user  staff   384 Dec 15 │   │
│  │ -rw-r--r--   1 user  staff  1234 Dec 15 │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
│  $ git status                                   │
│  ┌─────────────────────────────────────────┐   │
│  │ On branch main                          │   │
│  │ nothing to commit, working tree clean   │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
├─────────────────────────────────────────────────┤
│ ~/projects/myapp                    main ✓     │  <- Status bar
└─────────────────────────────────────────────────┘
```

### Key Features

| Feature | Description |
|---------|-------------|
| **Command Blocks** | Output is grouped into collapsible blocks |
| **Tabs** | Multiple terminal sessions in tabs |
| **Split Panes** | Divide your view horizontally/vertically |
| **AI Panel** | Chat with AI assistant (Cmd+I) |
| **Command Palette** | Quick actions (Cmd+K) |

---

## Your First Commands

### Basic Terminal Usage

Warp_Open works like any terminal:

```bash
# Navigate
cd ~/projects

# List files
ls -la

# Create a file
echo "Hello, Warp_Open!" > hello.txt

# View file
cat hello.txt
```

### Command Blocks

When you run a command, the output is captured in a **command block**:

- **Click** the block header to collapse/expand
- **Copy** the entire output with one click
- **Re-run** the command from the block menu

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+K` | Command palette |
| `Cmd+T` | New tab |
| `Cmd+W` | Close tab |
| `Cmd+D` | Split pane |
| `Cmd+I` | Toggle AI panel |
| `Cmd+,` | Settings |
| `Ctrl+C` | Cancel command |
| `Ctrl+L` | Clear screen |

---

## Using the AI Assistant

### Opening the AI Panel

Press `Cmd+I` or click the AI button in the top right.

### Chat Mode

Ask questions naturally:

```
You: How do I find all Python files modified in the last week?

AI: You can use the find command with -mtime:

    find . -name "*.py" -mtime -7

This searches the current directory for .py files modified
in the last 7 days.
```

### Agent Mode

The AI can execute commands on your behalf:

```
You: Create a Python script that reads data.csv and converts it to JSON

AI: I'll create that script for you.

[AI writes file: convert.py]
[AI executes: python convert.py]

Done! The script has been created and executed.
Output saved to data.json.
```

### What the AI Can Do

| Tool | Description |
|------|-------------|
| **Read** | Read files from your filesystem |
| **Write** | Create new files |
| **Edit** | Modify existing files |
| **Bash** | Execute shell commands |
| **Grep** | Search file contents |
| **Glob** | Find files by pattern |

### Privacy Note

All AI processing happens locally via Ollama. Your data never leaves your machine.

---

## Customization

### Themes

Open Settings (`Cmd+,`) and navigate to Appearance:

- **Dark** (default)
- **Light**
- **Custom** (define your own colors)

### Font Settings

```json
{
  "terminal": {
    "fontFamily": "JetBrains Mono",
    "fontSize": 14,
    "lineHeight": 1.4
  }
}
```

### Shell Configuration

Warp_Open respects your shell configuration:

- **zsh**: `~/.zshrc`
- **bash**: `~/.bashrc`
- **fish**: `~/.config/fish/config.fish`

### Plugins

Enable/disable plugins in Settings > Plugins:

- **Git Insights** – Branch status, command history
- **Command Linter** – Dangerous command warnings
- **Session Annotator** – Notes and tags
- **Command Timer** – Execution stats

---

## Next Steps

### Learn More

- [Plugin Development Guide](./PLUGIN_DEV_GUIDE.md) – Build your own plugins
- [Configuration Reference](./CONFIGURATION.md) – All settings explained
- [Keyboard Shortcuts](./SHORTCUTS.md) – Full shortcut reference
- [Troubleshooting](./TROUBLESHOOTING.md) – Common issues and fixes

### Community

- **GitHub Issues** – Report bugs, request features
- **Discussions** – Ask questions, share tips
- **Contributing** – See CONTRIBUTING.md

### Explore Plugins

Check out the [Plugin Ideas](../launch/PLUGIN_IDEAS_ISSUE.md) for inspiration or claim one to build!

---

## Troubleshooting Quick Fixes

### AI not responding?

```bash
# Check Ollama is running
ollama list

# If not, start it
ollama serve
```

### Slow performance?

1. Check WebGL is enabled in your browser/WebView
2. Reduce font size for large outputs
3. Clear terminal history: `Ctrl+L`

### Commands not working?

Make sure your shell is configured:

```bash
# Check current shell
echo $SHELL

# Warp_Open supports: bash, zsh, fish
```

---

**Welcome to Warp_Open!** If you have questions, open an issue on GitHub.
