# Maintainer Response Templates

Use these templates to respond consistently to common questions. Adapt tone as needed.

---

## "Why not contribute to Warp instead?"

> Great question! Warp is proprietary software, so contributing directly isn't possible. More importantly, my goals are different:
>
> 1. **Local-first** - I wanted no cloud dependencies whatsoever
> 2. **Open AI** - Using Ollama means any model, no API keys, works offline
> 3. **Extensible** - The Plugin API v2 lets anyone extend the terminal
>
> Think of Warp_Open as "what if Warp was open source and local-first from day one."

---

## "Is this production ready?"

> v1.0.0 is stable for daily use. I've been using it as my primary terminal.
>
> **What's solid:**
> - Core terminal functionality (PTY, tabs, splits)
> - Session persistence and recovery
> - AI features with Ollama
>
> **Caveats:**
> - Windows support is experimental
> - No SSH integration yet (v2 roadmap)
> - New project, fewer battle-tested edge cases than iTerm2
>
> If you hit issues, please file them! We have crash logging and 53 tests.

---

## "Windows support?"

> Windows is supported but experimental. Known issues:
>
> - ConPTY behavior differs from Unix PTY
> - Some keyboard shortcuts conflict with Windows defaults
> - Performance may be lower than macOS/Linux
>
> We'd love Windows contributors to help improve this. See the [contributing guide](./CONTRIBUTING.md).

---

## "Why local AI only? Can I use OpenAI/Anthropic?"

> Intentional design choice. Local-first means:
>
> 1. **Privacy** - Your terminal data never leaves your machine
> 2. **No cost** - No API keys, no usage fees
> 3. **Offline** - Works without internet
> 4. **Control** - Use any model you want via Ollama
>
> That said, the architecture could support external APIs. If there's demand, we could add it as an opt-in feature with clear privacy warnings.

---

## "How does this compare to iTerm2/Alacritty/Kitty?"

> Different goals:
>
> | Feature | Warp_Open | iTerm2 | Alacritty |
> |---------|-----------|--------|-----------|
> | Command Blocks | Yes | No | No |
> | AI Assistant | Yes (local) | No | No |
> | Notebooks | Yes | No | No |
> | Plugins | Yes (v2 API) | Scripts | No |
> | GPU Rendering | Yes (WebGL) | No | Yes |
>
> If you want a fast, minimal terminal → Alacritty
> If you want mature macOS features → iTerm2
> If you want Warp's UX + local AI → Warp_Open

---

## "Why Tauri instead of Electron?"

> Performance and security:
>
> 1. **Smaller binary** - Tauri apps are ~10MB vs Electron's ~150MB+
> 2. **Lower memory** - No bundled Chromium
> 3. **Native performance** - Rust backend
> 4. **Security** - Explicit permission system
>
> Trade-off: Slightly less cross-platform consistency (WebView varies by OS).

---

## "Can I use this with tmux/screen?"

> Yes! Warp_Open is a terminal emulator, so tmux/screen work normally inside it.
>
> However, some Warp-style features (command blocks) rely on shell integration. If you're inside tmux, the OSC 133 sequences may not pass through correctly.
>
> For best results, use Warp_Open's built-in tabs/splits instead of tmux.

---

## "How do I install Ollama?"

> ```bash
> # macOS
> brew install ollama
>
> # Linux
> curl -fsSL https://ollama.ai/install.sh | sh
>
> # Then start Ollama
> ollama serve
>
> # Pull a coding model
> ollama pull qwen2.5-coder:7b
> ```
>
> See [ollama.ai](https://ollama.ai) for more models and options.

---

## "Plugin idea: [X]"

> Thanks for the suggestion! Please open an issue using the [Plugin Idea template](.github/ISSUE_TEMPLATE/plugin_idea.md).
>
> If you're interested in building it yourself, check out:
> - [PLUGINS.md](./PLUGINS.md) for API documentation
> - `src/plugins/demos/` for examples
> - The "Good First Plugin Ideas" issue for inspiration

---

## "Found a bug"

> Thanks for reporting! Please open an issue with:
>
> 1. Steps to reproduce
> 2. Expected vs actual behavior
> 3. OS and Warp_Open version
> 4. Any logs from `~/.warp_open/crash.log`
>
> Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md).

---

## "How can I contribute?"

> Awesome! Here's how to get started:
>
> 1. Read [CONTRIBUTING.md](./CONTRIBUTING.md)
> 2. Check issues labeled `good-first-issue` or `help-wanted`
> 3. Look at the "Good First Plugin Ideas" issue
> 4. Join discussions for bigger features
>
> Priority areas: Windows fixes, plugins, performance, docs.

---

## "Will you add [cloud feature]?"

> Warp_Open is intentionally local-first. We won't add features that require:
>
> - User accounts
> - Cloud storage
> - External telemetry
>
> However, we may add **opt-in** cloud features in the future with:
> - Clear privacy disclosures
> - Self-hosted options
> - Easy disable
>
> The core will always work 100% offline.

---

## General Positive Response

> Thank you! Really appreciate the kind words. If you find it useful, starring the repo helps others discover it. And if you have ideas for improvements, issues and PRs are welcome!

---

## General Constructive Criticism Response

> Thanks for the feedback! This is helpful. [Acknowledge the specific point]. I've noted this for consideration. If you'd like to discuss further or have specific suggestions, feel free to open an issue or discussion.
