# Reddit Launch Posts

## r/commandline

**Title:** I built an open-source Warp alternative with local AI (no cloud, no API keys)

**Body:**

After using Warp and wanting its features without the cloud dependency, I built Warp_Open – a local-first terminal that combines Warp's UX with agentic AI.

**Features:**
- Command blocks with collapsible output
- Notebook mode (Jupyter-style cells)
- AI assistant using Ollama (100% local)
- Agent mode with file read/write/edit
- Split panes, tabs, session recovery
- Plugin system with permissions

**Tech:** Tauri + Rust + Vue 3 + xterm.js

**No cloud. No API keys. No telemetry.**

Everything runs locally. The AI uses Ollama so you can use any model you want.

GitHub: https://github.com/warp-open/warp_open

Would love feedback on what features you'd want to see!

---

## r/rust

**Title:** Warp_Open: A Warp-style terminal built with Tauri + Rust (local AI, no cloud)

**Body:**

I've been working on Warp_Open, a terminal emulator built with Tauri and Rust that brings Warp's modern UX to an open-source, local-first package.

**Rust backend handles:**
- PTY management with portable-pty
- Session persistence
- Ollama LLM integration
- File operations for AI agent mode
- Crash recovery with panic logs

**Architecture highlights:**
- Event-driven PTY (no polling)
- Mutex recovery helpers for crash resilience
- 10+ Tauri commands
- SQLite for policy/session storage

**Frontend:** Vue 3 + TypeScript + xterm.js (WebGL)

**Performance:**
- 100k lines rendered in 23ms
- 60 FPS with WebGL
- ~80MB base memory

The codebase includes 107KB of documentation and 53 tests.

GitHub: https://github.com/warp-open/warp_open

Happy to discuss the architecture or answer questions about using Tauri for terminal apps!

---

## r/selfhosted

**Title:** Warp_Open – Self-hosted terminal with local AI (Ollama), no cloud required

**Body:**

For those who want a modern terminal without cloud dependencies:

**Warp_Open** is an open-source terminal with:
- AI command search (natural language → shell commands)
- Agent mode (AI can read/write files, run commands)
- Command blocks and notebooks
- Session snapshots and recovery

**The key difference from Warp:** Everything runs locally.

- AI uses Ollama (run your own models)
- No telemetry
- No API keys
- Works offline

**Self-hosting benefits:**
- Your terminal data never leaves your machine
- Use any Ollama model (Qwen, Llama, CodeLlama, etc.)
- Full control over the AI's capabilities

Built with Tauri (Rust) + Vue 3. MIT licensed.

GitHub: https://github.com/warp-open/warp_open

---

## r/vuejs

**Title:** Built a full terminal app with Vue 3 Composition API + Tauri

**Body:**

Wanted to share Warp_Open, a terminal emulator I built using Vue 3 and Tauri.

**Vue 3 architecture:**
- 15+ composables for state management
- 20+ components
- Full TypeScript
- Composition API throughout

**Key composables:**
- `usePty.ts` – PTY management
- `useBlocks.ts` – Command grouping
- `useNotebook.ts` – Jupyter-style cells
- `useTools.ts` – AI tool framework
- `useAgentMode.ts` – Agentic AI loop

**Patterns used:**
- Reactive state without Vuex/Pinia
- Composable-based architecture
- Lazy component loading
- Event-driven updates from Rust

**Performance:**
- Code-split Monaco + xterm
- 63KB core bundle (gzipped)
- 60 FPS rendering

The project has comprehensive docs including a full composables reference.

GitHub: https://github.com/warp-open/warp_open

Happy to discuss Vue patterns or answer questions!

---

## Posting Schedule

| Platform | Best Time | Notes |
|----------|-----------|-------|
| r/commandline | Tue-Thu, morning | Most relevant audience |
| r/rust | Tue-Wed, afternoon | Technical audience |
| r/selfhosted | Weekend | Privacy-focused |
| r/vuejs | Anytime | Framework community |

**Tips:**
1. Don't crosspost simultaneously
2. Engage with comments
3. Be humble about limitations
4. Link to specific docs
5. Thank people for feedback
