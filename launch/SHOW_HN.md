# Show HN: Warp_Open – Local-first terminal with Warp's UX and Claude Code's AI

**Title:** Show HN: Warp_Open – A local-first terminal combining Warp's UX with agentic AI

**URL:** https://github.com/warp-open/warp_open

---

**Post Body:**

Hi HN,

I built Warp_Open, an open-source terminal that combines Warp's modern UX with Claude Code-style agentic AI – all running locally with no cloud dependencies.

**Why I built this:**

I loved Warp's command blocks and notebooks, but didn't want to send my terminal data to the cloud. I also wanted Claude Code's agentic capabilities (file read/write, shell execution) integrated directly into my terminal. So I built both.

**Key features:**

- **Command Blocks** – Group commands with collapsible output (OSC 133 + heuristics)
- **Agent Mode** – AI with tool execution (Read/Write/Edit/Bash/Grep/Glob)
- **Notebook Mode** – Jupyter-style cells in your terminal
- **100% Local** – Uses Ollama for AI, no API keys needed
- **Plugin System** – Extensible v2 API with permissions, hot reload, background workers

**Official Plugins (shipping with v1.0.0):**

- **Git Insights** – Branch status, ahead/behind, command history
- **Command Linter** – Warns before dangerous commands (rm -rf, chmod 777, curl|bash)
- **Session Annotator** – Notes, tags, and stars on commands with markdown export
- **Command Timer** – Execution timing and stats

**Maintainer Automation (for open source maintainers):**

- Real-time notifications for GitHub/HN/Reddit activity
- Auto-tagging for issues based on content analysis
- Response suggestion engine with 14 templates
- Metrics dashboard with ASCII terminal display

**Tech stack:**

- Tauri + Rust (backend)
- Vue 3 + TypeScript (frontend)
- xterm.js with WebGL rendering
- Ollama for local LLM

**Performance:**

- 60 FPS terminal rendering
- 100k lines in 23ms
- 63 KB core bundle (gzipped)
- < 1.5s cold start

**Comparison with Warp:**

| Feature | Warp_Open | Warp |
|---------|-----------|------|
| Open source | MIT | No |
| AI | Local (Ollama) | Cloud API |
| Privacy | 100% local | Cloud telemetry |
| Notebooks | Full | Partial |
| Plugins | v2 API | Limited |
| Maintainer Tools | Built-in | No |

The codebase has 107KB of documentation – enough to rebuild from scratch. 66 tests passing.

I'd love feedback on:
1. What plugins would you want?
2. What features are missing vs your current terminal?
3. Any UX improvements?

GitHub: https://github.com/warp-open/warp_open

Thanks for checking it out!

---

## Tips for posting:

1. Post on a weekday, 9-11 AM EST
2. Don't ask for upvotes
3. Respond to comments quickly
4. Be honest about limitations
5. Link to specific docs when answering questions
