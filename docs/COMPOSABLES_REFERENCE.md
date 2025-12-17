# Composables Reference

Complete documentation for all Vue composables in the project.

## Table of Contents

1. [Terminal Core](#terminal-core)
2. [Warp Features](#warp-features)
3. [Claude Code Features](#claude-code-features)
4. [UI Management](#ui-management)
5. [Utilities](#utilities)

---

## Terminal Core

### usePty.ts

PTY (pseudo-terminal) management for shell sessions.

```typescript
interface UsePtyOptions {
  paneId: string
  shell?: string
  cwd?: string
  env?: Record<string, string>
}

interface UsePtyReturn {
  // State
  isConnected: ComputedRef<boolean>
  isLoading: ComputedRef<boolean>
  error: ComputedRef<string | null>

  // Actions
  create(): Promise<void>
  write(data: string): Promise<void>
  resize(cols: number, rows: number): Promise<void>
  destroy(): Promise<void>

  // Events
  onData(callback: (data: string) => void): void
  onExit(callback: (code: number) => void): void
}
```

**Usage:**
```typescript
const { create, write, resize, destroy, onData } = usePty({ paneId: 'pane-1' })

await create()
onData((data) => terminal.write(data))
await write('ls -la\n')
```

**Rust Commands Used:**
- `create_pty` - Create new PTY
- `write_to_pty` - Send input to PTY
- `resize_pty` - Resize terminal dimensions
- `destroy_pty` - Clean up PTY

---

### useTerminalBuffer.ts

Efficient terminal output buffering with search and virtual scrolling.

```typescript
interface UseTerminalBufferOptions {
  maxLines?: number        // Default: 10000
  chunkSize?: number       // Default: 1000
}

interface UseTerminalBufferReturn {
  // State
  lines: ComputedRef<string[]>
  lineCount: ComputedRef<number>

  // Actions
  appendOutput(text: string): void
  clear(): void
  getRange(start: number, end: number): string[]

  // Search
  search(query: string): SearchResult[]
  highlightMatches(query: string): void
  clearHighlights(): void
}

interface SearchResult {
  lineIndex: number
  columnStart: number
  columnEnd: number
  text: string
}
```

**Usage:**
```typescript
const buffer = useTerminalBuffer({ maxLines: 50000 })

buffer.appendOutput('Command output here\n')
const results = buffer.search('error')
```

---

### useBlocks.ts

Warp-style command blocks with output grouping.

```typescript
type BlockType = 'command' | 'output' | 'error'

interface Block {
  id: string
  type: BlockType
  command?: string
  output: string
  exitCode?: number
  startTime: number
  endTime?: number
  collapsed: boolean
  outputType?: 'text' | 'json' | 'error' | 'diff' | 'table'
}

interface UseBlocksReturn {
  // State
  blocks: ComputedRef<Block[]>
  activeBlockId: ComputedRef<string | null>

  // Actions
  startBlock(command: string): Block
  appendToBlock(id: string, output: string): void
  endBlock(id: string, exitCode: number): void
  toggleCollapse(id: string): void
  deleteBlock(id: string): void
  clearBlocks(): void

  // Processing
  processOutput(raw: string): void  // OSC 133 + heuristic detection
}
```

**Block Detection Methods:**
1. **OSC 133** - Shell integration escape sequences
2. **Prompt Heuristics** - Pattern matching for common prompts:
   ```typescript
   const PROMPT_PATTERNS = [
     /^[\w\-\.]+@[\w\-\.]+:[~\/][\w\/\-\.]*[$#]\s*/,  // user@host:path$
     /^[$#]\s+/,                                        // Simple $ or #
     /^[❯➜→▶]\s*/,                                     // Modern prompts
     /^\([\w\-]+\)\s*[$#>]\s*/,                        // (venv) $
   ]
   ```

---

## Warp Features

### useAutocomplete.ts

Command autocompletion with fuzzy matching.

```typescript
type SuggestionType = 'command' | 'path' | 'flag' | 'git' | 'env' | 'history' | 'snippet'

interface Suggestion {
  id: string
  text: string
  type: SuggestionType
  description?: string
  score: number
}

interface UseAutocompleteReturn {
  // State
  suggestions: ComputedRef<Suggestion[]>
  selectedIndex: Ref<number>
  isLoading: ComputedRef<boolean>

  // Actions
  getSuggestions(input: string, cursorPos: number): Promise<Suggestion[]>
  selectNext(): void
  selectPrevious(): void
  acceptSuggestion(): string | null
  dismiss(): void

  // History
  addToHistory(command: string): void
  getHistory(): string[]
}
```

**Suggestion Sources:**
1. Command history (localStorage)
2. Common shell commands (45+ builtin)
3. Git subcommands (when input starts with `git `)
4. npm subcommands (when input starts with `npm `)
5. Path completion (via Rust `list_directory`)
6. Environment variables (when input contains `$`)

**Fuzzy Matching Algorithm:**
```typescript
function fuzzyScore(input: string, candidate: string): number {
  // Exact match: 100
  // Starts with: 80 + position bonus
  // Contains: 50 + position bonus
  // Fuzzy match: character-by-character scoring
}
```

---

### useWorkflows.ts

Saved command workflows with parameters.

```typescript
interface WorkflowParameter {
  name: string
  type: 'string' | 'path' | 'number' | 'boolean' | 'select'
  description: string
  default?: string
  options?: string[]  // For select type
}

interface Workflow {
  id: string
  name: string
  description: string
  command: string              // Contains {{paramName}} placeholders
  parameters: WorkflowParameter[]
  category: 'git' | 'docker' | 'npm' | 'system' | 'network' | 'custom'
  tags: string[]
  icon?: string
  isBuiltin: boolean
  isFavorite: boolean
  usageCount: number
  createdAt: number
  updatedAt: number
}

interface UseWorkflowsReturn {
  // State
  workflows: ComputedRef<Workflow[]>
  favorites: ComputedRef<Workflow[]>
  categories: ComputedRef<string[]>

  // CRUD
  createWorkflow(data: Partial<Workflow>): Workflow
  updateWorkflow(id: string, updates: Partial<Workflow>): void
  deleteWorkflow(id: string): void

  // Actions
  executeWorkflow(id: string, params: Record<string, string>): string
  toggleFavorite(id: string): void
  incrementUsage(id: string): void

  // Import/Export
  exportWorkflows(): string  // JSON
  importWorkflows(json: string): void

  // Search
  searchWorkflows(query: string): Workflow[]
  filterByCategory(category: string): Workflow[]
  filterByTags(tags: string[]): Workflow[]
}
```

**Builtin Workflows (15+):**
- Git: status, commit, push, pull, branch, stash
- Docker: ps, images, logs, exec, compose
- npm: install, run, test, build
- System: disk usage, process list, ports
- Network: ping, curl, netstat

**Parameter Resolution:**
```typescript
function resolveCommand(command: string, params: Record<string, string>): string {
  return command.replace(/\{\{(\w+)\}\}/g, (_, name) => params[name] || '')
}
// "git commit -m '{{message}}'" + {message: "fix bug"}
// → "git commit -m 'fix bug'"
```

---

### useNotebook.ts

Jupyter-style notebook for terminal sessions.

```typescript
type CellType = 'code' | 'markdown' | 'output' | 'error'

interface NotebookCell {
  id: string
  type: CellType
  content: string
  language?: string           // For code cells, default 'bash'
  executionCount?: number
  output?: string
  error?: string
  startTime?: number
  endTime?: number
  collapsed: boolean
  metadata: Record<string, unknown>
}

interface Notebook {
  id: string
  name: string
  cells: NotebookCell[]
  metadata: {
    createdAt: number
    updatedAt: number
    kernel?: string
    cwd?: string
  }
}

interface UseNotebookReturn {
  // State
  notebooks: ComputedRef<Notebook[]>
  activeNotebook: ComputedRef<Notebook | null>
  activeCell: ComputedRef<NotebookCell | null>
  activeCellId: ComputedRef<string | null>
  isExecuting: ComputedRef<boolean>

  // Notebook CRUD
  createNotebook(name?: string): Notebook
  openNotebook(id: string): void
  closeNotebook(): void
  deleteNotebook(id: string): void
  renameNotebook(id: string, name: string): void

  // Cell CRUD
  addCell(type?: CellType, content?: string, afterId?: string): NotebookCell | null
  updateCell(cellId: string, updates: Partial<NotebookCell>): void
  deleteCell(cellId: string): void
  moveCell(cellId: string, direction: 'up' | 'down'): void
  toggleCollapse(cellId: string): void

  // Navigation
  selectCell(cellId: string | null): void
  navigateCell(direction: 'next' | 'prev'): void

  // Execution
  executeCell(cellId: string): Promise<void>
  executeAll(): Promise<void>
  clearOutputs(): void

  // Import/Export
  importFromBlocks(blocks: Array<{command: string, output: string, exitCode?: number}>): Notebook
  exportToJson(id?: string): string
  exportToMarkdown(id?: string): string
  exportToScript(id?: string): string
}
```

**Cell Execution:**
```typescript
async function executeCell(cellId: string): Promise<void> {
  const cell = findCell(cellId)
  if (!cell || cell.type !== 'code') return

  cell.startTime = Date.now()
  const result = await invoke('execute_shell', { command: cell.content })
  cell.output = result.stdout
  cell.error = result.stderr || undefined
  cell.executionCount = (cell.executionCount || 0) + 1
  cell.endTime = Date.now()
}
```

---

### useAICommandSearch.ts

Natural language to shell command conversion.

```typescript
interface CommandSuggestion {
  id: string
  command: string
  description: string
  explanation: string
  confidence: number
  dangerous: boolean
}

interface SearchResult {
  query: string
  suggestions: CommandSuggestion[]
  timestamp: number
}

interface UseAICommandSearchReturn {
  // State
  isSearching: ComputedRef<boolean>
  currentQuery: ComputedRef<string>
  suggestions: ComputedRef<CommandSuggestion[]>
  error: ComputedRef<string | null>
  history: ComputedRef<SearchResult[]>
  model: Ref<string>

  // Actions
  search(query: string): Promise<void>
  quickSearch(query: string): CommandSuggestion[]  // Offline patterns
  getRecentSearches(): string[]
  clearResults(): void
  clearHistory(): void
  getSuggestion(id: string): CommandSuggestion | undefined
}
```

**Quick Patterns (Offline):**
```typescript
const QUICK_PATTERNS: Record<string, CommandSuggestion[]> = {
  'list': [{ command: 'ls -la', description: 'List all files with details', ... }],
  'find file': [{ command: 'find . -name "*.txt"', ... }],
  'disk': [{ command: 'df -h', ... }],
  'memory': [{ command: 'free -h', ... }, { command: 'top -l 1 | head -10', ... }],
  'process': [{ command: 'ps aux', ... }],
  'kill': [{ command: 'pkill -f "process_name"', dangerous: true, ... }],
  // ... 15+ more patterns
}
```

**LLM Prompt Format:**
```
You are a shell command expert. Given a natural language description,
suggest the best shell commands to accomplish the task.

Format your response EXACTLY like this:
COMMAND: <the shell command>
DESCRIPTION: <short 5-10 word description>
EXPLANATION: <1 sentence explaining what it does>
DANGEROUS: <yes or no>
```

---

## Claude Code Features

### useTools.ts

Claude Code-style tool execution framework.

```typescript
interface Tool {
  name: string
  description: string
  parameters: ToolParameter[]
  execute: (params: Record<string, unknown>) => Promise<ToolResult>
}

interface ToolParameter {
  name: string
  type: 'string' | 'number' | 'boolean' | 'array' | 'object'
  description: string
  required: boolean
  default?: unknown
}

interface ToolResult {
  success: boolean
  output: string
  error?: string
  metadata?: Record<string, unknown>
}

interface ToolCall {
  id: string
  tool: string
  params: Record<string, unknown>
  status: 'pending' | 'running' | 'completed' | 'failed'
  result?: ToolResult
  startTime: number
  endTime?: number
}

interface UseToolsReturn {
  // State
  tools: ComputedRef<Tool[]>
  history: ComputedRef<ToolCall[]>
  recentCalls: ComputedRef<ToolCall[]>
  isExecuting: ComputedRef<boolean>
  currentCall: ComputedRef<ToolCall | null>

  // Actions
  getTool(name: string): Tool | undefined
  executeTool(toolName: string, params: Record<string, unknown>): Promise<ToolResult>
  parseToolCall(text: string): { tool: string; params: Record<string, unknown> } | null
  getToolsDocumentation(): string
  clearHistory(): void
}
```

**Available Tools:**

| Tool | Description | Parameters |
|------|-------------|------------|
| Read | Read file contents | `path` (required) |
| Write | Write content to file | `path`, `content` (required) |
| Edit | Replace text in file | `path`, `oldText`, `newText` (required) |
| Bash | Execute shell command | `command` (required), `cwd` (optional) |
| Grep | Search for patterns | `pattern` (required), `path`, `caseInsensitive` |
| Glob | Find files by pattern | `pattern` (required), `path` |
| ListDir | List directory contents | `path` |
| GetCwd | Get current directory | (none) |

**Tool Call Parsing:**
Supports three formats:

1. **XML (preferred):**
```xml
<tool name="Read">
  <param name="path">/path/to/file</param>
</tool>
```

2. **JSON:**
```json
{"tool": "Read", "params": {"path": "/path/to/file"}}
```

3. **Function call:**
```
Read(path="/path/to/file")
```

---

### useAgentMode.ts

Agentic AI assistant with tool execution loop.

```typescript
interface AgentMessage {
  id: string
  role: 'user' | 'assistant' | 'tool' | 'system'
  content: string
  timestamp: number
  toolCall?: {
    tool: string
    params: Record<string, unknown>
    result?: ToolResult
  }
}

interface AgentContext {
  cwd: string
  recentFiles: string[]
  recentCommands: string[]
}

interface UseAgentModeReturn {
  // State
  messages: ComputedRef<AgentMessage[]>
  isProcessing: ComputedRef<boolean>
  context: ComputedRef<AgentContext>
  model: Ref<string>

  // Actions
  processMessage(userMessage: string): Promise<void>
  updateContext(updates: Partial<AgentContext>): void
  clearMessages(): void
  addMessage(msg: Omit<AgentMessage, 'id' | 'timestamp'>): AgentMessage
}
```

**Agent Loop:**
```typescript
async function processMessage(userMessage: string): Promise<void> {
  addMessage({ role: 'user', content: userMessage })

  for (let i = 0; i < 10; i++) {  // Max 10 iterations
    const prompt = buildPrompt(userMessage)
    const response = await queryLLM(prompt)
    const toolCall = tools.parseToolCall(response)

    if (toolCall) {
      // Execute tool and continue loop
      const result = await tools.executeTool(toolCall.tool, toolCall.params)
      addMessage({ role: 'tool', content: result.output, toolCall: { ...toolCall, result } })
      if (!result.success) break
    } else {
      // No tool call = final response
      addMessage({ role: 'assistant', content: response })
      break
    }
  }
}
```

**System Prompt:**
```
You are an AI coding assistant. Use tools in XML format:
<tool name="Read"><param name="path">/path/file</param></tool>

Guidelines: Read before modifying, make minimal changes, be concise.
```

---

## UI Management

### useTabs.ts

Tab management for terminal panes.

```typescript
interface Tab {
  id: string
  title: string
  paneId: string
  icon?: string
  isActive: boolean
  isPinned: boolean
  order: number
}

interface UseTabsReturn {
  tabs: ComputedRef<Tab[]>
  activeTab: ComputedRef<Tab | null>

  createTab(options?: Partial<Tab>): Tab
  closeTab(id: string): void
  activateTab(id: string): void
  renameTab(id: string, title: string): void
  pinTab(id: string): void
  unpinTab(id: string): void
  reorderTabs(fromIndex: number, toIndex: number): void

  // Keyboard navigation
  nextTab(): void
  previousTab(): void
  goToTab(index: number): void
}
```

---

### useSplitPane.ts

Pane splitting and layout management.

```typescript
type SplitDirection = 'horizontal' | 'vertical'

interface Pane {
  id: string
  type: 'terminal' | 'editor' | 'notebook' | 'agent'
  parentId?: string
  children?: string[]
  splitDirection?: SplitDirection
  size: number  // Percentage 0-100
}

interface UseSplitPaneReturn {
  panes: ComputedRef<Pane[]>
  activePane: ComputedRef<Pane | null>

  splitPane(paneId: string, direction: SplitDirection): Pane
  closePane(paneId: string): void
  resizePane(paneId: string, size: number): void
  focusPane(paneId: string): void

  // Navigation
  focusNext(): void
  focusPrevious(): void
  focusDirection(direction: 'up' | 'down' | 'left' | 'right'): void
}
```

---

### useTheme.ts

Theme management with CSS variables.

```typescript
interface Theme {
  id: string
  name: string
  type: 'light' | 'dark'
  colors: {
    background: string
    foreground: string
    primary: string
    secondary: string
    accent: string
    error: string
    warning: string
    success: string
    border: string
    // Terminal colors
    black: string
    red: string
    green: string
    yellow: string
    blue: string
    magenta: string
    cyan: string
    white: string
    brightBlack: string
    // ... bright variants
  }
  fonts: {
    ui: string
    mono: string
    size: number
  }
}

interface UseThemeReturn {
  currentTheme: ComputedRef<Theme>
  themes: ComputedRef<Theme[]>
  isDark: ComputedRef<boolean>

  setTheme(id: string): void
  toggleDarkMode(): void
  createCustomTheme(theme: Partial<Theme>): Theme
  deleteCustomTheme(id: string): void
  exportTheme(id: string): string
  importTheme(json: string): Theme
}
```

---

### useSnapshots.ts

Workspace state snapshots.

```typescript
interface Snapshot {
  id: string
  name: string
  timestamp: number
  tabs: Tab[]
  panes: Pane[]
  cwds: Record<string, string>  // paneId → cwd
  tags: string[]
  thumbnail?: string
}

interface UseSnapshotsReturn {
  snapshots: ComputedRef<Snapshot[]>

  createSnapshot(name: string): Snapshot
  restoreSnapshot(id: string): void
  deleteSnapshot(id: string): void
  renameSnapshot(id: string, name: string): void
  addTag(id: string, tag: string): void
  removeTag(id: string, tag: string): void

  // Search & Filter
  searchSnapshots(query: string): Snapshot[]
  filterByTags(tags: string[]): Snapshot[]

  // Auto-snapshot
  enableAutoSnapshot(intervalMs: number): void
  disableAutoSnapshot(): void

  clearAll(): void
  formatTimestamp(timestamp: number): string
}
```

---

### useSessionStore.ts

Session persistence and recovery.

```typescript
interface SessionState {
  version: number
  timestamp: number
  tabs: Tab[]
  panes: Pane[]
  activeTabId: string | null
  activePaneId: string | null
  cwds: Record<string, string>
}

interface UseSessionStoreReturn {
  hasRecoverableSession: ComputedRef<boolean>
  lastSession: ComputedRef<SessionState | null>

  save(): void
  load(): SessionState | null
  clear(): void

  // Auto-save
  startAutoSave(intervalMs?: number): void
  stopAutoSave(): void
  forceSave(): void

  // Pane tracking
  updatePaneCwd(paneId: string, cwd: string): void
  getPaneCwd(paneId: string): string | undefined
}
```

---

## Utilities

### useToast.ts

Toast notification system.

```typescript
type ToastType = 'info' | 'success' | 'warning' | 'error'

interface Toast {
  id: string
  type: ToastType
  message: string
  duration: number
  dismissible: boolean
}

interface UseToastReturn {
  toasts: ComputedRef<Toast[]>

  show(message: string, type?: ToastType, duration?: number): void
  info(message: string): void
  success(message: string): void
  warning(message: string): void
  error(message: string): void
  dismiss(id: string): void
  dismissAll(): void
}
```

---

## Storage Keys

All composables use localStorage with these keys:

| Key | Composable | Description |
|-----|------------|-------------|
| `warp_session` | useSessionStore | Current session state |
| `warp_snapshots` | useSnapshots | Saved workspace snapshots |
| `warp_theme` | useTheme | Current theme ID |
| `warp_custom_themes` | useTheme | User-created themes |
| `warp_workflows` | useWorkflows | Custom workflows |
| `warp_command_history` | useAutocomplete | Command history |
| `warp_notebooks` | useNotebook | Saved notebooks |
| `warp_ai_search_history` | useAICommandSearch | AI search history |
