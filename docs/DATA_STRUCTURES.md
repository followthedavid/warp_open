# Data Structures Reference

Complete TypeScript interfaces and types used throughout the application.

## Table of Contents

1. [Terminal Types](#terminal-types)
2. [Block Types](#block-types)
3. [Notebook Types](#notebook-types)
4. [Workflow Types](#workflow-types)
5. [AI Types](#ai-types)
6. [UI Types](#ui-types)
7. [Storage Types](#storage-types)

---

## Terminal Types

### PTY Types

```typescript
/**
 * Options for creating a PTY
 */
interface PtyOptions {
  paneId: string
  shell?: string        // Default: $SHELL or /bin/zsh
  cwd?: string          // Default: $HOME
  env?: Record<string, string>
}

/**
 * PTY resize dimensions
 */
interface PtySize {
  cols: number
  rows: number
}

/**
 * Shell command execution result
 */
interface ShellOutput {
  stdout: string
  stderr: string
  exit_code: number
}
```

### Terminal Buffer Types

```typescript
/**
 * Search result in terminal buffer
 */
interface SearchResult {
  lineIndex: number
  columnStart: number
  columnEnd: number
  text: string
}

/**
 * Terminal buffer options
 */
interface TerminalBufferOptions {
  maxLines?: number    // Default: 10000
  chunkSize?: number   // Default: 1000
}
```

---

## Block Types

### Block

```typescript
/**
 * Type of block content
 */
type BlockType = 'command' | 'output' | 'error'

/**
 * Detected output format
 */
type OutputType = 'text' | 'json' | 'error' | 'diff' | 'table'

/**
 * A command block with its output
 */
interface Block {
  id: string                    // Unique identifier
  type: BlockType               // Block type
  command?: string              // The command that was run
  output: string                // Command output
  exitCode?: number             // Exit code (0 = success)
  startTime: number             // Execution start timestamp
  endTime?: number              // Execution end timestamp
  collapsed: boolean            // UI collapse state
  isRunning?: boolean           // Currently executing
  outputType?: OutputType       // Detected output format
  outputLines?: number          // Number of output lines
}
```

### Block Detection Patterns

```typescript
/**
 * OSC 133 shell integration sequences
 */
const OSC_133 = {
  PROMPT_START: '\x1b]133;A\x07',      // Start of prompt
  PROMPT_END: '\x1b]133;B\x07',        // End of prompt (command starts)
  COMMAND_START: '\x1b]133;C\x07',     // Command execution starts
  COMMAND_END: '\x1b]133;D;{code}\x07' // Command finished with exit code
}

/**
 * Prompt detection regex patterns
 */
const PROMPT_PATTERNS: RegExp[] = [
  /^[\w\-\.]+@[\w\-\.]+:[~\/][\w\/\-\.]*[$#]\s*/,  // user@host:path$
  /^[$#]\s+/,                                        // Simple $ or #
  /^[❯➜→▶]\s*/,                                     // Modern prompts
  /^\([\w\-]+\)\s*[$#>]\s*/,                        // (venv) $
  /^[\w\-]+\s*[$#>]\s*/,                            // name $
  /^\[\d{2}:\d{2}(:\d{2})?\]\s*[$#>]\s*/,          // [HH:MM] $
]
```

---

## Notebook Types

### NotebookCell

```typescript
/**
 * Type of notebook cell
 */
type CellType = 'code' | 'markdown' | 'output' | 'error'

/**
 * A single cell in a notebook
 */
interface NotebookCell {
  id: string                          // Unique identifier
  type: CellType                      // Cell type
  content: string                     // Cell content/source
  language?: string                   // For code cells (default: 'bash')
  executionCount?: number             // Times executed
  output?: string                     // Execution output
  error?: string                      // Error message if failed
  startTime?: number                  // Execution start
  endTime?: number                    // Execution end
  collapsed: boolean                  // UI collapse state
  metadata: Record<string, unknown>   // Additional metadata
}
```

### Notebook

```typescript
/**
 * A complete notebook document
 */
interface Notebook {
  id: string                          // Unique identifier
  name: string                        // Display name
  cells: NotebookCell[]               // Ordered cells
  metadata: {
    createdAt: number                 // Creation timestamp
    updatedAt: number                 // Last modified timestamp
    kernel?: string                   // Shell/kernel type
    cwd?: string                      // Working directory
  }
}
```

---

## Workflow Types

### WorkflowParameter

```typescript
/**
 * Parameter type for workflow placeholders
 */
type ParameterType = 'string' | 'path' | 'number' | 'boolean' | 'select'

/**
 * A parameter that can be filled when executing a workflow
 */
interface WorkflowParameter {
  name: string                        // Parameter name (used in {{name}})
  type: ParameterType                 // Input type
  description: string                 // Help text
  default?: string                    // Default value
  options?: string[]                  // For 'select' type
  required?: boolean                  // Is required (default: true)
}
```

### Workflow

```typescript
/**
 * Workflow category
 */
type WorkflowCategory = 'git' | 'docker' | 'npm' | 'system' | 'network' | 'custom'

/**
 * A saved command workflow/snippet
 */
interface Workflow {
  id: string                          // Unique identifier
  name: string                        // Display name
  description: string                 // What it does
  command: string                     // Command with {{param}} placeholders
  parameters: WorkflowParameter[]     // Parameters to fill
  category: WorkflowCategory          // Category for grouping
  tags: string[]                      // Search tags
  icon?: string                       // Emoji icon
  isBuiltin: boolean                  // System-provided workflow
  isFavorite: boolean                 // User favorited
  usageCount: number                  // Times executed
  createdAt: number                   // Creation timestamp
  updatedAt: number                   // Last modified timestamp
}
```

### Builtin Workflows

```typescript
/**
 * Example builtin workflows
 */
const BUILTIN_WORKFLOWS: Workflow[] = [
  {
    id: 'git-status',
    name: 'Git Status',
    description: 'Show git repository status',
    command: 'git status',
    parameters: [],
    category: 'git',
    tags: ['git', 'status', 'changes'],
    icon: '',
    isBuiltin: true,
    isFavorite: false,
    usageCount: 0,
    createdAt: 0,
    updatedAt: 0,
  },
  {
    id: 'git-commit',
    name: 'Git Commit',
    description: 'Commit staged changes',
    command: 'git commit -m "{{message}}"',
    parameters: [
      {
        name: 'message',
        type: 'string',
        description: 'Commit message',
        required: true,
      }
    ],
    category: 'git',
    tags: ['git', 'commit'],
    icon: '',
    isBuiltin: true,
    isFavorite: false,
    usageCount: 0,
    createdAt: 0,
    updatedAt: 0,
  },
  // ... more workflows
]
```

---

## AI Types

### Tool Types

```typescript
/**
 * Parameter type for tools
 */
type ToolParameterType = 'string' | 'number' | 'boolean' | 'array' | 'object'

/**
 * Tool parameter definition
 */
interface ToolParameter {
  name: string
  type: ToolParameterType
  description: string
  required: boolean
  default?: unknown
}

/**
 * Result of tool execution
 */
interface ToolResult {
  success: boolean
  output: string
  error?: string
  metadata?: Record<string, unknown>
}

/**
 * Tool definition
 */
interface Tool {
  name: string
  description: string
  parameters: ToolParameter[]
  execute: (params: Record<string, unknown>) => Promise<ToolResult>
}

/**
 * Record of a tool invocation
 */
interface ToolCall {
  id: string
  tool: string
  params: Record<string, unknown>
  status: 'pending' | 'running' | 'completed' | 'failed'
  result?: ToolResult
  startTime: number
  endTime?: number
}
```

### Available Tools

```typescript
/**
 * Tool definitions
 */
const TOOLS: Tool[] = [
  {
    name: 'Read',
    description: 'Read the contents of a file',
    parameters: [
      { name: 'path', type: 'string', description: 'File path', required: true }
    ],
    execute: readFile
  },
  {
    name: 'Write',
    description: 'Write content to a file',
    parameters: [
      { name: 'path', type: 'string', description: 'File path', required: true },
      { name: 'content', type: 'string', description: 'Content', required: true }
    ],
    execute: writeFile
  },
  {
    name: 'Edit',
    description: 'Replace text in a file',
    parameters: [
      { name: 'path', type: 'string', description: 'File path', required: true },
      { name: 'oldText', type: 'string', description: 'Text to find', required: true },
      { name: 'newText', type: 'string', description: 'Replacement', required: true }
    ],
    execute: editFile
  },
  {
    name: 'Bash',
    description: 'Execute a shell command',
    parameters: [
      { name: 'command', type: 'string', description: 'Command', required: true },
      { name: 'cwd', type: 'string', description: 'Working directory', required: false }
    ],
    execute: executeShell
  },
  {
    name: 'Grep',
    description: 'Search for patterns in files',
    parameters: [
      { name: 'pattern', type: 'string', description: 'Search pattern', required: true },
      { name: 'path', type: 'string', description: 'Search path', required: false, default: '.' },
      { name: 'caseInsensitive', type: 'boolean', description: 'Ignore case', required: false }
    ],
    execute: searchFiles
  },
  {
    name: 'Glob',
    description: 'Find files by pattern',
    parameters: [
      { name: 'pattern', type: 'string', description: 'File pattern', required: true },
      { name: 'path', type: 'string', description: 'Search path', required: false, default: '.' }
    ],
    execute: findFiles
  },
  {
    name: 'ListDir',
    description: 'List directory contents',
    parameters: [
      { name: 'path', type: 'string', description: 'Directory', required: false, default: '.' }
    ],
    execute: listDirectory
  },
  {
    name: 'GetCwd',
    description: 'Get current working directory',
    parameters: [],
    execute: getCwd
  }
]
```

### Agent Types

```typescript
/**
 * Agent message role
 */
type MessageRole = 'user' | 'assistant' | 'tool' | 'system'

/**
 * A message in the agent conversation
 */
interface AgentMessage {
  id: string
  role: MessageRole
  content: string
  timestamp: number
  toolCall?: {
    tool: string
    params: Record<string, unknown>
    result?: ToolResult
  }
}

/**
 * Agent context information
 */
interface AgentContext {
  cwd: string                         // Current working directory
  recentFiles: string[]               // Recently accessed files
  recentCommands: string[]            // Recently run commands
}
```

### AI Command Search Types

```typescript
/**
 * A command suggestion from AI search
 */
interface CommandSuggestion {
  id: string
  command: string                     // The shell command
  description: string                 // Short description
  explanation: string                 // Detailed explanation
  confidence: number                  // 0-1 confidence score
  dangerous: boolean                  // Potentially destructive
}

/**
 * Result of an AI command search
 */
interface SearchResult {
  query: string                       // Original query
  suggestions: CommandSuggestion[]    // Suggestions returned
  timestamp: number                   // When searched
}
```

---

## UI Types

### Tab Types

```typescript
/**
 * A tab in the tab bar
 */
interface Tab {
  id: string
  title: string                       // Display title
  paneId: string                      // Associated pane
  icon?: string                       // Tab icon
  isActive: boolean                   // Currently selected
  isPinned: boolean                   // Cannot be closed
  order: number                       // Position in tab bar
}
```

### Pane Types

```typescript
/**
 * Direction of split
 */
type SplitDirection = 'horizontal' | 'vertical'

/**
 * Type of pane content
 */
type PaneType = 'terminal' | 'editor' | 'notebook' | 'agent'

/**
 * A pane in the split layout
 */
interface Pane {
  id: string
  type: PaneType
  parentId?: string                   // Parent pane (for nested splits)
  children?: string[]                 // Child pane IDs
  splitDirection?: SplitDirection     // How this pane is split
  size: number                        // Percentage 0-100
}
```

### Theme Types

```typescript
/**
 * Theme type
 */
type ThemeType = 'light' | 'dark'

/**
 * Color scheme for theme
 */
interface ThemeColors {
  // UI colors
  background: string
  foreground: string
  primary: string
  secondary: string
  accent: string
  error: string
  warning: string
  success: string
  border: string

  // Terminal ANSI colors
  black: string
  red: string
  green: string
  yellow: string
  blue: string
  magenta: string
  cyan: string
  white: string
  brightBlack: string
  brightRed: string
  brightGreen: string
  brightYellow: string
  brightBlue: string
  brightMagenta: string
  brightCyan: string
  brightWhite: string
}

/**
 * Font configuration
 */
interface ThemeFonts {
  ui: string                          // UI font family
  mono: string                        // Monospace font family
  size: number                        // Base font size
}

/**
 * Complete theme definition
 */
interface Theme {
  id: string
  name: string
  type: ThemeType
  colors: ThemeColors
  fonts: ThemeFonts
}
```

### Toast Types

```typescript
/**
 * Toast notification type
 */
type ToastType = 'info' | 'success' | 'warning' | 'error'

/**
 * A toast notification
 */
interface Toast {
  id: string
  type: ToastType
  message: string
  duration: number                    // Auto-dismiss after ms (0 = no auto)
  dismissible: boolean                // Can be manually dismissed
}
```

### Autocomplete Types

```typescript
/**
 * Type of autocomplete suggestion
 */
type SuggestionType = 'command' | 'path' | 'flag' | 'git' | 'env' | 'history' | 'snippet'

/**
 * An autocomplete suggestion
 */
interface Suggestion {
  id: string
  text: string                        // The suggestion text
  type: SuggestionType                // Suggestion source
  description?: string                // Help text
  score: number                       // Match score for sorting
}
```

---

## Storage Types

### Session Storage

```typescript
/**
 * Session state for persistence
 */
interface SessionState {
  version: number                     // Schema version
  timestamp: number                   // Last save time
  tabs: Tab[]                         // All tabs
  panes: Pane[]                       // All panes
  activeTabId: string | null          // Currently active tab
  activePaneId: string | null         // Currently focused pane
  cwds: Record<string, string>        // paneId → working directory
}

// Storage key: 'warp_session'
```

### Snapshot Storage

```typescript
/**
 * A workspace snapshot
 */
interface Snapshot {
  id: string
  name: string
  timestamp: number
  tabs: Tab[]
  panes: Pane[]
  cwds: Record<string, string>
  tags: string[]
  thumbnail?: string                  // Base64 screenshot
}

// Storage key: 'warp_snapshots'
```

### Workflow Storage

```typescript
/**
 * Custom workflows are stored as array
 */
type WorkflowStorage = Workflow[]

// Storage key: 'warp_workflows'
```

### Theme Storage

```typescript
/**
 * Theme preferences
 */
interface ThemeStorage {
  currentThemeId: string
  customThemes: Theme[]
}

// Storage key: 'warp_theme' (current ID)
// Storage key: 'warp_custom_themes' (custom themes array)
```

### History Storage

```typescript
/**
 * Command history for autocomplete
 */
type HistoryStorage = string[]        // Array of commands, newest first

// Storage key: 'warp_command_history'
```

### Notebook Storage

```typescript
/**
 * All notebooks
 */
type NotebookStorage = Notebook[]

// Storage key: 'warp_notebooks'
```

### AI Search History Storage

```typescript
/**
 * AI command search history
 */
type AISearchHistoryStorage = SearchResult[]

// Storage key: 'warp_ai_search_history'
```

---

## Utility Types

### Common Patterns

```typescript
/**
 * Generate unique ID
 */
function genId(prefix: string = ''): string {
  return `${prefix}${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
}

/**
 * Nullable type helper
 */
type Nullable<T> = T | null

/**
 * Deep partial type
 */
type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P]
}

/**
 * Timestamp in milliseconds
 */
type Timestamp = number
```

### Computed Return Types

```typescript
/**
 * Return type for composables (pattern)
 */
interface UseExampleReturn {
  // Reactive state (read-only from outside)
  items: ComputedRef<Item[]>
  activeItem: ComputedRef<Item | null>
  isLoading: ComputedRef<boolean>
  error: ComputedRef<string | null>

  // Mutable refs
  selectedId: Ref<string | null>

  // Actions
  create(data: Partial<Item>): Item
  update(id: string, data: Partial<Item>): void
  delete(id: string): void

  // Queries
  getById(id: string): Item | undefined
  search(query: string): Item[]
}

// Export type for external use
export type UseExampleReturn = ReturnType<typeof useExample>
```
