/**
 * useAutocomplete - Warp-style intelligent command autocomplete
 *
 * Provides suggestions for:
 * - Commands (from shell history, common commands)
 * - File/directory paths
 * - Command flags/options
 * - Git branches, remotes
 * - Environment variables
 */

import { ref, computed, watch } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

export interface Suggestion {
  id: string
  text: string
  type: 'command' | 'path' | 'flag' | 'git' | 'env' | 'history' | 'snippet'
  description?: string
  icon?: string
  insertText?: string // What to insert (may differ from text)
  cursorOffset?: number // Where to place cursor after insert
  score: number // Relevance score for sorting
}

export interface AutocompleteState {
  isActive: boolean
  suggestions: Suggestion[]
  selectedIndex: number
  query: string
  triggerPosition: number
}

// Common shell commands with descriptions
const COMMON_COMMANDS: Array<{ cmd: string; desc: string }> = [
  { cmd: 'ls', desc: 'List directory contents' },
  { cmd: 'cd', desc: 'Change directory' },
  { cmd: 'pwd', desc: 'Print working directory' },
  { cmd: 'cat', desc: 'Concatenate and print files' },
  { cmd: 'grep', desc: 'Search text patterns' },
  { cmd: 'find', desc: 'Search for files' },
  { cmd: 'mkdir', desc: 'Create directory' },
  { cmd: 'rm', desc: 'Remove files' },
  { cmd: 'cp', desc: 'Copy files' },
  { cmd: 'mv', desc: 'Move/rename files' },
  { cmd: 'touch', desc: 'Create empty file' },
  { cmd: 'echo', desc: 'Print text' },
  { cmd: 'head', desc: 'Show first lines' },
  { cmd: 'tail', desc: 'Show last lines' },
  { cmd: 'less', desc: 'View file with paging' },
  { cmd: 'vim', desc: 'Text editor' },
  { cmd: 'nano', desc: 'Simple text editor' },
  { cmd: 'git', desc: 'Version control' },
  { cmd: 'npm', desc: 'Node package manager' },
  { cmd: 'yarn', desc: 'Node package manager' },
  { cmd: 'pnpm', desc: 'Node package manager' },
  { cmd: 'node', desc: 'Run JavaScript' },
  { cmd: 'python', desc: 'Run Python' },
  { cmd: 'python3', desc: 'Run Python 3' },
  { cmd: 'pip', desc: 'Python package manager' },
  { cmd: 'cargo', desc: 'Rust package manager' },
  { cmd: 'rustc', desc: 'Rust compiler' },
  { cmd: 'docker', desc: 'Container management' },
  { cmd: 'kubectl', desc: 'Kubernetes CLI' },
  { cmd: 'aws', desc: 'AWS CLI' },
  { cmd: 'gcloud', desc: 'Google Cloud CLI' },
  { cmd: 'ssh', desc: 'Secure shell' },
  { cmd: 'scp', desc: 'Secure copy' },
  { cmd: 'curl', desc: 'Transfer data from URL' },
  { cmd: 'wget', desc: 'Download files' },
  { cmd: 'tar', desc: 'Archive files' },
  { cmd: 'zip', desc: 'Compress files' },
  { cmd: 'unzip', desc: 'Extract zip files' },
  { cmd: 'chmod', desc: 'Change permissions' },
  { cmd: 'chown', desc: 'Change ownership' },
  { cmd: 'sudo', desc: 'Run as superuser' },
  { cmd: 'man', desc: 'Show manual page' },
  { cmd: 'which', desc: 'Locate command' },
  { cmd: 'whereis', desc: 'Locate binary' },
  { cmd: 'history', desc: 'Show command history' },
  { cmd: 'clear', desc: 'Clear terminal' },
  { cmd: 'exit', desc: 'Exit shell' },
]

// Common git subcommands
const GIT_COMMANDS: Array<{ cmd: string; desc: string }> = [
  { cmd: 'status', desc: 'Show working tree status' },
  { cmd: 'add', desc: 'Add files to staging' },
  { cmd: 'commit', desc: 'Record changes' },
  { cmd: 'push', desc: 'Upload to remote' },
  { cmd: 'pull', desc: 'Download from remote' },
  { cmd: 'fetch', desc: 'Download objects' },
  { cmd: 'branch', desc: 'List/create branches' },
  { cmd: 'checkout', desc: 'Switch branches' },
  { cmd: 'switch', desc: 'Switch branches' },
  { cmd: 'merge', desc: 'Join branches' },
  { cmd: 'rebase', desc: 'Reapply commits' },
  { cmd: 'log', desc: 'Show commit history' },
  { cmd: 'diff', desc: 'Show changes' },
  { cmd: 'stash', desc: 'Stash changes' },
  { cmd: 'reset', desc: 'Reset HEAD' },
  { cmd: 'revert', desc: 'Revert commit' },
  { cmd: 'clone', desc: 'Clone repository' },
  { cmd: 'init', desc: 'Initialize repository' },
  { cmd: 'remote', desc: 'Manage remotes' },
  { cmd: 'tag', desc: 'Manage tags' },
]

// Common npm subcommands
const NPM_COMMANDS: Array<{ cmd: string; desc: string }> = [
  { cmd: 'install', desc: 'Install packages' },
  { cmd: 'run', desc: 'Run script' },
  { cmd: 'start', desc: 'Start application' },
  { cmd: 'test', desc: 'Run tests' },
  { cmd: 'build', desc: 'Build project' },
  { cmd: 'init', desc: 'Initialize package' },
  { cmd: 'publish', desc: 'Publish package' },
  { cmd: 'update', desc: 'Update packages' },
  { cmd: 'uninstall', desc: 'Remove package' },
  { cmd: 'list', desc: 'List packages' },
  { cmd: 'outdated', desc: 'Show outdated' },
  { cmd: 'audit', desc: 'Security audit' },
]

// Command history storage
const commandHistory = ref<string[]>([])
const MAX_HISTORY = 500

// Load history from localStorage
function loadHistory(): string[] {
  try {
    const stored = localStorage.getItem('warp_command_history')
    if (stored) {
      return JSON.parse(stored)
    }
  } catch {}
  return []
}

// Save history to localStorage
function saveHistory(history: string[]): void {
  try {
    localStorage.setItem('warp_command_history', JSON.stringify(history.slice(-MAX_HISTORY)))
  } catch {}
}

// Initialize history
commandHistory.value = loadHistory()

export function useAutocomplete(paneId: string) {
  const state = ref<AutocompleteState>({
    isActive: false,
    suggestions: [],
    selectedIndex: 0,
    query: '',
    triggerPosition: 0,
  })

  const currentCwd = ref('~')

  // Computed for UI binding
  const isActive = computed(() => state.value.isActive)
  const suggestions = computed(() => state.value.suggestions)
  const selectedIndex = computed(() => state.value.selectedIndex)
  const selectedSuggestion = computed(() =>
    state.value.suggestions[state.value.selectedIndex] || null
  )

  /**
   * Add command to history
   */
  function addToHistory(command: string): void {
    const trimmed = command.trim()
    if (!trimmed) return

    // Remove duplicates
    const filtered = commandHistory.value.filter(c => c !== trimmed)
    filtered.push(trimmed)

    // Limit size
    commandHistory.value = filtered.slice(-MAX_HISTORY)
    saveHistory(commandHistory.value)
  }

  /**
   * Generate unique suggestion ID
   */
  function genId(): string {
    return `sug-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`
  }

  /**
   * Calculate fuzzy match score
   */
  function fuzzyScore(query: string, target: string): number {
    if (!query) return 0
    const q = query.toLowerCase()
    const t = target.toLowerCase()

    // Exact match
    if (t === q) return 100

    // Starts with
    if (t.startsWith(q)) return 90 + (q.length / t.length) * 10

    // Contains
    if (t.includes(q)) return 70 + (q.length / t.length) * 10

    // Fuzzy match
    let score = 0
    let qIdx = 0
    for (let i = 0; i < t.length && qIdx < q.length; i++) {
      if (t[i] === q[qIdx]) {
        score += 10
        qIdx++
      }
    }
    return qIdx === q.length ? score : 0
  }

  /**
   * Get command suggestions
   */
  function getCommandSuggestions(query: string): Suggestion[] {
    const results: Suggestion[] = []

    // Search common commands
    for (const { cmd, desc } of COMMON_COMMANDS) {
      const score = fuzzyScore(query, cmd)
      if (score > 0) {
        results.push({
          id: genId(),
          text: cmd,
          type: 'command',
          description: desc,
          icon: '⌘',
          score,
        })
      }
    }

    // Search history
    for (const cmd of commandHistory.value) {
      const score = fuzzyScore(query, cmd)
      if (score > 0) {
        results.push({
          id: genId(),
          text: cmd,
          type: 'history',
          description: 'From history',
          icon: '⏱',
          score: score + 5, // Boost history slightly
        })
      }
    }

    return results
  }

  /**
   * Get git subcommand suggestions
   */
  function getGitSuggestions(subquery: string): Suggestion[] {
    const results: Suggestion[] = []

    for (const { cmd, desc } of GIT_COMMANDS) {
      const score = fuzzyScore(subquery, cmd)
      if (score > 0 || !subquery) {
        results.push({
          id: genId(),
          text: `git ${cmd}`,
          type: 'git',
          description: desc,
          icon: '',
          insertText: cmd,
          score: score || 50,
        })
      }
    }

    return results
  }

  /**
   * Get npm subcommand suggestions
   */
  function getNpmSuggestions(subquery: string): Suggestion[] {
    const results: Suggestion[] = []

    for (const { cmd, desc } of NPM_COMMANDS) {
      const score = fuzzyScore(subquery, cmd)
      if (score > 0 || !subquery) {
        results.push({
          id: genId(),
          text: `npm ${cmd}`,
          type: 'command',
          description: desc,
          icon: '📦',
          insertText: cmd,
          score: score || 50,
        })
      }
    }

    return results
  }

  /**
   * Get file/path suggestions
   */
  async function getPathSuggestions(pathQuery: string): Promise<Suggestion[]> {
    const results: Suggestion[] = []

    try {
      // Call Rust backend to list directory
      const entries = await invoke<string[]>('list_directory', {
        path: currentCwd.value,
        prefix: pathQuery,
      })

      for (const entry of entries || []) {
        const isDir = entry.endsWith('/')
        const score = fuzzyScore(pathQuery, entry)
        results.push({
          id: genId(),
          text: entry,
          type: 'path',
          description: isDir ? 'Directory' : 'File',
          icon: isDir ? '📁' : '📄',
          score: score || 50,
        })
      }
    } catch {
      // Silently fail - path completion is optional
    }

    return results
  }

  /**
   * Get environment variable suggestions
   */
  function getEnvSuggestions(query: string): Suggestion[] {
    const results: Suggestion[] = []
    const commonEnvVars = [
      'HOME', 'PATH', 'USER', 'SHELL', 'PWD', 'TERM',
      'EDITOR', 'LANG', 'LC_ALL', 'NODE_ENV', 'DEBUG',
    ]

    for (const env of commonEnvVars) {
      const score = fuzzyScore(query.replace('$', ''), env)
      if (score > 0) {
        results.push({
          id: genId(),
          text: `$${env}`,
          type: 'env',
          description: 'Environment variable',
          icon: '🔧',
          score,
        })
      }
    }

    return results
  }

  /**
   * Update suggestions based on current input
   */
  async function updateSuggestions(input: string, cursorPosition: number): Promise<void> {
    if (!input.trim()) {
      state.value.isActive = false
      state.value.suggestions = []
      return
    }

    const beforeCursor = input.slice(0, cursorPosition)
    const words = beforeCursor.split(/\s+/)
    const currentWord = words[words.length - 1] || ''
    const firstWord = words[0] || ''

    let suggestions: Suggestion[] = []

    // Detect context
    if (currentWord.startsWith('$')) {
      // Environment variable
      suggestions = getEnvSuggestions(currentWord)
    } else if (currentWord.startsWith('./') || currentWord.startsWith('/') || currentWord.startsWith('~') || currentWord.includes('/')) {
      // Path completion
      suggestions = await getPathSuggestions(currentWord)
    } else if (firstWord === 'git' && words.length >= 2) {
      // Git subcommand
      suggestions = getGitSuggestions(currentWord)
    } else if ((firstWord === 'npm' || firstWord === 'yarn' || firstWord === 'pnpm') && words.length >= 2) {
      // npm subcommand
      suggestions = getNpmSuggestions(currentWord)
    } else if (words.length === 1) {
      // Command completion
      suggestions = getCommandSuggestions(currentWord)
    } else {
      // Flag/argument completion (TODO: implement per-command)
      suggestions = []
    }

    // Sort by score
    suggestions.sort((a, b) => b.score - a.score)

    // Limit results
    suggestions = suggestions.slice(0, 10)

    // Remove duplicates
    const seen = new Set<string>()
    suggestions = suggestions.filter(s => {
      if (seen.has(s.text)) return false
      seen.add(s.text)
      return true
    })

    state.value.suggestions = suggestions
    state.value.query = currentWord
    state.value.triggerPosition = cursorPosition - currentWord.length
    state.value.isActive = suggestions.length > 0
    state.value.selectedIndex = 0
  }

  /**
   * Navigate suggestions
   */
  function navigateUp(): void {
    if (!state.value.isActive) return
    state.value.selectedIndex = Math.max(0, state.value.selectedIndex - 1)
  }

  function navigateDown(): void {
    if (!state.value.isActive) return
    state.value.selectedIndex = Math.min(
      state.value.suggestions.length - 1,
      state.value.selectedIndex + 1
    )
  }

  /**
   * Accept current suggestion
   */
  function acceptSuggestion(): { text: string; cursorOffset: number } | null {
    const suggestion = selectedSuggestion.value
    if (!suggestion) return null

    state.value.isActive = false

    return {
      text: suggestion.insertText || suggestion.text,
      cursorOffset: suggestion.cursorOffset || 0,
    }
  }

  /**
   * Dismiss autocomplete
   */
  function dismiss(): void {
    state.value.isActive = false
    state.value.suggestions = []
  }

  /**
   * Update CWD for path completion
   */
  function setCwd(cwd: string): void {
    currentCwd.value = cwd
  }

  return {
    // State
    isActive,
    suggestions,
    selectedIndex,
    selectedSuggestion,
    query: computed(() => state.value.query),
    triggerPosition: computed(() => state.value.triggerPosition),

    // Actions
    updateSuggestions,
    navigateUp,
    navigateDown,
    acceptSuggestion,
    dismiss,
    addToHistory,
    setCwd,
  }
}

export type UseAutocompleteReturn = ReturnType<typeof useAutocomplete>
