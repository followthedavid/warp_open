/**
 * useAICommandSearch - Warp-style AI Command Search
 *
 * Allows users to describe what they want to do in natural language
 * and get command suggestions. Uses local LLM (Ollama) to generate
 * relevant shell commands.
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

export interface CommandSuggestion {
  id: string
  command: string
  description: string
  explanation: string
  confidence: number
  dangerous: boolean
}

export interface SearchResult {
  query: string
  suggestions: CommandSuggestion[]
  timestamp: number
}

const SYSTEM_PROMPT = `You are a shell command expert. Given a natural language description, suggest the best shell commands to accomplish the task.

Rules:
1. Return 1-3 commands, most relevant first
2. For each command, explain what it does
3. Mark dangerous commands (rm -rf, sudo, etc.)
4. Use common Unix/macOS commands
5. Be concise

Format your response EXACTLY like this:
COMMAND: <the shell command>
DESCRIPTION: <short 5-10 word description>
EXPLANATION: <1 sentence explaining what it does>
DANGEROUS: <yes or no>

---

Example for "find large files":
COMMAND: find . -type f -size +100M
DESCRIPTION: Find files larger than 100MB
EXPLANATION: Searches current directory recursively for files exceeding 100 megabytes.
DANGEROUS: no

---

COMMAND: du -sh * | sort -rh | head -20
DESCRIPTION: Show 20 largest items in directory
EXPLANATION: Lists disk usage of items, sorted by size descending, showing top 20.
DANGEROUS: no`

const searchHistory = ref<SearchResult[]>([])
const MAX_HISTORY = 50

// Common command patterns for quick offline suggestions
const QUICK_PATTERNS: Record<string, CommandSuggestion[]> = {
  'list': [
    { id: 'ls1', command: 'ls -la', description: 'List all files with details', explanation: 'Shows all files including hidden, with permissions, size, and dates.', confidence: 0.95, dangerous: false }
  ],
  'find file': [
    { id: 'find1', command: 'find . -name "*.txt"', description: 'Find files by name pattern', explanation: 'Recursively searches for files matching the pattern in current directory.', confidence: 0.9, dangerous: false }
  ],
  'disk': [
    { id: 'df1', command: 'df -h', description: 'Show disk space usage', explanation: 'Displays filesystem disk space usage in human-readable format.', confidence: 0.95, dangerous: false }
  ],
  'memory': [
    { id: 'mem1', command: 'free -h', description: 'Show memory usage', explanation: 'Displays system memory usage including RAM and swap.', confidence: 0.9, dangerous: false },
    { id: 'mem2', command: 'top -l 1 | head -10', description: 'Show top processes (macOS)', explanation: 'Lists running processes sorted by resource usage on macOS.', confidence: 0.85, dangerous: false }
  ],
  'process': [
    { id: 'ps1', command: 'ps aux', description: 'List all running processes', explanation: 'Shows all running processes with user, CPU, memory usage.', confidence: 0.95, dangerous: false }
  ],
  'kill': [
    { id: 'kill1', command: 'pkill -f "process_name"', description: 'Kill process by name', explanation: 'Terminates all processes matching the given name pattern.', confidence: 0.85, dangerous: true }
  ],
  'network': [
    { id: 'net1', command: 'netstat -an | grep LISTEN', description: 'Show listening ports', explanation: 'Displays all network connections currently listening for connections.', confidence: 0.9, dangerous: false }
  ],
  'git': [
    { id: 'git1', command: 'git status', description: 'Show git repository status', explanation: 'Displays the state of working directory and staging area.', confidence: 0.95, dangerous: false }
  ],
  'search': [
    { id: 'grep1', command: 'grep -rn "pattern" .', description: 'Search for text in files', explanation: 'Recursively searches files for the pattern, showing line numbers.', confidence: 0.9, dangerous: false }
  ],
  'compress': [
    { id: 'tar1', command: 'tar -czvf archive.tar.gz folder/', description: 'Create compressed archive', explanation: 'Creates a gzip-compressed tar archive of the specified folder.', confidence: 0.9, dangerous: false }
  ],
  'extract': [
    { id: 'tar2', command: 'tar -xzvf archive.tar.gz', description: 'Extract compressed archive', explanation: 'Extracts files from a gzip-compressed tar archive.', confidence: 0.9, dangerous: false }
  ],
  'permission': [
    { id: 'chmod1', command: 'chmod +x script.sh', description: 'Make file executable', explanation: 'Adds execute permission to the specified script file.', confidence: 0.9, dangerous: false }
  ],
  'delete': [
    { id: 'rm1', command: 'rm -i file', description: 'Delete file with confirmation', explanation: 'Removes file, prompting for confirmation before each deletion.', confidence: 0.85, dangerous: true }
  ],
  'copy': [
    { id: 'cp1', command: 'cp -r source/ dest/', description: 'Copy directory recursively', explanation: 'Copies directory and all its contents to destination.', confidence: 0.9, dangerous: false }
  ],
  'move': [
    { id: 'mv1', command: 'mv source dest', description: 'Move or rename file', explanation: 'Moves file to new location or renames it.', confidence: 0.9, dangerous: false }
  ],
  'docker': [
    { id: 'docker1', command: 'docker ps -a', description: 'List all Docker containers', explanation: 'Shows all Docker containers including stopped ones.', confidence: 0.95, dangerous: false }
  ],
  'port': [
    { id: 'port1', command: 'lsof -i :8080', description: 'Find process using port', explanation: 'Lists processes currently using the specified port.', confidence: 0.9, dangerous: false }
  ]
}

export function useAICommandSearch() {
  const isSearching = ref(false)
  const currentQuery = ref('')
  const suggestions = ref<CommandSuggestion[]>([])
  const error = ref<string | null>(null)
  const model = ref('qwen2.5-coder:1.5b')

  // Search history
  const history = computed(() => searchHistory.value)

  /**
   * Quick local search based on patterns
   */
  function quickSearch(query: string): CommandSuggestion[] {
    const q = query.toLowerCase()
    const results: CommandSuggestion[] = []

    for (const [key, commands] of Object.entries(QUICK_PATTERNS)) {
      if (q.includes(key) || key.includes(q)) {
        results.push(...commands)
      }
    }

    return results.slice(0, 5)
  }

  /**
   * AI-powered search using local LLM
   */
  async function aiSearch(query: string): Promise<CommandSuggestion[]> {
    const prompt = `${SYSTEM_PROMPT}\n\nUser request: "${query}"\n\nSuggest commands:`

    try {
      const response = await invoke<string>('query_ollama', { prompt, model: model.value })
      return parseResponse(response)
    } catch (e) {
      console.error('AI search error:', e)
      return []
    }
  }

  /**
   * Parse LLM response into suggestions
   */
  function parseResponse(response: string): CommandSuggestion[] {
    const suggestions: CommandSuggestion[] = []
    const blocks = response.split('---').filter(b => b.trim())

    for (const block of blocks) {
      const commandMatch = block.match(/COMMAND:\s*(.+)/i)
      const descMatch = block.match(/DESCRIPTION:\s*(.+)/i)
      const explainMatch = block.match(/EXPLANATION:\s*(.+)/i)
      const dangerMatch = block.match(/DANGEROUS:\s*(yes|no)/i)

      if (commandMatch) {
        suggestions.push({
          id: `ai-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
          command: commandMatch[1].trim(),
          description: descMatch?.[1]?.trim() || 'Command suggestion',
          explanation: explainMatch?.[1]?.trim() || '',
          confidence: 0.8,
          dangerous: dangerMatch?.[1]?.toLowerCase() === 'yes'
        })
      }
    }

    return suggestions
  }

  /**
   * Search for commands
   */
  async function search(query: string): Promise<void> {
    if (!query.trim() || isSearching.value) return

    currentQuery.value = query
    isSearching.value = true
    error.value = null
    suggestions.value = []

    try {
      // First, get quick local results
      const quickResults = quickSearch(query)
      if (quickResults.length > 0) {
        suggestions.value = quickResults
      }

      // Then, get AI results
      const aiResults = await aiSearch(query)

      // Merge results, prioritizing AI results but keeping unique quick results
      const commandSet = new Set(aiResults.map(r => r.command))
      const uniqueQuick = quickResults.filter(r => !commandSet.has(r.command))

      suggestions.value = [...aiResults, ...uniqueQuick].slice(0, 5)

      // Save to history
      if (suggestions.value.length > 0) {
        const result: SearchResult = {
          query,
          suggestions: suggestions.value,
          timestamp: Date.now()
        }
        searchHistory.value.unshift(result)
        if (searchHistory.value.length > MAX_HISTORY) {
          searchHistory.value = searchHistory.value.slice(0, MAX_HISTORY)
        }
      }
    } catch (e) {
      error.value = `Search failed: ${e}`
    } finally {
      isSearching.value = false
    }
  }

  /**
   * Get recent searches
   */
  function getRecentSearches(): string[] {
    return [...new Set(searchHistory.value.map(r => r.query))].slice(0, 10)
  }

  /**
   * Clear search results
   */
  function clearResults(): void {
    suggestions.value = []
    currentQuery.value = ''
    error.value = null
  }

  /**
   * Clear history
   */
  function clearHistory(): void {
    searchHistory.value = []
  }

  /**
   * Get suggestion by ID
   */
  function getSuggestion(id: string): CommandSuggestion | undefined {
    return suggestions.value.find(s => s.id === id)
  }

  return {
    // State
    isSearching: computed(() => isSearching.value),
    currentQuery: computed(() => currentQuery.value),
    suggestions: computed(() => suggestions.value),
    error: computed(() => error.value),
    history,
    model,

    // Actions
    search,
    quickSearch,
    getRecentSearches,
    clearResults,
    clearHistory,
    getSuggestion
  }
}

export type UseAICommandSearchReturn = ReturnType<typeof useAICommandSearch>
