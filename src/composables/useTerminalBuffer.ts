/**
 * Terminal Buffer Composable
 *
 * High-performance line buffer abstraction for terminal output.
 * Supports:
 * - Large scrollback buffers (10k-100k+ lines)
 * - Windowed rendering (visible lines + overscan)
 * - Full buffer search/indexing
 * - Recording integration
 * - Memory-efficient line storage
 */

import { ref, computed, shallowRef } from 'vue'

export interface BufferLine {
  content: string
  timestamp: number
  index: number
}

export interface BufferWindow {
  start: number
  end: number
  lines: BufferLine[]
}

export interface BufferSearchResult {
  lineIndex: number
  charIndex: number
  matchLength: number
  lineContent: string
}

export interface TerminalBufferConfig {
  maxLines: number          // Maximum lines to keep in buffer
  overscan: number          // Lines to render above/below viewport
  batchSize: number         // Lines to process in batch
  searchTimeout: number     // Max ms for search operation
}

const DEFAULT_CONFIG: TerminalBufferConfig = {
  maxLines: 100000,         // 100k lines max
  overscan: 50,             // 50 lines overscan
  batchSize: 1000,          // Process 1000 lines at a time
  searchTimeout: 100        // 100ms search timeout
}

/**
 * Creates a terminal buffer instance for managing large amounts of terminal output
 */
export function useTerminalBuffer(paneId: string, config: Partial<TerminalBufferConfig> = {}) {
  const finalConfig = { ...DEFAULT_CONFIG, ...config }

  // Use shallowRef for better performance with large arrays
  const lines = shallowRef<BufferLine[]>([])
  const totalLines = ref(0)
  const viewportStart = ref(0)
  const viewportSize = ref(24)  // Default terminal rows

  // Search index - maps words to line indices for fast lookup
  const searchIndex = new Map<string, Set<number>>()

  // Statistics
  const stats = computed(() => ({
    totalLines: totalLines.value,
    memoryEstimate: estimateMemoryUsage(),
    bufferUtilization: (totalLines.value / finalConfig.maxLines) * 100
  }))

  /**
   * Append raw output to the buffer
   * Handles ANSI escape sequences and line splitting
   */
  function appendOutput(data: string): number {
    const timestamp = Date.now()
    const newLines: BufferLine[] = []

    // Split into lines - filter out empty trailing lines from newline at end
    const outputLines = data.split('\n')

    for (let i = 0; i < outputLines.length; i++) {
      const content = outputLines[i]

      // Skip empty lines at the end (from trailing newline)
      if (i === outputLines.length - 1 && content === '') {
        continue
      }

      const lineIndex = lines.value.length + newLines.length
      newLines.push({
        content,
        timestamp,
        index: lineIndex
      })

      // Index for search
      updateSearchIndex(content, lineIndex)
    }

    // Add new lines to buffer
    if (newLines.length > 0) {
      const currentLines = lines.value
      let updatedLines = [...currentLines, ...newLines]

      // Trim buffer if exceeds max lines
      if (updatedLines.length > finalConfig.maxLines) {
        const trimCount = updatedLines.length - finalConfig.maxLines
        updatedLines = updatedLines.slice(trimCount)

        // Cleanup search index for trimmed lines
        cleanupSearchIndex(trimCount)

        // Re-index remaining lines
        updatedLines = updatedLines.map((line, idx) => ({
          ...line,
          index: idx
        }))
      }

      lines.value = updatedLines
      totalLines.value = updatedLines.length
    }

    return newLines.length
  }

  /**
   * Get a window of lines for rendering
   * Includes overscan for smooth scrolling
   */
  function getWindow(): BufferWindow {
    const start = Math.max(0, viewportStart.value - finalConfig.overscan)
    const end = Math.min(
      lines.value.length,
      viewportStart.value + viewportSize.value + finalConfig.overscan
    )

    return {
      start,
      end,
      lines: lines.value.slice(start, end)
    }
  }

  /**
   * Get all lines (for search, recording, export)
   * Warning: May be memory-intensive for large buffers
   */
  function getAllLines(): BufferLine[] {
    return lines.value
  }

  /**
   * Get raw content for the entire buffer
   */
  function getRawContent(): string {
    return lines.value.map(l => l.content).join('\n')
  }

  /**
   * Search the buffer for a pattern
   * Uses indexed search for common terms, full scan for regex
   */
  function search(
    pattern: string | RegExp,
    options: { limit?: number; caseSensitive?: boolean } = {}
  ): BufferSearchResult[] {
    const results: BufferSearchResult[] = []
    const limit = options.limit || 100
    const startTime = Date.now()

    if (typeof pattern === 'string') {
      // Simple string search - use index if available
      const searchTerm = options.caseSensitive ? pattern : pattern.toLowerCase()

      // First check indexed words
      const indexedMatches = searchIndex.get(searchTerm)
      if (indexedMatches && indexedMatches.size > 0) {
        for (const lineIndex of indexedMatches) {
          if (results.length >= limit) break
          if (Date.now() - startTime > finalConfig.searchTimeout) break

          const line = lines.value.find(l => l.index === lineIndex)
          if (line) {
            const searchContent = options.caseSensitive ? line.content : line.content.toLowerCase()
            const charIndex = searchContent.indexOf(searchTerm)
            if (charIndex !== -1) {
              results.push({
                lineIndex: line.index,
                charIndex,
                matchLength: pattern.length,
                lineContent: line.content
              })
            }
          }
        }
      }

      // Fall back to full scan if index didn't find enough
      if (results.length < limit) {
        for (const line of lines.value) {
          if (results.length >= limit) break
          if (Date.now() - startTime > finalConfig.searchTimeout) break

          // Skip if already found via index
          if (results.some(r => r.lineIndex === line.index)) continue

          const searchContent = options.caseSensitive ? line.content : line.content.toLowerCase()
          const charIndex = searchContent.indexOf(searchTerm)
          if (charIndex !== -1) {
            results.push({
              lineIndex: line.index,
              charIndex,
              matchLength: pattern.length,
              lineContent: line.content
            })
          }
        }
      }
    } else {
      // Regex search - must scan all lines
      for (const line of lines.value) {
        if (results.length >= limit) break
        if (Date.now() - startTime > finalConfig.searchTimeout) break

        const match = pattern.exec(line.content)
        if (match) {
          results.push({
            lineIndex: line.index,
            charIndex: match.index,
            matchLength: match[0].length,
            lineContent: line.content
          })
        }
      }
    }

    return results
  }

  /**
   * Set the viewport position (for virtual scrolling)
   */
  function setViewport(start: number, size: number) {
    viewportStart.value = Math.max(0, Math.min(start, lines.value.length - size))
    viewportSize.value = size
  }

  /**
   * Scroll to a specific line
   */
  function scrollToLine(lineIndex: number) {
    const actualIndex = lines.value.findIndex(l => l.index === lineIndex)
    if (actualIndex !== -1) {
      viewportStart.value = Math.max(0, actualIndex - Math.floor(viewportSize.value / 2))
    }
  }

  /**
   * Clear the buffer
   */
  function clear() {
    lines.value = []
    totalLines.value = 0
    viewportStart.value = 0
    searchIndex.clear()
  }

  /**
   * Export buffer for recording/sharing
   */
  function exportBuffer(): { lines: BufferLine[]; metadata: object } {
    return {
      lines: lines.value,
      metadata: {
        paneId,
        totalLines: totalLines.value,
        exportedAt: Date.now(),
        config: finalConfig
      }
    }
  }

  /**
   * Import buffer from recording
   */
  function importBuffer(data: { lines: BufferLine[]; metadata?: object }) {
    clear()
    lines.value = data.lines
    totalLines.value = data.lines.length

    // Rebuild search index
    for (const line of data.lines) {
      updateSearchIndex(line.content, line.index)
    }
  }

  // Internal helpers

  function updateSearchIndex(content: string, lineIndex: number) {
    // Index words for fast search
    // Only index alphanumeric words of 3+ chars
    const words = content.toLowerCase().match(/\b[a-z0-9]{3,}\b/g) || []
    for (const word of words) {
      if (!searchIndex.has(word)) {
        searchIndex.set(word, new Set())
      }
      searchIndex.get(word)!.add(lineIndex)
    }
  }

  function cleanupSearchIndex(trimCount: number) {
    // Remove references to trimmed lines from search index
    for (const [word, lineSet] of searchIndex.entries()) {
      const newSet = new Set<number>()
      for (const lineIndex of lineSet) {
        if (lineIndex >= trimCount) {
          newSet.add(lineIndex - trimCount)
        }
      }
      if (newSet.size > 0) {
        searchIndex.set(word, newSet)
      } else {
        searchIndex.delete(word)
      }
    }
  }

  function estimateMemoryUsage(): number {
    // Rough estimate: ~100 bytes per line on average
    return lines.value.length * 100
  }

  return {
    // State
    lines: computed(() => lines.value),
    totalLines,
    stats,
    viewportStart,
    viewportSize,

    // Methods
    appendOutput,
    getWindow,
    getAllLines,
    getRawContent,
    search,
    setViewport,
    scrollToLine,
    clear,
    exportBuffer,
    importBuffer
  }
}

export type TerminalBuffer = ReturnType<typeof useTerminalBuffer>
