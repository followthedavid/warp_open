/**
 * useDirectoryJump - z/zoxide-style directory jumping
 *
 * Tracks directory usage and provides fuzzy matching for quick navigation
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

interface DirectoryEntry {
  path: string
  score: number // Frecency score (frequency + recency)
  lastAccess: number
  accessCount: number
}

const STORAGE_KEY = 'warp-open-directory-history'
const MAX_ENTRIES = 100
const DECAY_FACTOR = 0.9 // Score decay per hour

// Load from storage
const directories = ref<DirectoryEntry[]>([])

const savedDirs = localStorage.getItem(STORAGE_KEY)
if (savedDirs) {
  try {
    directories.value = JSON.parse(savedDirs)
  } catch {}
}

// Calculate frecency score
function calculateScore(entry: DirectoryEntry): number {
  const now = Date.now()
  const hoursSinceAccess = (now - entry.lastAccess) / (1000 * 60 * 60)
  const decayedScore = entry.score * Math.pow(DECAY_FACTOR, hoursSinceAccess)
  return decayedScore
}

// Save to storage
function persist() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(directories.value))
}

export function useDirectoryJump() {
  const currentDir = ref('')

  // Sorted by frecency score
  const sortedDirectories = computed(() => {
    return [...directories.value]
      .map(d => ({ ...d, currentScore: calculateScore(d) }))
      .sort((a, b) => b.currentScore - a.currentScore)
  })

  /**
   * Record a directory access
   */
  function recordAccess(path: string) {
    const normalizedPath = path.replace(/\/$/, '') // Remove trailing slash

    const existing = directories.value.find(d => d.path === normalizedPath)

    if (existing) {
      existing.score = calculateScore(existing) + 1
      existing.lastAccess = Date.now()
      existing.accessCount++
    } else {
      directories.value.push({
        path: normalizedPath,
        score: 1,
        lastAccess: Date.now(),
        accessCount: 1
      })
    }

    // Trim old entries
    if (directories.value.length > MAX_ENTRIES) {
      directories.value = sortedDirectories.value.slice(0, MAX_ENTRIES)
    }

    currentDir.value = normalizedPath
    persist()
  }

  /**
   * Find best matching directory
   */
  function findMatch(query: string): DirectoryEntry | null {
    if (!query) return null

    const lowerQuery = query.toLowerCase()

    // Score each directory by match quality
    const scored = sortedDirectories.value.map(entry => {
      const lowerPath = entry.path.toLowerCase()
      const pathParts = lowerPath.split('/')

      let matchScore = 0

      // Exact match - highest priority
      if (lowerPath === lowerQuery) {
        matchScore = 1000
      }
      // Ends with query
      else if (lowerPath.endsWith('/' + lowerQuery) || pathParts[pathParts.length - 1] === lowerQuery) {
        matchScore = 100
      }
      // Contains query
      else if (lowerPath.includes(lowerQuery)) {
        matchScore = 50
      }
      // Fuzzy match - query chars appear in order
      else {
        let queryIdx = 0
        for (const char of lowerPath) {
          if (queryIdx < lowerQuery.length && char === lowerQuery[queryIdx]) {
            queryIdx++
          }
        }
        if (queryIdx === lowerQuery.length) {
          matchScore = 10
        }
      }

      return {
        entry,
        totalScore: matchScore * entry.currentScore
      }
    })

    // Return best match
    const best = scored.filter(s => s.totalScore > 0).sort((a, b) => b.totalScore - a.totalScore)[0]
    return best?.entry || null
  }

  /**
   * Get suggestions for a query
   */
  function getSuggestions(query: string, limit = 5): DirectoryEntry[] {
    if (!query) {
      return sortedDirectories.value.slice(0, limit)
    }

    const lowerQuery = query.toLowerCase()

    return sortedDirectories.value
      .filter(d => d.path.toLowerCase().includes(lowerQuery))
      .slice(0, limit)
  }

  /**
   * Jump to directory matching query
   */
  async function jump(query: string): Promise<{ success: boolean; path?: string; error?: string }> {
    const match = findMatch(query)

    if (!match) {
      return { success: false, error: `No match found for: ${query}` }
    }

    try {
      // Verify directory exists
      const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
        command: `test -d "${match.path}" && echo "exists"`,
        cwd: undefined
      })

      if (result.stdout.includes('exists')) {
        recordAccess(match.path)
        return { success: true, path: match.path }
      } else {
        // Remove non-existent directory
        directories.value = directories.value.filter(d => d.path !== match.path)
        persist()
        return { success: false, error: `Directory no longer exists: ${match.path}` }
      }
    } catch (error) {
      return { success: false, error: `Failed to access directory: ${error}` }
    }
  }

  /**
   * Clear history
   */
  function clearHistory() {
    directories.value = []
    persist()
  }

  /**
   * Remove specific directory
   */
  function removeDirectory(path: string) {
    directories.value = directories.value.filter(d => d.path !== path)
    persist()
  }

  return {
    currentDir,
    directories: sortedDirectories,
    recordAccess,
    findMatch,
    getSuggestions,
    jump,
    clearHistory,
    removeDirectory
  }
}

export default useDirectoryJump
