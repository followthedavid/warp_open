/**
 * Session Snapshots Composable
 *
 * Save and restore complete workspace state including:
 * - Tab layout and names
 * - Pane structure
 * - Working directories
 * - Named snapshots with timestamps
 *
 * This is a key differentiator - "Resume my work, not just my terminals"
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import type { LayoutNode, Tab } from './useTabs'

export interface Snapshot {
  id: string
  name: string
  timestamp: number
  description?: string
  tags?: string[]
  tabs: SnapshotTab[]
  activeTabId?: string
}

export interface SnapshotTab {
  id: string
  kind: 'terminal' | 'editor' | 'ai' | 'developer'
  name: string
  layout?: SnapshotLayoutNode  // For terminal tabs with panes
  filePath?: string            // For editor tabs
}

export interface SnapshotLayoutNode {
  type: 'leaf' | 'split'
  // Leaf properties
  paneId?: string
  cwd?: string
  // Split properties
  direction?: 'horizontal' | 'vertical'
  ratio?: number
  first?: SnapshotLayoutNode
  second?: SnapshotLayoutNode
}

const STORAGE_KEY = 'warp_open_snapshots'
const MAX_SNAPSHOTS = 20

// Global state
const snapshots = ref<Snapshot[]>([])
const isLoaded = ref(false)
const searchQuery = ref('')
const selectedTags = ref<string[]>([])
const dateFilter = ref<'all' | 'today' | 'week' | 'month'>('all')

// Load snapshots from localStorage
function loadSnapshots(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      snapshots.value = JSON.parse(stored)
    }
  } catch (e) {
    console.warn('[useSnapshots] Failed to load snapshots:', e)
    snapshots.value = []
  }
  isLoaded.value = true
}

// Save snapshots to localStorage
function saveSnapshotsToStorage(): void {
  try {
    // Keep only the most recent MAX_SNAPSHOTS
    const toSave = snapshots.value.slice(-MAX_SNAPSHOTS)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave))
  } catch (e) {
    console.error('[useSnapshots] Failed to save snapshots:', e)
  }
}

// Initialize on first import
if (!isLoaded.value) {
  loadSnapshots()
}

// Convert LayoutNode to SnapshotLayoutNode (strips PTY IDs, keeps structure)
function layoutToSnapshot(node: LayoutNode, cwdMap: Map<string, string>): SnapshotLayoutNode {
  if (node.type === 'leaf') {
    return {
      type: 'leaf',
      paneId: node.paneId,
      cwd: cwdMap.get(node.paneId) || undefined
    }
  } else {
    return {
      type: 'split',
      direction: node.direction,
      ratio: node.ratio,
      first: layoutToSnapshot(node.first, cwdMap),
      second: layoutToSnapshot(node.second, cwdMap)
    }
  }
}

export function useSnapshots() {
  // List all snapshots
  const allSnapshots = computed(() =>
    [...snapshots.value].sort((a, b) => b.timestamp - a.timestamp)
  )

  // Create a new snapshot from current workspace state
  function createSnapshot(
    name: string,
    tabs: Tab[],
    activeTabId: string | null,
    paneCwds: Map<string, string>,
    description?: string,
    tags?: string[]
  ): Snapshot {
    const id = `snap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

    // Convert tabs to snapshot format
    const snapshotTabs: SnapshotTab[] = tabs.map(tab => {
      const snapTab: SnapshotTab = {
        id: tab.id,
        kind: tab.kind,
        name: tab.name
      }

      if (tab.kind === 'terminal' && tab.layout) {
        snapTab.layout = layoutToSnapshot(tab.layout, paneCwds)
      }

      if (tab.kind === 'editor' && tab.file_path) {
        snapTab.filePath = tab.file_path
      }

      return snapTab
    })

    const snapshot: Snapshot = {
      id,
      name: name || `Snapshot ${new Date().toLocaleString()}`,
      timestamp: Date.now(),
      description,
      tags: tags || [],
      tabs: snapshotTabs,
      activeTabId: activeTabId || undefined
    }

    snapshots.value.push(snapshot)
    saveSnapshotsToStorage()

    console.log('[useSnapshots] Created snapshot:', snapshot.name, 'with', snapshot.tabs.length, 'tabs')
    return snapshot
  }

  // Auto-snapshot (on exit)
  function createAutoSnapshot(
    tabs: Tab[],
    activeTabId: string | null,
    paneCwds: Map<string, string>
  ): Snapshot | null {
    // Only create auto-snapshot if there are tabs
    if (tabs.length === 0) return null

    // Check if we already have a recent auto-snapshot (within 5 minutes)
    const recentAuto = snapshots.value.find(
      s => s.name.startsWith('Auto:') && (Date.now() - s.timestamp) < 5 * 60 * 1000
    )
    if (recentAuto) {
      console.log('[useSnapshots] Skipping auto-snapshot (recent exists)')
      return null
    }

    return createSnapshot(
      `Auto: ${new Date().toLocaleString()}`,
      tabs,
      activeTabId,
      paneCwds,
      'Automatic snapshot on exit'
    )
  }

  // Get a specific snapshot by ID
  function getSnapshot(id: string): Snapshot | undefined {
    return snapshots.value.find(s => s.id === id)
  }

  // Delete a snapshot
  function deleteSnapshot(id: string): boolean {
    const index = snapshots.value.findIndex(s => s.id === id)
    if (index !== -1) {
      snapshots.value.splice(index, 1)
      saveSnapshotsToStorage()
      console.log('[useSnapshots] Deleted snapshot:', id)
      return true
    }
    return false
  }

  // Rename a snapshot
  function renameSnapshot(id: string, newName: string): boolean {
    const snapshot = snapshots.value.find(s => s.id === id)
    if (snapshot) {
      snapshot.name = newName
      saveSnapshotsToStorage()
      return true
    }
    return false
  }

  // Add tag to snapshot
  function addTag(id: string, tag: string): boolean {
    const snapshot = snapshots.value.find(s => s.id === id)
    if (snapshot) {
      if (!snapshot.tags) snapshot.tags = []
      if (!snapshot.tags.includes(tag)) {
        snapshot.tags.push(tag)
        saveSnapshotsToStorage()
      }
      return true
    }
    return false
  }

  // Remove tag from snapshot
  function removeTag(id: string, tag: string): boolean {
    const snapshot = snapshots.value.find(s => s.id === id)
    if (snapshot && snapshot.tags) {
      const index = snapshot.tags.indexOf(tag)
      if (index !== -1) {
        snapshot.tags.splice(index, 1)
        saveSnapshotsToStorage()
        return true
      }
    }
    return false
  }

  // Get all unique tags
  const allTags = computed(() => {
    const tagSet = new Set<string>()
    for (const snapshot of snapshots.value) {
      if (snapshot.tags) {
        for (const tag of snapshot.tags) {
          tagSet.add(tag)
        }
      }
    }
    return Array.from(tagSet).sort()
  })

  // Filtered snapshots based on search, tags, and date
  const filteredSnapshots = computed(() => {
    let filtered = [...snapshots.value]

    // Filter by search query
    if (searchQuery.value.trim()) {
      const query = searchQuery.value.toLowerCase()
      filtered = filtered.filter(s =>
        s.name.toLowerCase().includes(query) ||
        (s.description && s.description.toLowerCase().includes(query)) ||
        (s.tags && s.tags.some(t => t.toLowerCase().includes(query)))
      )
    }

    // Filter by selected tags
    if (selectedTags.value.length > 0) {
      filtered = filtered.filter(s =>
        s.tags && selectedTags.value.every(tag => s.tags!.includes(tag))
      )
    }

    // Filter by date range
    if (dateFilter.value !== 'all') {
      const now = Date.now()
      const ranges: Record<string, number> = {
        'today': 24 * 60 * 60 * 1000,
        'week': 7 * 24 * 60 * 60 * 1000,
        'month': 30 * 24 * 60 * 60 * 1000
      }
      const cutoff = now - ranges[dateFilter.value]
      filtered = filtered.filter(s => s.timestamp >= cutoff)
    }

    // Sort by timestamp descending
    return filtered.sort((a, b) => b.timestamp - a.timestamp)
  })

  // Set search query
  function setSearchQuery(query: string) {
    searchQuery.value = query
  }

  // Toggle tag filter
  function toggleTagFilter(tag: string) {
    const index = selectedTags.value.indexOf(tag)
    if (index === -1) {
      selectedTags.value.push(tag)
    } else {
      selectedTags.value.splice(index, 1)
    }
  }

  // Set date filter
  function setDateFilter(filter: 'all' | 'today' | 'week' | 'month') {
    dateFilter.value = filter
  }

  // Clear all filters
  function clearFilters() {
    searchQuery.value = ''
    selectedTags.value = []
    dateFilter.value = 'all'
  }

  // Clear all snapshots
  function clearAllSnapshots(): void {
    snapshots.value = []
    saveSnapshotsToStorage()
    console.log('[useSnapshots] Cleared all snapshots')
  }

  // Format timestamp for display
  function formatTimestamp(timestamp: number): string {
    const date = new Date(timestamp)
    const now = new Date()
    const diff = now.getTime() - timestamp

    // Less than a minute
    if (diff < 60000) return 'Just now'

    // Less than an hour
    if (diff < 3600000) {
      const mins = Math.floor(diff / 60000)
      return `${mins} minute${mins !== 1 ? 's' : ''} ago`
    }

    // Less than a day
    if (diff < 86400000) {
      const hours = Math.floor(diff / 3600000)
      return `${hours} hour${hours !== 1 ? 's' : ''} ago`
    }

    // Less than a week
    if (diff < 604800000) {
      const days = Math.floor(diff / 86400000)
      return `${days} day${days !== 1 ? 's' : ''} ago`
    }

    // Full date
    return date.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
  }

  // Export a snapshot to JSON file
  async function exportSnapshot(id: string): Promise<boolean> {
    const snapshot = snapshots.value.find(s => s.id === id)
    if (!snapshot) {
      console.error('[useSnapshots] Snapshot not found for export:', id)
      return false
    }

    try {
      // Create export data with metadata
      const exportData = {
        version: 1,
        exportedAt: new Date().toISOString(),
        application: 'Warp_Open',
        snapshot: snapshot
      }

      const json = JSON.stringify(exportData, null, 2)
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)

      // Create download link
      const a = document.createElement('a')
      a.href = url
      a.download = `warp_snapshot_${snapshot.name.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      console.log('[useSnapshots] Exported snapshot:', snapshot.name)
      return true
    } catch (e) {
      console.error('[useSnapshots] Failed to export snapshot:', e)
      return false
    }
  }

  // Export all snapshots to JSON file
  async function exportAllSnapshots(): Promise<boolean> {
    if (snapshots.value.length === 0) {
      console.warn('[useSnapshots] No snapshots to export')
      return false
    }

    try {
      const exportData = {
        version: 1,
        exportedAt: new Date().toISOString(),
        application: 'Warp_Open',
        snapshotCount: snapshots.value.length,
        snapshots: snapshots.value
      }

      const json = JSON.stringify(exportData, null, 2)
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)

      const a = document.createElement('a')
      a.href = url
      a.download = `warp_snapshots_all_${Date.now()}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      console.log('[useSnapshots] Exported all snapshots:', snapshots.value.length)
      return true
    } catch (e) {
      console.error('[useSnapshots] Failed to export snapshots:', e)
      return false
    }
  }

  // Import snapshots from JSON file
  async function importSnapshots(file: File): Promise<{ success: boolean; imported: number; errors: string[] }> {
    const errors: string[] = []
    let imported = 0

    try {
      const text = await file.text()
      const data = JSON.parse(text)

      // Validate format
      if (!data.application || data.application !== 'Warp_Open') {
        errors.push('Invalid file format: not a Warp_Open snapshot file')
        return { success: false, imported: 0, errors }
      }

      // Handle single snapshot export
      if (data.snapshot) {
        const snapshot = data.snapshot as Snapshot
        if (validateSnapshot(snapshot)) {
          // Generate new ID to avoid conflicts
          snapshot.id = `snap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
          snapshot.name = `${snapshot.name} (imported)`
          snapshots.value.push(snapshot)
          imported++
        } else {
          errors.push('Invalid snapshot data')
        }
      }

      // Handle multiple snapshots export
      if (data.snapshots && Array.isArray(data.snapshots)) {
        for (const snapshot of data.snapshots) {
          if (validateSnapshot(snapshot)) {
            // Check for duplicates by name and timestamp
            const exists = snapshots.value.some(
              s => s.name === snapshot.name && s.timestamp === snapshot.timestamp
            )
            if (!exists) {
              // Generate new ID
              snapshot.id = `snap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}-${imported}`
              snapshots.value.push(snapshot)
              imported++
            } else {
              errors.push(`Skipped duplicate: ${snapshot.name}`)
            }
          } else {
            errors.push(`Invalid snapshot data: ${snapshot.name || 'unknown'}`)
          }
        }
      }

      if (imported > 0) {
        saveSnapshotsToStorage()
        console.log('[useSnapshots] Imported', imported, 'snapshots')
      }

      return { success: imported > 0, imported, errors }
    } catch (e) {
      console.error('[useSnapshots] Failed to import snapshots:', e)
      errors.push(`Parse error: ${e instanceof Error ? e.message : 'Unknown error'}`)
      return { success: false, imported: 0, errors }
    }
  }

  // Validate snapshot structure
  function validateSnapshot(snapshot: unknown): snapshot is Snapshot {
    if (typeof snapshot !== 'object' || snapshot === null) return false
    const s = snapshot as Record<string, unknown>
    return (
      typeof s.name === 'string' &&
      typeof s.timestamp === 'number' &&
      Array.isArray(s.tabs)
    )
  }

  return {
    snapshots: allSnapshots,
    filteredSnapshots,
    createSnapshot,
    createAutoSnapshot,
    getSnapshot,
    deleteSnapshot,
    renameSnapshot,
    clearAllSnapshots,
    formatTimestamp,
    loadSnapshots,
    // Tags
    addTag,
    removeTag,
    allTags,
    // Search/Filter
    searchQuery,
    selectedTags,
    dateFilter,
    setSearchQuery,
    setDateFilter,
    toggleTagFilter,
    clearFilters,
    // Export/Import
    exportSnapshot,
    exportAllSnapshots,
    importSnapshots,
  }
}

export type { Snapshot, SnapshotTab, SnapshotLayoutNode }
