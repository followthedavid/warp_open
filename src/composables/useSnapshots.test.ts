import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useSnapshots } from './useSnapshots'
import type { Tab } from './useTabs'

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {}
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => { store[key] = value },
    removeItem: (key: string) => { delete store[key] },
    clear: () => { store = {} }
  }
})()

Object.defineProperty(window, 'localStorage', { value: localStorageMock })

describe('useSnapshots', () => {
  beforeEach(() => {
    localStorageMock.clear()
    // Reset snapshot state by creating fresh instance and clearing
    const { clearAllSnapshots } = useSnapshots()
    clearAllSnapshots()
  })

  const createMockTabs = (): Tab[] => [
    {
      id: 'tab-1',
      kind: 'terminal',
      name: 'Terminal 1',
      layout: {
        type: 'leaf',
        paneId: 'pane-1',
        ptyId: 1
      },
      activePaneId: 'pane-1'
    },
    {
      id: 'tab-2',
      kind: 'terminal',
      name: 'Terminal 2',
      layout: {
        type: 'split',
        direction: 'horizontal',
        ratio: 0.5,
        first: { type: 'leaf', paneId: 'pane-2', ptyId: 2 },
        second: { type: 'leaf', paneId: 'pane-3', ptyId: 3 }
      },
      activePaneId: 'pane-2'
    }
  ]

  it('should create a snapshot', () => {
    const { createSnapshot, snapshots } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map([['pane-1', '/home/user'], ['pane-2', '/home/user/project']])

    const snapshot = createSnapshot('Test Snapshot', tabs, 'tab-1', cwdMap, 'Test description')

    expect(snapshot).toBeDefined()
    expect(snapshot.name).toBe('Test Snapshot')
    expect(snapshot.description).toBe('Test description')
    expect(snapshot.tabs).toHaveLength(2)
    expect(snapshots.value).toHaveLength(1)
  })

  it('should include CWDs in snapshot', () => {
    const { createSnapshot } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map([['pane-1', '/home/user'], ['pane-2', '/home/user/project']])

    const snapshot = createSnapshot('Test', tabs, null, cwdMap)

    expect(snapshot.tabs[0].layout?.cwd).toBe('/home/user')
  })

  it('should get a snapshot by ID', () => {
    const { createSnapshot, getSnapshot } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map()

    const created = createSnapshot('Test', tabs, null, cwdMap)
    const retrieved = getSnapshot(created.id)

    expect(retrieved).toBeDefined()
    expect(retrieved?.id).toBe(created.id)
  })

  it('should delete a snapshot', () => {
    const { createSnapshot, deleteSnapshot, snapshots } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map()

    const snapshot = createSnapshot('Test', tabs, null, cwdMap)
    expect(snapshots.value).toHaveLength(1)

    const deleted = deleteSnapshot(snapshot.id)
    expect(deleted).toBe(true)
    expect(snapshots.value).toHaveLength(0)
  })

  it('should rename a snapshot', () => {
    const { createSnapshot, renameSnapshot, getSnapshot } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map()

    const snapshot = createSnapshot('Original Name', tabs, null, cwdMap)
    const renamed = renameSnapshot(snapshot.id, 'New Name')

    expect(renamed).toBe(true)
    expect(getSnapshot(snapshot.id)?.name).toBe('New Name')
  })

  it('should add and remove tags', () => {
    const { createSnapshot, addTag, removeTag, getSnapshot } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map()

    const snapshot = createSnapshot('Test', tabs, null, cwdMap)

    addTag(snapshot.id, 'work')
    addTag(snapshot.id, 'important')
    expect(getSnapshot(snapshot.id)?.tags).toContain('work')
    expect(getSnapshot(snapshot.id)?.tags).toContain('important')

    removeTag(snapshot.id, 'work')
    expect(getSnapshot(snapshot.id)?.tags).not.toContain('work')
    expect(getSnapshot(snapshot.id)?.tags).toContain('important')
  })

  it('should filter snapshots by search query', () => {
    const { createSnapshot, filteredSnapshots, setSearchQuery, clearFilters } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map()

    createSnapshot('Project Alpha', tabs, null, cwdMap, 'Main project')
    createSnapshot('Project Beta', tabs, null, cwdMap, 'Secondary project')
    createSnapshot('Work Session', tabs, null, cwdMap, 'Daily work')

    setSearchQuery('alpha')
    expect(filteredSnapshots.value).toHaveLength(1)
    expect(filteredSnapshots.value[0].name).toBe('Project Alpha')

    clearFilters()
    expect(filteredSnapshots.value).toHaveLength(3)
  })

  it('should filter by tags', () => {
    const { createSnapshot, addTag, filteredSnapshots, toggleTagFilter, clearFilters } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map()

    const s1 = createSnapshot('Work 1', tabs, null, cwdMap)
    const s2 = createSnapshot('Personal', tabs, null, cwdMap)
    const s3 = createSnapshot('Work 2', tabs, null, cwdMap)

    addTag(s1.id, 'work')
    addTag(s3.id, 'work')
    addTag(s2.id, 'personal')

    toggleTagFilter('work')
    expect(filteredSnapshots.value).toHaveLength(2)

    clearFilters()
    expect(filteredSnapshots.value).toHaveLength(3)
  })

  it('should format timestamps correctly', () => {
    const { formatTimestamp } = useSnapshots()

    const now = Date.now()
    expect(formatTimestamp(now)).toBe('Just now')

    const fiveMinutesAgo = now - 5 * 60 * 1000
    expect(formatTimestamp(fiveMinutesAgo)).toBe('5 minutes ago')

    const twoHoursAgo = now - 2 * 60 * 60 * 1000
    expect(formatTimestamp(twoHoursAgo)).toBe('2 hours ago')
  })

  it('should clear all snapshots', () => {
    const { createSnapshot, clearAllSnapshots, snapshots } = useSnapshots()
    const tabs = createMockTabs()
    const cwdMap = new Map()

    createSnapshot('One', tabs, null, cwdMap)
    createSnapshot('Two', tabs, null, cwdMap)
    createSnapshot('Three', tabs, null, cwdMap)

    expect(snapshots.value).toHaveLength(3)

    clearAllSnapshots()
    expect(snapshots.value).toHaveLength(0)
  })

  it('should auto-snapshot only when there are tabs', () => {
    const { createAutoSnapshot } = useSnapshots()
    const cwdMap = new Map()

    const emptyResult = createAutoSnapshot([], null, cwdMap)
    expect(emptyResult).toBeNull()
  })
})
