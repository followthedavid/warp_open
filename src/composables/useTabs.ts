import { reactive, readonly, ref, toRef } from 'vue'
import { v4 as uuidv4 } from 'uuid'
import { invoke } from '@tauri-apps/api/tauri'

// -----------------------------
// Types
// -----------------------------
export type TabKind = 'terminal' | 'ai' | 'editor' | 'developer'

export interface ChatMessage {
  id: string
  role: 'user' | 'ai' | 'system'
  content: string
  timestamp: number
}

// Split pane layout types
export type SplitDirection = 'horizontal' | 'vertical'

export interface LeafNode {
  type: 'leaf'
  paneId: string
  ptyId: number
  cwd?: string
}

export interface SplitNode {
  type: 'split'
  direction: SplitDirection
  ratio: number  // 0-1, portion for first child
  first: LayoutNode
  second: LayoutNode
}

export type LayoutNode = LeafNode | SplitNode

export interface Tab {
  id: string
  kind: TabKind
  name: string
  ptyId?: number            // Only for terminal tabs (legacy single-pane)
  layout?: LayoutNode       // For terminal tabs with panes
  activePaneId?: string     // Currently focused pane
  messages?: ChatMessage[]  // Only for AI tabs
  is_thinking?: boolean     // Only for AI tabs
  filePath?: string         // Only for editor tabs
  content?: string
  lastSavedContent?: string
  isDirty?: boolean
  runTerminalTabId?: string
}

// -----------------------------
// State - Using reactive for proper Vue reactivity
// -----------------------------
interface TabsState {
  tabs: Tab[]
  activeTabId: string | null
}

const state = reactive<TabsState>({
  tabs: [],
  activeTabId: null
})

// Active tab reference - updated when activeTabId changes
const activeTab = ref<Tab | null>(null)

function updateActiveTab() {
  activeTab.value = state.tabs.find(t => t.id === state.activeTabId) || null
}

// -----------------------------
// Actions
// -----------------------------
async function createTerminalTab(name?: string): Promise<Tab | null> {
  try {
    const ptyInfo = await invoke<{ id: number }>('spawn_pty', { shell: null })
    const paneId = uuidv4()
    const tab: Tab = {
      id: uuidv4(),
      kind: 'terminal',
      name: name || `Terminal ${state.tabs.filter(t => t.kind === 'terminal').length + 1}`,
      ptyId: ptyInfo.id,  // Keep for backward compatibility
      layout: {
        type: 'leaf',
        paneId,
        ptyId: ptyInfo.id,
      },
      activePaneId: paneId,
    }
    state.tabs.push(tab)
    state.activeTabId = tab.id
    updateActiveTab()
    scheduleAutoSave()
    console.log('[useTabs] Created terminal tab:', tab)
    return tab
  } catch (error) {
    console.error('[useTabs] Failed to create terminal tab:', error)
    return null
  }
}

function createAITab(name?: string): Tab {
  const tab: Tab = {
    id: uuidv4(),
    kind: 'ai',
    name: name || `AI ${state.tabs.filter(t => t.kind === 'ai').length + 1}`,
    messages: [],
    is_thinking: false
  }
  state.tabs.push(tab)
  state.activeTabId = tab.id
  updateActiveTab()
  scheduleAutoSave()
  console.log('[useTabs] Created AI chat tab:', tab)
  return tab
}

function createEditorTab(name?: string, filePath?: string): Tab {
  const tabName = name || filePath?.split('/').pop() || `Untitled ${state.tabs.filter(t => t.kind === 'editor').length + 1}`
  const tab: Tab = {
    id: uuidv4(),
    kind: 'editor',
    name: tabName,
    filePath,
    content: '',
    lastSavedContent: '',
    isDirty: false,
  }
  state.tabs.push(tab)
  state.activeTabId = tab.id
  updateActiveTab()
  scheduleAutoSave()
  return tab
}

function createDeveloperTab(name?: string): Tab {
  const tab: Tab = {
    id: uuidv4(),
    kind: 'developer',
    name: name || 'AI Developer'
  }
  state.tabs.push(tab)
  state.activeTabId = tab.id
  updateActiveTab()
  scheduleAutoSave()
  console.log('[useTabs] Created developer tab:', tab)
  return tab
}

// Helper: collect all PTY IDs from a layout tree
function collectPtyIds(node: LayoutNode | undefined): number[] {
  if (!node) return []
  if (node.type === 'leaf') {
    return [node.ptyId]
  }
  return [...collectPtyIds(node.first), ...collectPtyIds(node.second)]
}

// Helper: find a pane in the layout tree
function findPaneInLayout(node: LayoutNode | undefined, paneId: string): LeafNode | null {
  if (!node) return null
  if (node.type === 'leaf') {
    return node.paneId === paneId ? node : null
  }
  return findPaneInLayout(node.first, paneId) || findPaneInLayout(node.second, paneId)
}

// Helper: replace a pane in the layout tree (returns new tree)
function replacePaneInLayout(node: LayoutNode, paneId: string, newNode: LayoutNode): LayoutNode {
  if (node.type === 'leaf') {
    return node.paneId === paneId ? newNode : node
  }
  return {
    ...node,
    first: replacePaneInLayout(node.first, paneId, newNode),
    second: replacePaneInLayout(node.second, paneId, newNode),
  }
}

// Helper: remove a pane from the layout tree (returns sibling or null)
function removePaneFromLayout(node: LayoutNode, paneId: string): LayoutNode | null {
  if (node.type === 'leaf') {
    return node.paneId === paneId ? null : node
  }
  // Check if the pane to remove is in either child
  if (node.first.type === 'leaf' && node.first.paneId === paneId) {
    return node.second
  }
  if (node.second.type === 'leaf' && node.second.paneId === paneId) {
    return node.first
  }
  // Recurse into children
  const newFirst = removePaneFromLayout(node.first, paneId)
  const newSecond = removePaneFromLayout(node.second, paneId)
  if (newFirst === null) return newSecond
  if (newSecond === null) return newFirst
  return { ...node, first: newFirst, second: newSecond }
}

// Helper: get all leaf panes from a layout tree
function getAllPanes(node: LayoutNode | undefined): LeafNode[] {
  if (!node) return []
  if (node.type === 'leaf') {
    return [node]
  }
  return [...getAllPanes(node.first), ...getAllPanes(node.second)]
}

// Split the active pane
async function splitPane(tabId: string, direction: SplitDirection): Promise<boolean> {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab || tab.kind !== 'terminal' || !tab.layout || !tab.activePaneId) {
    console.error('[useTabs] Cannot split: invalid tab or no active pane')
    return false
  }

  const activePaneId = tab.activePaneId
  const activePane = findPaneInLayout(tab.layout, activePaneId)
  if (!activePane) {
    console.error('[useTabs] Cannot split: active pane not found')
    return false
  }

  let ptyInfo: { id: number } | null = null
  try {
    // Create new PTY
    ptyInfo = await invoke<{ id: number }>('spawn_pty', { shell: null })
    const newPaneId = uuidv4()

    // Create new leaf node
    const newLeaf: LeafNode = {
      type: 'leaf',
      paneId: newPaneId,
      ptyId: ptyInfo.id,
    }

    // Create split node replacing the active pane
    const splitNode: SplitNode = {
      type: 'split',
      direction,
      ratio: 0.5,
      first: { ...activePane },  // Clone the active pane
      second: newLeaf,
    }

    // Replace in layout tree
    tab.layout = replacePaneInLayout(tab.layout, activePaneId, splitNode)
    tab.activePaneId = newPaneId  // Focus the new pane

    scheduleAutoSave()
    console.log('[useTabs] Split pane:', direction, 'new PTY:', ptyInfo.id)
    return true
  } catch (error) {
    console.error('[useTabs] Failed to split pane:', error)
    // PTY LEAK FIX: Clean up orphaned PTY if it was spawned but layout update failed
    if (ptyInfo) {
      try {
        await invoke('close_pty', { id: ptyInfo.id })
        console.log('[useTabs] Cleaned up orphaned PTY:', ptyInfo.id)
      } catch (cleanupError) {
        console.error('[useTabs] Failed to cleanup orphaned PTY:', cleanupError)
      }
    }
    return false
  }
}

// Close a specific pane (not the whole tab)
async function closePane(tabId: string, paneId: string): Promise<boolean> {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab || tab.kind !== 'terminal' || !tab.layout) {
    return false
  }

  // Find the pane to close
  const pane = findPaneInLayout(tab.layout, paneId)
  if (!pane) {
    return false
  }

  // If this is the only pane, close the whole tab instead
  const allPanes = getAllPanes(tab.layout)
  if (allPanes.length === 1) {
    await closeTab(tabId)
    return true
  }

  // Close the PTY
  try {
    await invoke('close_pty', { id: pane.ptyId })
  } catch (error) {
    console.error('[useTabs] Failed to close pane PTY:', error)
  }

  // Remove from layout
  const newLayout = removePaneFromLayout(tab.layout, paneId)
  if (newLayout) {
    tab.layout = newLayout
    // Update active pane if needed
    if (tab.activePaneId === paneId) {
      const remainingPanes = getAllPanes(newLayout)
      tab.activePaneId = remainingPanes[0]?.paneId
    }
  }

  scheduleAutoSave()
  console.log('[useTabs] Closed pane:', paneId)
  return true
}

// Set active pane within a tab
function setActivePane(tabId: string, paneId: string) {
  const tab = state.tabs.find(t => t.id === tabId)
  if (tab && tab.kind === 'terminal') {
    tab.activePaneId = paneId
    scheduleAutoSave()
  }
}

// Navigate to adjacent pane
function navigatePane(tabId: string, direction: 'up' | 'down' | 'left' | 'right') {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab || tab.kind !== 'terminal' || !tab.layout || !tab.activePaneId) {
    return
  }

  const allPanes = getAllPanes(tab.layout)
  if (allPanes.length <= 1) return

  const currentIndex = allPanes.findIndex(p => p.paneId === tab.activePaneId)
  if (currentIndex === -1) return

  // Simple wrap-around navigation (can be improved with spatial awareness)
  let nextIndex: number
  if (direction === 'left' || direction === 'up') {
    nextIndex = currentIndex > 0 ? currentIndex - 1 : allPanes.length - 1
  } else {
    nextIndex = currentIndex < allPanes.length - 1 ? currentIndex + 1 : 0
  }

  tab.activePaneId = allPanes[nextIndex].paneId
}

// Resize the active pane
const RESIZE_STEP = 0.05 // 5% per keypress
const MIN_RATIO = 0.1
const MAX_RATIO = 0.9

function resizeActivePane(tabId: string, direction: 'up' | 'down' | 'left' | 'right') {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab || tab.kind !== 'terminal' || !tab.layout || !tab.activePaneId) {
    return
  }

  // Find the parent split node of the active pane
  function findParentSplit(node: LayoutNode, paneId: string, parent: SplitNode | null, isFirst: boolean): { parent: SplitNode, isFirst: boolean } | null {
    if (node.type === 'leaf') {
      if (node.paneId === paneId && parent) {
        return { parent, isFirst }
      }
      return null
    }
    // Check children
    const fromFirst = findParentSplit(node.first, paneId, node, true)
    if (fromFirst) return fromFirst
    return findParentSplit(node.second, paneId, node, false)
  }

  const result = findParentSplit(tab.layout, tab.activePaneId, null, true)
  if (!result) return

  const { parent, isFirst } = result

  // Determine if this resize makes sense for the split direction
  const isHorizontalSplit = parent.direction === 'horizontal'
  const isHorizontalResize = direction === 'left' || direction === 'right'

  // Only resize if the direction matches the split orientation
  if (isHorizontalSplit !== isHorizontalResize) {
    return
  }

  // Calculate new ratio
  let delta = RESIZE_STEP
  // Growing first pane: right or down when in first, left or up when in second
  // Shrinking first pane: left or up when in first, right or down when in second
  if (isFirst) {
    if (direction === 'left' || direction === 'up') delta = -delta
  } else {
    if (direction === 'right' || direction === 'down') delta = -delta
  }

  const newRatio = Math.max(MIN_RATIO, Math.min(MAX_RATIO, parent.ratio + delta))
  parent.ratio = newRatio
  scheduleAutoSave()
}

// Update split ratio (called from drag resize)
function updateSplitRatio(tabId: string, nodeId: string, ratio: number) {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab || tab.kind !== 'terminal' || !tab.layout) {
    return
  }

  // Find and update the split node's ratio in the layout tree
  function updateRatioInNode(node: LayoutNode): boolean {
    if (node.type === 'leaf') {
      return false
    }
    // Check if this is the target node
    const currentNodeId = `split-${getNodeIdHelper(node.first)}-${getNodeIdHelper(node.second)}`
    if (currentNodeId === nodeId) {
      node.ratio = ratio
      return true
    }
    // Recurse into children
    return updateRatioInNode(node.first) || updateRatioInNode(node.second)
  }

  function getNodeIdHelper(node: LayoutNode): string {
    if (node.type === 'leaf') {
      return node.paneId
    }
    return `split-${getNodeIdHelper(node.first)}-${getNodeIdHelper(node.second)}`
  }

  if (updateRatioInNode(tab.layout)) {
    scheduleAutoSave()
  }
}

// Update pane cwd (called from OSC 7 handler)
function updatePaneCwd(tabId: string, paneId: string, cwd: string) {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab || tab.kind !== 'terminal' || !tab.layout) {
    return
  }

  // Find and update the pane's cwd in the layout tree
  function updateCwdInNode(node: LayoutNode): boolean {
    if (node.type === 'leaf') {
      if (node.paneId === paneId) {
        node.cwd = cwd
        return true
      }
      return false
    }
    return updateCwdInNode(node.first) || updateCwdInNode(node.second)
  }

  if (updateCwdInNode(tab.layout)) {
    scheduleAutoSave()
  }
}

// Get active pane's cwd for a tab
function getActivePaneCwd(tabId: string): string | undefined {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab || tab.kind !== 'terminal' || !tab.layout || !tab.activePaneId) {
    return undefined
  }
  const pane = findPaneInLayout(tab.layout, tab.activePaneId)
  return pane?.cwd
}

async function closeTab(tabId: string) {
  const tab = state.tabs.find(t => t.id === tabId)
  if (!tab) return

  if (tab.kind === 'terminal') {
    // Close all PTYs in the layout tree
    const ptyIds = tab.layout ? collectPtyIds(tab.layout) : (tab.ptyId != null ? [tab.ptyId] : [])
    for (const ptyId of ptyIds) {
      try {
        await invoke('close_pty', { id: ptyId })
        console.log('[useTabs] Closed PTY:', ptyId)
      } catch (error) {
        console.error('[useTabs] Failed to close PTY:', ptyId, error)
      }
    }
  }

  // Remove tab from state
  const index = state.tabs.findIndex(t => t.id === tabId)
  if (index !== -1) {
    state.tabs.splice(index, 1)
  }

  // Switch active tab if needed
  if (state.activeTabId === tabId) {
    state.activeTabId = state.tabs.length ? state.tabs[Math.max(index - 1, 0)].id : null
  }

  updateActiveTab()
  scheduleAutoSave()
  console.log('[useTabs] Closed tab:', tabId)
}

function setActiveTab(tabId: string | null) {
  if (tabId === null || state.tabs.find(t => t.id === tabId)) {
    state.activeTabId = tabId
    updateActiveTab()
    scheduleAutoSave()
  }
}

function renameTab(tabId: string, newName: string) {
  const tab = state.tabs.find(t => t.id === tabId)
  if (tab) {
    tab.name = newName
    scheduleAutoSave()
  }
}

function reorderTabs(fromIndex: number, toIndex: number) {
  if (fromIndex === toIndex || fromIndex < 0 || toIndex < 0) return
  if (fromIndex >= state.tabs.length || toIndex >= state.tabs.length) return

  const tab = state.tabs.splice(fromIndex, 1)[0]
  state.tabs.splice(toIndex, 0, tab)
  scheduleAutoSave()
}

function openTabForFile(path: string): Tab | null {
  let tab = state.tabs.find(t => t.kind === 'editor' && t.filePath === path)
  if (tab) {
    state.activeTabId = tab.id
    updateActiveTab()
    return tab
  }
  tab = createEditorTab(undefined, path)
  return tab
}

function setEditorInitialContent(tabId: string, content: string) {
  const tab = state.tabs.find(t => t.id === tabId && t.kind === 'editor')
  if (!tab) return
  tab.content = content
  tab.lastSavedContent = content
  tab.isDirty = false
}

function updateEditorContent(tabId: string, content: string) {
  const tab = state.tabs.find(t => t.id === tabId && t.kind === 'editor')
  if (!tab) return
  tab.content = content
  tab.isDirty = tab.lastSavedContent !== content
}

function markEditorSaved(tabId: string, content: string) {
  const tab = state.tabs.find(t => t.id === tabId && t.kind === 'editor')
  if (!tab) return
  tab.content = content
  tab.lastSavedContent = content
  tab.isDirty = false
}

// -----------------------------
// Session Persistence
// -----------------------------

// Serializable layout node (PTY IDs are removed, will be re-created)
interface SavedLeafNode {
  type: 'leaf'
  paneId: string
  cwd?: string
}

interface SavedSplitNode {
  type: 'split'
  direction: SplitDirection
  ratio: number
  first: SavedLayoutNode
  second: SavedLayoutNode
}

type SavedLayoutNode = SavedLeafNode | SavedSplitNode

interface SavedTabState {
  id: string
  kind: string
  name: string
  pty_id: number | null
  cwd: string | null
  file_path: string | null
  layout?: SavedLayoutNode  // For split pane terminals
  activePaneId?: string
}

interface SavedSession {
  tabs: SavedTabState[]
  active_tab_id: string | null
  version: number
}

// Convert layout to saveable format (strip PTY IDs)
function layoutToSaved(node: LayoutNode | undefined): SavedLayoutNode | undefined {
  if (!node) return undefined
  if (node.type === 'leaf') {
    return {
      type: 'leaf',
      paneId: node.paneId,
      cwd: node.cwd,
    }
  }
  return {
    type: 'split',
    direction: node.direction,
    ratio: node.ratio,
    first: layoutToSaved(node.first)!,
    second: layoutToSaved(node.second)!,
  }
}

// Restore layout from saved format (spawn PTYs for each leaf)
async function savedToLayout(node: SavedLayoutNode): Promise<LayoutNode> {
  if (node.type === 'leaf') {
    const ptyInfo = await invoke<{ id: number }>('spawn_pty', { shell: null })
    return {
      type: 'leaf',
      paneId: node.paneId,
      ptyId: ptyInfo.id,
      cwd: node.cwd,
    }
  }
  const [first, second] = await Promise.all([
    savedToLayout(node.first),
    savedToLayout(node.second),
  ])
  return {
    type: 'split',
    direction: node.direction,
    ratio: node.ratio,
    first,
    second,
  }
}

async function saveSession(): Promise<void> {
  try {
    const sessionData: SavedSession = {
      tabs: state.tabs.map(tab => ({
        id: tab.id,
        kind: tab.kind,
        name: tab.name,
        pty_id: tab.ptyId ?? null,
        cwd: null,
        file_path: tab.filePath ?? null,
        layout: tab.layout ? layoutToSaved(tab.layout) : undefined,
        activePaneId: tab.activePaneId,
      })),
      active_tab_id: state.activeTabId,
      version: 2,  // Bump version for layout support
    }

    await invoke('save_session', { sessionJson: JSON.stringify(sessionData) })
    console.log('[useTabs] Session saved:', sessionData.tabs.length, 'tabs')
  } catch (error) {
    console.error('[useTabs] Failed to save session:', error)
  }
}

async function loadSession(): Promise<void> {
  // PTY LEAK FIX: Track spawned PTYs during restoration for cleanup on failure
  const spawnedPtyIds: number[] = []

  try {
    const session = await invoke<SavedSession>('load_session')

    if (!session || !session.tabs || session.tabs.length === 0) {
      console.log('[useTabs] No saved session found, creating default tab')
      await createTerminalTab()
      return
    }

    console.log('[useTabs] Restoring session:', session.tabs.length, 'tabs')

    // Clear current tabs
    state.tabs = []

    // Restore each tab
    for (const savedTab of session.tabs) {
      if (savedTab.kind === 'terminal') {
        // Check if we have a saved layout (v2+ session)
        if (savedTab.layout) {
          // Restore with layout (creates PTYs for all panes)
          const layout = await savedToLayout(savedTab.layout)
          // Track all PTYs spawned for this layout
          const allPanes = getAllPanes(layout)
          allPanes.forEach(p => spawnedPtyIds.push(p.ptyId))

          const tab: Tab = {
            id: savedTab.id,
            kind: 'terminal',
            name: savedTab.name,
            ptyId: allPanes[0]?.ptyId,  // Legacy ptyId for compatibility
            layout,
            activePaneId: savedTab.activePaneId || allPanes[0]?.paneId,
          }
          state.tabs.push(tab)
        } else {
          // Legacy: single pane terminal
          const tab = await createTerminalTab(savedTab.name)
          if (tab) {
            // Track PTY for potential cleanup
            if (tab.ptyId != null) spawnedPtyIds.push(tab.ptyId)
            const index = state.tabs.findIndex(t => t.id === tab.id)
            if (index !== -1) {
              state.tabs[index].id = savedTab.id
            }
          }
        }
      } else if (savedTab.kind === 'ai') {
        const tab = createAITab(savedTab.name)
        const index = state.tabs.findIndex(t => t.id === tab.id)
        if (index !== -1) {
          state.tabs[index].id = savedTab.id
        }
      } else if (savedTab.kind === 'editor') {
        const tab = createEditorTab(savedTab.name, savedTab.file_path ?? undefined)
        const index = state.tabs.findIndex(t => t.id === tab.id)
        if (index !== -1) {
          state.tabs[index].id = savedTab.id
        }
      } else if (savedTab.kind === 'developer') {
        const tab = createDeveloperTab(savedTab.name)
        const index = state.tabs.findIndex(t => t.id === tab.id)
        if (index !== -1) {
          state.tabs[index].id = savedTab.id
        }
      }
    }

    // Restore active tab
    if (session.active_tab_id && state.tabs.find(t => t.id === session.active_tab_id)) {
      state.activeTabId = session.active_tab_id
    } else if (state.tabs.length > 0) {
      state.activeTabId = state.tabs[0].id
    }

    updateActiveTab()
    console.log('[useTabs] Session restored successfully with', spawnedPtyIds.length, 'PTYs')
  } catch (error) {
    console.error('[useTabs] Failed to load session:', error)
    // PTY LEAK FIX: Clean up any PTYs that were spawned before the failure
    if (spawnedPtyIds.length > 0) {
      console.log('[useTabs] Cleaning up', spawnedPtyIds.length, 'orphaned PTYs from failed session restore')
      for (const ptyId of spawnedPtyIds) {
        try {
          await invoke('close_pty', { id: ptyId })
        } catch (cleanupError) {
          console.error('[useTabs] Failed to cleanup PTY', ptyId, ':', cleanupError)
        }
      }
    }
    // Clear any partially restored tabs
    state.tabs = []
    // Create default tab on error
    await createTerminalTab()
  }
}

// Auto-save debounce
let saveTimeout: ReturnType<typeof setTimeout> | null = null

function scheduleAutoSave(): void {
  if (saveTimeout) {
    clearTimeout(saveTimeout)
  }
  saveTimeout = setTimeout(() => {
    saveSession()
  }, 1000) // Save 1 second after last change
}

// -----------------------------
// PTY Cleanup & Diagnostics
// -----------------------------

// Clean up all PTYs on app shutdown
async function cleanupAllPtys(): Promise<void> {
  console.log('[useTabs] Cleaning up all PTYs on shutdown...')
  const allPtyIds: number[] = []

  for (const tab of state.tabs) {
    if (tab.kind === 'terminal') {
      if (tab.layout) {
        const panes = getAllPanes(tab.layout)
        panes.forEach(p => allPtyIds.push(p.ptyId))
      } else if (tab.ptyId != null) {
        allPtyIds.push(tab.ptyId)
      }
    }
  }

  console.log('[useTabs] Found', allPtyIds.length, 'PTYs to clean up')
  for (const ptyId of allPtyIds) {
    try {
      await invoke('close_pty', { id: ptyId })
      console.log('[useTabs] Closed PTY:', ptyId)
    } catch (error) {
      console.error('[useTabs] Failed to close PTY:', ptyId, error)
    }
  }
}

// Get PTY count for diagnostics (useful for leak detection)
function getPtyCount(): number {
  let count = 0
  for (const tab of state.tabs) {
    if (tab.kind === 'terminal') {
      if (tab.layout) {
        count += getAllPanes(tab.layout).length
      } else if (tab.ptyId != null) {
        count += 1
      }
    }
  }
  return count
}

// -----------------------------
// AI Tab Utilities
// -----------------------------
function sendMessage(tabId: string, content: string) {
  const tab = state.tabs.find(t => t.id === tabId && t.kind === 'ai')
  if (!tab || !tab.messages) return

  const message: ChatMessage = {
    id: uuidv4(),
    role: 'user',
    content,
    timestamp: Date.now()
  }

  tab.messages.push(message)
  tab.is_thinking = true

  // Emit event for backend to handle
  import('@tauri-apps/api/event').then(({ emit }) => {
    emit('ai_user_message', { tabId, content })
  })
}

function addAIMessage(tabId: string, content: string) {
  const tab = state.tabs.find(t => t.id === tabId && t.kind === 'ai')
  if (!tab || !tab.messages) return

  tab.messages.push({
    id: uuidv4(),
    role: 'ai',
    content,
    timestamp: Date.now()
  })
  tab.is_thinking = false
}

function addSystemMessage(tabId: string, content: string) {
  const tab = state.tabs.find(t => t.id === tabId && t.kind === 'ai')
  if (!tab || !tab.messages) return

  tab.messages.push({
    id: uuidv4(),
    role: 'system',
    content,
    timestamp: Date.now()
  })
}

// -----------------------------
// Exports
// -----------------------------
export function useTabs() {
  const tabsRef = toRef(state, 'tabs')
  const activeIdRef = toRef(state, 'activeTabId')
  return {
    tabs: readonly(tabsRef),
    activeTabId: readonly(activeIdRef),
    activeTab,
    createTerminalTab,
    createAITab,
    createEditorTab,
    createDeveloperTab,
    closeTab,
    setActiveTab,
    renameTab,
    reorderTabs,
    openTabForFile,
    setEditorInitialContent,
    updateEditorContent,
    markEditorSaved,
    sendMessage,
    addAIMessage,
    addSystemMessage,
    // Session persistence
    saveSession,
    loadSession,
    // Split pane operations
    splitPane,
    closePane,
    setActivePane,
    navigatePane,
    resizeActivePane,
    getAllPanes,
    // OSC handlers
    updatePaneCwd,
    getActivePaneCwd,
    // Split ratio updates
    updateSplitRatio,
    // PTY cleanup & diagnostics
    cleanupAllPtys,
    getPtyCount,
    // Snapshot restore
    restoreFromSnapshot,
  }
}

// -----------------------------
// Snapshot Restore
// -----------------------------
import type { Snapshot, SnapshotTab, SnapshotLayoutNode } from './useSnapshots'

// Convert snapshot layout to live layout (spawn PTYs)
async function snapshotLayoutToLive(node: SnapshotLayoutNode): Promise<LayoutNode> {
  if (node.type === 'leaf') {
    const ptyInfo = await invoke<{ id: number }>('spawn_pty', { shell: null })
    return {
      type: 'leaf',
      paneId: node.paneId || uuidv4(),
      ptyId: ptyInfo.id,
      cwd: node.cwd,
    }
  }
  const [first, second] = await Promise.all([
    snapshotLayoutToLive(node.first!),
    snapshotLayoutToLive(node.second!),
  ])
  return {
    type: 'split',
    direction: node.direction!,
    ratio: node.ratio!,
    first,
    second,
  }
}

// Restore workspace from a snapshot
async function restoreFromSnapshot(snapshot: Snapshot): Promise<boolean> {
  console.log('[useTabs] Restoring from snapshot:', snapshot.name, 'with', snapshot.tabs.length, 'tabs')

  // Track PTYs spawned during restore for cleanup on failure
  const spawnedPtyIds: number[] = []

  try {
    // Step 1: Close all existing tabs and their PTYs
    console.log('[useTabs] Closing', state.tabs.length, 'existing tabs...')
    for (const tab of [...state.tabs]) {
      if (tab.kind === 'terminal') {
        const ptyIds = tab.layout ? collectPtyIds(tab.layout) : (tab.ptyId != null ? [tab.ptyId] : [])
        for (const ptyId of ptyIds) {
          try {
            await invoke('close_pty', { id: ptyId })
          } catch (e) {
            console.warn('[useTabs] Failed to close PTY during restore:', ptyId, e)
          }
        }
      }
    }

    // Clear state
    state.tabs = []
    state.activeTabId = null

    // Step 2: Recreate tabs from snapshot
    for (const snapTab of snapshot.tabs) {
      if (snapTab.kind === 'terminal') {
        if (snapTab.layout) {
          // Restore terminal with layout
          const layout = await snapshotLayoutToLive(snapTab.layout)
          const allPanes = getAllPanes(layout)
          allPanes.forEach(p => spawnedPtyIds.push(p.ptyId))

          const tab: Tab = {
            id: snapTab.id,
            kind: 'terminal',
            name: snapTab.name,
            ptyId: allPanes[0]?.ptyId,
            layout,
            activePaneId: allPanes[0]?.paneId,
          }
          state.tabs.push(tab)
        } else {
          // Simple terminal without layout
          const created = await createTerminalTab(snapTab.name)
          if (created) {
            if (created.ptyId != null) spawnedPtyIds.push(created.ptyId)
            // Use original ID
            const idx = state.tabs.findIndex(t => t.id === created.id)
            if (idx !== -1) state.tabs[idx].id = snapTab.id
          }
        }
      } else if (snapTab.kind === 'editor') {
        const tab = createEditorTab(snapTab.name, snapTab.filePath)
        const idx = state.tabs.findIndex(t => t.id === tab.id)
        if (idx !== -1) state.tabs[idx].id = snapTab.id
      } else if (snapTab.kind === 'ai') {
        const tab = createAITab(snapTab.name)
        const idx = state.tabs.findIndex(t => t.id === tab.id)
        if (idx !== -1) state.tabs[idx].id = snapTab.id
      } else if (snapTab.kind === 'developer') {
        const tab = createDeveloperTab(snapTab.name)
        const idx = state.tabs.findIndex(t => t.id === tab.id)
        if (idx !== -1) state.tabs[idx].id = snapTab.id
      }
    }

    // Step 3: Restore active tab
    if (snapshot.activeTabId && state.tabs.find(t => t.id === snapshot.activeTabId)) {
      state.activeTabId = snapshot.activeTabId
    } else if (state.tabs.length > 0) {
      state.activeTabId = state.tabs[0].id
    }

    updateActiveTab()
    scheduleAutoSave()

    console.log('[useTabs] Snapshot restored successfully:', state.tabs.length, 'tabs')
    return true
  } catch (error) {
    console.error('[useTabs] Failed to restore snapshot:', error)

    // Clean up any PTYs spawned before failure
    for (const ptyId of spawnedPtyIds) {
      try {
        await invoke('close_pty', { id: ptyId })
      } catch (e) {
        console.warn('[useTabs] Failed to cleanup PTY after restore failure:', ptyId, e)
      }
    }

    // Create a default tab so user isn't left with nothing
    state.tabs = []
    await createTerminalTab()

    return false
  }
}

// Re-export types for use in components
export type { LayoutNode, LeafNode, SplitNode }
