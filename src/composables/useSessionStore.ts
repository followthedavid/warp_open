/**
 * Session Store Composable
 *
 * Persists terminal session metadata for recovery after:
 * - App crashes
 * - Window reloads
 * - Tauri restarts
 *
 * Stores lightweight metadata (not full output):
 * - Working directories
 * - Tab/pane layout
 * - Running command hints (best-effort)
 */

import { ref, watch, computed } from 'vue'
import type { LayoutNode, Tab } from './useTabs'

// Persisted session state
export interface PersistedSession {
  version: number
  timestamp: number
  tabs: PersistedTab[]
  activeTabId: string | null
  lastKnownCwds: Record<string, string>  // paneId -> cwd
  recoveryHints: Record<string, RecoveryHint>  // paneId -> hint
}

export interface PersistedTab {
  id: string
  name: string
  kind: 'terminal' | 'editor' | 'ai' | 'developer'
  layout?: PersistedLayout
  filePath?: string
}

export interface PersistedLayout {
  type: 'leaf' | 'split'
  paneId?: string
  direction?: 'horizontal' | 'vertical'
  ratio?: number
  first?: PersistedLayout
  second?: PersistedLayout
}

export interface RecoveryHint {
  lastCommand?: string
  lastCommandTime?: number
  shellPid?: number
  isRunning?: boolean
}

export interface RecoveryResult {
  recovered: boolean
  tabsRecovered: number
  panesRecovered: number
  cwdsRestored: number
  errors: string[]
}

const STORAGE_KEY = 'warp_session_state'
const SESSION_VERSION = 1
const AUTO_SAVE_INTERVAL = 30000  // Save every 30 seconds

// Global state
const sessionState = ref<PersistedSession | null>(null)
const isDirty = ref(false)
const lastSaveTime = ref(0)
const autoSaveEnabled = ref(true)

// Initialize on first import
loadSession()

function loadSession(): PersistedSession | null {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      const parsed = JSON.parse(stored) as PersistedSession
      if (parsed.version === SESSION_VERSION) {
        sessionState.value = parsed
        console.log('[useSessionStore] Loaded session from', new Date(parsed.timestamp).toLocaleString())
        return parsed
      } else {
        console.warn('[useSessionStore] Session version mismatch, ignoring stored session')
      }
    }
  } catch (e) {
    console.error('[useSessionStore] Failed to load session:', e)
  }
  return null
}

function saveSession(): void {
  if (!sessionState.value) return

  try {
    sessionState.value.timestamp = Date.now()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sessionState.value))
    lastSaveTime.value = Date.now()
    isDirty.value = false
    console.log('[useSessionStore] Saved session')
  } catch (e) {
    console.error('[useSessionStore] Failed to save session:', e)
  }
}

export function useSessionStore() {
  // Convert Tab layout to persisted format
  function layoutToPersisted(layout: LayoutNode | undefined): PersistedLayout | undefined {
    if (!layout) return undefined

    if (layout.type === 'leaf') {
      return {
        type: 'leaf',
        paneId: layout.paneId
      }
    } else {
      return {
        type: 'split',
        direction: layout.direction,
        ratio: layout.ratio,
        first: layoutToPersisted(layout.first),
        second: layoutToPersisted(layout.second)
      }
    }
  }

  // Update session state from current tabs
  function updateSession(
    tabs: Tab[],
    activeTabId: string | null,
    cwds: Map<string, string>
  ): void {
    const persistedTabs: PersistedTab[] = tabs.map(tab => ({
      id: tab.id,
      name: tab.name,
      kind: tab.kind,
      layout: tab.kind === 'terminal' ? layoutToPersisted(tab.layout) : undefined,
      filePath: tab.kind === 'editor' ? tab.file_path : undefined
    }))

    const lastKnownCwds: Record<string, string> = {}
    cwds.forEach((cwd, paneId) => {
      lastKnownCwds[paneId] = cwd
    })

    sessionState.value = {
      version: SESSION_VERSION,
      timestamp: Date.now(),
      tabs: persistedTabs,
      activeTabId,
      lastKnownCwds,
      recoveryHints: sessionState.value?.recoveryHints || {}
    }

    isDirty.value = true
  }

  // Update CWD for a pane
  function updatePaneCwd(paneId: string, cwd: string): void {
    if (!sessionState.value) {
      sessionState.value = {
        version: SESSION_VERSION,
        timestamp: Date.now(),
        tabs: [],
        activeTabId: null,
        lastKnownCwds: {},
        recoveryHints: {}
      }
    }
    sessionState.value.lastKnownCwds[paneId] = cwd
    isDirty.value = true
  }

  // Update recovery hint for a pane
  function updateRecoveryHint(paneId: string, hint: Partial<RecoveryHint>): void {
    if (!sessionState.value) return

    if (!sessionState.value.recoveryHints[paneId]) {
      sessionState.value.recoveryHints[paneId] = {}
    }
    Object.assign(sessionState.value.recoveryHints[paneId], hint)
    isDirty.value = true
  }

  // Get persisted session for recovery
  function getPersistedSession(): PersistedSession | null {
    return sessionState.value
  }

  // Get last known CWD for a pane
  function getLastKnownCwd(paneId: string): string | undefined {
    return sessionState.value?.lastKnownCwds[paneId]
  }

  // Get recovery hint for a pane
  function getRecoveryHint(paneId: string): RecoveryHint | undefined {
    return sessionState.value?.recoveryHints[paneId]
  }

  // Check if we have a session to recover
  function hasRecoverableSession(): boolean {
    const session = sessionState.value
    if (!session) return false
    if (session.tabs.length === 0) return false

    // Check if session is not too old (max 24 hours)
    const maxAge = 24 * 60 * 60 * 1000
    if (Date.now() - session.timestamp > maxAge) {
      console.log('[useSessionStore] Session too old, not recoverable')
      return false
    }

    return true
  }

  // Clear session (after successful recovery or explicit clear)
  function clearSession(): void {
    sessionState.value = null
    localStorage.removeItem(STORAGE_KEY)
    console.log('[useSessionStore] Cleared session')
  }

  // Force save (call before app close)
  function forceSave(): void {
    if (isDirty.value) {
      saveSession()
    }
  }

  // Start auto-save timer
  let autoSaveTimer: ReturnType<typeof setInterval> | null = null

  function startAutoSave(): void {
    if (autoSaveTimer) return

    autoSaveTimer = setInterval(() => {
      if (autoSaveEnabled.value && isDirty.value) {
        saveSession()
      }
    }, AUTO_SAVE_INTERVAL)

    console.log('[useSessionStore] Auto-save started')
  }

  function stopAutoSave(): void {
    if (autoSaveTimer) {
      clearInterval(autoSaveTimer)
      autoSaveTimer = null
    }
  }

  // Enable/disable auto-save
  function setAutoSaveEnabled(enabled: boolean): void {
    autoSaveEnabled.value = enabled
  }

  // Session recovery statistics
  const stats = computed(() => ({
    hasSavedSession: sessionState.value !== null,
    tabCount: sessionState.value?.tabs.length || 0,
    cwdCount: Object.keys(sessionState.value?.lastKnownCwds || {}).length,
    lastSaved: lastSaveTime.value,
    isDirty: isDirty.value,
    autoSaveEnabled: autoSaveEnabled.value
  }))

  return {
    // State
    stats,

    // Update methods
    updateSession,
    updatePaneCwd,
    updateRecoveryHint,

    // Query methods
    getPersistedSession,
    getLastKnownCwd,
    getRecoveryHint,
    hasRecoverableSession,

    // Lifecycle
    clearSession,
    forceSave,
    startAutoSave,
    stopAutoSave,
    setAutoSaveEnabled
  }
}

export type SessionStore = ReturnType<typeof useSessionStore>
