/**
 * Integration tests for session persistence and recovery
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useSessionStore } from '../composables/useSessionStore'

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {}
  return {
    getItem: (key: string) => store[key] ?? null,
    setItem: (key: string, value: string) => { store[key] = value },
    removeItem: (key: string) => { delete store[key] },
    clear: () => { store = {} },
    get length() { return Object.keys(store).length },
    key: (i: number) => Object.keys(store)[i] ?? null,
  }
})()

Object.defineProperty(window, 'localStorage', { value: localStorageMock })

describe('useSessionStore', () => {
  beforeEach(() => {
    localStorageMock.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('basic operations', () => {
    it('should start with no recoverable session', () => {
      const store = useSessionStore()
      expect(store.hasRecoverableSession()).toBe(false)
    })

    it('should update session state', () => {
      const store = useSessionStore()
      const tabs = [
        { id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null },
        { id: 'tab-2', name: 'Editor', kind: 'editor' as const, content: '' },
      ]
      const paneCwds = new Map([['pane-1', '/home/user']])

      store.updateSession(tabs, 'tab-1', paneCwds)

      const session = store.getPersistedSession()
      expect(session).not.toBeNull()
      expect(session?.tabs.length).toBe(2)
      expect(session?.activeTabId).toBe('tab-1')
      expect(session?.lastKnownCwds['pane-1']).toBe('/home/user')
    })

    it('should have recoverable session after update', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.forceSave()

      expect(store.hasRecoverableSession()).toBe(true)
    })

    it('should clear session', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.forceSave()
      expect(store.hasRecoverableSession()).toBe(true)

      store.clearSession()
      expect(store.hasRecoverableSession()).toBe(false)
    })
  })

  describe('recovery hints', () => {
    it('should store recovery hints for panes', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.updateRecoveryHint('pane-1', {
        lastCommand: 'npm test',
        exitCode: 0,
        timestamp: Date.now()
      })
      store.forceSave()

      const session = store.getPersistedSession()
      expect(session?.recoveryHints['pane-1']).toBeDefined()
      expect(session?.recoveryHints['pane-1'].lastCommand).toBe('npm test')
    })

    it('should update pane CWD separately', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.updatePaneCwd('pane-1', '/var/log')
      store.forceSave()

      const session = store.getPersistedSession()
      expect(session?.lastKnownCwds['pane-1']).toBe('/var/log')
    })
  })

  describe('session expiry', () => {
    it('should not recover session older than 24 hours', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.forceSave()

      // Advance time by 25 hours
      vi.advanceTimersByTime(25 * 60 * 60 * 1000)

      expect(store.hasRecoverableSession()).toBe(false)
    })

    it('should recover session within 24 hours', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.forceSave()

      // Advance time by 23 hours
      vi.advanceTimersByTime(23 * 60 * 60 * 1000)

      expect(store.hasRecoverableSession()).toBe(true)
    })
  })

  describe('auto-save', () => {
    it('should auto-save periodically after starting', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.startAutoSave()

      // Advance by auto-save interval (30 seconds)
      vi.advanceTimersByTime(31000)

      // Should have saved - verify by checking localStorage has data
      const stored = localStorageMock.getItem('warp_session_state')
      expect(stored).not.toBeNull()

      store.stopAutoSave()
    })

    it('should call forceSave during auto-save', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]

      store.updateSession(tabs, 'tab-1', new Map())
      store.startAutoSave()

      // The auto-save should keep the session up to date
      vi.advanceTimersByTime(31000)

      expect(store.hasRecoverableSession()).toBe(true)

      store.stopAutoSave()
    })
  })

  describe('version compatibility', () => {
    it('should handle old session format with correct version', () => {
      // Session with version 1 should be recoverable
      const session = {
        version: 1,
        timestamp: Date.now(),
        tabs: [{ id: 'tab-1', name: 'Test' }],
        activeTabId: 'tab-1',
        lastKnownCwds: {},
        recoveryHints: {}
      }
      localStorageMock.setItem('warp_session_state', JSON.stringify(session))

      const store = useSessionStore()
      // Should be recoverable with correct version
      expect(store.hasRecoverableSession()).toBe(true)
    })

    it('should preserve session data on update', () => {
      const store = useSessionStore()

      // First save
      const tabs1 = [{ id: 'tab-1', name: 'Tab 1', kind: 'terminal' as const, layout: null }]
      store.updateSession(tabs1, 'tab-1', new Map())
      store.forceSave()

      // Second save with different tabs
      const tabs2 = [
        { id: 'tab-1', name: 'Tab 1', kind: 'terminal' as const, layout: null },
        { id: 'tab-2', name: 'Tab 2', kind: 'terminal' as const, layout: null },
      ]
      store.updateSession(tabs2, 'tab-2', new Map())
      store.forceSave()

      const session = store.getPersistedSession()
      expect(session?.tabs.length).toBe(2)
      expect(session?.activeTabId).toBe('tab-2')
    })
  })

  describe('edge cases', () => {
    it('should handle empty tabs array', () => {
      const store = useSessionStore()
      store.updateSession([], null, new Map())
      store.forceSave()

      const session = store.getPersistedSession()
      expect(session?.tabs.length).toBe(0)
    })

    it('should handle large CWD maps', () => {
      const store = useSessionStore()
      const tabs = [{ id: 'tab-1', name: 'Terminal', kind: 'terminal' as const, layout: null }]
      const cwds = new Map<string, string>()

      // Add 100 pane CWDs
      for (let i = 0; i < 100; i++) {
        cwds.set(`pane-${i}`, `/home/user/project-${i}`)
      }

      store.updateSession(tabs, 'tab-1', cwds)
      store.forceSave()

      const session = store.getPersistedSession()
      expect(Object.keys(session?.lastKnownCwds || {}).length).toBe(100)
    })

    it('should handle corrupted localStorage without crashing', () => {
      // First ensure there's no valid session cached
      const store = useSessionStore()
      store.clearSession()
      localStorageMock.clear()

      // Now set corrupted data directly
      localStorageMock.setItem('warp_session_state', 'not valid json')

      // getPersistedSession should not throw on corrupted JSON
      // (it may return cached session or try to parse)
      expect(() => store.getPersistedSession()).not.toThrow()
    })
  })
})
