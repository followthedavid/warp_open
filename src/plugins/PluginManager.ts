/**
 * Plugin Manager
 *
 * Central manager for loading, unloading, and managing plugins.
 * Enforces security boundaries and provides sandboxed APIs.
 */

import { ref, computed, shallowRef } from 'vue'
import type {
  WarpPlugin,
  PluginContext,
  PluginState,
  PluginAPI,
  PluginEvent,
  PluginEventType,
  PluginPermission,
  PluginRegistration,
  PluginLogger,
  EventHandler,
  PaneInfo,
  TabInfo,
  CommandEntry,
  SessionMetadata,
  PluginDevLogEntry,
  PluginPermissionGrant,
  PluginValidationResult,
  PluginError,
} from './types'
import { SUPPORTED_API_VERSIONS, CURRENT_API_VERSION } from './types'

// Plugin instance with metadata
interface PluginInstance {
  id: string
  plugin: WarpPlugin
  registration: PluginRegistration
  context: PluginContext
  state: Map<string, unknown>
  subscriptions: Map<PluginEventType, Set<EventHandler>>
  container?: HTMLElement
}

// External data providers (set by App.vue)
interface DataProviders {
  getPanes: () => PaneInfo[]
  getTabs: () => TabInfo[]
  getActivePane: () => PaneInfo | null
  getRecentOutput: (paneId: string, lines?: number) => string[]
  getCommandHistory: (paneId: string, limit?: number) => CommandEntry[]
  getSessionMetadata: () => SessionMetadata
  showNotification: (message: string, type?: 'info' | 'success' | 'warning' | 'error') => void
}

// Shared state
const plugins = ref<Map<string, PluginInstance>>(new Map())
const enabledPlugins = ref<Set<string>>(new Set())
let dataProviders: DataProviders | null = null

// Dev Console state
const devLogs = shallowRef<PluginDevLogEntry[]>([])
const permissionGrants = shallowRef<PluginPermissionGrant[]>([])
const MAX_DEV_LOGS = 500
const MAX_PERMISSION_GRANTS = 100

// Storage key
const PLUGIN_STATE_KEY = 'warp_plugin_states'
const ENABLED_PLUGINS_KEY = 'warp_enabled_plugins'

export function usePluginManager() {
  // Generate unique plugin ID
  function generateId(): string {
    return `plugin-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`
  }

  // Create sandboxed state for a plugin
  function createPluginState(pluginId: string): PluginState {
    const stateMap = new Map<string, unknown>()

    // Load persisted state
    try {
      const stored = localStorage.getItem(`${PLUGIN_STATE_KEY}_${pluginId}`)
      if (stored) {
        const parsed = JSON.parse(stored)
        Object.entries(parsed).forEach(([k, v]) => stateMap.set(k, v))
      }
    } catch (e) {
      console.warn(`[PluginManager] Failed to load state for ${pluginId}`)
    }

    const saveState = () => {
      try {
        const obj: Record<string, unknown> = {}
        stateMap.forEach((v, k) => { obj[k] = v })
        localStorage.setItem(`${PLUGIN_STATE_KEY}_${pluginId}`, JSON.stringify(obj))
      } catch (e) {
        console.warn(`[PluginManager] Failed to save state for ${pluginId}`)
      }
    }

    return {
      get<T>(key: string): T | undefined {
        return stateMap.get(key) as T | undefined
      },
      set<T>(key: string, value: T): void {
        stateMap.set(key, value)
        saveState()
      },
      delete(key: string): void {
        stateMap.delete(key)
        saveState()
      },
      clear(): void {
        stateMap.clear()
        saveState()
      },
      toJSON(): Record<string, unknown> {
        const obj: Record<string, unknown> = {}
        stateMap.forEach((v, k) => { obj[k] = v })
        return obj
      },
    }
  }

  // Add entry to dev logs
  function addDevLog(
    pluginId: string,
    pluginName: string,
    level: 'info' | 'warn' | 'error' | 'debug',
    message: string,
    args?: unknown[]
  ): void {
    const entry: PluginDevLogEntry = {
      id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      pluginId,
      pluginName,
      level,
      message,
      args,
      timestamp: Date.now()
    }

    // Add to beginning (newest first)
    const newLogs = [entry, ...devLogs.value]
    if (newLogs.length > MAX_DEV_LOGS) {
      newLogs.length = MAX_DEV_LOGS
    }
    devLogs.value = newLogs
  }

  // Add permission grant record
  function addPermissionGrant(
    pluginId: string,
    pluginName: string,
    permission: PluginPermission,
    granted: boolean,
    reason?: string
  ): void {
    const entry: PluginPermissionGrant = {
      pluginId,
      pluginName,
      permission,
      granted,
      timestamp: Date.now(),
      reason
    }

    const newGrants = [entry, ...permissionGrants.value]
    if (newGrants.length > MAX_PERMISSION_GRANTS) {
      newGrants.length = MAX_PERMISSION_GRANTS
    }
    permissionGrants.value = newGrants
  }

  // Create sandboxed logger for a plugin (with dev console integration)
  function createPluginLogger(pluginId: string, pluginName: string): PluginLogger {
    const prefix = `[Plugin:${pluginName}]`
    return {
      info: (msg, ...args) => {
        console.log(prefix, msg, ...args)
        addDevLog(pluginId, pluginName, 'info', msg, args)
      },
      warn: (msg, ...args) => {
        console.warn(prefix, msg, ...args)
        addDevLog(pluginId, pluginName, 'warn', msg, args)
      },
      error: (msg, ...args) => {
        console.error(prefix, msg, ...args)
        addDevLog(pluginId, pluginName, 'error', msg, args)
      },
      debug: (msg, ...args) => {
        console.debug(prefix, msg, ...args)
        addDevLog(pluginId, pluginName, 'debug', msg, args)
      },
    }
  }

  // Create sandboxed API for a plugin
  function createPluginAPI(pluginId: string, permissions: PluginPermission[]): PluginAPI {
    const hasPermission = (p: PluginPermission) => permissions.includes(p)

    return {
      getPanes(): PaneInfo[] {
        if (!dataProviders) return []
        return dataProviders.getPanes()
      },

      getTabs(): TabInfo[] {
        if (!dataProviders) return []
        return dataProviders.getTabs()
      },

      getActivePane(): PaneInfo | null {
        if (!dataProviders) return null
        return dataProviders.getActivePane()
      },

      getRecentOutput(paneId: string, lines = 50): string[] {
        if (!hasPermission('read-output') || !dataProviders) return []
        return dataProviders.getRecentOutput(paneId, lines)
      },

      getCommandHistory(paneId: string, limit = 100): CommandEntry[] {
        if (!hasPermission('read-commands') || !dataProviders) return []
        return dataProviders.getCommandHistory(paneId, limit)
      },

      getSessionMetadata(): SessionMetadata {
        if (!hasPermission('read-session') || !dataProviders) {
          return { tabCount: 0, paneCount: 0, snapshotCount: 0, uptime: 0 }
        }
        return dataProviders.getSessionMetadata()
      },

      async writeToClipboard(text: string): Promise<boolean> {
        if (!hasPermission('write-clipboard')) {
          console.warn(`[PluginManager] Plugin ${pluginId} lacks write-clipboard permission`)
          return false
        }
        try {
          await navigator.clipboard.writeText(text)
          return true
        } catch (e) {
          console.error(`[PluginManager] Clipboard write failed:`, e)
          return false
        }
      },

      showNotification(message: string, type = 'info'): void {
        if (dataProviders) {
          dataProviders.showNotification(`[${pluginId}] ${message}`, type)
        }
      },
    }
  }

  // Create plugin context
  function createPluginContext(
    pluginId: string,
    pluginName: string,
    permissions: PluginPermission[],
    subscriptions: Map<PluginEventType, Set<EventHandler>>
  ): PluginContext {
    return {
      state: createPluginState(pluginId),
      api: createPluginAPI(pluginId, permissions),
      log: createPluginLogger(pluginId, pluginName),

      subscribe(eventType: PluginEventType, handler: EventHandler): () => void {
        // Check if event type is allowed by permissions
        const eventPermissions: Record<PluginEventType, PluginPermission> = {
          'output': 'read-output',
          'command': 'read-commands',
          'tab-opened': 'read-session',
          'tab-closed': 'read-session',
          'pane-focused': 'read-session',
          'cwd-changed': 'read-output',
          'snapshot-saved': 'read-session',
          'snapshot-restored': 'read-session',
        }

        const requiredPerm = eventPermissions[eventType]
        if (requiredPerm && !permissions.includes(requiredPerm)) {
          console.warn(`[PluginManager] Plugin ${pluginName} lacks ${requiredPerm} for ${eventType}`)
          return () => {}
        }

        if (!subscriptions.has(eventType)) {
          subscriptions.set(eventType, new Set())
        }
        subscriptions.get(eventType)!.add(handler)

        // Return unsubscribe function
        return () => {
          subscriptions.get(eventType)?.delete(handler)
        }
      },
    }
  }

  // Register a plugin
  async function registerPlugin(
    plugin: WarpPlugin,
    permissions: PluginPermission[] = []
  ): Promise<PluginRegistration | null> {
    const id = generateId()

    try {
      const subscriptions = new Map<PluginEventType, Set<EventHandler>>()
      const context = createPluginContext(id, plugin.name, permissions, subscriptions)

      const registration: PluginRegistration = {
        id,
        name: plugin.name,
        version: plugin.version,
        enabled: true,
        permissions,
        loadedAt: Date.now(),
      }

      const instance: PluginInstance = {
        id,
        plugin,
        registration,
        context,
        state: new Map(),
        subscriptions,
      }

      // Initialize plugin
      await plugin.init(context)

      // Store instance
      plugins.value.set(id, instance)
      enabledPlugins.value.add(id)
      saveEnabledPlugins()

      console.log(`[PluginManager] Registered plugin: ${plugin.name} v${plugin.version}`)
      return registration

    } catch (error) {
      console.error(`[PluginManager] Failed to register plugin ${plugin.name}:`, error)
      return null
    }
  }

  // Unregister a plugin
  async function unregisterPlugin(pluginId: string): Promise<boolean> {
    const instance = plugins.value.get(pluginId)
    if (!instance) {
      return false
    }

    try {
      // Call destroy hook
      await instance.plugin.destroy()

      // Clear subscriptions
      instance.subscriptions.clear()

      // Remove from registry
      plugins.value.delete(pluginId)
      enabledPlugins.value.delete(pluginId)
      saveEnabledPlugins()

      console.log(`[PluginManager] Unregistered plugin: ${instance.plugin.name}`)
      return true

    } catch (error) {
      console.error(`[PluginManager] Failed to unregister plugin ${pluginId}:`, error)
      return false
    }
  }

  // Enable/disable a plugin
  function setPluginEnabled(pluginId: string, enabled: boolean): boolean {
    const instance = plugins.value.get(pluginId)
    if (!instance) return false

    instance.registration.enabled = enabled
    if (enabled) {
      enabledPlugins.value.add(pluginId)
    } else {
      enabledPlugins.value.delete(pluginId)
    }
    saveEnabledPlugins()
    return true
  }

  // Dispatch event to all plugins
  function dispatchEvent(event: PluginEvent): void {
    plugins.value.forEach((instance) => {
      if (!instance.registration.enabled) return

      // Call subscribed handlers
      const handlers = instance.subscriptions.get(event.type)
      if (handlers) {
        handlers.forEach((handler) => {
          try {
            // Wrap in timeout to prevent blocking
            setTimeout(() => {
              try {
                handler(event)
              } catch (e) {
                console.error(`[PluginManager] Event handler error in ${instance.plugin.name}:`, e)
              }
            }, 0)
          } catch (e) {
            console.error(`[PluginManager] Failed to dispatch to ${instance.plugin.name}:`, e)
          }
        })
      }

      // Call general event handler
      if (instance.plugin.onEvent) {
        try {
          setTimeout(() => {
            try {
              instance.plugin.onEvent!(event)
            } catch (e) {
              console.error(`[PluginManager] onEvent error in ${instance.plugin.name}:`, e)
            }
          }, 0)
        } catch (e) {
          console.error(`[PluginManager] Failed to call onEvent for ${instance.plugin.name}:`, e)
        }
      }
    })
  }

  // Render plugin to container
  function renderPlugin(pluginId: string, container: HTMLElement): boolean {
    const instance = plugins.value.get(pluginId)
    if (!instance || !instance.plugin.render) return false

    try {
      instance.container = container
      instance.plugin.render(container, instance.context.state)
      return true
    } catch (e) {
      console.error(`[PluginManager] Render error for ${instance.plugin.name}:`, e)
      return false
    }
  }

  // Set data providers (called by App.vue)
  function setDataProviders(providers: DataProviders): void {
    dataProviders = providers
  }

  // Get all registered plugins
  function getPlugins(): PluginRegistration[] {
    return Array.from(plugins.value.values()).map(i => i.registration)
  }

  // Get plugin by ID
  function getPlugin(pluginId: string): PluginRegistration | null {
    return plugins.value.get(pluginId)?.registration || null
  }

  // Save enabled plugins to localStorage
  function saveEnabledPlugins(): void {
    try {
      localStorage.setItem(ENABLED_PLUGINS_KEY, JSON.stringify([...enabledPlugins.value]))
    } catch (e) {
      console.warn('[PluginManager] Failed to save enabled plugins')
    }
  }

  // Load enabled plugins from localStorage
  function loadEnabledPlugins(): string[] {
    try {
      const stored = localStorage.getItem(ENABLED_PLUGINS_KEY)
      if (stored) {
        return JSON.parse(stored)
      }
    } catch (e) {
      console.warn('[PluginManager] Failed to load enabled plugins')
    }
    return []
  }

  // Validate plugin before registration
  function validatePlugin(plugin: WarpPlugin, permissions: PluginPermission[]): PluginValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    // Check required fields
    if (!plugin.name) errors.push('Plugin must have a name')
    if (!plugin.version) errors.push('Plugin must have a version')
    if (!plugin.init) errors.push('Plugin must implement init()')
    if (!plugin.destroy) errors.push('Plugin must implement destroy()')

    // Check API version
    const apiVersion = plugin.apiVersion || '1.0'
    const apiVersionSupported = SUPPORTED_API_VERSIONS.includes(apiVersion as typeof SUPPORTED_API_VERSIONS[number])
    if (!apiVersionSupported) {
      errors.push(`Unsupported API version: ${apiVersion}. Supported: ${SUPPORTED_API_VERSIONS.join(', ')}`)
    }

    // Warn about deprecated API version
    if (apiVersion === '1.0') {
      warnings.push('API version 1.0 is deprecated. Please update to 1.1 for new lifecycle hooks.')
    }

    // Validate permissions
    const validPermissions: PluginPermission[] = [
      'read-output', 'read-session', 'read-commands', 'write-clipboard', 'render-panel'
    ]
    const permissionsAllowed = permissions.every(p => validPermissions.includes(p))
    if (!permissionsAllowed) {
      const invalid = permissions.filter(p => !validPermissions.includes(p))
      errors.push(`Invalid permissions: ${invalid.join(', ')}`)
    }

    // Security warnings
    if (permissions.includes('write-clipboard')) {
      warnings.push('Plugin requests clipboard access - user confirmation required')
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      apiVersionSupported,
      permissionsAllowed
    }
  }

  // Notify terminal ready to all plugins
  function notifyTerminalReady(paneId: string): void {
    plugins.value.forEach((instance) => {
      if (!instance.registration.enabled) return
      if (instance.plugin.onTerminalReady) {
        try {
          instance.plugin.onTerminalReady(paneId)
        } catch (e) {
          const error: PluginError = {
            code: 'TERMINAL_READY_ERROR',
            message: `Error in onTerminalReady: ${e}`,
            context: `paneId: ${paneId}`,
            timestamp: Date.now()
          }
          instance.plugin.onError?.(error)
          addDevLog(instance.id, instance.plugin.name, 'error', error.message)
        }
      }
    })
  }

  // Clear dev logs
  function clearDevLogs(): void {
    devLogs.value = []
  }

  // Clear permission grants
  function clearPermissionGrants(): void {
    permissionGrants.value = []
  }

  // Get logs for a specific plugin
  function getPluginLogs(pluginId: string): PluginDevLogEntry[] {
    return devLogs.value.filter(log => log.pluginId === pluginId)
  }

  return {
    // State
    plugins: computed(() => Array.from(plugins.value.values()).map(i => i.registration)),
    enabledPlugins: computed(() => enabledPlugins.value),

    // Dev Console state
    devLogs: computed(() => devLogs.value),
    permissionGrants: computed(() => permissionGrants.value),

    // Registration
    registerPlugin,
    unregisterPlugin,
    setPluginEnabled,
    validatePlugin,

    // Events
    dispatchEvent,
    notifyTerminalReady,

    // Rendering
    renderPlugin,

    // Data providers
    setDataProviders,

    // Dev Console
    clearDevLogs,
    clearPermissionGrants,
    getPluginLogs,

    // Queries
    getPlugins,
    getPlugin,
  }
}

// Singleton export for global access
export const pluginManager = usePluginManager()
