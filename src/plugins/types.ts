/**
 * Warp Plugin System - Type Definitions
 *
 * Plugins can:
 * - Render side panels
 * - Subscribe to read-only PTY output events
 * - Access read-only session metadata
 *
 * Plugins CANNOT:
 * - Write to PTY (send input)
 * - Access environment variables
 * - Modify terminal layouts
 * - Override security settings
 */

// Plugin metadata with versioning
export interface PluginManifest {
  // API version for compatibility checking
  apiVersion: '1.0' | '1.1' | '2.0'

  // Plugin identity
  name: string
  version: string
  description?: string
  author?: string
  homepage?: string
  icon?: string

  // Required permissions
  permissions: PluginPermission[]

  // Entry point (relative to plugin directory)
  main?: string

  // Minimum app version required
  minAppVersion?: string

  // Tags for categorization
  tags?: string[]

  // v2.0: Plugin type
  pluginType?: 'ui' | 'background' | 'hybrid'

  // v2.0: Resource limits
  resourceLimits?: PluginResourceLimits
}

// API version compatibility
export const CURRENT_API_VERSION = '2.0'
export const SUPPORTED_API_VERSIONS = ['1.0', '1.1', '2.0'] as const

// Available permissions
export type PluginPermission =
  | 'read-output'        // Read PTY output events
  | 'read-session'       // Read session/snapshot metadata
  | 'read-commands'      // Read command history
  | 'write-clipboard'    // Write to clipboard (user must confirm)
  | 'render-panel'       // Render a side panel
  // v2.0 permissions
  | 'read-files'         // Read files (scoped, requires prompt)
  | 'network-access'     // Access network (requires prompt)
  | 'keyboard-shortcuts' // Register custom keyboard shortcuts
  | 'toolbar-buttons'    // Add custom toolbar buttons
  | 'theme-customization' // Customize theme colors

// v2.0: Resource limits for plugins
export interface PluginResourceLimits {
  maxMemoryMB?: number       // Max memory usage in MB
  maxCPUPercent?: number     // Max CPU usage percentage
  executionTimeoutMs?: number // Max execution time per operation
  maxEventsPerSecond?: number // Rate limit for event handling
}

// Plugin lifecycle interface
export interface WarpPlugin {
  // Metadata
  name: string
  version: string
  apiVersion?: '1.0' | '1.1' | '2.0'  // Plugin API version
  pluginType?: 'ui' | 'background' | 'hybrid'  // v2.0

  // Core lifecycle hooks
  init(context: PluginContext): void | Promise<void>
  destroy(): void | Promise<void>

  // Extended lifecycle hooks (v1.1+)
  onActivate?(): void | Promise<void>        // Called when plugin is enabled
  onDeactivate?(): void | Promise<void>      // Called when plugin is disabled
  onTerminalReady?(paneId: string): void     // Called when terminal pane is ready

  // Optional: Render a panel component
  render?(container: HTMLElement, state: PluginState): void

  // Optional: Handle events
  onEvent?(event: PluginEvent): void

  // Optional: Called when snapshot is restored
  onSnapshotRestore?(snapshot: SnapshotMetadata): void

  // Optional: Handle errors gracefully
  onError?(error: PluginError): void

  // v2.0: Register keyboard shortcuts
  getKeyboardShortcuts?(): PluginKeyboardShortcut[]

  // v2.0: Register toolbar buttons
  getToolbarButtons?(): PluginToolbarButton[]

  // v2.0: Called when hot reload is triggered
  onHotReload?(newContext: PluginContext): void | Promise<void>

  // v2.0: Background task (for background/hybrid plugins)
  runBackground?(context: PluginContext): void | Promise<void>

  // v2.0: Replay events for determinism
  replayEvents?(events: PluginEvent[]): void | Promise<void>
}

// Plugin error type
export interface PluginError {
  code: string
  message: string
  context?: string
  timestamp: number
}

// Context provided to plugins
export interface PluginContext {
  // Plugin's isolated state
  state: PluginState

  // Event subscription
  subscribe(eventType: PluginEventType, handler: EventHandler): () => void

  // Read-only APIs
  api: PluginAPI

  // Logging
  log: PluginLogger
}

// Plugin's isolated state storage
export interface PluginState {
  get<T>(key: string): T | undefined
  set<T>(key: string, value: T): void
  delete(key: string): void
  clear(): void
  toJSON(): Record<string, unknown>
}

// Read-only API available to plugins
export interface PluginAPI {
  // Get list of active panes
  getPanes(): PaneInfo[]

  // Get list of tabs
  getTabs(): TabInfo[]

  // Get current active pane
  getActivePane(): PaneInfo | null

  // Get recent output for a pane (last N lines)
  getRecentOutput(paneId: string, lines?: number): string[]

  // Get command history for a pane
  getCommandHistory(paneId: string, limit?: number): CommandEntry[]

  // Get session metadata (no sensitive data)
  getSessionMetadata(): SessionMetadata

  // Write to clipboard (requires permission, user confirmation)
  writeToClipboard(text: string): Promise<boolean>

  // Show notification
  showNotification(message: string, type?: 'info' | 'success' | 'warning' | 'error'): void
}

// Event types plugins can subscribe to
export type PluginEventType =
  | 'output'           // PTY output received
  | 'command'          // Command executed
  | 'tab-opened'       // New tab opened
  | 'tab-closed'       // Tab closed
  | 'pane-focused'     // Pane received focus
  | 'cwd-changed'      // Working directory changed
  | 'snapshot-saved'   // Snapshot saved
  | 'snapshot-restored' // Snapshot restored

// Event payload
export interface PluginEvent {
  type: PluginEventType
  timestamp: number
  data: PluginEventData
}

// Event data by type
export type PluginEventData =
  | OutputEventData
  | CommandEventData
  | TabEventData
  | PaneEventData
  | CwdEventData
  | SnapshotEventData

export interface OutputEventData {
  type: 'output'
  paneId: string
  output: string
}

export interface CommandEventData {
  type: 'command'
  paneId: string
  command: string
  exitCode?: number
}

export interface TabEventData {
  type: 'tab-opened' | 'tab-closed'
  tabId: string
  tabName: string
}

export interface PaneEventData {
  type: 'pane-focused'
  paneId: string
  tabId: string
}

export interface CwdEventData {
  type: 'cwd-changed'
  paneId: string
  cwd: string
}

export interface SnapshotEventData {
  type: 'snapshot-saved' | 'snapshot-restored'
  snapshotId: string
  snapshotName: string
}

// Event handler type
export type EventHandler = (event: PluginEvent) => void

// Pane info (read-only)
export interface PaneInfo {
  id: string
  tabId: string
  ptyId: number
  cwd?: string
  isActive: boolean
}

// Tab info (read-only)
export interface TabInfo {
  id: string
  name: string
  kind: string
  paneCount: number
  isActive: boolean
}

// Command history entry
export interface CommandEntry {
  command: string
  timestamp: number
  exitCode?: number
  cwd?: string
}

// Session metadata (safe to expose)
export interface SessionMetadata {
  tabCount: number
  paneCount: number
  snapshotCount: number
  uptime: number
}

// Snapshot metadata (read-only)
export interface SnapshotMetadata {
  id: string
  name: string
  timestamp: number
  tabCount: number
  description?: string
}

// Plugin logger (sandboxed)
export interface PluginLogger {
  info(message: string, ...args: unknown[]): void
  warn(message: string, ...args: unknown[]): void
  error(message: string, ...args: unknown[]): void
  debug(message: string, ...args: unknown[]): void
}

// Plugin registration result
export interface PluginRegistration {
  id: string
  name: string
  version: string
  enabled: boolean
  permissions: PluginPermission[]
  loadedAt: number
}

// Plugin manager events
export type PluginManagerEvent =
  | { type: 'plugin-loaded'; plugin: PluginRegistration }
  | { type: 'plugin-unloaded'; pluginId: string }
  | { type: 'plugin-error'; pluginId: string; error: string }

// Dev Console types
export interface PluginDevLogEntry {
  id: string
  pluginId: string
  pluginName: string
  level: 'info' | 'warn' | 'error' | 'debug'
  message: string
  args?: unknown[]
  timestamp: number
}

export interface PluginPermissionGrant {
  pluginId: string
  pluginName: string
  permission: PluginPermission
  granted: boolean
  timestamp: number
  reason?: string
}

export interface PluginValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
  apiVersionSupported: boolean
  permissionsAllowed: boolean
}

// ============================================================================
// v2.0 Plugin API Extensions
// ============================================================================

// v2.0: Keyboard shortcut registration
export interface PluginKeyboardShortcut {
  id: string
  key: string                    // e.g., "ctrl+shift+p"
  label: string                  // Display label
  description?: string
  action: () => void | Promise<void>
  when?: 'always' | 'terminal-focused' | 'panel-open'
}

// v2.0: Toolbar button registration
export interface PluginToolbarButton {
  id: string
  icon: string                   // Icon name or SVG
  label: string
  tooltip?: string
  position?: 'left' | 'right'
  action: () => void | Promise<void>
  getState?: () => 'active' | 'inactive' | 'disabled'
}

// v2.0: Permission request dialog
export interface PluginPermissionRequest {
  pluginId: string
  pluginName: string
  permission: PluginPermission
  reason?: string                // Why the plugin needs this
  scope?: string                 // e.g., file path pattern for read-files
}

export interface PluginPermissionResponse {
  granted: boolean
  remember?: boolean             // Remember this choice
  expiresAt?: number            // When permission expires
}

// v2.0: Runtime permission API
export interface PluginPermissionAPI {
  // Request a permission at runtime (shows prompt to user)
  request(permission: PluginPermission, reason?: string): Promise<boolean>

  // Check if permission is currently granted
  hasPermission(permission: PluginPermission): boolean

  // Revoke a previously granted permission
  revoke(permission: PluginPermission): void

  // List all granted permissions
  listGranted(): PluginPermission[]
}

// v2.0: Extended context for v2 plugins
export interface PluginContextV2 extends PluginContext {
  // Runtime permission requests
  permissions: PluginPermissionAPI

  // Event recording for replay
  events: PluginEventRecorder

  // Hot reload support
  hotReload: PluginHotReloadAPI

  // Background worker API (for background plugins)
  worker?: PluginWorkerAPI
}

// v2.0: Event recording for deterministic replay
export interface PluginEventRecorder {
  // Record an event
  record(event: PluginEvent): void

  // Get all recorded events
  getRecorded(): PluginEvent[]

  // Clear recorded events
  clear(): void

  // Export events for replay
  export(): string  // JSON

  // Import events for replay
  import(json: string): PluginEvent[]
}

// v2.0: Hot reload API
export interface PluginHotReloadAPI {
  // Register for hot reload notifications
  onReload(callback: () => void): () => void

  // Manually trigger reload (for development)
  triggerReload(): void

  // Get current reload count
  getReloadCount(): number

  // Check if hot reload is enabled
  isEnabled(): boolean
}

// v2.0: Background worker API
export interface PluginWorkerAPI {
  // Post message to background worker
  postMessage(message: unknown): void

  // Receive message from background worker
  onMessage(callback: (message: unknown) => void): () => void

  // Terminate background worker
  terminate(): void

  // Check if worker is running
  isRunning(): boolean
}

// v2.0: Plugin dev tools
export interface PluginDevTools {
  // Open dev console for this plugin
  openConsole(): void

  // Log to dev console
  log(level: 'info' | 'warn' | 'error' | 'debug', message: string, ...args: unknown[]): void

  // Inspect state
  inspectState(): Record<string, unknown>

  // Performance profiling
  startProfile(label: string): void
  stopProfile(label: string): ProfileResult

  // Simulate events for testing
  simulateEvent(event: PluginEvent): void
}

export interface ProfileResult {
  label: string
  duration: number
  memoryDelta?: number
}

// v2.0: Plugin manager events extended
export type PluginManagerEventV2 =
  | { type: 'plugin-loaded'; plugin: PluginRegistration }
  | { type: 'plugin-unloaded'; pluginId: string }
  | { type: 'plugin-error'; pluginId: string; error: string }
  | { type: 'plugin-hot-reloaded'; pluginId: string }
  | { type: 'permission-requested'; request: PluginPermissionRequest }
  | { type: 'permission-granted'; pluginId: string; permission: PluginPermission }
  | { type: 'permission-denied'; pluginId: string; permission: PluginPermission }
  | { type: 'background-started'; pluginId: string }
  | { type: 'background-stopped'; pluginId: string }
