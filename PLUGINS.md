# Warp_Open Plugin Development Guide

This guide explains how to create plugins for Warp_Open terminal emulator.

## Overview

Warp_Open's plugin system allows you to extend the terminal with:
- **Side panels** for custom UI
- **Event subscriptions** for PTY output, commands, and session events
- **Read-only APIs** to access terminal state

Plugins run in a **sandboxed environment** with explicit permissions.

## Quick Start

### Minimal Plugin

```typescript
import type { WarpPlugin, PluginContext } from './types'

const MyPlugin: WarpPlugin = {
  name: 'my-plugin',
  version: '1.0.0',
  apiVersion: '1.1',

  init(context: PluginContext) {
    context.log.info('Plugin initialized!')
  },

  destroy() {
    // Cleanup when plugin is unloaded
  }
}

export default MyPlugin
```

### Plugin with Event Subscription

```typescript
const CommandLoggerPlugin: WarpPlugin = {
  name: 'command-logger',
  version: '1.0.0',
  apiVersion: '1.1',

  init(context) {
    // Subscribe to command events
    const unsub = context.subscribe('command', (event) => {
      if (event.data.type === 'command') {
        context.log.info(`Command executed: ${event.data.command}`)
        context.state.set('lastCommand', event.data.command)
      }
    })

    // Store unsubscribe for cleanup
    context.state.set('_unsub', unsub)
  },

  destroy() {
    // Cleanup (unsub is called automatically by manager)
  }
}
```

## Plugin Interface

```typescript
interface WarpPlugin {
  // Required metadata
  name: string
  version: string
  apiVersion?: '1.0' | '1.1'  // Default: '1.0', use '1.1' for latest

  // Required lifecycle hooks
  init(context: PluginContext): void | Promise<void>
  destroy(): void | Promise<void>

  // Optional lifecycle hooks (v1.1+)
  onActivate?(): void | Promise<void>
  onDeactivate?(): void | Promise<void>
  onTerminalReady?(paneId: string): void

  // Optional rendering
  render?(container: HTMLElement, state: PluginState): void

  // Optional event handler
  onEvent?(event: PluginEvent): void

  // Optional snapshot integration
  onSnapshotRestore?(snapshot: SnapshotMetadata): void

  // Optional error handler
  onError?(error: PluginError): void
}
```

## Plugin Context

Every plugin receives a `PluginContext` with:

### State Storage

```typescript
interface PluginState {
  get<T>(key: string): T | undefined
  set<T>(key: string, value: T): void
  delete(key: string): void
  clear(): void
  toJSON(): Record<string, unknown>
}

// Usage
context.state.set('counter', 0)
const count = context.state.get<number>('counter') ?? 0
context.state.set('counter', count + 1)
```

State is **automatically persisted** to localStorage per-plugin.

### Event Subscription

```typescript
// Subscribe to events (returns unsubscribe function)
const unsub = context.subscribe('output', (event) => {
  console.log('Output received:', event.data.output)
})

// Later: unsub()
```

### API Access

```typescript
interface PluginAPI {
  getPanes(): PaneInfo[]
  getTabs(): TabInfo[]
  getActivePane(): PaneInfo | null
  getRecentOutput(paneId: string, lines?: number): string[]
  getCommandHistory(paneId: string, limit?: number): CommandEntry[]
  getSessionMetadata(): SessionMetadata
  writeToClipboard(text: string): Promise<boolean>
  showNotification(message: string, type?: 'info' | 'success' | 'warning' | 'error'): void
}

// Usage
const panes = context.api.getPanes()
const output = context.api.getRecentOutput(panes[0].id, 100)
```

### Logging

```typescript
interface PluginLogger {
  info(message: string, ...args: unknown[]): void
  warn(message: string, ...args: unknown[]): void
  error(message: string, ...args: unknown[]): void
  debug(message: string, ...args: unknown[]): void
}

// Usage (logs appear in Plugin Dev Console)
context.log.info('Processing command', { count: 5 })
context.log.error('Failed to parse output')
```

## Permissions

Plugins must declare required permissions. Each permission grants access to specific APIs and events:

| Permission | Description | APIs | Events |
|------------|-------------|------|--------|
| `read-output` | Read PTY output | `getRecentOutput()` | `output`, `cwd-changed` |
| `read-commands` | Read command history | `getCommandHistory()` | `command` |
| `read-session` | Read session metadata | `getSessionMetadata()` | `tab-*`, `pane-focused`, `snapshot-*` |
| `write-clipboard` | Write to clipboard | `writeToClipboard()` | - |
| `render-panel` | Render side panel | - | - |

### Permission Checking

Permissions are enforced automatically:

```typescript
// If plugin lacks 'read-output' permission:
context.api.getRecentOutput(paneId)  // Returns empty array []
context.subscribe('output', handler)  // Handler never called
```

## Events

### Event Types

```typescript
type PluginEventType =
  | 'output'             // PTY output received
  | 'command'            // Command executed
  | 'tab-opened'         // New tab opened
  | 'tab-closed'         // Tab closed
  | 'pane-focused'       // Pane received focus
  | 'cwd-changed'        // Working directory changed
  | 'snapshot-saved'     // Snapshot saved
  | 'snapshot-restored'  // Snapshot restored
```

### Event Payloads

```typescript
// Output event
interface OutputEventData {
  type: 'output'
  paneId: string
  output: string
}

// Command event
interface CommandEventData {
  type: 'command'
  paneId: string
  command: string
  exitCode?: number
}

// Tab events
interface TabEventData {
  type: 'tab-opened' | 'tab-closed'
  tabId: string
  tabName: string
}

// Pane focus event
interface PaneEventData {
  type: 'pane-focused'
  paneId: string
  tabId: string
}

// CWD change event
interface CwdEventData {
  type: 'cwd-changed'
  paneId: string
  cwd: string
}
```

## Rendering Panels

Plugins can render custom UI in a side panel:

```typescript
const MyUIPlugin: WarpPlugin = {
  name: 'my-ui',
  version: '1.0.0',

  init(context) {
    context.state.set('items', [])
  },

  destroy() {},

  render(container: HTMLElement, state: PluginState) {
    const items = state.get<string[]>('items') ?? []

    container.innerHTML = `
      <div class="my-plugin-panel">
        <h3>My Plugin</h3>
        <ul>
          ${items.map(i => `<li>${i}</li>`).join('')}
        </ul>
      </div>
    `

    // Add interactivity
    const btn = document.createElement('button')
    btn.textContent = 'Add Item'
    btn.onclick = () => {
      items.push(`Item ${items.length + 1}`)
      state.set('items', items)
    }
    container.appendChild(btn)
  }
}
```

## Plugin Manifest

For external plugins, use a manifest file:

```json
{
  "apiVersion": "1.1",
  "name": "my-plugin",
  "version": "1.0.0",
  "description": "A sample plugin",
  "author": "Your Name",
  "homepage": "https://github.com/you/my-plugin",
  "permissions": ["read-output", "read-commands"],
  "main": "index.js",
  "minAppVersion": "0.1.0",
  "tags": ["utility", "logging"]
}
```

## Example: Command Frequency Plugin

A complete example that tracks command frequency:

```typescript
import type { WarpPlugin, PluginContext, PluginEvent } from './types'

interface CommandFrequency {
  command: string
  count: number
  lastUsed: number
}

const CommandFrequencyPlugin: WarpPlugin = {
  name: 'command-frequency',
  version: '1.0.0',
  apiVersion: '1.1',

  init(context: PluginContext) {
    // Initialize state
    if (!context.state.get('frequencies')) {
      context.state.set('frequencies', {})
    }

    // Subscribe to commands
    context.subscribe('command', (event) => {
      if (event.data.type !== 'command') return

      const cmd = event.data.command.split(' ')[0] // Get command name
      const frequencies = context.state.get<Record<string, CommandFrequency>>('frequencies') ?? {}

      if (!frequencies[cmd]) {
        frequencies[cmd] = { command: cmd, count: 0, lastUsed: 0 }
      }
      frequencies[cmd].count++
      frequencies[cmd].lastUsed = Date.now()

      context.state.set('frequencies', frequencies)
      context.log.debug(`Command "${cmd}" used ${frequencies[cmd].count} times`)
    })
  },

  destroy() {
    // State persists automatically
  },

  render(container: HTMLElement, state) {
    const frequencies = state.get<Record<string, CommandFrequency>>('frequencies') ?? {}
    const sorted = Object.values(frequencies).sort((a, b) => b.count - a.count)

    container.innerHTML = `
      <div style="padding: 12px; color: #e2e8f0;">
        <h4 style="margin: 0 0 12px 0;">Most Used Commands</h4>
        ${sorted.slice(0, 10).map((f, i) => `
          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155;">
            <span>${i + 1}. ${f.command}</span>
            <span style="color: #60a5fa;">${f.count}</span>
          </div>
        `).join('')}
        ${sorted.length === 0 ? '<p style="color: #64748b;">No commands tracked yet</p>' : ''}
      </div>
    `
  }
}

export default CommandFrequencyPlugin
```

## Security Model

### What Plugins CAN Do

- Read PTY output (with permission)
- Read command history (with permission)
- Read session metadata (with permission)
- Write to clipboard (with permission + user confirmation)
- Render custom UI in side panel
- Store persistent state in localStorage

### What Plugins CANNOT Do

- Write to PTY (send input to terminal)
- Access environment variables
- Modify terminal layouts
- Override security settings
- Access filesystem directly
- Make network requests (future: may add with permission)
- Execute system commands

### Isolation

- Each plugin gets **isolated state storage**
- State is keyed by plugin ID
- Plugins cannot access other plugins' state
- Events are delivered asynchronously (non-blocking)
- Errors in one plugin don't affect others

## Plugin Developer Console

Access the Plugin Developer Console (Cmd+Shift+D) to:

1. **View Logs** - See all plugin log output with filtering
2. **View Permissions** - Track permission grants/denials
3. **Monitor Plugins** - See loaded plugins and their status

## API Version History

### v1.1 (Current)

- Added lifecycle hooks: `onActivate`, `onDeactivate`, `onTerminalReady`
- Added `onError` handler for graceful error handling
- Added plugin validation before registration
- Added Plugin Developer Console integration

### v1.0 (Deprecated)

- Basic `init` and `destroy` hooks
- Event subscription system
- State storage and API access

## Registering Plugins

Currently, plugins are registered programmatically:

```typescript
import { pluginManager } from './plugins/PluginManager'
import MyPlugin from './MyPlugin'

// Register with permissions
const registration = await pluginManager.registerPlugin(
  MyPlugin,
  ['read-output', 'read-commands', 'render-panel']
)

if (registration) {
  console.log('Plugin loaded:', registration.id)
}

// Later: unregister
await pluginManager.unregisterPlugin(registration.id)
```

## Best Practices

1. **Minimal Permissions** - Only request permissions you need
2. **Async Operations** - Keep event handlers fast; defer heavy work
3. **Error Handling** - Implement `onError` for graceful degradation
4. **State Cleanup** - Clear temporary state in `destroy()`
5. **Versioning** - Use semver for plugin versions
6. **Logging** - Use `context.log` for debugging (appears in Dev Console)
7. **Accessibility** - Ensure rendered panels are keyboard-navigable

## Troubleshooting

### Plugin not receiving events

- Check if required permission is declared
- Verify event type matches subscription
- Check Plugin Developer Console for errors

### State not persisting

- Ensure state keys are strings
- Values must be JSON-serializable
- Check localStorage quota

### Render not updating

- Call `render()` again after state changes
- Store render container reference if needed
