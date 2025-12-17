# Plugin Development Guide

Learn how to build plugins for Warp_Open using Plugin API v2.

## Table of Contents

1. [Introduction](#introduction)
2. [Plugin Architecture](#plugin-architecture)
3. [Quick Start](#quick-start)
4. [Plugin API Reference](#plugin-api-reference)
5. [Building Your First Plugin](#building-your-first-plugin)
6. [Advanced Features](#advanced-features)
7. [Testing & Debugging](#testing--debugging)
8. [Publishing](#publishing)
9. [Best Practices](#best-practices)

---

## Introduction

### What are Plugins?

Plugins extend Warp_Open's functionality. They can:

- **React to events** – Command execution, output, directory changes
- **Render UI** – Side panels, toolbar buttons, overlays
- **Provide shortcuts** – Custom keyboard shortcuts
- **Run background tasks** – Polling, monitoring, syncing

### Plugin Types

| Type | Description | Example |
|------|-------------|---------|
| **UI** | Renders in side panel | Command Timer |
| **Background** | Runs without UI | Auto-save |
| **Hybrid** | Both UI and background | Git Insights |

---

## Plugin Architecture

### File Structure

```
my-plugin/
├── index.ts          # Main plugin entry
├── package.json      # Plugin metadata
├── README.md         # Documentation
└── assets/           # Icons, images (optional)
```

### Plugin Lifecycle

```
1. init()      → Plugin loaded, subscribe to events
2. render()    → UI rendered (if UI/hybrid type)
3. onEvent()   → Events received
4. destroy()   → Plugin unloaded, cleanup
```

### Permissions

Plugins declare required permissions:

| Permission | Description |
|------------|-------------|
| `read-output` | Read command output |
| `read-commands` | Read executed commands |
| `read-session` | Access session data |
| `write-clipboard` | Write to clipboard |
| `render-panel` | Render side panel |
| `keyboard-shortcuts` | Register shortcuts |
| `toolbar-buttons` | Add toolbar buttons |
| `network-access` | Make HTTP requests |
| `read-files` | Read filesystem |

---

## Quick Start

### Minimal Plugin

```typescript
import type { WarpPlugin, PluginContext } from '../types'

export const MyPlugin: WarpPlugin = {
  name: 'My Plugin',
  version: '1.0.0',
  apiVersion: '2.0',
  pluginType: 'ui',

  init(context: PluginContext): void {
    context.log.info('Plugin initialized!')

    // Subscribe to commands
    context.subscribe('command', (event) => {
      context.log.debug(`Command: ${event.data.command}`)
    })
  },

  render(container: HTMLElement, state: PluginState): void {
    container.innerHTML = '<div>Hello from My Plugin!</div>'
  },

  destroy(): void {
    console.log('Plugin destroyed')
  }
}

export default MyPlugin
```

### Register the Plugin

Add to `src/plugins/index.ts`:

```typescript
import { MyPlugin } from './my-plugin'

export const plugins = [
  // ... other plugins
  MyPlugin,
]
```

---

## Plugin API Reference

### WarpPlugin Interface

```typescript
interface WarpPlugin {
  // Required
  name: string
  version: string
  apiVersion: '2.0'
  pluginType: 'ui' | 'background' | 'hybrid'

  // Lifecycle
  init(context: PluginContext): void
  destroy(): void

  // UI (optional)
  render?(container: HTMLElement, state: PluginState): void

  // Events (optional)
  onEvent?(event: PluginEvent): void

  // Extensions (optional)
  getToolbarButtons?(): PluginToolbarButton[]
  getKeyboardShortcuts?(): PluginKeyboardShortcut[]
}
```

### PluginContext

```typescript
interface PluginContext {
  // Logging
  log: {
    info(msg: string): void
    warn(msg: string): void
    error(msg: string): void
    debug(msg: string): void
  }

  // State management
  state: PluginState

  // Event subscription
  subscribe(event: string, handler: Function): void
  unsubscribe(event: string, handler: Function): void

  // Emit events
  emit(event: string, data: any): void
}
```

### PluginState

```typescript
interface PluginState {
  get<T>(key: string): T | undefined
  set(key: string, value: any): void
  delete(key: string): void
  clear(): void
}
```

### Event Types

```typescript
type PluginEventType =
  | 'command'      // Command executed
  | 'output'       // Command output received
  | 'cwd-changed'  // Directory changed
  | 'tab-changed'  // Active tab changed
  | 'session-start'
  | 'session-end'
```

### PluginEvent

```typescript
interface PluginEvent {
  type: PluginEventType
  timestamp: number
  data: {
    type: string
    command?: string
    output?: string
    paneId?: string
    // ... event-specific data
  }
}
```

---

## Building Your First Plugin

Let's build a **Command Counter** plugin that tracks how many commands you've run.

### Step 1: Create the Plugin File

Create `src/plugins/demos/CommandCounterPlugin.ts`:

```typescript
import type {
  WarpPlugin,
  PluginContext,
  PluginState,
  PluginEvent,
} from '../types'
import { sanitizePluginHtml } from '../../utils/sanitize'

export const CommandCounterPlugin: WarpPlugin = {
  name: 'Command Counter',
  version: '1.0.0',
  apiVersion: '2.0',
  pluginType: 'ui',

  init(context: PluginContext): void {
    context.log.info('Command Counter initialized')

    // Initialize state
    context.state.set('count', 0)
    context.state.set('commands', [])

    // Subscribe to command events
    context.subscribe('command', (event: PluginEvent) => {
      if (event.data.type !== 'command') return

      const count = context.state.get<number>('count') || 0
      const commands = context.state.get<string[]>('commands') || []

      // Update count
      context.state.set('count', count + 1)

      // Store last 10 commands
      const cmd = (event.data as { command: string }).command
      context.state.set('commands', [cmd, ...commands].slice(0, 10))

      context.log.debug(`Command #${count + 1}: ${cmd}`)
    })
  },

  render(container: HTMLElement, state: PluginState): void {
    const count = state.get<number>('count') || 0
    const commands = state.get<string[]>('commands') || []

    container.innerHTML = sanitizePluginHtml(`
      <div style="padding: 12px; font-family: system-ui;">
        <h3 style="margin: 0 0 12px; color: #fff;">
          Command Counter
        </h3>

        <div style="
          font-size: 48px;
          font-weight: bold;
          color: #4ade80;
          text-align: center;
          padding: 20px;
        ">
          ${count}
        </div>

        <div style="font-size: 12px; color: #888; text-align: center;">
          commands executed
        </div>

        ${commands.length > 0 ? `
          <div style="margin-top: 16px;">
            <div style="font-size: 11px; color: #666; margin-bottom: 8px;">
              Recent:
            </div>
            ${commands.slice(0, 5).map(cmd => `
              <div style="
                font-size: 11px;
                color: #888;
                padding: 4px 0;
                border-bottom: 1px solid #333;
                overflow: hidden;
                text-overflow: ellipsis;
              ">
                <code>${cmd.slice(0, 30)}${cmd.length > 30 ? '...' : ''}</code>
              </div>
            `).join('')}
          </div>
        ` : ''}
      </div>
    `)
  },

  destroy(): void {
    console.log('[CommandCounter] Destroyed')
  },
}

export default CommandCounterPlugin
```

### Step 2: Register the Plugin

Edit `src/plugins/demos/index.ts`:

```typescript
export { CommandCounterPlugin } from './CommandCounterPlugin'
```

### Step 3: Test It

```bash
npm run tauri:dev
```

Run some commands and watch the counter update!

---

## Advanced Features

### Toolbar Buttons

```typescript
getToolbarButtons(): PluginToolbarButton[] {
  return [
    {
      id: 'my-button',
      icon: '🔔',
      label: 'Notify',
      tooltip: 'Send a notification',
      position: 'right',
      action: () => {
        console.log('Button clicked!')
      },
    },
  ]
}
```

### Keyboard Shortcuts

```typescript
getKeyboardShortcuts(): PluginKeyboardShortcut[] {
  return [
    {
      id: 'my-shortcut',
      key: 'ctrl+shift+m',
      label: 'My Action',
      description: 'Does something cool',
      action: () => {
        console.log('Shortcut triggered!')
      },
    },
  ]
}
```

### Background Workers (Hybrid plugins)

```typescript
// In init():
if (context.worker) {
  context.worker.postMessage({ type: 'start-polling' })

  context.worker.onMessage((msg) => {
    if (msg.type === 'poll-result') {
      context.state.set('data', msg.data)
    }
  })
}
```

### Resource Limits

```typescript
const MyPlugin: WarpPlugin = {
  // ...
  resourceLimits: {
    maxMemoryMB: 50,
    maxCPUPercent: 10,
    executionTimeoutMs: 5000,
    maxEventsPerSecond: 100,
  },
}
```

---

## Testing & Debugging

### Enable Debug Logging

```typescript
context.log.debug('Debug message')  // Only shown in dev mode
```

### Plugin Dev Console

Open the Plugin Dev Console from Settings > Plugins > Dev Console to:
- View plugin logs
- Inspect plugin state
- Trigger events manually
- Hot reload plugins

### Testing Commands

```typescript
// In your test file
import { CommandCounterPlugin } from './CommandCounterPlugin'

describe('CommandCounterPlugin', () => {
  it('initializes with zero count', () => {
    const mockContext = createMockContext()
    CommandCounterPlugin.init(mockContext)

    expect(mockContext.state.get('count')).toBe(0)
  })
})
```

---

## Publishing

### Package Your Plugin

1. Create `package.json`:

```json
{
  "name": "warp-plugin-my-plugin",
  "version": "1.0.0",
  "description": "My awesome Warp_Open plugin",
  "main": "index.ts",
  "keywords": ["warp-open", "plugin"],
  "author": "Your Name",
  "license": "MIT",
  "peerDependencies": {
    "warp-open": "^1.0.0"
  }
}
```

2. Create `README.md` with:
   - What it does
   - Installation instructions
   - Configuration options
   - Screenshots

### Share on GitHub

1. Create a repository named `warp-plugin-<name>`
2. Add the `warp-open-plugin` topic
3. Submit to the community plugins list

---

## Best Practices

### Performance

- **Debounce** frequent events
- **Limit** stored data (e.g., last 50 items)
- **Lazy load** heavy components
- **Clean up** in `destroy()`

### Security

- **Always sanitize** HTML with `sanitizePluginHtml()`
- **Never** store secrets in state
- **Validate** all input
- **Request minimal** permissions

### UX

- **Respect** the dark theme
- **Use consistent** styling
- **Provide feedback** for actions
- **Don't block** the main thread

### Code Style

```typescript
// Good: Descriptive names
const commandHistory = state.get<string[]>('commandHistory')

// Bad: Cryptic names
const ch = state.get<string[]>('ch')

// Good: Handle missing state
const count = state.get<number>('count') ?? 0

// Bad: Assume state exists
const count = state.get<number>('count')!
```

---

## Example Plugins

Study these official plugins for patterns:

| Plugin | Demonstrates |
|--------|--------------|
| **Git Insights** | Hybrid type, polling, toolbar buttons |
| **Command Linter** | Pattern matching, warnings, UI |
| **Session Annotator** | State management, export |
| **Command Timer** | Event handling, stats |

Source: `src/plugins/official/` and `src/plugins/demos/`

---

## Need Help?

- **GitHub Issues** – Report bugs or request features
- **Discussions** – Ask questions
- **Plugin Ideas** – See what others want built

Happy plugin building!
