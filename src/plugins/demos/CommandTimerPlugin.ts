/**
 * Command Timer Plugin
 *
 * Tracks execution time for each command.
 * Displays timing in a side panel.
 *
 * This is a reference plugin demonstrating Plugin API v2.
 */

import type {
  WarpPlugin,
  PluginContext,
  PluginState,
  PluginEvent,
  PluginKeyboardShortcut,
} from '../types'
import { sanitizePluginHtml } from '../../utils/sanitize'

interface CommandTiming {
  id: string
  command: string
  startTime: number
  endTime?: number
  duration?: number
  paneId: string
}

export const CommandTimerPlugin: WarpPlugin = {
  name: 'Command Timer',
  version: '1.0.0',
  apiVersion: '2.0',
  pluginType: 'ui',

  init(context: PluginContext): void {
    context.log.info('Initializing Command Timer')

    // Track command starts
    context.subscribe('command', (event: PluginEvent) => {
      if (event.data.type !== 'command') return

      const timings = context.state.get<CommandTiming[]>('timings') || []
      const commandData = event.data as { command: string; paneId: string }

      // Create new timing entry
      const timing: CommandTiming = {
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        command: commandData.command.trim(),
        startTime: event.timestamp,
        paneId: commandData.paneId,
      }

      // Keep last 50 timings
      const updated = [timing, ...timings].slice(0, 50)
      context.state.set('timings', updated)

      context.log.debug(`Command started: ${timing.command}`)
    })

    // Track command completions (via output containing exit code or prompt)
    context.subscribe('output', (event: PluginEvent) => {
      if (event.data.type !== 'output') return

      const timings = context.state.get<CommandTiming[]>('timings') || []
      const outputData = event.data as { paneId: string; output: string }

      // Find most recent incomplete timing for this pane
      const pendingIndex = timings.findIndex(
        t => t.paneId === outputData.paneId && !t.endTime
      )

      if (pendingIndex >= 0) {
        // Check if output looks like command completion (prompt returned)
        const output = outputData.output
        if (output.includes('$') || output.includes('%') || output.includes('>')) {
          const timing = { ...timings[pendingIndex] }
          timing.endTime = event.timestamp
          timing.duration = timing.endTime - timing.startTime

          const updated = [...timings]
          updated[pendingIndex] = timing
          context.state.set('timings', updated)

          context.log.debug(`Command completed: ${timing.command} (${timing.duration}ms)`)
        }
      }
    })
  },

  getKeyboardShortcuts(): PluginKeyboardShortcut[] {
    return [
      {
        id: 'clear-timings',
        key: 'ctrl+shift+t',
        label: 'Clear Timings',
        description: 'Clear all command timing history',
        action: () => {
          // This would need context access - simplified for demo
          console.log('[CommandTimerPlugin] Clear timings triggered')
        },
      },
    ]
  },

  render(container: HTMLElement, state: PluginState): void {
    const timings = state.get<CommandTiming[]>('timings') || []
    const completed = timings.filter(t => t.duration !== undefined)
    const pending = timings.filter(t => t.duration === undefined)

    // Calculate stats
    const avgDuration = completed.length > 0
      ? Math.round(completed.reduce((sum, t) => sum + (t.duration || 0), 0) / completed.length)
      : 0

    const slowest = completed.length > 0
      ? completed.reduce((max, t) => (t.duration || 0) > (max.duration || 0) ? t : max)
      : null

    container.innerHTML = sanitizePluginHtml(`
      <div style="padding: 12px; font-family: system-ui, -apple-system, sans-serif;">
        <h3 style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #fff;">
          Command Timer
        </h3>

        <!-- Stats -->
        <div style="
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 8px;
          margin-bottom: 16px;
        ">
          <div style="
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 6px;
            padding: 8px;
            text-align: center;
          ">
            <div style="font-size: 18px; font-weight: 600; color: #a5b4fc;">
              ${completed.length}
            </div>
            <div style="font-size: 10px; color: #888;">Completed</div>
          </div>
          <div style="
            background: rgba(52, 211, 153, 0.1);
            border: 1px solid rgba(52, 211, 153, 0.3);
            border-radius: 6px;
            padding: 8px;
            text-align: center;
          ">
            <div style="font-size: 18px; font-weight: 600; color: #6ee7b7;">
              ${formatDuration(avgDuration)}
            </div>
            <div style="font-size: 10px; color: #888;">Avg Time</div>
          </div>
        </div>

        ${pending.length > 0 ? `
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; color: #f59e0b; margin-bottom: 6px;">
              Running (${pending.length})
            </div>
            ${pending.slice(0, 3).map(t => `
              <div style="
                font-size: 11px;
                color: #888;
                padding: 4px 0;
                border-bottom: 1px solid #333;
              ">
                <code style="color: #f59e0b;">${truncate(t.command, 30)}</code>
                <span style="float: right; color: #666;">
                  ${formatDuration(Date.now() - t.startTime)}...
                </span>
              </div>
            `).join('')}
          </div>
        ` : ''}

        <!-- Recent commands -->
        <div style="font-size: 11px; color: #888; margin-bottom: 6px;">
          Recent Commands
        </div>
        ${completed.length === 0 ? `
          <p style="color: #666; font-size: 12px;">
            No commands timed yet. Run some commands to see timing data.
          </p>
        ` : `
          <div style="max-height: 200px; overflow-y: auto;">
            ${completed.slice(0, 10).map(t => `
              <div style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 6px 0;
                border-bottom: 1px solid #333;
                font-size: 11px;
              ">
                <code style="color: #4ade80; flex: 1; overflow: hidden; text-overflow: ellipsis;">
                  ${truncate(t.command, 25)}
                </code>
                <span style="
                  ${getDurationColor(t.duration || 0)}
                  padding: 2px 6px;
                  border-radius: 10px;
                  font-size: 10px;
                  margin-left: 8px;
                ">
                  ${formatDuration(t.duration || 0)}
                </span>
              </div>
            `).join('')}
          </div>
        `}

        ${slowest ? `
          <div style="
            margin-top: 12px;
            padding: 8px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 6px;
            font-size: 11px;
          ">
            <div style="color: #f87171; margin-bottom: 4px;">Slowest Command</div>
            <code style="color: #fca5a5;">${truncate(slowest.command, 35)}</code>
            <span style="float: right; color: #f87171;">
              ${formatDuration(slowest.duration || 0)}
            </span>
          </div>
        ` : ''}
      </div>
    `)
  },

  onEvent(event: PluginEvent): void {
    // Optional: Handle other events
  },

  destroy(): void {
    console.log('[CommandTimerPlugin] Destroyed')
  },
}

// Helper functions
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? text.slice(0, maxLength) + '...' : text
}

function getDurationColor(ms: number): string {
  if (ms < 100) return 'background: rgba(52, 211, 153, 0.2); color: #6ee7b7;'
  if (ms < 1000) return 'background: rgba(250, 204, 21, 0.2); color: #fde047;'
  if (ms < 5000) return 'background: rgba(251, 146, 60, 0.2); color: #fb923c;'
  return 'background: rgba(239, 68, 68, 0.2); color: #f87171;'
}

export default CommandTimerPlugin
