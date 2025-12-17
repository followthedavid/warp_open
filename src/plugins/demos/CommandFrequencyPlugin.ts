/**
 * Command Frequency Tracker Plugin
 *
 * Demo plugin that tracks command usage frequency.
 * Shows most-used commands in a side panel.
 */

import type {
  WarpPlugin,
  PluginContext,
  PluginState,
  PluginEvent,
} from '../types'
import { sanitizePluginHtml } from '../../utils/sanitize'

interface CommandStats {
  command: string
  count: number
  lastUsed: number
}

export const CommandFrequencyPlugin: WarpPlugin = {
  name: 'Command Frequency Tracker',
  version: '1.0.0',

  init(context: PluginContext): void {
    context.log.info('Initializing Command Frequency Tracker')

    // Subscribe to command events
    context.subscribe('command', (event: PluginEvent) => {
      if (event.data.type !== 'command') return

      const command = event.data.command.trim()
      if (!command) return

      // Get base command (first word)
      const baseCommand = command.split(/\s+/)[0]

      // Update stats
      const stats = context.state.get<Record<string, CommandStats>>('commandStats') || {}

      if (!stats[baseCommand]) {
        stats[baseCommand] = { command: baseCommand, count: 0, lastUsed: 0 }
      }

      stats[baseCommand].count++
      stats[baseCommand].lastUsed = Date.now()

      context.state.set('commandStats', stats)
      context.log.debug(`Command tracked: ${baseCommand} (${stats[baseCommand].count} uses)`)
    })
  },

  render(container: HTMLElement, state: PluginState): void {
    const stats = state.get<Record<string, CommandStats>>('commandStats') || {}

    // Sort by count
    const sorted = Object.values(stats)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)

    // Render HTML with sanitization for XSS protection
    container.innerHTML = sanitizePluginHtml(`
      <div style="padding: 12px; font-family: system-ui, -apple-system, sans-serif;">
        <h3 style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #fff;">
          Top Commands
        </h3>
        ${sorted.length === 0 ? `
          <p style="color: #888; font-size: 12px;">
            No commands tracked yet. Start typing to see your most-used commands.
          </p>
        ` : `
          <ul style="list-style: none; padding: 0; margin: 0;">
            ${sorted.map((s, i) => `
              <li style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 8px;
                margin-bottom: 4px;
                background: rgba(255,255,255,0.05);
                border-radius: 4px;
                font-size: 12px;
              ">
                <span style="display: flex; align-items: center; gap: 8px;">
                  <span style="
                    width: 20px;
                    height: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: ${i < 3 ? '#6366f1' : '#444'};
                    border-radius: 4px;
                    font-size: 10px;
                    font-weight: 600;
                  ">${i + 1}</span>
                  <code style="color: #4ade80;">${s.command}</code>
                </span>
                <span style="
                  background: rgba(99, 102, 241, 0.2);
                  color: #a5b4fc;
                  padding: 2px 8px;
                  border-radius: 12px;
                  font-size: 11px;
                ">${s.count}x</span>
              </li>
            `).join('')}
          </ul>
        `}
        <p style="
          margin-top: 12px;
          padding-top: 12px;
          border-top: 1px solid #333;
          font-size: 10px;
          color: #666;
        ">
          Total unique commands: ${Object.keys(stats).length}
        </p>
      </div>
    `)
  },

  onEvent(event: PluginEvent): void {
    // Optional: Handle other events
  },

  destroy(): void {
    console.log('[CommandFrequencyPlugin] Destroyed')
  },
}

export default CommandFrequencyPlugin
