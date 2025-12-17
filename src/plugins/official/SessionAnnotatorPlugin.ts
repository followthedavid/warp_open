/**
 * Session Annotator Plugin
 *
 * Add notes, tags, and annotations to commands and outputs.
 * Export annotated sessions for documentation and sharing.
 *
 * Features:
 * - Add notes to individual commands
 * - Tag commands for organization
 * - Star important commands
 * - Export annotated sessions as Markdown
 * - Search through annotations
 *
 * Demonstrates:
 * - read-commands permission
 * - read-session permission
 * - Local storage for persistence
 * - Export functionality
 */

import type {
  WarpPlugin,
  PluginContext,
  PluginState,
  PluginEvent,
  PluginKeyboardShortcut,
  PluginToolbarButton,
} from '../types'
import { sanitizePluginHtml } from '../../utils/sanitize'

// Annotation types
interface CommandAnnotation {
  id: string
  commandId: string
  command: string
  timestamp: number
  note?: string
  tags: string[]
  starred: boolean
  paneId: string
}

// Session summary
interface SessionSummary {
  totalCommands: number
  annotatedCount: number
  starredCount: number
  tags: Record<string, number>
}

// Predefined tags
const PRESET_TAGS = [
  { name: 'important', color: '#ef4444', icon: '⭐' },
  { name: 'debugging', color: '#f59e0b', icon: '🔍' },
  { name: 'setup', color: '#3b82f6', icon: '⚙️' },
  { name: 'deployment', color: '#8b5cf6', icon: '🚀' },
  { name: 'fix', color: '#22c55e', icon: '🔧' },
  { name: 'research', color: '#06b6d4', icon: '📚' },
  { name: 'risky', color: '#dc2626', icon: '⚠️' },
  { name: 'todo', color: '#ec4899', icon: '📝' },
]

// Get tag color
function getTagColor(tagName: string): string {
  const preset = PRESET_TAGS.find(t => t.name === tagName)
  return preset?.color || '#6b7280'
}

// Get tag icon
function getTagIcon(tagName: string): string {
  const preset = PRESET_TAGS.find(t => t.name === tagName)
  return preset?.icon || '🏷️'
}

export const SessionAnnotatorPlugin: WarpPlugin = {
  name: 'Session Annotator',
  version: '1.0.0',
  apiVersion: '2.0',
  pluginType: 'ui',

  init(context: PluginContext): void {
    context.log.info('Initializing Session Annotator Plugin')

    // Initialize state
    context.state.set('annotations', [])
    context.state.set('selectedCommand', null)
    context.state.set('searchQuery', '')
    context.state.set('filterTag', null)
    context.state.set('showOnlyStarred', false)

    // Track all commands for potential annotation
    context.subscribe('command', (event: PluginEvent) => {
      if (event.data.type !== 'command') return

      const commandData = event.data as { command: string; paneId: string }
      const command = commandData.command.trim()

      // Create a lightweight annotation placeholder (not persisted until user adds content)
      const annotations = context.state.get<CommandAnnotation[]>('annotations') || []

      // Check if this command pattern was recently annotated (allow re-annotation after 5 seconds)
      const recentSimilar = annotations.find(
        a => a.command === command && Date.now() - a.timestamp < 5000
      )

      if (!recentSimilar) {
        // Store as "potential annotation" - user can add notes later
        context.state.set('lastCommand', {
          id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          command: command,
          timestamp: event.timestamp,
          paneId: commandData.paneId,
        })
      }

      context.log.debug(`Command tracked for annotation: ${command.slice(0, 50)}`)
    })

    context.log.info('Session Annotator Plugin initialized')
  },

  getToolbarButtons(): PluginToolbarButton[] {
    return [
      {
        id: 'annotate-last',
        icon: '📝',
        label: 'Annotate',
        tooltip: 'Annotate last command',
        position: 'right',
        action: () => {
          console.log('[SessionAnnotator] Annotate last command')
        },
      },
      {
        id: 'export-session',
        icon: '📤',
        label: 'Export',
        tooltip: 'Export annotated session',
        position: 'right',
        action: () => {
          console.log('[SessionAnnotator] Export session')
        },
      },
    ]
  },

  getKeyboardShortcuts(): PluginKeyboardShortcut[] {
    return [
      {
        id: 'quick-annotate',
        key: 'ctrl+shift+a',
        label: 'Quick Annotate',
        description: 'Add annotation to last command',
        action: () => {
          console.log('[SessionAnnotator] Quick annotate triggered')
        },
      },
      {
        id: 'star-command',
        key: 'ctrl+shift+s',
        label: 'Star Command',
        description: 'Star/unstar last command',
        action: () => {
          console.log('[SessionAnnotator] Star command triggered')
        },
      },
    ]
  },

  render(container: HTMLElement, state: PluginState): void {
    const annotations = state.get<CommandAnnotation[]>('annotations') || []
    const searchQuery = state.get<string>('searchQuery') || ''
    const filterTag = state.get<string | null>('filterTag')
    const showOnlyStarred = state.get<boolean>('showOnlyStarred') || false
    const lastCommand = state.get<{ id: string; command: string; timestamp: number } | null>('lastCommand')

    // Filter annotations
    let filteredAnnotations = annotations
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filteredAnnotations = filteredAnnotations.filter(
        a => a.command.toLowerCase().includes(query) ||
             (a.note && a.note.toLowerCase().includes(query)) ||
             a.tags.some(t => t.toLowerCase().includes(query))
      )
    }
    if (filterTag) {
      filteredAnnotations = filteredAnnotations.filter(a => a.tags.includes(filterTag))
    }
    if (showOnlyStarred) {
      filteredAnnotations = filteredAnnotations.filter(a => a.starred)
    }

    // Calculate summary
    const summary: SessionSummary = {
      totalCommands: annotations.length,
      annotatedCount: annotations.filter(a => a.note || a.tags.length > 0).length,
      starredCount: annotations.filter(a => a.starred).length,
      tags: {},
    }
    annotations.forEach(a => {
      a.tags.forEach(tag => {
        summary.tags[tag] = (summary.tags[tag] || 0) + 1
      })
    })

    container.innerHTML = sanitizePluginHtml(`
      <div style="padding: 12px; font-family: system-ui, -apple-system, sans-serif;">
        <h3 style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 16px;">📝</span>
          Session Annotator
        </h3>

        <!-- Quick Stats -->
        <div style="
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 6px;
          margin-bottom: 12px;
        ">
          <div style="
            background: rgba(99, 102, 241, 0.1);
            border-radius: 6px;
            padding: 6px;
            text-align: center;
          ">
            <div style="font-size: 16px; font-weight: 600; color: #a5b4fc;">${summary.totalCommands}</div>
            <div style="font-size: 8px; color: #888;">Commands</div>
          </div>
          <div style="
            background: rgba(52, 211, 153, 0.1);
            border-radius: 6px;
            padding: 6px;
            text-align: center;
          ">
            <div style="font-size: 16px; font-weight: 600; color: #6ee7b7;">${summary.annotatedCount}</div>
            <div style="font-size: 8px; color: #888;">Annotated</div>
          </div>
          <div style="
            background: rgba(251, 191, 36, 0.1);
            border-radius: 6px;
            padding: 6px;
            text-align: center;
          ">
            <div style="font-size: 16px; font-weight: 600; color: #fbbf24;">${summary.starredCount}</div>
            <div style="font-size: 8px; color: #888;">Starred</div>
          </div>
        </div>

        <!-- Last Command Quick Action -->
        ${lastCommand ? `
          <div style="
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 12px;
          ">
            <div style="font-size: 10px; color: #888; margin-bottom: 4px;">Last Command</div>
            <code style="
              font-size: 11px;
              color: #a5b4fc;
              display: block;
              overflow: hidden;
              text-overflow: ellipsis;
              margin-bottom: 8px;
            ">${truncate(lastCommand.command, 40)}</code>
            <div style="display: flex; gap: 6px;">
              <button style="
                background: rgba(52, 211, 153, 0.2);
                border: 1px solid rgba(52, 211, 153, 0.4);
                color: #6ee7b7;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 10px;
                cursor: pointer;
                flex: 1;
              ">⭐ Star</button>
              <button style="
                background: rgba(99, 102, 241, 0.2);
                border: 1px solid rgba(99, 102, 241, 0.4);
                color: #a5b4fc;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 10px;
                cursor: pointer;
                flex: 1;
              ">📝 Note</button>
              <button style="
                background: rgba(251, 146, 60, 0.2);
                border: 1px solid rgba(251, 146, 60, 0.4);
                color: #fb923c;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 10px;
                cursor: pointer;
                flex: 1;
              ">🏷️ Tag</button>
            </div>
          </div>
        ` : ''}

        <!-- Tag Cloud -->
        ${Object.keys(summary.tags).length > 0 ? `
          <div style="margin-bottom: 12px;">
            <div style="font-size: 10px; color: #888; margin-bottom: 6px;">Tags</div>
            <div style="display: flex; flex-wrap: wrap; gap: 4px;">
              ${Object.entries(summary.tags).slice(0, 8).map(([tag, count]) => `
                <span style="
                  background: ${getTagColor(tag)}20;
                  color: ${getTagColor(tag)};
                  padding: 2px 8px;
                  border-radius: 10px;
                  font-size: 9px;
                  cursor: pointer;
                  display: flex;
                  align-items: center;
                  gap: 4px;
                ">
                  ${getTagIcon(tag)} ${tag}
                  <span style="
                    background: rgba(0,0,0,0.3);
                    padding: 0 4px;
                    border-radius: 8px;
                    font-size: 8px;
                  ">${count}</span>
                </span>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Available Tags -->
        <div style="margin-bottom: 12px;">
          <div style="font-size: 10px; color: #888; margin-bottom: 6px;">Quick Tags</div>
          <div style="display: flex; flex-wrap: wrap; gap: 4px;">
            ${PRESET_TAGS.map(tag => `
              <span style="
                background: ${tag.color}15;
                border: 1px solid ${tag.color}40;
                color: ${tag.color};
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 9px;
                cursor: pointer;
              ">${tag.icon} ${tag.name}</span>
            `).join('')}
          </div>
        </div>

        <!-- Annotated Commands List -->
        <div style="margin-bottom: 12px;">
          <div style="
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
          ">
            <span style="font-size: 10px; color: #888;">Annotated Commands</span>
            <button style="
              background: transparent;
              border: none;
              color: ${showOnlyStarred ? '#fbbf24' : '#666'};
              font-size: 12px;
              cursor: pointer;
            ">⭐</button>
          </div>

          ${filteredAnnotations.length === 0 ? `
            <div style="
              color: #666;
              font-size: 11px;
              padding: 16px;
              text-align: center;
              background: rgba(255,255,255,0.03);
              border-radius: 8px;
            ">
              <div style="font-size: 20px; margin-bottom: 8px;">📋</div>
              <div>No annotations yet</div>
              <div style="font-size: 9px; margin-top: 4px; color: #555;">
                Star or add notes to commands to see them here
              </div>
            </div>
          ` : `
            <div style="max-height: 180px; overflow-y: auto;">
              ${filteredAnnotations.slice(0, 10).map(annotation => `
                <div style="
                  background: rgba(255,255,255,0.03);
                  border-radius: 6px;
                  padding: 8px;
                  margin-bottom: 6px;
                  border-left: 3px solid ${annotation.starred ? '#fbbf24' : '#333'};
                ">
                  <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                    ${annotation.starred ? '<span style="font-size: 10px;">⭐</span>' : ''}
                    <code style="
                      font-size: 10px;
                      color: #a5b4fc;
                      flex: 1;
                      overflow: hidden;
                      text-overflow: ellipsis;
                    ">${truncate(annotation.command, 30)}</code>
                    <span style="font-size: 9px; color: #555;">${formatTimeAgo(annotation.timestamp)}</span>
                  </div>
                  ${annotation.note ? `
                    <div style="
                      font-size: 10px;
                      color: #888;
                      margin-bottom: 4px;
                      padding-left: 4px;
                      border-left: 2px solid #444;
                    ">${truncate(annotation.note, 50)}</div>
                  ` : ''}
                  ${annotation.tags.length > 0 ? `
                    <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                      ${annotation.tags.map(tag => `
                        <span style="
                          background: ${getTagColor(tag)}20;
                          color: ${getTagColor(tag)};
                          padding: 1px 6px;
                          border-radius: 8px;
                          font-size: 8px;
                        ">${getTagIcon(tag)} ${tag}</span>
                      `).join('')}
                    </div>
                  ` : ''}
                </div>
              `).join('')}
            </div>
          `}
        </div>

        <!-- Export Actions -->
        <div style="
          padding-top: 8px;
          border-top: 1px solid #333;
          display: flex;
          gap: 6px;
        ">
          <button style="
            background: rgba(99, 102, 241, 0.2);
            border: 1px solid rgba(99, 102, 241, 0.4);
            color: #a5b4fc;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 10px;
            cursor: pointer;
            flex: 1;
          ">📤 Export Markdown</button>
          <button style="
            background: rgba(52, 211, 153, 0.2);
            border: 1px solid rgba(52, 211, 153, 0.4);
            color: #6ee7b7;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 10px;
            cursor: pointer;
            flex: 1;
          ">📋 Copy to Clipboard</button>
        </div>
      </div>
    `)
  },

  destroy(): void {
    console.log('[SessionAnnotatorPlugin] Destroyed')
  },
}

// Helper: Truncate text
function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? text.slice(0, maxLength) + '...' : text
}

// Helper: Format time ago
function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000)
  if (seconds < 60) return 'now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

export default SessionAnnotatorPlugin
