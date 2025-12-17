/**
 * Git Insights Plugin
 *
 * Shows git repository status, branch info, and command insights.
 * This is the primary reference plugin for Plugin API v2.
 *
 * Features:
 * - Current branch and dirty state
 * - Ahead/behind remote tracking
 * - Recent git commands with timing
 * - Inline annotations after git operations
 *
 * Demonstrates:
 * - Hybrid plugin (UI + background)
 * - PluginWorkerAPI for git polling
 * - toolbar-buttons permission
 * - read-output for command detection
 */

import type {
  WarpPlugin,
  PluginContext,
  PluginState,
  PluginEvent,
  PluginToolbarButton,
  PluginKeyboardShortcut,
} from '../types'
import { sanitizePluginHtml } from '../../utils/sanitize'

// Git repository state
interface GitState {
  isRepo: boolean
  branch: string
  isDirty: boolean
  staged: number
  unstaged: number
  untracked: number
  ahead: number
  behind: number
  lastCommit: string
  lastCommitTime: number
  remoteUrl?: string
  lastUpdated: number
}

// Git command tracking
interface GitCommand {
  id: string
  command: string
  timestamp: number
  duration?: number
  success?: boolean
  output?: string
}

// Default empty state
const defaultGitState: GitState = {
  isRepo: false,
  branch: '',
  isDirty: false,
  staged: 0,
  unstaged: 0,
  untracked: 0,
  ahead: 0,
  behind: 0,
  lastCommit: '',
  lastCommitTime: 0,
  lastUpdated: 0,
}

export const GitInsightsPlugin: WarpPlugin = {
  name: 'Git Insights',
  version: '1.0.0',
  apiVersion: '2.0',
  pluginType: 'hybrid',

  init(context: PluginContext): void {
    context.log.info('Initializing Git Insights Plugin')

    // Initialize state
    context.state.set('gitState', defaultGitState)
    context.state.set('gitCommands', [])
    context.state.set('showPanel', true)

    // Subscribe to command events to detect git commands
    context.subscribe('command', (event: PluginEvent) => {
      if (event.data.type !== 'command') return

      const commandData = event.data as { command: string; paneId: string }
      const command = commandData.command.trim()

      // Track git commands
      if (command.startsWith('git ')) {
        const gitCommands = context.state.get<GitCommand[]>('gitCommands') || []

        const gitCmd: GitCommand = {
          id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          command: command,
          timestamp: event.timestamp,
        }

        // Keep last 20 git commands
        const updated = [gitCmd, ...gitCommands].slice(0, 20)
        context.state.set('gitCommands', updated)

        context.log.debug(`Git command detected: ${command}`)

        // Trigger refresh after git commands that change state
        const refreshTriggers = ['commit', 'push', 'pull', 'fetch', 'checkout', 'merge', 'rebase', 'stash', 'add', 'reset']
        if (refreshTriggers.some(t => command.includes(t))) {
          // Mark for refresh
          context.state.set('needsRefresh', true)
        }
      }
    })

    // Subscribe to output to detect git command results
    context.subscribe('output', (event: PluginEvent) => {
      if (event.data.type !== 'output') return

      const outputData = event.data as { output: string; paneId: string }
      const output = outputData.output

      // Parse git status output if detected
      if (output.includes('On branch') || output.includes('HEAD detached')) {
        const gitState = parseGitStatusOutput(output)
        if (gitState) {
          context.state.set('gitState', { ...gitState, lastUpdated: Date.now() })
          context.log.debug('Git state updated from output')
        }
      }

      // Update command success/failure
      const gitCommands = context.state.get<GitCommand[]>('gitCommands') || []
      if (gitCommands.length > 0 && !gitCommands[0].success) {
        const updated = [...gitCommands]
        updated[0] = {
          ...updated[0],
          duration: Date.now() - updated[0].timestamp,
          success: !output.includes('error:') && !output.includes('fatal:'),
          output: output.slice(0, 200),
        }
        context.state.set('gitCommands', updated)
      }
    })

    // Subscribe to cwd changes to detect repo changes
    context.subscribe('cwd-changed', (event: PluginEvent) => {
      if (event.data.type !== 'cwd-changed') return
      context.state.set('needsRefresh', true)
      context.log.debug('CWD changed, marking for refresh')
    })

    context.log.info('Git Insights Plugin initialized')
  },

  getToolbarButtons(): PluginToolbarButton[] {
    return [
      {
        id: 'git-refresh',
        icon: '↻',
        label: 'Refresh Git',
        tooltip: 'Refresh git status',
        position: 'right',
        action: () => {
          console.log('[GitInsights] Manual refresh triggered')
        },
        getState: () => 'active',
      },
      {
        id: 'git-toggle-panel',
        icon: '',
        label: 'Git Panel',
        tooltip: 'Toggle git insights panel',
        position: 'right',
        action: () => {
          console.log('[GitInsights] Toggle panel')
        },
      },
    ]
  },

  getKeyboardShortcuts(): PluginKeyboardShortcut[] {
    return [
      {
        id: 'git-status',
        key: 'ctrl+shift+g',
        label: 'Git Status',
        description: 'Show git status in panel',
        action: () => {
          console.log('[GitInsights] Show git status')
        },
      },
    ]
  },

  render(container: HTMLElement, state: PluginState): void {
    const gitState = state.get<GitState>('gitState') || defaultGitState
    const gitCommands = state.get<GitCommand[]>('gitCommands') || []
    const showPanel = state.get<boolean>('showPanel') ?? true

    if (!showPanel) {
      container.innerHTML = ''
      return
    }

    container.innerHTML = sanitizePluginHtml(`
      <div style="padding: 12px; font-family: system-ui, -apple-system, sans-serif;">
        <h3 style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 16px;"></span>
          Git Insights
        </h3>

        ${!gitState.isRepo ? `
          <div style="
            color: #888;
            font-size: 12px;
            padding: 16px;
            text-align: center;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
          ">
            <div style="font-size: 24px; margin-bottom: 8px;">📁</div>
            <div>Not a git repository</div>
            <div style="font-size: 10px; margin-top: 4px; color: #666;">
              Run <code style="color: #4ade80;">git init</code> or navigate to a repo
            </div>
          </div>
        ` : `
          <!-- Branch & Status -->
          <div style="
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 12px;
          ">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 14px;"></span>
                <span style="font-weight: 600; color: #a5b4fc;">${gitState.branch || 'unknown'}</span>
              </div>
              ${gitState.isDirty ? `
                <span style="
                  background: rgba(251, 146, 60, 0.2);
                  color: #fb923c;
                  padding: 2px 8px;
                  border-radius: 10px;
                  font-size: 10px;
                ">Modified</span>
              ` : `
                <span style="
                  background: rgba(52, 211, 153, 0.2);
                  color: #6ee7b7;
                  padding: 2px 8px;
                  border-radius: 10px;
                  font-size: 10px;
                ">Clean</span>
              `}
            </div>

            ${(gitState.ahead > 0 || gitState.behind > 0) ? `
              <div style="margin-top: 8px; font-size: 11px; color: #888;">
                ${gitState.ahead > 0 ? `<span style="color: #4ade80;">↑${gitState.ahead}</span>` : ''}
                ${gitState.behind > 0 ? `<span style="color: #f87171;">↓${gitState.behind}</span>` : ''}
                ${gitState.ahead > 0 && gitState.behind > 0 ? ' (diverged)' : ''}
              </div>
            ` : ''}
          </div>

          <!-- File Status -->
          ${gitState.isDirty ? `
            <div style="
              display: grid;
              grid-template-columns: repeat(3, 1fr);
              gap: 8px;
              margin-bottom: 12px;
            ">
              <div style="
                background: rgba(52, 211, 153, 0.1);
                border-radius: 6px;
                padding: 8px;
                text-align: center;
              ">
                <div style="font-size: 16px; font-weight: 600; color: #6ee7b7;">${gitState.staged}</div>
                <div style="font-size: 9px; color: #888;">Staged</div>
              </div>
              <div style="
                background: rgba(251, 146, 60, 0.1);
                border-radius: 6px;
                padding: 8px;
                text-align: center;
              ">
                <div style="font-size: 16px; font-weight: 600; color: #fb923c;">${gitState.unstaged}</div>
                <div style="font-size: 9px; color: #888;">Modified</div>
              </div>
              <div style="
                background: rgba(239, 68, 68, 0.1);
                border-radius: 6px;
                padding: 8px;
                text-align: center;
              ">
                <div style="font-size: 16px; font-weight: 600; color: #f87171;">${gitState.untracked}</div>
                <div style="font-size: 9px; color: #888;">Untracked</div>
              </div>
            </div>
          ` : ''}

          <!-- Last Commit -->
          ${gitState.lastCommit ? `
            <div style="
              background: rgba(255,255,255,0.03);
              border-radius: 6px;
              padding: 8px;
              margin-bottom: 12px;
              font-size: 11px;
            ">
              <div style="color: #888; margin-bottom: 4px;">Last Commit</div>
              <div style="color: #ddd; word-break: break-word;">${truncate(gitState.lastCommit, 50)}</div>
              ${gitState.lastCommitTime ? `
                <div style="color: #666; margin-top: 4px; font-size: 10px;">
                  ${formatTimeAgo(gitState.lastCommitTime)}
                </div>
              ` : ''}
            </div>
          ` : ''}
        `}

        <!-- Recent Git Commands -->
        ${gitCommands.length > 0 ? `
          <div style="margin-top: 12px;">
            <div style="font-size: 11px; color: #888; margin-bottom: 8px;">Recent Commands</div>
            <div style="max-height: 150px; overflow-y: auto;">
              ${gitCommands.slice(0, 5).map(cmd => `
                <div style="
                  display: flex;
                  align-items: center;
                  gap: 8px;
                  padding: 6px 0;
                  border-bottom: 1px solid #333;
                  font-size: 11px;
                ">
                  <span style="
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    background: ${cmd.success === undefined ? '#888' : cmd.success ? '#4ade80' : '#f87171'};
                  "></span>
                  <code style="color: #a5b4fc; flex: 1; overflow: hidden; text-overflow: ellipsis;">
                    ${truncate(cmd.command, 30)}
                  </code>
                  ${cmd.duration ? `
                    <span style="color: #666; font-size: 10px;">${formatDuration(cmd.duration)}</span>
                  ` : ''}
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Quick Actions -->
        <div style="
          margin-top: 12px;
          padding-top: 12px;
          border-top: 1px solid #333;
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
        ">
          <button style="
            background: rgba(99, 102, 241, 0.2);
            border: 1px solid rgba(99, 102, 241, 0.4);
            color: #a5b4fc;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
          ">git status</button>
          <button style="
            background: rgba(52, 211, 153, 0.2);
            border: 1px solid rgba(52, 211, 153, 0.4);
            color: #6ee7b7;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
          ">git pull</button>
          <button style="
            background: rgba(251, 146, 60, 0.2);
            border: 1px solid rgba(251, 146, 60, 0.4);
            color: #fb923c;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
          ">git diff</button>
        </div>

        <div style="
          margin-top: 8px;
          font-size: 9px;
          color: #555;
          text-align: right;
        ">
          ${gitState.lastUpdated ? `Updated ${formatTimeAgo(gitState.lastUpdated)}` : ''}
        </div>
      </div>
    `)
  },

  destroy(): void {
    console.log('[GitInsightsPlugin] Destroyed')
  },
}

// Helper: Parse git status output
function parseGitStatusOutput(output: string): Partial<GitState> | null {
  try {
    const state: Partial<GitState> = {
      isRepo: true,
      isDirty: false,
      staged: 0,
      unstaged: 0,
      untracked: 0,
    }

    // Parse branch
    const branchMatch = output.match(/On branch (\S+)/)
    if (branchMatch) {
      state.branch = branchMatch[1]
    }

    // Parse ahead/behind
    const aheadMatch = output.match(/ahead.*?(\d+)/)
    const behindMatch = output.match(/behind.*?(\d+)/)
    if (aheadMatch) state.ahead = parseInt(aheadMatch[1])
    if (behindMatch) state.behind = parseInt(behindMatch[1])

    // Count file states
    const lines = output.split('\n')
    for (const line of lines) {
      if (line.match(/^\s*M\s/)) state.unstaged = (state.unstaged || 0) + 1
      if (line.match(/^M\s/)) state.staged = (state.staged || 0) + 1
      if (line.match(/^\?\?\s/)) state.untracked = (state.untracked || 0) + 1
    }

    state.isDirty = (state.staged || 0) > 0 || (state.unstaged || 0) > 0 || (state.untracked || 0) > 0

    return state
  } catch {
    return null
  }
}

// Helper: Truncate text
function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? text.slice(0, maxLength) + '...' : text
}

// Helper: Format duration
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m`
}

// Helper: Format time ago
function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export default GitInsightsPlugin
