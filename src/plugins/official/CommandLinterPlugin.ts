/**
 * Command Linter Plugin
 *
 * Warns users before executing dangerous commands.
 * Provides safer alternatives and educational context.
 *
 * Features:
 * - Pre-execution warnings for destructive commands
 * - Customizable rule sets
 * - Severity levels (info, warn, danger)
 * - Suggested safer alternatives
 * - Learn mode with explanations
 *
 * Demonstrates:
 * - read-commands permission
 * - Inline annotations
 * - User interaction patterns
 */

import type {
  WarpPlugin,
  PluginContext,
  PluginState,
  PluginEvent,
  PluginKeyboardShortcut,
} from '../types'
import { sanitizePluginHtml } from '../../utils/sanitize'

// Danger levels
type DangerLevel = 'info' | 'warn' | 'danger' | 'critical'

// Lint rule definition
interface LintRule {
  id: string
  name: string
  pattern: RegExp
  level: DangerLevel
  message: string
  explanation: string
  alternative?: string
  category: 'destructive' | 'security' | 'performance' | 'best-practice'
}

// Lint result
interface LintResult {
  id: string
  command: string
  timestamp: number
  rules: LintRule[]
  acknowledged: boolean
}

// Built-in rules
const DEFAULT_RULES: LintRule[] = [
  // Critical - Data Loss
  {
    id: 'rm-rf-root',
    name: 'Recursive Delete Root',
    pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?[\/~]\s*$/,
    level: 'critical',
    message: 'This will delete your entire filesystem!',
    explanation: 'The command "rm -rf /" or "rm -rf ~" will recursively delete everything from the root or home directory without confirmation.',
    alternative: 'Be specific about what to delete: rm -rf ./specific-folder',
    category: 'destructive',
  },
  {
    id: 'rm-rf-star',
    name: 'Recursive Delete All',
    pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)+(-[a-zA-Z]*f[a-zA-Z]*\s+)?\*/,
    level: 'danger',
    message: 'Deleting all files recursively without confirmation',
    explanation: 'Using "rm -rf *" will delete all files and folders in the current directory without asking for confirmation.',
    alternative: 'Use "rm -ri *" for interactive mode, or list files first with "ls"',
    category: 'destructive',
  },
  {
    id: 'rm-rf-force',
    name: 'Force Delete',
    pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*)/,
    level: 'warn',
    message: 'Force deleting without confirmation',
    explanation: 'The -f flag removes files without prompting, even if write-protected.',
    alternative: 'Use "rm -i" for interactive deletion',
    category: 'destructive',
  },

  // Security Issues
  {
    id: 'chmod-777',
    name: 'World Writable',
    pattern: /chmod\s+777/,
    level: 'danger',
    message: 'Setting world-writable permissions',
    explanation: 'chmod 777 makes files readable, writable, and executable by everyone. This is a security risk.',
    alternative: 'Use chmod 755 for executables or chmod 644 for files',
    category: 'security',
  },
  {
    id: 'chmod-recursive',
    name: 'Recursive Permission Change',
    pattern: /chmod\s+-[rR]/,
    level: 'warn',
    message: 'Changing permissions recursively',
    explanation: 'Recursive permission changes can affect many files unintentionally.',
    alternative: 'Apply permissions to specific files or use find with -exec',
    category: 'security',
  },
  {
    id: 'curl-pipe-bash',
    name: 'Curl Pipe to Bash',
    pattern: /curl\s+.*\|\s*(sudo\s+)?bash/,
    level: 'danger',
    message: 'Piping untrusted content directly to shell',
    explanation: 'Downloading and executing scripts in one command is risky. You cannot inspect the script before it runs.',
    alternative: 'Download first: curl -O url; review script; then execute',
    category: 'security',
  },
  {
    id: 'wget-pipe-bash',
    name: 'Wget Pipe to Bash',
    pattern: /wget\s+.*-O\s*-\s*\|\s*(sudo\s+)?bash/,
    level: 'danger',
    message: 'Piping untrusted content directly to shell',
    explanation: 'Downloading and executing scripts in one command is risky. You cannot inspect the script before it runs.',
    alternative: 'Download first: wget url; review script; then execute',
    category: 'security',
  },
  {
    id: 'sudo-password-echo',
    name: 'Password in Command',
    pattern: /echo\s+['"]?[^'"|\s]+['"]?\s*\|\s*sudo/,
    level: 'danger',
    message: 'Password may be exposed in shell history',
    explanation: 'Echoing passwords can leave them in shell history and process lists.',
    alternative: 'Let sudo prompt for password, or use sudo -S with secure input',
    category: 'security',
  },

  // Destructive Operations
  {
    id: 'dd-of-disk',
    name: 'DD to Disk Device',
    pattern: /dd\s+.*of=\/dev\/(sd[a-z]|nvme|hd[a-z]|disk)/,
    level: 'critical',
    message: 'Writing directly to disk device - data loss risk!',
    explanation: 'dd writes raw data to devices. Wrong target = destroyed data.',
    alternative: 'Triple-check the device path. Use "lsblk" to verify.',
    category: 'destructive',
  },
  {
    id: 'mkfs-format',
    name: 'Filesystem Format',
    pattern: /mkfs\./,
    level: 'danger',
    message: 'Formatting filesystem - all data will be lost',
    explanation: 'mkfs creates a new filesystem, erasing all existing data.',
    alternative: 'Verify the correct device with "lsblk" before formatting',
    category: 'destructive',
  },
  {
    id: 'git-force-push',
    name: 'Git Force Push',
    pattern: /git\s+push\s+.*(-f|--force)/,
    level: 'warn',
    message: 'Force pushing can overwrite remote history',
    explanation: 'Force push rewrites remote history. Others may lose their work.',
    alternative: 'Use "git push --force-with-lease" for safer force push',
    category: 'destructive',
  },
  {
    id: 'git-reset-hard',
    name: 'Git Hard Reset',
    pattern: /git\s+reset\s+--hard/,
    level: 'warn',
    message: 'Hard reset discards all uncommitted changes',
    explanation: 'git reset --hard removes all staged and unstaged changes permanently.',
    alternative: 'Stash changes first: "git stash" then reset',
    category: 'destructive',
  },
  {
    id: 'drop-database',
    name: 'Drop Database',
    pattern: /drop\s+(database|table|schema)/i,
    level: 'danger',
    message: 'Dropping database objects is irreversible',
    explanation: 'DROP commands permanently delete database structures and data.',
    alternative: 'Create a backup first. Use transactions if possible.',
    category: 'destructive',
  },

  // Performance & Best Practice
  {
    id: 'find-exec-plus',
    name: 'Find Exec Inefficient',
    pattern: /find\s+.*-exec\s+.*\{\}\s*;/,
    level: 'info',
    message: 'Consider using -exec + for better performance',
    explanation: 'Using -exec {} ; runs a new process for each file. Using + batches files.',
    alternative: 'Use "find ... -exec cmd {} +" to batch operations',
    category: 'performance',
  },
  {
    id: 'cat-useless',
    name: 'Useless Cat',
    pattern: /cat\s+[^\|]+\|\s*(grep|awk|sed|head|tail)/,
    level: 'info',
    message: 'Unnecessary use of cat',
    explanation: 'Most tools can read files directly without cat.',
    alternative: 'Use "grep pattern file" instead of "cat file | grep pattern"',
    category: 'best-practice',
  },
  {
    id: 'sudo-su',
    name: 'Sudo Su',
    pattern: /sudo\s+su\b/,
    level: 'info',
    message: 'Consider using "sudo -i" instead',
    explanation: 'sudo su is redundant. sudo -i provides a proper root login shell.',
    alternative: 'Use "sudo -i" for root shell or "sudo -u user -i" for other users',
    category: 'best-practice',
  },
]

// Get danger color
function getDangerColor(level: DangerLevel): string {
  switch (level) {
    case 'critical': return '#ef4444' // red-500
    case 'danger': return '#f97316'   // orange-500
    case 'warn': return '#eab308'     // yellow-500
    case 'info': return '#3b82f6'     // blue-500
  }
}

// Get danger background
function getDangerBg(level: DangerLevel): string {
  switch (level) {
    case 'critical': return 'rgba(239, 68, 68, 0.1)'
    case 'danger': return 'rgba(249, 115, 22, 0.1)'
    case 'warn': return 'rgba(234, 179, 8, 0.1)'
    case 'info': return 'rgba(59, 130, 246, 0.1)'
  }
}

// Get danger icon
function getDangerIcon(level: DangerLevel): string {
  switch (level) {
    case 'critical': return '🚨'
    case 'danger': return '⚠️'
    case 'warn': return '⚡'
    case 'info': return 'ℹ️'
  }
}

export const CommandLinterPlugin: WarpPlugin = {
  name: 'Command Linter',
  version: '1.0.0',
  apiVersion: '2.0',
  pluginType: 'ui',

  init(context: PluginContext): void {
    context.log.info('Initializing Command Linter Plugin')

    // Initialize state
    context.state.set('rules', DEFAULT_RULES)
    context.state.set('results', [])
    context.state.set('enabled', true)
    context.state.set('showExplanations', true)
    context.state.set('blockedCount', 0)
    context.state.set('warningCount', 0)

    // Subscribe to commands
    context.subscribe('command', (event: PluginEvent) => {
      if (event.data.type !== 'command') return

      const enabled = context.state.get<boolean>('enabled')
      if (!enabled) return

      const commandData = event.data as { command: string; paneId: string }
      const command = commandData.command.trim()

      // Lint the command
      const rules = context.state.get<LintRule[]>('rules') || DEFAULT_RULES
      const matchedRules = rules.filter(rule => rule.pattern.test(command))

      if (matchedRules.length > 0) {
        const results = context.state.get<LintResult[]>('results') || []

        const result: LintResult = {
          id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          command: command,
          timestamp: event.timestamp,
          rules: matchedRules,
          acknowledged: false,
        }

        // Keep last 50 results
        const updated = [result, ...results].slice(0, 50)
        context.state.set('results', updated)

        // Update counts
        const maxLevel = matchedRules.reduce((max, rule) => {
          const levels: DangerLevel[] = ['info', 'warn', 'danger', 'critical']
          return levels.indexOf(rule.level) > levels.indexOf(max) ? rule.level : max
        }, 'info' as DangerLevel)

        if (maxLevel === 'critical' || maxLevel === 'danger') {
          const blocked = context.state.get<number>('blockedCount') || 0
          context.state.set('blockedCount', blocked + 1)
        } else {
          const warnings = context.state.get<number>('warningCount') || 0
          context.state.set('warningCount', warnings + 1)
        }

        context.log.warn(`Command lint: ${matchedRules.map(r => r.id).join(', ')} - ${command}`)
      }
    })

    context.log.info('Command Linter Plugin initialized')
  },

  getKeyboardShortcuts(): PluginKeyboardShortcut[] {
    return [
      {
        id: 'toggle-linter',
        key: 'ctrl+shift+l',
        label: 'Toggle Linter',
        description: 'Enable/disable command linting',
        action: () => {
          console.log('[CommandLinter] Toggle triggered')
        },
      },
      {
        id: 'clear-lint-history',
        key: 'ctrl+alt+l',
        label: 'Clear Lint History',
        description: 'Clear all lint warnings',
        action: () => {
          console.log('[CommandLinter] Clear history triggered')
        },
      },
    ]
  },

  render(container: HTMLElement, state: PluginState): void {
    const enabled = state.get<boolean>('enabled') ?? true
    const showExplanations = state.get<boolean>('showExplanations') ?? true
    const results = state.get<LintResult[]>('results') || []
    const blockedCount = state.get<number>('blockedCount') || 0
    const warningCount = state.get<number>('warningCount') || 0

    // Recent unacknowledged warnings
    const recentWarnings = results.filter(r => !r.acknowledged).slice(0, 5)

    container.innerHTML = sanitizePluginHtml(`
      <div style="padding: 12px; font-family: system-ui, -apple-system, sans-serif;">
        <h3 style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 16px;">🛡️</span>
          Command Linter
          <span style="
            margin-left: auto;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            background: ${enabled ? 'rgba(52, 211, 153, 0.2)' : 'rgba(107, 114, 128, 0.2)'};
            color: ${enabled ? '#6ee7b7' : '#9ca3af'};
          ">${enabled ? 'Active' : 'Paused'}</span>
        </h3>

        <!-- Stats -->
        <div style="
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 8px;
          margin-bottom: 12px;
        ">
          <div style="
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 6px;
            padding: 8px;
            text-align: center;
          ">
            <div style="font-size: 20px; font-weight: 600; color: #f87171;">${blockedCount}</div>
            <div style="font-size: 9px; color: #888;">Dangerous</div>
          </div>
          <div style="
            background: rgba(234, 179, 8, 0.1);
            border: 1px solid rgba(234, 179, 8, 0.3);
            border-radius: 6px;
            padding: 8px;
            text-align: center;
          ">
            <div style="font-size: 20px; font-weight: 600; color: #fde047;">${warningCount}</div>
            <div style="font-size: 9px; color: #888;">Warnings</div>
          </div>
        </div>

        <!-- Active Warnings -->
        ${recentWarnings.length > 0 ? `
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; color: #888; margin-bottom: 8px;">
              Recent Warnings
            </div>
            ${recentWarnings.map(result => {
              const topRule = result.rules[0]
              return `
                <div style="
                  background: ${getDangerBg(topRule.level)};
                  border: 1px solid ${getDangerColor(topRule.level)}40;
                  border-radius: 6px;
                  padding: 8px;
                  margin-bottom: 8px;
                ">
                  <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                    <span style="font-size: 12px;">${getDangerIcon(topRule.level)}</span>
                    <span style="font-size: 11px; font-weight: 600; color: ${getDangerColor(topRule.level)};">
                      ${topRule.name}
                    </span>
                  </div>
                  <code style="
                    font-size: 10px;
                    color: #ddd;
                    background: rgba(0,0,0,0.3);
                    padding: 2px 6px;
                    border-radius: 3px;
                    display: block;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    margin-bottom: 4px;
                  ">${truncate(result.command, 40)}</code>
                  <div style="font-size: 10px; color: #888;">
                    ${topRule.message}
                  </div>
                  ${showExplanations && topRule.alternative ? `
                    <div style="
                      margin-top: 6px;
                      padding-top: 6px;
                      border-top: 1px solid rgba(255,255,255,0.1);
                      font-size: 9px;
                      color: #6ee7b7;
                    ">
                      💡 ${topRule.alternative}
                    </div>
                  ` : ''}
                </div>
              `
            }).join('')}
          </div>
        ` : `
          <div style="
            color: #888;
            font-size: 12px;
            padding: 16px;
            text-align: center;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
            margin-bottom: 12px;
          ">
            <div style="font-size: 24px; margin-bottom: 8px;">✅</div>
            <div>No warnings</div>
            <div style="font-size: 10px; color: #666; margin-top: 4px;">
              Your recent commands look safe
            </div>
          </div>
        `}

        <!-- Rule Categories -->
        <div style="margin-bottom: 12px;">
          <div style="font-size: 11px; color: #888; margin-bottom: 6px;">Protected Against</div>
          <div style="display: flex; flex-wrap: wrap; gap: 4px;">
            <span style="
              background: rgba(239, 68, 68, 0.2);
              color: #f87171;
              padding: 2px 8px;
              border-radius: 10px;
              font-size: 9px;
            ">Destructive</span>
            <span style="
              background: rgba(249, 115, 22, 0.2);
              color: #fb923c;
              padding: 2px 8px;
              border-radius: 10px;
              font-size: 9px;
            ">Security</span>
            <span style="
              background: rgba(234, 179, 8, 0.2);
              color: #fde047;
              padding: 2px 8px;
              border-radius: 10px;
              font-size: 9px;
            ">Performance</span>
            <span style="
              background: rgba(59, 130, 246, 0.2);
              color: #60a5fa;
              padding: 2px 8px;
              border-radius: 10px;
              font-size: 9px;
            ">Best Practice</span>
          </div>
        </div>

        <!-- Quick Reference -->
        <div style="
          background: rgba(255,255,255,0.03);
          border-radius: 6px;
          padding: 8px;
          font-size: 10px;
        ">
          <div style="color: #888; margin-bottom: 6px;">Examples of flagged commands:</div>
          <div style="color: #f87171; margin-bottom: 2px;"><code>rm -rf /</code> - Critical</div>
          <div style="color: #fb923c; margin-bottom: 2px;"><code>chmod 777</code> - Danger</div>
          <div style="color: #fde047; margin-bottom: 2px;"><code>git push -f</code> - Warning</div>
          <div style="color: #60a5fa;"><code>cat file | grep</code> - Info</div>
        </div>

        <!-- Toggle -->
        <div style="
          margin-top: 12px;
          padding-top: 8px;
          border-top: 1px solid #333;
          display: flex;
          justify-content: space-between;
          align-items: center;
        ">
          <span style="font-size: 10px; color: #888;">
            ${DEFAULT_RULES.length} rules active
          </span>
          <button style="
            background: rgba(99, 102, 241, 0.2);
            border: 1px solid rgba(99, 102, 241, 0.4);
            color: #a5b4fc;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 10px;
            cursor: pointer;
          ">Configure Rules</button>
        </div>
      </div>
    `)
  },

  destroy(): void {
    console.log('[CommandLinterPlugin] Destroyed')
  },
}

// Helper: Truncate text
function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? text.slice(0, maxLength) + '...' : text
}

export default CommandLinterPlugin
