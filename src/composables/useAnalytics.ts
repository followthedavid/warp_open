/**
 * Session Analytics Composable
 * Tracks commands executed, time per pane/tab, most-used commands
 */

import { ref, computed, watch } from 'vue'

export interface CommandExecution {
  command: string
  timestamp: number
  paneId: string
  tabId: string
  exitCode?: number
  duration?: number
}

export interface PaneTime {
  paneId: string
  tabId: string
  totalTime: number // milliseconds
  lastActive: number
}

export interface SessionStats {
  sessionStart: number
  totalCommands: number
  uniqueCommands: number
  totalActiveTime: number
  commandsByTab: Record<string, number>
  commandsByPane: Record<string, number>
}

export interface AnalyticsData {
  commands: CommandExecution[]
  paneTimes: PaneTime[]
  sessionStart: number
  lastUpdate: number
}

const STORAGE_KEY = 'warp-analytics'
const MAX_COMMANDS = 1000

// Shared state
const commands = ref<CommandExecution[]>([])
const paneTimes = ref<Map<string, PaneTime>>(new Map())
const sessionStart = ref<number>(Date.now())
const currentPaneId = ref<string | null>(null)
const paneStartTime = ref<number | null>(null)

// Load from localStorage
function loadAnalytics() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      const data: AnalyticsData = JSON.parse(stored)
      commands.value = data.commands || []
      sessionStart.value = data.sessionStart || Date.now()

      // Convert paneTimes array back to Map
      const times = new Map<string, PaneTime>()
      for (const pt of (data.paneTimes || [])) {
        times.set(pt.paneId, pt)
      }
      paneTimes.value = times
    }
  } catch (e) {
    console.warn('[Analytics] Failed to load:', e)
  }
}

// Save to localStorage
function saveAnalytics() {
  try {
    const data: AnalyticsData = {
      commands: commands.value.slice(-MAX_COMMANDS),
      paneTimes: Array.from(paneTimes.value.values()),
      sessionStart: sessionStart.value,
      lastUpdate: Date.now()
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data))
  } catch (e) {
    console.warn('[Analytics] Failed to save:', e)
  }
}

export function useAnalytics() {
  // Load on first use
  if (commands.value.length === 0 && paneTimes.value.size === 0) {
    loadAnalytics()
  }

  // Track command execution
  function trackCommand(command: string, paneId: string, tabId: string, exitCode?: number, duration?: number) {
    const execution: CommandExecution = {
      command: command.trim(),
      timestamp: Date.now(),
      paneId,
      tabId,
      exitCode,
      duration
    }

    commands.value.push(execution)

    // Keep only last MAX_COMMANDS
    if (commands.value.length > MAX_COMMANDS) {
      commands.value = commands.value.slice(-MAX_COMMANDS)
    }

    saveAnalytics()
  }

  // Track pane focus time
  function trackPaneFocus(paneId: string, tabId: string) {
    const now = Date.now()

    // End previous pane tracking
    if (currentPaneId.value && paneStartTime.value) {
      const elapsed = now - paneStartTime.value
      const existing = paneTimes.value.get(currentPaneId.value)

      if (existing) {
        existing.totalTime += elapsed
        existing.lastActive = now
      }
    }

    // Start tracking new pane
    currentPaneId.value = paneId
    paneStartTime.value = now

    // Initialize pane time if needed
    if (!paneTimes.value.has(paneId)) {
      paneTimes.value.set(paneId, {
        paneId,
        tabId,
        totalTime: 0,
        lastActive: now
      })
    }

    saveAnalytics()
  }

  // Get most used commands
  const mostUsedCommands = computed(() => {
    const counts = new Map<string, number>()

    for (const cmd of commands.value) {
      // Extract just the command name (first word)
      const cmdName = cmd.command.split(/\s+/)[0]
      if (cmdName) {
        counts.set(cmdName, (counts.get(cmdName) || 0) + 1)
      }
    }

    return Array.from(counts.entries())
      .map(([command, count]) => ({ command, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20)
  })

  // Get full command frequency (exact commands)
  const fullCommandFrequency = computed(() => {
    const counts = new Map<string, number>()

    for (const cmd of commands.value) {
      const fullCmd = cmd.command
      if (fullCmd) {
        counts.set(fullCmd, (counts.get(fullCmd) || 0) + 1)
      }
    }

    return Array.from(counts.entries())
      .map(([command, count]) => ({ command, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 50)
  })

  // Session stats
  const sessionStats = computed((): SessionStats => {
    const commandSet = new Set(commands.value.map(c => c.command.split(/\s+/)[0]))
    const byTab = new Map<string, number>()
    const byPane = new Map<string, number>()

    for (const cmd of commands.value) {
      byTab.set(cmd.tabId, (byTab.get(cmd.tabId) || 0) + 1)
      byPane.set(cmd.paneId, (byPane.get(cmd.paneId) || 0) + 1)
    }

    const totalActiveTime = Array.from(paneTimes.value.values())
      .reduce((sum, pt) => sum + pt.totalTime, 0)

    return {
      sessionStart: sessionStart.value,
      totalCommands: commands.value.length,
      uniqueCommands: commandSet.size,
      totalActiveTime,
      commandsByTab: Object.fromEntries(byTab),
      commandsByPane: Object.fromEntries(byPane)
    }
  })

  // Commands per hour (for chart)
  const commandsPerHour = computed(() => {
    const hours = new Map<string, number>()

    for (const cmd of commands.value) {
      const date = new Date(cmd.timestamp)
      const hour = `${date.toLocaleDateString()} ${date.getHours()}:00`
      hours.set(hour, (hours.get(hour) || 0) + 1)
    }

    return Array.from(hours.entries())
      .map(([hour, count]) => ({ hour, count }))
      .slice(-24) // Last 24 hours
  })

  // Commands by day
  const commandsByDay = computed(() => {
    const days = new Map<string, number>()

    for (const cmd of commands.value) {
      const date = new Date(cmd.timestamp)
      const day = date.toLocaleDateString()
      days.set(day, (days.get(day) || 0) + 1)
    }

    return Array.from(days.entries())
      .map(([day, count]) => ({ day, count }))
      .slice(-30) // Last 30 days
  })

  // Pane time distribution
  const paneTimeDistribution = computed(() => {
    return Array.from(paneTimes.value.values())
      .map(pt => ({
        paneId: pt.paneId,
        tabId: pt.tabId,
        minutes: Math.round(pt.totalTime / 60000),
        percentage: 0 // Will be calculated
      }))
      .sort((a, b) => b.minutes - a.minutes)
      .map((item, _, arr) => {
        const total = arr.reduce((sum, i) => sum + i.minutes, 0)
        return {
          ...item,
          percentage: total > 0 ? Math.round((item.minutes / total) * 100) : 0
        }
      })
  })

  // Recent commands
  const recentCommands = computed(() => {
    return [...commands.value]
      .reverse()
      .slice(0, 100)
  })

  // Export as CSV
  function exportToCSV(): string {
    const headers = ['Timestamp', 'Command', 'Pane ID', 'Tab ID', 'Exit Code', 'Duration (ms)']
    const rows = commands.value.map(cmd => [
      new Date(cmd.timestamp).toISOString(),
      `"${cmd.command.replace(/"/g, '""')}"`,
      cmd.paneId,
      cmd.tabId,
      cmd.exitCode ?? '',
      cmd.duration ?? ''
    ])

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
  }

  // Export as JSON
  function exportToJSON(): string {
    return JSON.stringify({
      exportedAt: new Date().toISOString(),
      sessionStart: new Date(sessionStart.value).toISOString(),
      stats: sessionStats.value,
      commands: commands.value,
      paneTimes: Array.from(paneTimes.value.values()),
      mostUsedCommands: mostUsedCommands.value,
      commandsPerHour: commandsPerHour.value,
      commandsByDay: commandsByDay.value
    }, null, 2)
  }

  // Clear all analytics
  function clearAnalytics() {
    commands.value = []
    paneTimes.value = new Map()
    sessionStart.value = Date.now()
    localStorage.removeItem(STORAGE_KEY)
  }

  // Reset session (keep historical data but start new session)
  function resetSession() {
    sessionStart.value = Date.now()
    paneStartTime.value = null
    currentPaneId.value = null
    saveAnalytics()
  }

  return {
    // State
    commands,
    paneTimes,
    sessionStart,

    // Actions
    trackCommand,
    trackPaneFocus,
    clearAnalytics,
    resetSession,
    exportToCSV,
    exportToJSON,

    // Computed
    mostUsedCommands,
    fullCommandFrequency,
    sessionStats,
    commandsPerHour,
    commandsByDay,
    paneTimeDistribution,
    recentCommands
  }
}
