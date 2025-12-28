/**
 * useDaemonOrchestrator - 24/7 Background Intelligence Coordinator
 *
 * This is the "brain" that coordinates all autonomous systems:
 * - Schedules and runs background tasks
 * - Manages the approval queue
 * - Enforces constitutional constraints
 * - Maintains the dead man's switch
 * - Coordinates between all subsystems
 * - Runs the perpetual improvement ladder
 *
 * Designed to run while you sleep, making your digital life better.
 */

import { ref, computed, reactive, watch } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

import { useConstitution } from './useConstitution'
import { useAuditLog } from './useAuditLog'
import { useUniversalMemory } from './useUniversalMemory'
import { useTokenVault } from './useTokenVault'
import { useAccountAnonymizer } from './useAccountAnonymizer'
import { useEmailCleaner } from './useEmailCleaner'
import { useAutonomousImprover } from './useAutonomousImprover'

// ============================================================================
// TYPES
// ============================================================================

export type TaskType =
  | 'memory_index'
  | 'code_improve'
  | 'email_clean'
  | 'account_anonymize'
  | 'token_refresh'
  | 'web_search'
  | 'health_check'
  | 'backup'
  | 'custom'

export type TaskPriority = 'low' | 'normal' | 'high' | 'critical'

export interface ScheduledTask {
  id: string
  type: TaskType
  name: string
  description: string
  cronPattern?: string // e.g., "0 3 * * *" for 3am daily
  intervalMinutes?: number // Alternative to cron
  lastRun?: Date
  nextRun: Date
  enabled: boolean
  priority: TaskPriority
  config?: Record<string, unknown>
  stats: {
    runCount: number
    successCount: number
    lastDuration?: number
    avgDuration?: number
  }
}

export interface ApprovalRequest {
  id: string
  timestamp: Date
  type: TaskType
  action: string
  target?: string
  description: string
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  data?: unknown
  expiresAt?: Date
  status: 'pending' | 'approved' | 'rejected' | 'expired'
}

export interface DaemonStatus {
  running: boolean
  startedAt?: Date
  lastActivity: Date
  tasksRunning: number
  tasksCompleted: number
  tasksFailed: number
  approvalsWaiting: number
  healthStatus: 'healthy' | 'degraded' | 'unhealthy'
  nextScheduledTask?: { name: string; at: Date }
}

// ============================================================================
// STORAGE
// ============================================================================

const TASKS_KEY = 'warp_daemon_tasks'
const APPROVALS_KEY = 'warp_daemon_approvals'
const STATUS_KEY = 'warp_daemon_status'

function loadTasks(): ScheduledTask[] {
  try {
    const stored = localStorage.getItem(TASKS_KEY)
    if (stored) {
      return JSON.parse(stored).map((t: any) => ({
        ...t,
        lastRun: t.lastRun ? new Date(t.lastRun) : undefined,
        nextRun: new Date(t.nextRun)
      }))
    }
  } catch {}
  return getDefaultTasks()
}

function saveTasks(tasks: ScheduledTask[]): void {
  localStorage.setItem(TASKS_KEY, JSON.stringify(tasks))
}

function loadApprovals(): ApprovalRequest[] {
  try {
    const stored = localStorage.getItem(APPROVALS_KEY)
    if (stored) {
      return JSON.parse(stored).map((a: any) => ({
        ...a,
        timestamp: new Date(a.timestamp),
        expiresAt: a.expiresAt ? new Date(a.expiresAt) : undefined
      }))
    }
  } catch {}
  return []
}

function saveApprovals(approvals: ApprovalRequest[]): void {
  localStorage.setItem(APPROVALS_KEY, JSON.stringify(approvals))
}

function getDefaultTasks(): ScheduledTask[] {
  const now = new Date()

  return [
    {
      id: 'task_memory_index',
      type: 'memory_index',
      name: 'Index Codebase',
      description: 'Update universal memory with new/changed files',
      intervalMinutes: 60,
      nextRun: new Date(now.getTime() + 60 * 60 * 1000),
      enabled: true,
      priority: 'normal',
      stats: { runCount: 0, successCount: 0 }
    },
    {
      id: 'task_code_improve',
      type: 'code_improve',
      name: 'Scan for Improvements',
      description: 'Find and optionally apply code improvements',
      intervalMinutes: 120,
      nextRun: new Date(now.getTime() + 2 * 60 * 60 * 1000),
      enabled: true,
      priority: 'normal',
      stats: { runCount: 0, successCount: 0 }
    },
    {
      id: 'task_email_clean',
      type: 'email_clean',
      name: 'Clean Inbox',
      description: 'Process and clean email inbox',
      cronPattern: '0 6 * * *', // 6am daily
      nextRun: getNextCronTime('0 6 * * *'),
      enabled: false, // Disabled by default until configured
      priority: 'low',
      stats: { runCount: 0, successCount: 0 }
    },
    {
      id: 'task_token_refresh',
      type: 'token_refresh',
      name: 'Refresh Tokens',
      description: 'Check and refresh expiring tokens',
      intervalMinutes: 360, // Every 6 hours
      nextRun: new Date(now.getTime() + 6 * 60 * 60 * 1000),
      enabled: true,
      priority: 'high',
      stats: { runCount: 0, successCount: 0 }
    },
    {
      id: 'task_health_check',
      type: 'health_check',
      name: 'System Health Check',
      description: 'Verify all systems operational',
      intervalMinutes: 30,
      nextRun: new Date(now.getTime() + 30 * 60 * 1000),
      enabled: true,
      priority: 'critical',
      stats: { runCount: 0, successCount: 0 }
    },
    {
      id: 'task_backup',
      type: 'backup',
      name: 'Backup Configuration',
      description: 'Backup all configuration and audit logs',
      cronPattern: '0 4 * * *', // 4am daily
      nextRun: getNextCronTime('0 4 * * *'),
      enabled: true,
      priority: 'normal',
      stats: { runCount: 0, successCount: 0 }
    }
  ]
}

function getNextCronTime(pattern: string): Date {
  // Simplified cron parsing - in real implementation use a library
  const parts = pattern.split(' ')
  const now = new Date()
  const next = new Date(now)

  if (parts.length >= 2) {
    const minute = parseInt(parts[0])
    const hour = parseInt(parts[1])

    next.setHours(hour, minute, 0, 0)
    if (next <= now) {
      next.setDate(next.getDate() + 1)
    }
  }

  return next
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useDaemonOrchestrator() {
  const tasks = ref<ScheduledTask[]>(loadTasks())
  const approvals = ref<ApprovalRequest[]>(loadApprovals())
  const status = reactive<DaemonStatus>({
    running: false,
    lastActivity: new Date(),
    tasksRunning: 0,
    tasksCompleted: 0,
    tasksFailed: 0,
    approvalsWaiting: 0,
    healthStatus: 'healthy'
  })

  // Subsystems
  const constitution = useConstitution()
  const auditLog = useAuditLog()
  const memory = useUniversalMemory()
  const tokenVault = useTokenVault()
  const accountAnonymizer = useAccountAnonymizer()
  const emailCleaner = useEmailCleaner()
  const improver = useAutonomousImprover()

  // Internal state
  let schedulerInterval: ReturnType<typeof setInterval> | null = null
  let checkinInterval: ReturnType<typeof setInterval> | null = null
  const runningTasks = new Set<string>()

  // ========================================================================
  // DAEMON LIFECYCLE
  // ========================================================================

  /**
   * Start the daemon
   */
  function start(): void {
    if (status.running) return

    status.running = true
    status.startedAt = new Date()
    status.lastActivity = new Date()

    // Start scheduler
    schedulerInterval = setInterval(checkScheduledTasks, 60 * 1000) // Check every minute

    // Start checkin timer (dead man's switch)
    checkinInterval = setInterval(() => {
      constitution.checkin()
      status.lastActivity = new Date()
    }, 5 * 60 * 1000) // Checkin every 5 minutes

    // Initial check
    checkScheduledTasks()
    checkApprovalExpiry()

    auditLog.log('daemon_start', 'Daemon started', { riskLevel: 'low' })
    console.log('[Daemon] Started')
  }

  /**
   * Stop the daemon
   */
  function stop(): void {
    if (!status.running) return

    status.running = false

    if (schedulerInterval) {
      clearInterval(schedulerInterval)
      schedulerInterval = null
    }

    if (checkinInterval) {
      clearInterval(checkinInterval)
      checkinInterval = null
    }

    auditLog.log('daemon_stop', 'Daemon stopped', { riskLevel: 'low' })
    console.log('[Daemon] Stopped')
  }

  /**
   * Check if daemon is alive (for external monitoring)
   */
  function isAlive(): boolean {
    if (!status.running) return false
    if (!constitution.isAlive(1)) return false // Check if checkin happened in last hour

    const hourAgo = new Date(Date.now() - 60 * 60 * 1000)
    return status.lastActivity > hourAgo
  }

  // ========================================================================
  // TASK SCHEDULING
  // ========================================================================

  /**
   * Check and run scheduled tasks
   */
  async function checkScheduledTasks(): Promise<void> {
    const now = new Date()
    status.lastActivity = now

    // Update approvals waiting count
    status.approvalsWaiting = approvals.value.filter(a => a.status === 'pending').length

    for (const task of tasks.value) {
      if (!task.enabled) continue
      if (runningTasks.has(task.id)) continue
      if (task.nextRun > now) continue

      // Run the task
      runTask(task)
    }
  }

  /**
   * Run a specific task
   */
  async function runTask(task: ScheduledTask): Promise<boolean> {
    if (runningTasks.has(task.id)) return false

    // Constitution check
    if (!constitution.isAlive()) {
      console.warn('[Daemon] Dead man\'s switch triggered, skipping task')
      return false
    }

    runningTasks.add(task.id)
    status.tasksRunning = runningTasks.size
    const startTime = Date.now()

    try {
      console.log(`[Daemon] Running task: ${task.name}`)

      let success = false

      switch (task.type) {
        case 'memory_index':
          success = await runMemoryIndex(task)
          break
        case 'code_improve':
          success = await runCodeImprove(task)
          break
        case 'email_clean':
          success = await runEmailClean(task)
          break
        case 'token_refresh':
          success = await runTokenRefresh(task)
          break
        case 'health_check':
          success = await runHealthCheck(task)
          break
        case 'backup':
          success = await runBackup(task)
          break
        default:
          console.warn(`[Daemon] Unknown task type: ${task.type}`)
      }

      const duration = Date.now() - startTime

      // Update stats
      task.stats.runCount++
      if (success) task.stats.successCount++
      task.stats.lastDuration = duration
      task.stats.avgDuration = task.stats.avgDuration
        ? (task.stats.avgDuration + duration) / 2
        : duration

      task.lastRun = new Date()

      // Calculate next run
      if (task.cronPattern) {
        task.nextRun = getNextCronTime(task.cronPattern)
      } else if (task.intervalMinutes) {
        task.nextRun = new Date(Date.now() + task.intervalMinutes * 60 * 1000)
      }

      saveTasks(tasks.value)

      if (success) {
        status.tasksCompleted++
      } else {
        status.tasksFailed++
      }

      return success

    } catch (error) {
      console.error(`[Daemon] Task failed: ${task.name}`, error)
      status.tasksFailed++
      return false
    } finally {
      runningTasks.delete(task.id)
      status.tasksRunning = runningTasks.size
    }
  }

  // ========================================================================
  // TASK IMPLEMENTATIONS
  // ========================================================================

  async function runMemoryIndex(task: ScheduledTask): Promise<boolean> {
    try {
      const paths = memory.config.indexedPaths
      let totalIndexed = 0

      for (const path of paths) {
        const expandedPath = path.replace('~', process.env.HOME || '')
        try {
          const count = await memory.indexDirectory(expandedPath)
          totalIndexed += count
        } catch {}
      }

      await auditLog.log('file_read', `Indexed ${totalIndexed} files`, {
        details: { paths },
        riskLevel: 'low'
      })

      return true
    } catch {
      return false
    }
  }

  async function runCodeImprove(task: ScheduledTask): Promise<boolean> {
    try {
      const projects = memory.projects.value

      for (const project of projects.slice(0, 5)) { // Limit to 5 projects per run
        await improver.scanProject(project.path)
      }

      // Auto-apply low-risk improvements
      const applied = await improver.autoApplyLowRisk()

      // Queue high-risk for approval
      const pending = improver.pendingApproval.value
      for (const imp of pending) {
        requestApproval('code_improve', `Apply: ${imp.title}`, {
          target: imp.file,
          description: imp.description,
          riskLevel: imp.riskLevel,
          data: { improvementId: imp.id }
        })
      }

      return true
    } catch {
      return false
    }
  }

  async function runEmailClean(task: ScheduledTask): Promise<boolean> {
    try {
      const result = await emailCleaner.runCleaningPass()

      await auditLog.log('email_read', `Email cleaning: ${result.quarantined} quarantined`, {
        details: result,
        riskLevel: 'low'
      })

      // Purge old quarantine
      await emailCleaner.purgeQuarantine()

      return true
    } catch {
      return false
    }
  }

  async function runTokenRefresh(task: ScheduledTask): Promise<boolean> {
    try {
      const expiring = tokenVault.getExpiringTokens(7) // Expiring in 7 days

      for (const token of expiring) {
        if (token.autoRefresh) {
          // Attempt auto-refresh handled by vault
        } else {
          // Request approval for manual refresh
          requestApproval('token_refresh', `Token expiring: ${token.name}`, {
            target: token.service,
            description: `Token for ${token.service} expires on ${token.expiresAt?.toLocaleDateString()}`,
            riskLevel: 'high',
            data: { tokenId: token.id }
          })
        }
      }

      return true
    } catch {
      return false
    }
  }

  async function runHealthCheck(task: ScheduledTask): Promise<boolean> {
    const issues: string[] = []

    // Check constitution
    if (!constitution.isCompliant.value) {
      issues.push('Constitution violations detected')
    }

    // Check audit log integrity
    const auditVerify = await auditLog.verifyChain()
    if (!auditVerify.valid) {
      issues.push('Audit log integrity compromised')
    }

    // Check token health
    const tokenHealth = await tokenVault.checkHealth()
    if (tokenHealth.expiredTokens > 0) {
      issues.push(`${tokenHealth.expiredTokens} expired tokens`)
    }

    // Update status
    if (issues.length === 0) {
      status.healthStatus = 'healthy'
    } else if (issues.length <= 2) {
      status.healthStatus = 'degraded'
    } else {
      status.healthStatus = 'unhealthy'
    }

    if (issues.length > 0) {
      await auditLog.log('health_check', `Health issues: ${issues.join(', ')}`, {
        details: { issues },
        riskLevel: issues.length > 2 ? 'high' : 'medium'
      })
    }

    return issues.length === 0
  }

  async function runBackup(task: ScheduledTask): Promise<boolean> {
    try {
      const timestamp = new Date().toISOString().split('T')[0]
      const backupDir = `~/.warp_open/backups/${timestamp}`

      await invoke('execute_shell', {
        command: `mkdir -p ${backupDir}`,
        cwd: undefined
      })

      // Backup localStorage keys
      const keysToBackup = [
        'warp_audit_log',
        'warp_token_registry',
        'warp_memory_files',
        'warp_memory_patterns',
        'warp_memory_solutions',
        'warp_improvements',
        'warp_daemon_tasks'
      ]

      for (const key of keysToBackup) {
        const data = localStorage.getItem(key)
        if (data) {
          await invoke('execute_shell', {
            command: `echo '${data.replace(/'/g, "\\'")}' > ${backupDir}/${key}.json`,
            cwd: undefined
          })
        }
      }

      await auditLog.log('backup', `Backup completed to ${backupDir}`, {
        riskLevel: 'low'
      })

      return true
    } catch {
      return false
    }
  }

  // ========================================================================
  // APPROVAL SYSTEM
  // ========================================================================

  /**
   * Request approval for an action
   */
  function requestApproval(
    type: TaskType,
    action: string,
    options: {
      target?: string
      description: string
      riskLevel: ApprovalRequest['riskLevel']
      data?: unknown
      expiresInHours?: number
    }
  ): ApprovalRequest {
    const request: ApprovalRequest = {
      id: `approval_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      type,
      action,
      target: options.target,
      description: options.description,
      riskLevel: options.riskLevel,
      data: options.data,
      expiresAt: options.expiresInHours
        ? new Date(Date.now() + options.expiresInHours * 60 * 60 * 1000)
        : undefined,
      status: 'pending'
    }

    approvals.value.push(request)
    saveApprovals(approvals.value)

    auditLog.log('approval_request', `Approval requested: ${action}`, {
      target: options.target,
      riskLevel: options.riskLevel
    })

    return request
  }

  /**
   * Approve a request
   */
  async function approve(approvalId: string): Promise<boolean> {
    const request = approvals.value.find(a => a.id === approvalId)
    if (!request || request.status !== 'pending') return false

    request.status = 'approved'
    saveApprovals(approvals.value)

    await auditLog.log('approval_granted', `Approved: ${request.action}`, {
      target: request.target,
      riskLevel: request.riskLevel
    })

    // Execute the approved action
    return executeApprovedAction(request)
  }

  /**
   * Reject a request
   */
  async function reject(approvalId: string, reason?: string): Promise<void> {
    const request = approvals.value.find(a => a.id === approvalId)
    if (!request || request.status !== 'pending') return

    request.status = 'rejected'
    saveApprovals(approvals.value)

    await auditLog.log('approval_denied', `Rejected: ${request.action}${reason ? ` - ${reason}` : ''}`, {
      target: request.target,
      riskLevel: 'low'
    })
  }

  /**
   * Execute an approved action
   */
  async function executeApprovedAction(request: ApprovalRequest): Promise<boolean> {
    try {
      switch (request.type) {
        case 'code_improve':
          const impData = request.data as { improvementId: string }
          if (impData?.improvementId) {
            return improver.applyImprovement(impData.improvementId)
          }
          break
        case 'account_anonymize':
          const accData = request.data as { accountId: string }
          if (accData?.accountId) {
            return accountAnonymizer.anonymizeAccount(accData.accountId)
          }
          break
        // Add more cases as needed
      }
      return false
    } catch {
      return false
    }
  }

  /**
   * Check for expired approvals
   */
  function checkApprovalExpiry(): void {
    const now = new Date()
    let changed = false

    for (const request of approvals.value) {
      if (request.status === 'pending' && request.expiresAt && request.expiresAt < now) {
        request.status = 'expired'
        changed = true
      }
    }

    if (changed) {
      saveApprovals(approvals.value)
    }
  }

  // ========================================================================
  // TASK MANAGEMENT
  // ========================================================================

  /**
   * Add a new scheduled task
   */
  function addTask(task: Omit<ScheduledTask, 'id' | 'stats'>): ScheduledTask {
    const newTask: ScheduledTask = {
      ...task,
      id: `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      stats: { runCount: 0, successCount: 0 }
    }

    tasks.value.push(newTask)
    saveTasks(tasks.value)
    return newTask
  }

  /**
   * Enable/disable a task
   */
  function setTaskEnabled(taskId: string, enabled: boolean): void {
    const task = tasks.value.find(t => t.id === taskId)
    if (task) {
      task.enabled = enabled
      saveTasks(tasks.value)
    }
  }

  /**
   * Manually trigger a task
   */
  async function triggerTask(taskId: string): Promise<boolean> {
    const task = tasks.value.find(t => t.id === taskId)
    if (!task) return false

    return runTask(task)
  }

  // ========================================================================
  // COMPUTED
  // ========================================================================

  const pendingApprovals = computed(() =>
    approvals.value.filter(a => a.status === 'pending')
  )

  const nextTask = computed(() => {
    const enabledTasks = tasks.value.filter(t => t.enabled)
    if (enabledTasks.length === 0) return null

    return enabledTasks.reduce((earliest, current) =>
      current.nextRun < earliest.nextRun ? current : earliest
    )
  })

  // Update status.nextScheduledTask
  watch(nextTask, (task) => {
    if (task) {
      status.nextScheduledTask = { name: task.name, at: task.nextRun }
    } else {
      status.nextScheduledTask = undefined
    }
  }, { immediate: true })

  return {
    // Lifecycle
    start,
    stop,
    isAlive,

    // State
    status: computed(() => status),
    tasks: computed(() => tasks.value),
    pendingApprovals,
    nextTask,

    // Task management
    addTask,
    setTaskEnabled,
    triggerTask,
    runTask,

    // Approval system
    requestApproval,
    approve,
    reject,

    // Subsystems (exposed for direct access)
    subsystems: {
      constitution,
      auditLog,
      memory,
      tokenVault,
      accountAnonymizer,
      emailCleaner,
      improver
    }
  }
}

export type UseDaemonOrchestratorReturn = ReturnType<typeof useDaemonOrchestrator>
