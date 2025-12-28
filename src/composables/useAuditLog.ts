/**
 * useAuditLog - Immutable Action Logging for Personal Automation Intelligence
 *
 * Every action taken by the autonomous system is logged here.
 * Logs are append-only and cryptographically chained for tamper detection.
 * This provides complete transparency and the ability to review/rollback.
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

// ============================================================================
// TYPES
// ============================================================================

export type ActionCategory =
  | 'file_read'
  | 'file_write'
  | 'file_delete'
  | 'code_modify'
  | 'git_operation'
  | 'web_search'
  | 'web_fetch'
  | 'email_read'
  | 'email_delete'
  | 'email_unsubscribe'
  | 'account_login'
  | 'account_modify'
  | 'token_use'
  | 'token_refresh'
  | 'approval_request'
  | 'approval_granted'
  | 'approval_denied'
  | 'constitution_check'
  | 'constitution_violation'
  | 'daemon_start'
  | 'daemon_stop'
  | 'checkin'
  | 'rollback'
  | 'error'

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface AuditEntry {
  id: string
  timestamp: Date
  category: ActionCategory
  action: string
  target?: string
  details?: Record<string, unknown>
  riskLevel: RiskLevel
  automated: boolean
  approved: boolean
  approvedBy?: 'auto' | 'user' | 'constitution'
  success: boolean
  error?: string
  rollbackData?: string // Serialized data needed to undo this action
  previousHash: string // Hash of previous entry (chain integrity)
  hash: string // Hash of this entry
}

export interface AuditStats {
  totalActions: number
  byCategory: Record<ActionCategory, number>
  byRiskLevel: Record<RiskLevel, number>
  successRate: number
  automatedRate: number
  violationCount: number
}

// ============================================================================
// STORAGE
// ============================================================================

const AUDIT_LOG_KEY = 'warp_audit_log'
const MAX_MEMORY_ENTRIES = 1000 // Keep last 1000 in memory, rest on disk

function loadAuditLog(): AuditEntry[] {
  try {
    const stored = localStorage.getItem(AUDIT_LOG_KEY)
    if (stored) {
      const entries = JSON.parse(stored)
      return entries.map((e: any) => ({
        ...e,
        timestamp: new Date(e.timestamp)
      }))
    }
  } catch {}
  return []
}

function saveAuditLog(entries: AuditEntry[]): void {
  try {
    // Only keep most recent in localStorage, archive older ones
    const recentEntries = entries.slice(-MAX_MEMORY_ENTRIES)
    localStorage.setItem(AUDIT_LOG_KEY, JSON.stringify(recentEntries))

    // Archive older entries to file system (append-only)
    if (entries.length > MAX_MEMORY_ENTRIES) {
      const toArchive = entries.slice(0, -MAX_MEMORY_ENTRIES)
      archiveEntries(toArchive)
    }
  } catch {}
}

async function archiveEntries(entries: AuditEntry[]): Promise<void> {
  try {
    const archivePath = `~/.warp_open/audit_archive_${Date.now()}.jsonl`
    const lines = entries.map(e => JSON.stringify(e)).join('\n')
    await invoke('execute_shell', {
      command: `mkdir -p ~/.warp_open && echo '${lines.replace(/'/g, "\\'")}' >> ${archivePath}`,
      cwd: undefined
    })
  } catch (error) {
    console.error('Failed to archive audit entries:', error)
  }
}

// ============================================================================
// HASHING
// ============================================================================

async function hashEntry(entry: Omit<AuditEntry, 'hash'>): Promise<string> {
  const data = JSON.stringify({
    ...entry,
    timestamp: entry.timestamp.toISOString()
  })

  // Use SubtleCrypto for hashing
  const encoder = new TextEncoder()
  const dataBuffer = encoder.encode(data)

  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  } catch {
    // Fallback for environments without SubtleCrypto
    return simpleHash(data)
  }
}

function simpleHash(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash
  }
  return Math.abs(hash).toString(16).padStart(16, '0')
}

function generateId(): string {
  return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useAuditLog() {
  const entries = ref<AuditEntry[]>(loadAuditLog())
  const isVerified = ref(true)

  /**
   * Log an action to the audit trail
   */
  async function log(
    category: ActionCategory,
    action: string,
    options: {
      target?: string
      details?: Record<string, unknown>
      riskLevel?: RiskLevel
      automated?: boolean
      approved?: boolean
      approvedBy?: 'auto' | 'user' | 'constitution'
      success?: boolean
      error?: string
      rollbackData?: string
    } = {}
  ): Promise<AuditEntry> {
    const previousEntry = entries.value[entries.value.length - 1]
    const previousHash = previousEntry?.hash || '0'.repeat(64)

    const entryWithoutHash: Omit<AuditEntry, 'hash'> = {
      id: generateId(),
      timestamp: new Date(),
      category,
      action,
      target: options.target,
      details: options.details,
      riskLevel: options.riskLevel || determineRiskLevel(category, action),
      automated: options.automated ?? true,
      approved: options.approved ?? true,
      approvedBy: options.approvedBy,
      success: options.success ?? true,
      error: options.error,
      rollbackData: options.rollbackData,
      previousHash
    }

    const hash = await hashEntry(entryWithoutHash)
    const entry: AuditEntry = { ...entryWithoutHash, hash }

    entries.value.push(entry)
    saveAuditLog(entries.value)

    return entry
  }

  /**
   * Determine risk level based on action type
   */
  function determineRiskLevel(category: ActionCategory, action: string): RiskLevel {
    // Critical actions
    if (
      category === 'file_delete' ||
      category === 'email_delete' ||
      category === 'account_modify' ||
      category === 'constitution_violation'
    ) {
      return 'critical'
    }

    // High risk actions
    if (
      category === 'code_modify' ||
      category === 'token_use' ||
      action.includes('password') ||
      action.includes('credential')
    ) {
      return 'high'
    }

    // Medium risk actions
    if (
      category === 'git_operation' ||
      category === 'file_write' ||
      category === 'email_unsubscribe' ||
      category === 'account_login'
    ) {
      return 'medium'
    }

    // Low risk actions
    return 'low'
  }

  /**
   * Verify the integrity of the audit chain
   */
  async function verifyChain(): Promise<{ valid: boolean; brokenAt?: number }> {
    for (let i = 1; i < entries.value.length; i++) {
      const entry = entries.value[i]
      const previousEntry = entries.value[i - 1]

      // Check chain link
      if (entry.previousHash !== previousEntry.hash) {
        isVerified.value = false
        return { valid: false, brokenAt: i }
      }

      // Verify entry hash
      const { hash, ...entryWithoutHash } = entry
      const computedHash = await hashEntry(entryWithoutHash as Omit<AuditEntry, 'hash'>)
      if (computedHash !== hash) {
        isVerified.value = false
        return { valid: false, brokenAt: i }
      }
    }

    isVerified.value = true
    return { valid: true }
  }

  /**
   * Get entries within a time range
   */
  function getEntries(options: {
    since?: Date
    until?: Date
    category?: ActionCategory
    riskLevel?: RiskLevel
    automated?: boolean
    limit?: number
  } = {}): AuditEntry[] {
    let result = entries.value

    if (options.since) {
      result = result.filter(e => e.timestamp >= options.since!)
    }
    if (options.until) {
      result = result.filter(e => e.timestamp <= options.until!)
    }
    if (options.category) {
      result = result.filter(e => e.category === options.category)
    }
    if (options.riskLevel) {
      result = result.filter(e => e.riskLevel === options.riskLevel)
    }
    if (options.automated !== undefined) {
      result = result.filter(e => e.automated === options.automated)
    }
    if (options.limit) {
      result = result.slice(-options.limit)
    }

    return result
  }

  /**
   * Get statistics about the audit log
   */
  function getStats(since?: Date): AuditStats {
    const relevantEntries = since
      ? entries.value.filter(e => e.timestamp >= since)
      : entries.value

    const byCategory: Record<string, number> = {}
    const byRiskLevel: Record<string, number> = {}
    let successCount = 0
    let automatedCount = 0
    let violationCount = 0

    for (const entry of relevantEntries) {
      byCategory[entry.category] = (byCategory[entry.category] || 0) + 1
      byRiskLevel[entry.riskLevel] = (byRiskLevel[entry.riskLevel] || 0) + 1
      if (entry.success) successCount++
      if (entry.automated) automatedCount++
      if (entry.category === 'constitution_violation') violationCount++
    }

    return {
      totalActions: relevantEntries.length,
      byCategory: byCategory as Record<ActionCategory, number>,
      byRiskLevel: byRiskLevel as Record<RiskLevel, number>,
      successRate: relevantEntries.length > 0 ? successCount / relevantEntries.length : 1,
      automatedRate: relevantEntries.length > 0 ? automatedCount / relevantEntries.length : 0,
      violationCount
    }
  }

  /**
   * Find entries that can be rolled back
   */
  function getRollbackCandidates(): AuditEntry[] {
    return entries.value.filter(e =>
      e.rollbackData &&
      e.success &&
      e.automated
    ).slice(-50) // Last 50 rollback-able actions
  }

  /**
   * Get the most recent actions for review
   */
  function getRecentActions(count: number = 10): AuditEntry[] {
    return entries.value.slice(-count)
  }

  /**
   * Export audit log to file
   */
  async function exportLog(filepath: string): Promise<void> {
    const data = JSON.stringify(entries.value, null, 2)
    await invoke('execute_shell', {
      command: `echo '${data.replace(/'/g, "\\'")}' > "${filepath}"`,
      cwd: undefined
    })
  }

  /**
   * Get actions pending review (high/critical risk automated actions)
   */
  const pendingReview = computed(() =>
    entries.value.filter(e =>
      e.automated &&
      (e.riskLevel === 'high' || e.riskLevel === 'critical') &&
      !e.details?.reviewed
    )
  )

  /**
   * Mark an action as reviewed
   */
  function markReviewed(entryId: string): void {
    const entry = entries.value.find(e => e.id === entryId)
    if (entry) {
      entry.details = { ...entry.details, reviewed: true, reviewedAt: new Date() }
      saveAuditLog(entries.value)
    }
  }

  return {
    // Core logging
    log,

    // Verification
    verifyChain,
    isVerified: computed(() => isVerified.value),

    // Queries
    getEntries,
    getStats,
    getRollbackCandidates,
    getRecentActions,
    pendingReview,

    // Actions
    markReviewed,
    exportLog,

    // Raw access (for debugging)
    entries: computed(() => entries.value),
    count: computed(() => entries.value.length)
  }
}

export type UseAuditLogReturn = ReturnType<typeof useAuditLog>
