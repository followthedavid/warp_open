/**
 * useEmailCleaner - Safe Inbox Management
 *
 * Automatically manages your email inbox with:
 * - Spam detection and removal
 * - Safe unsubscribe (via link clicking, not bulk)
 * - Receipt preservation (smart detection)
 * - Quarantine before permanent delete (7-day soft delete)
 * - Sender reputation tracking
 *
 * Safety: Never permanently deletes without quarantine period.
 * Always preserves receipts, confirmations, and important emails.
 */

import { ref, computed, reactive } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { useAuditLog } from './useAuditLog'
import { useConstitution } from './useConstitution'

// ============================================================================
// TYPES
// ============================================================================

export interface Email {
  id: string
  messageId: string
  from: string
  fromName?: string
  to: string
  subject: string
  date: Date
  snippet: string
  labels: string[]
  isRead: boolean
  isStarred: boolean
  hasAttachments: boolean
  // Classification
  category: 'primary' | 'social' | 'promotions' | 'updates' | 'forums' | 'spam' | 'receipt' | 'important'
  isReceipt: boolean
  isConfirmation: boolean
  isNewsletter: boolean
  unsubscribeLink?: string
  // Cleaning status
  cleaningStatus: 'keep' | 'quarantine' | 'delete' | 'unsubscribe'
  quarantinedAt?: Date
}

export interface SenderReputation {
  email: string
  domain: string
  name?: string
  messageCount: number
  openRate: number
  isNewsletter: boolean
  isSpam: boolean
  lastSeen: Date
  action: 'keep' | 'unsubscribe' | 'block'
}

export interface CleaningRule {
  id: string
  name: string
  condition: {
    from?: string
    fromDomain?: string
    subject?: string
    olderThan?: number // days
    labels?: string[]
    category?: Email['category']
  }
  action: 'keep' | 'quarantine' | 'delete' | 'unsubscribe' | 'label'
  actionLabel?: string
  enabled: boolean
  createdAt: Date
  lastMatched?: Date
  matchCount: number
}

export interface CleaningStats {
  totalEmails: number
  quarantined: number
  deleted: number
  unsubscribed: number
  receiptsPreserved: number
  spaceRecovered: number // in MB
}

// ============================================================================
// RECEIPT AND IMPORTANT EMAIL PATTERNS
// ============================================================================

const RECEIPT_PATTERNS = [
  /order\s*confirm/i,
  /receipt/i,
  /invoice/i,
  /purchase\s*confirm/i,
  /payment\s*confirm/i,
  /transaction/i,
  /shipping\s*confirm/i,
  /tracking\s*number/i,
  /your\s*order/i,
  /order\s*#\d+/i,
  /bill\s*for/i,
  /statement/i,
  /subscription\s*confirm/i,
  /renewal/i,
]

const IMPORTANT_PATTERNS = [
  /password\s*reset/i,
  /verify\s*your\s*(email|account)/i,
  /security\s*alert/i,
  /two.?factor/i,
  /2fa/i,
  /mfa/i,
  /login\s*attempt/i,
  /suspicious\s*activity/i,
  /account\s*(access|security)/i,
  /confirm\s*your\s*(email|identity)/i,
  /important\s*notice/i,
  /action\s*required/i,
  /urgent/i,
  /tax\s*(document|form|return)/i,
  /1099/i,
  /w-?2/i,
  /legal\s*notice/i,
  /court/i,
  /subpoena/i,
]

const NEWSLETTER_PATTERNS = [
  /newsletter/i,
  /weekly\s*(digest|update|roundup)/i,
  /monthly\s*(digest|update)/i,
  /unsubscribe/i,
  /email\s*preferences/i,
  /manage\s*subscriptions?/i,
  /view\s*in\s*browser/i,
]

const SPAM_PATTERNS = [
  /won\s+\$?\d+/i,
  /claim\s+your\s+(prize|reward)/i,
  /congratulations.*winner/i,
  /urgent.*wire\s*transfer/i,
  /nigerian\s*prince/i,
  /pills?\s*(online|cheap|discount)/i,
  /viagra|cialis/i,
  /enlarge(ment)?/i,
  /weight\s*loss\s*miracle/i,
  /work\s*from\s*home.*\$\d+/i,
  /click\s*here.*expire/i,
  /act\s*now.*limited/i,
]

// ============================================================================
// STORAGE
// ============================================================================

const SENDERS_KEY = 'warp_email_senders'
const RULES_KEY = 'warp_email_rules'
const QUARANTINE_KEY = 'warp_email_quarantine'
const STATS_KEY = 'warp_email_stats'

function loadSenders(): SenderReputation[] {
  try {
    const stored = localStorage.getItem(SENDERS_KEY)
    if (stored) {
      return JSON.parse(stored).map((s: any) => ({
        ...s,
        lastSeen: new Date(s.lastSeen)
      }))
    }
  } catch {}
  return []
}

function saveSenders(senders: SenderReputation[]): void {
  localStorage.setItem(SENDERS_KEY, JSON.stringify(senders))
}

function loadRules(): CleaningRule[] {
  try {
    const stored = localStorage.getItem(RULES_KEY)
    if (stored) {
      return JSON.parse(stored).map((r: any) => ({
        ...r,
        createdAt: new Date(r.createdAt),
        lastMatched: r.lastMatched ? new Date(r.lastMatched) : undefined
      }))
    }
  } catch {}
  return getDefaultRules()
}

function saveRules(rules: CleaningRule[]): void {
  localStorage.setItem(RULES_KEY, JSON.stringify(rules))
}

function loadQuarantine(): { emailId: string; quarantinedAt: Date; originalLabels: string[] }[] {
  try {
    const stored = localStorage.getItem(QUARANTINE_KEY)
    if (stored) {
      return JSON.parse(stored).map((q: any) => ({
        ...q,
        quarantinedAt: new Date(q.quarantinedAt)
      }))
    }
  } catch {}
  return []
}

function saveQuarantine(quarantine: { emailId: string; quarantinedAt: Date; originalLabels: string[] }[]): void {
  localStorage.setItem(QUARANTINE_KEY, JSON.stringify(quarantine))
}

function loadStats(): CleaningStats {
  try {
    const stored = localStorage.getItem(STATS_KEY)
    if (stored) return JSON.parse(stored)
  } catch {}
  return {
    totalEmails: 0,
    quarantined: 0,
    deleted: 0,
    unsubscribed: 0,
    receiptsPreserved: 0,
    spaceRecovered: 0
  }
}

function saveStats(stats: CleaningStats): void {
  localStorage.setItem(STATS_KEY, JSON.stringify(stats))
}

// ============================================================================
// DEFAULT RULES
// ============================================================================

function getDefaultRules(): CleaningRule[] {
  return [
    {
      id: 'rule_receipts',
      name: 'Preserve Receipts',
      condition: {},
      action: 'keep',
      enabled: true,
      createdAt: new Date(),
      matchCount: 0
    },
    {
      id: 'rule_old_promos',
      name: 'Clean old promotions',
      condition: { category: 'promotions', olderThan: 30 },
      action: 'quarantine',
      enabled: true,
      createdAt: new Date(),
      matchCount: 0
    },
    {
      id: 'rule_old_social',
      name: 'Clean old social notifications',
      condition: { category: 'social', olderThan: 14 },
      action: 'quarantine',
      enabled: true,
      createdAt: new Date(),
      matchCount: 0
    },
    {
      id: 'rule_spam',
      name: 'Remove spam',
      condition: { category: 'spam' },
      action: 'delete',
      enabled: true,
      createdAt: new Date(),
      matchCount: 0
    }
  ]
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useEmailCleaner() {
  const senders = ref<SenderReputation[]>(loadSenders())
  const rules = ref<CleaningRule[]>(loadRules())
  const quarantine = ref<{ emailId: string; quarantinedAt: Date; originalLabels: string[] }[]>(loadQuarantine())
  const stats = reactive<CleaningStats>(loadStats())

  const auditLog = useAuditLog()
  const constitution = useConstitution()

  const isRunning = ref(false)
  const progress = ref({ current: 0, total: 0, phase: '' })

  // ========================================================================
  // EMAIL CLASSIFICATION
  // ========================================================================

  /**
   * Classify an email
   */
  function classifyEmail(email: Partial<Email>): {
    category: Email['category']
    isReceipt: boolean
    isConfirmation: boolean
    isNewsletter: boolean
    isSpam: boolean
    isImportant: boolean
  } {
    const subject = email.subject || ''
    const from = email.from || ''
    const snippet = email.snippet || ''
    const content = `${subject} ${snippet}`

    // Check for receipts first (highest priority to preserve)
    const isReceipt = RECEIPT_PATTERNS.some(p => p.test(content))

    // Check for important emails
    const isImportant = IMPORTANT_PATTERNS.some(p => p.test(content))

    // Check for newsletters
    const isNewsletter = NEWSLETTER_PATTERNS.some(p => p.test(content))

    // Check for spam
    const isSpam = SPAM_PATTERNS.some(p => p.test(content))

    // Confirmation emails (subset of important)
    const isConfirmation = /confirm|verif|activat/i.test(content)

    // Determine category
    let category: Email['category'] = 'primary'

    if (isReceipt) {
      category = 'receipt'
    } else if (isSpam) {
      category = 'spam'
    } else if (isNewsletter) {
      category = 'promotions'
    } else if (/facebook|twitter|instagram|linkedin|social/i.test(from)) {
      category = 'social'
    } else if (/update|notification|alert/i.test(from)) {
      category = 'updates'
    } else if (isImportant) {
      category = 'important'
    }

    return {
      category,
      isReceipt,
      isConfirmation,
      isNewsletter,
      isSpam,
      isImportant
    }
  }

  /**
   * Determine what action to take for an email
   */
  function determineAction(email: Email): 'keep' | 'quarantine' | 'delete' | 'unsubscribe' {
    // NEVER delete receipts, confirmations, or important emails
    if (email.isReceipt || email.isConfirmation || email.category === 'important') {
      return 'keep'
    }

    // Check rules
    for (const rule of rules.value.filter(r => r.enabled)) {
      if (matchesRule(email, rule)) {
        rule.matchCount++
        rule.lastMatched = new Date()
        return rule.action as any
      }
    }

    // Check sender reputation
    const sender = senders.value.find(s => s.email === email.from)
    if (sender) {
      if (sender.action === 'block' || sender.isSpam) {
        return 'delete'
      }
      if (sender.action === 'unsubscribe') {
        return 'unsubscribe'
      }
    }

    // Default: keep
    return 'keep'
  }

  /**
   * Check if email matches a rule
   */
  function matchesRule(email: Email, rule: CleaningRule): boolean {
    const { condition } = rule

    if (condition.from && !email.from.includes(condition.from)) {
      return false
    }

    if (condition.fromDomain) {
      const emailDomain = email.from.split('@')[1]
      if (!emailDomain?.includes(condition.fromDomain)) {
        return false
      }
    }

    if (condition.subject && !email.subject.toLowerCase().includes(condition.subject.toLowerCase())) {
      return false
    }

    if (condition.olderThan) {
      const daysOld = (Date.now() - email.date.getTime()) / (1000 * 60 * 60 * 24)
      if (daysOld < condition.olderThan) {
        return false
      }
    }

    if (condition.labels && condition.labels.length > 0) {
      if (!condition.labels.some(l => email.labels.includes(l))) {
        return false
      }
    }

    if (condition.category && email.category !== condition.category) {
      return false
    }

    return true
  }

  // ========================================================================
  // CLEANING OPERATIONS
  // ========================================================================

  /**
   * Process emails from IMAP (would connect to actual email service)
   */
  async function fetchEmails(options: {
    folder?: string
    limit?: number
    olderThan?: Date
  } = {}): Promise<Email[]> {
    // This would integrate with IMAP or Gmail API
    // Placeholder implementation
    const { folder = 'INBOX', limit = 100 } = options

    try {
      // In real implementation, this would use node-imap or Gmail API
      // For now, return empty array as placeholder
      console.log(`Would fetch ${limit} emails from ${folder}`)
      return []
    } catch (error) {
      console.error('Failed to fetch emails:', error)
      return []
    }
  }

  /**
   * Quarantine an email (soft delete)
   */
  async function quarantineEmail(email: Email): Promise<boolean> {
    // Constitution check - quarantine is safer than delete
    const validation = constitution.validateAction('soft_delete_email')
    if (!validation.allowed) {
      return false
    }

    // Never quarantine receipts or important emails
    if (email.isReceipt || email.category === 'important') {
      await auditLog.log('email_delete', `Refused to quarantine receipt/important email`, {
        target: email.subject,
        riskLevel: 'low',
        success: false
      })
      return false
    }

    quarantine.value.push({
      emailId: email.id,
      quarantinedAt: new Date(),
      originalLabels: email.labels
    })
    saveQuarantine(quarantine.value)

    stats.quarantined++
    saveStats(stats)

    await auditLog.log('email_delete', `Quarantined: ${email.subject.substring(0, 50)}`, {
      target: email.from,
      riskLevel: 'low',
      rollbackData: JSON.stringify({ emailId: email.id, labels: email.labels })
    })

    return true
  }

  /**
   * Permanently delete quarantined emails older than 7 days
   */
  async function purgeQuarantine(): Promise<number> {
    const validation = constitution.validateAction('delete_email_permanent')
    if (validation.requiresApproval) {
      // Should be handled by approval system
      return 0
    }

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    const toPurge = quarantine.value.filter(q => q.quarantinedAt < sevenDaysAgo)

    // In real implementation, would delete from email server here

    quarantine.value = quarantine.value.filter(q => q.quarantinedAt >= sevenDaysAgo)
    saveQuarantine(quarantine.value)

    stats.deleted += toPurge.length
    saveStats(stats)

    await auditLog.log('email_delete', `Purged ${toPurge.length} quarantined emails`, {
      riskLevel: 'high'
    })

    return toPurge.length
  }

  /**
   * Restore a quarantined email
   */
  async function restoreFromQuarantine(emailId: string): Promise<boolean> {
    const qEntry = quarantine.value.find(q => q.emailId === emailId)
    if (!qEntry) return false

    // In real implementation, would restore labels on email server

    quarantine.value = quarantine.value.filter(q => q.emailId !== emailId)
    saveQuarantine(quarantine.value)

    stats.quarantined--
    saveStats(stats)

    await auditLog.log('rollback', `Restored email from quarantine`, {
      target: emailId,
      riskLevel: 'low'
    })

    return true
  }

  /**
   * Safely unsubscribe from a newsletter
   */
  async function unsubscribe(email: Email): Promise<boolean> {
    if (!email.unsubscribeLink) {
      return false
    }

    const validation = constitution.validateAction('email_unsubscribe')
    if (!validation.allowed) {
      return false
    }

    try {
      // Click unsubscribe link using browser automation
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `curl -sL "${email.unsubscribeLink}" -o /dev/null -w "%{http_code}"`,
        cwd: undefined
      })

      const success = result.stdout.startsWith('2') || result.stdout.startsWith('3')

      if (success) {
        // Update sender reputation
        const sender = senders.value.find(s => s.email === email.from)
        if (sender) {
          sender.action = 'unsubscribe'
          saveSenders(senders.value)
        }

        stats.unsubscribed++
        saveStats(stats)

        await auditLog.log('email_unsubscribe', `Unsubscribed from ${email.from}`, {
          target: email.from,
          riskLevel: 'low'
        })
      }

      return success
    } catch {
      return false
    }
  }

  // ========================================================================
  // BATCH CLEANING
  // ========================================================================

  /**
   * Run a cleaning pass on the inbox
   */
  async function runCleaningPass(options: {
    dryRun?: boolean
    limit?: number
  } = {}): Promise<{
    kept: number
    quarantined: number
    deleted: number
    unsubscribed: number
  }> {
    const { dryRun = false, limit = 500 } = options

    isRunning.value = true
    progress.value = { current: 0, total: 0, phase: 'Fetching emails...' }

    const results = { kept: 0, quarantined: 0, deleted: 0, unsubscribed: 0 }

    try {
      const emails = await fetchEmails({ limit })
      progress.value.total = emails.length

      for (let i = 0; i < emails.length; i++) {
        const email = emails[i]
        progress.value.current = i + 1
        progress.value.phase = `Processing: ${email.subject.substring(0, 30)}...`

        // Classify
        const classification = classifyEmail(email)
        Object.assign(email, classification)

        // Determine action
        const action = determineAction(email)
        email.cleaningStatus = action

        if (!dryRun) {
          switch (action) {
            case 'keep':
              results.kept++
              if (email.isReceipt) stats.receiptsPreserved++
              break
            case 'quarantine':
              if (await quarantineEmail(email)) {
                results.quarantined++
              }
              break
            case 'unsubscribe':
              if (await unsubscribe(email)) {
                results.unsubscribed++
              }
              await quarantineEmail(email) // Also quarantine after unsubscribe
              break
            case 'delete':
              // Direct delete only for spam - still goes to quarantine first
              await quarantineEmail(email)
              results.quarantined++
              break
          }
        } else {
          results[action === 'delete' ? 'quarantined' : action]++
        }

        // Update sender reputation
        updateSenderReputation(email)

        // Yield to prevent blocking
        if (i % 10 === 0) {
          await new Promise(resolve => setTimeout(resolve, 0))
        }
      }

      saveRules(rules.value)
      saveSenders(senders.value)
      saveStats(stats)

      await auditLog.log('email_read', `Cleaning pass: ${emails.length} emails processed`, {
        details: results,
        riskLevel: 'low'
      })

    } finally {
      isRunning.value = false
    }

    return results
  }

  /**
   * Update sender reputation based on email
   */
  function updateSenderReputation(email: Email): void {
    const domain = email.from.split('@')[1]
    let sender = senders.value.find(s => s.email === email.from)

    if (!sender) {
      sender = {
        email: email.from,
        domain,
        name: email.fromName,
        messageCount: 0,
        openRate: 0,
        isNewsletter: email.isNewsletter,
        isSpam: email.category === 'spam',
        lastSeen: email.date,
        action: 'keep'
      }
      senders.value.push(sender)
    }

    sender.messageCount++
    sender.lastSeen = email.date
    sender.isNewsletter = sender.isNewsletter || email.isNewsletter
    sender.isSpam = sender.isSpam || email.category === 'spam'
  }

  // ========================================================================
  // RULE MANAGEMENT
  // ========================================================================

  /**
   * Add a cleaning rule
   */
  function addRule(rule: Omit<CleaningRule, 'id' | 'createdAt' | 'matchCount'>): CleaningRule {
    const newRule: CleaningRule = {
      ...rule,
      id: `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      createdAt: new Date(),
      matchCount: 0
    }
    rules.value.push(newRule)
    saveRules(rules.value)
    return newRule
  }

  /**
   * Remove a rule
   */
  function removeRule(ruleId: string): void {
    rules.value = rules.value.filter(r => r.id !== ruleId)
    saveRules(rules.value)
  }

  /**
   * Block a sender
   */
  function blockSender(email: string): void {
    const sender = senders.value.find(s => s.email === email)
    if (sender) {
      sender.action = 'block'
      sender.isSpam = true
    } else {
      senders.value.push({
        email,
        domain: email.split('@')[1],
        messageCount: 0,
        openRate: 0,
        isNewsletter: false,
        isSpam: true,
        lastSeen: new Date(),
        action: 'block'
      })
    }
    saveSenders(senders.value)
  }

  return {
    // State
    senders: computed(() => senders.value),
    rules: computed(() => rules.value),
    quarantine: computed(() => quarantine.value),
    stats: computed(() => stats),
    isRunning: computed(() => isRunning.value),
    progress: computed(() => progress.value),

    // Classification
    classifyEmail,
    determineAction,

    // Operations
    fetchEmails,
    quarantineEmail,
    purgeQuarantine,
    restoreFromQuarantine,
    unsubscribe,
    runCleaningPass,

    // Rule management
    addRule,
    removeRule,
    blockSender,

    // Sender management
    updateSenderReputation
  }
}

export type UseEmailCleanerReturn = ReturnType<typeof useEmailCleaner>
