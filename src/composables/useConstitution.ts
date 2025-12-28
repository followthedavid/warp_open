/**
 * useConstitution - Hardcoded Safety Rules for Personal Automation Intelligence
 *
 * These rules CANNOT be overridden by prompts, user requests during automation,
 * or any external input. They are the fundamental constraints that make the
 * system trustworthy with intimate access.
 *
 * Philosophy: "Intimacy without leverage" - knows everything, can't weaponize it
 */

import { ref, computed } from 'vue'

// ============================================================================
// IMMUTABLE CONSTITUTIONAL RULES
// These are hardcoded and cannot be modified at runtime
// ============================================================================

/**
 * Data that can NEVER leave the local machine under any circumstances
 */
export const NEVER_TRANSMIT_PATTERNS = Object.freeze([
  // Source code and IP
  /\.(ts|js|py|rs|go|java|cpp|c|h|vue|svelte|jsx|tsx)$/i,
  /package\.json$/i,
  /Cargo\.toml$/i,
  /\.git\//,

  // Personal documents
  /\.(pdf|doc|docx|odt|rtf)$/i,
  /\.(jpg|jpeg|png|gif|heic|raw|cr2)$/i,
  /\.(mp4|mov|avi|mkv)$/i,

  // Financial
  /bank/i,
  /tax/i,
  /statement/i,
  /invoice/i,
  /1099/i,
  /w-?2/i,

  // Medical
  /medical/i,
  /health/i,
  /prescription/i,
  /diagnosis/i,
  /hipaa/i,

  // Secrets
  /\.env/,
  /\.pem$/,
  /\.key$/,
  /id_rsa/,
  /id_ed25519/,
  /\.ssh\//,
  /credentials/i,
  /secrets/i,

  // Personal
  /diary/i,
  /journal/i,
  /personal/i,
  /private/i,
  /passport/i,
  /license/i,
  /ssn/i,
  /social.?security/i,
])

/**
 * Directories that are completely off-limits for transmission
 */
export const BLOCKED_DIRECTORIES = Object.freeze([
  '~/.ssh',
  '~/.gnupg',
  '~/.aws',
  '~/.config/gcloud',
  '~/Documents',
  '~/Pictures',
  '~/Movies',
  '~/Desktop',
  '~/Downloads',
  '~/.local/share/keyrings',
  '/private',
  '/etc/passwd',
  '/etc/shadow',
])

/**
 * Allowlisted API endpoints for token/API usage
 */
export const ALLOWLISTED_ENDPOINTS = Object.freeze([
  // Git platforms
  'api.github.com',
  'gitlab.com/api',
  'bitbucket.org/api',

  // Package registries
  'registry.npmjs.org',
  'pypi.org',
  'crates.io',

  // Apple services
  'appleid.apple.com',
  'icloud.com',
  'apple.com/auth',

  // Password managers (for sync)
  'lastpass.com/api',

  // Search (anonymous)
  'duckduckgo.com',
  'html.duckduckgo.com',

  // LLM (local only)
  'localhost:11434', // Ollama
  '127.0.0.1:11434',
])

/**
 * Actions that ALWAYS require human approval
 */
export const REQUIRES_APPROVAL = Object.freeze([
  'delete_file_permanent',
  'delete_email_permanent',
  'send_email',
  'make_purchase',
  'change_password',
  'revoke_token',
  'grant_permission',
  'modify_constitution', // This will always fail anyway
  'access_financial',
  'share_externally',
  'execute_unknown_binary',
  'modify_system_files',
  'install_package_global',
])

/**
 * Actions allowed without approval (low risk, reversible)
 */
export const AUTO_APPROVED_ACTIONS = Object.freeze([
  'read_file',
  'index_file',
  'search_local',
  'search_web_anonymous',
  'format_code',
  'add_types',
  'add_documentation',
  'create_branch',
  'run_tests',
  'lint_code',
  'update_lockfile',
  'soft_delete_email', // Moves to trash, not permanent
  'unsubscribe_email', // Via link click
])

/**
 * PII patterns to strip from web searches
 */
export const PII_PATTERNS = Object.freeze([
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
  /\b\d{3}-\d{2}-\d{4}\b/, // SSN
  /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/, // Phone
  /\b\d{16}\b/, // Credit card
  /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, // Credit card with spaces
  /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/, // Visa/MC
  /\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b/i, // UK postcode
  /\b\d{5}(?:-\d{4})?\b/, // US ZIP
])

/**
 * Queries that should be flagged for review
 */
export const FLAGGED_QUERY_PATTERNS = Object.freeze([
  /how to (hack|break into|exploit)/i,
  /bypass (security|authentication|password)/i,
  /(illegal|pirate|torrent|crack)\s+(download|software)/i,
  /\b(drugs?|weapons?|explosives?)\b.*\b(buy|purchase|make)\b/i,
  /personal.*(information|data).*someone/i,
  /track.*person/i,
  /spy.*on/i,
])

// ============================================================================
// CONSTITUTION COMPOSABLE
// ============================================================================

export interface ConstitutionViolation {
  rule: string
  action: string
  data?: string
  timestamp: Date
  blocked: boolean
}

export function useConstitution() {
  const violations = ref<ConstitutionViolation[]>([])
  const lastCheck = ref<Date>(new Date())

  /**
   * Check if data can be transmitted externally
   */
  function canTransmit(filepath: string, destination: string): { allowed: boolean; reason?: string } {
    // Check blocked directories
    for (const dir of BLOCKED_DIRECTORIES) {
      const expandedDir = dir.replace('~', process.env.HOME || '')
      if (filepath.startsWith(expandedDir)) {
        logViolation('BLOCKED_DIRECTORY', `transmit ${filepath}`, filepath)
        return { allowed: false, reason: `Directory ${dir} is protected` }
      }
    }

    // Check file patterns
    for (const pattern of NEVER_TRANSMIT_PATTERNS) {
      if (pattern.test(filepath)) {
        logViolation('NEVER_TRANSMIT', `transmit ${filepath}`, filepath)
        return { allowed: false, reason: `File matches protected pattern: ${pattern}` }
      }
    }

    // Check destination is allowlisted
    const isAllowlisted = ALLOWLISTED_ENDPOINTS.some(endpoint =>
      destination.includes(endpoint)
    )

    if (!isAllowlisted) {
      logViolation('ENDPOINT_NOT_ALLOWLISTED', `transmit to ${destination}`, destination)
      return { allowed: false, reason: `Endpoint ${destination} is not allowlisted` }
    }

    return { allowed: true }
  }

  /**
   * Check if an action requires approval
   */
  function requiresApproval(action: string): boolean {
    return REQUIRES_APPROVAL.includes(action as any)
  }

  /**
   * Check if an action is auto-approved
   */
  function isAutoApproved(action: string): boolean {
    return AUTO_APPROVED_ACTIONS.includes(action as any)
  }

  /**
   * Sanitize a search query by removing PII
   */
  function sanitizeQuery(query: string): { sanitized: string; piiFound: boolean } {
    let sanitized = query
    let piiFound = false

    for (const pattern of PII_PATTERNS) {
      if (pattern.test(sanitized)) {
        piiFound = true
        sanitized = sanitized.replace(pattern, '[REDACTED]')
      }
    }

    return { sanitized, piiFound }
  }

  /**
   * Check if a query should be flagged for review
   */
  function shouldFlagQuery(query: string): { flagged: boolean; reason?: string } {
    for (const pattern of FLAGGED_QUERY_PATTERNS) {
      if (pattern.test(query)) {
        return { flagged: true, reason: `Query matches sensitive pattern` }
      }
    }
    return { flagged: false }
  }

  /**
   * Validate an action against the constitution
   */
  function validateAction(
    action: string,
    target?: string,
    destination?: string
  ): {
    allowed: boolean
    requiresApproval: boolean
    reason?: string
  } {
    // Check if action is explicitly blocked
    if (action === 'modify_constitution') {
      logViolation('CONSTITUTION_MODIFICATION', action)
      return {
        allowed: false,
        requiresApproval: false,
        reason: 'Constitutional rules cannot be modified'
      }
    }

    // Check transmission rules
    if (action.includes('transmit') || action.includes('send') || action.includes('upload')) {
      if (target && destination) {
        const canTx = canTransmit(target, destination)
        if (!canTx.allowed) {
          return { allowed: false, requiresApproval: false, reason: canTx.reason }
        }
      }
    }

    // Check if requires approval
    if (requiresApproval(action)) {
      return { allowed: true, requiresApproval: true }
    }

    // Auto-approved actions
    if (isAutoApproved(action)) {
      return { allowed: true, requiresApproval: false }
    }

    // Unknown actions require approval by default
    return { allowed: true, requiresApproval: true, reason: 'Unknown action requires approval' }
  }

  /**
   * Log a constitutional violation
   */
  function logViolation(rule: string, action: string, data?: string) {
    const violation: ConstitutionViolation = {
      rule,
      action,
      data: data?.substring(0, 100), // Truncate for safety
      timestamp: new Date(),
      blocked: true
    }
    violations.value.push(violation)

    // Also log to console for debugging
    console.warn(`[CONSTITUTION] Violation: ${rule} - ${action}`)
  }

  /**
   * Get violation history
   */
  function getViolations(since?: Date): ConstitutionViolation[] {
    if (since) {
      return violations.value.filter(v => v.timestamp >= since)
    }
    return violations.value
  }

  /**
   * Check if system is operating within constitutional bounds
   */
  const isCompliant = computed(() => {
    const recentViolations = getViolations(
      new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
    )
    return recentViolations.length === 0
  })

  /**
   * Dead man's switch - call this regularly to keep system running
   */
  function checkin() {
    lastCheck.value = new Date()
  }

  /**
   * Check if dead man's switch has been triggered
   */
  function isAlive(maxHours: number = 24): boolean {
    const hoursSinceCheck = (Date.now() - lastCheck.value.getTime()) / (1000 * 60 * 60)
    return hoursSinceCheck < maxHours
  }

  return {
    // Validation
    canTransmit,
    requiresApproval,
    isAutoApproved,
    sanitizeQuery,
    shouldFlagQuery,
    validateAction,

    // Monitoring
    violations: computed(() => violations.value),
    getViolations,
    isCompliant,

    // Dead man's switch
    checkin,
    isAlive,

    // Constants (exposed for UI/debugging)
    ALLOWLISTED_ENDPOINTS,
    REQUIRES_APPROVAL,
    AUTO_APPROVED_ACTIONS,
  }
}

export type UseConstitutionReturn = ReturnType<typeof useConstitution>
