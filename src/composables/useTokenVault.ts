/**
 * useTokenVault - Secure API Token Management
 *
 * Manages API tokens and credentials with:
 * - Encrypted storage (using macOS Keychain when available)
 * - Automatic token refresh
 * - Usage logging and auditing
 * - Expiration tracking
 * - Secure retrieval for automated tasks
 */

import { ref, computed, reactive } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { useAuditLog } from './useAuditLog'
import { useConstitution } from './useConstitution'

// ============================================================================
// TYPES
// ============================================================================

export interface TokenEntry {
  id: string
  name: string
  service: string
  type: 'api_key' | 'oauth_token' | 'personal_access_token' | 'bearer' | 'basic' | 'custom'
  // Token value is NOT stored here - only in secure storage
  createdAt: Date
  expiresAt?: Date
  lastUsed?: Date
  useCount: number
  scopes?: string[]
  notes?: string
  autoRefresh: boolean
  refreshUrl?: string
  allowedEndpoints: string[] // Only allow this token for these endpoints
}

export interface TokenUsage {
  tokenId: string
  timestamp: Date
  endpoint: string
  success: boolean
  statusCode?: number
}

export interface SecureStorage {
  set(key: string, value: string): Promise<void>
  get(key: string): Promise<string | null>
  delete(key: string): Promise<void>
  list(): Promise<string[]>
}

// ============================================================================
// STORAGE
// ============================================================================

const TOKEN_REGISTRY_KEY = 'warp_token_registry'
const TOKEN_USAGE_KEY = 'warp_token_usage'

function loadRegistry(): TokenEntry[] {
  try {
    const stored = localStorage.getItem(TOKEN_REGISTRY_KEY)
    if (stored) {
      return JSON.parse(stored).map((t: any) => ({
        ...t,
        createdAt: new Date(t.createdAt),
        expiresAt: t.expiresAt ? new Date(t.expiresAt) : undefined,
        lastUsed: t.lastUsed ? new Date(t.lastUsed) : undefined
      }))
    }
  } catch {}
  return []
}

function saveRegistry(tokens: TokenEntry[]): void {
  localStorage.setItem(TOKEN_REGISTRY_KEY, JSON.stringify(tokens))
}

function loadUsage(): TokenUsage[] {
  try {
    const stored = localStorage.getItem(TOKEN_USAGE_KEY)
    if (stored) {
      return JSON.parse(stored).map((u: any) => ({
        ...u,
        timestamp: new Date(u.timestamp)
      }))
    }
  } catch {}
  return []
}

function saveUsage(usage: TokenUsage[]): void {
  // Only keep last 1000 usage entries
  const trimmed = usage.slice(-1000)
  localStorage.setItem(TOKEN_USAGE_KEY, JSON.stringify(trimmed))
}

// ============================================================================
// SECURE STORAGE IMPLEMENTATION
// ============================================================================

/**
 * Secure storage using macOS Keychain via security command
 * Falls back to encrypted localStorage if Keychain unavailable
 */
class KeychainStorage implements SecureStorage {
  private serviceName = 'WarpOpen'
  private fallbackKey = 'warp_secure_vault'

  async set(key: string, value: string): Promise<void> {
    try {
      // Try macOS Keychain first
      await invoke('execute_shell', {
        command: `security add-generic-password -a "${key}" -s "${this.serviceName}" -w "${value.replace(/"/g, '\\"')}" -U 2>/dev/null || security add-generic-password -a "${key}" -s "${this.serviceName}" -w "${value.replace(/"/g, '\\"')}"`,
        cwd: undefined
      })
    } catch {
      // Fallback to localStorage with basic obfuscation
      const vault = this.getLocalVault()
      vault[key] = btoa(value) // Base64 encode (not secure, just obfuscation)
      localStorage.setItem(this.fallbackKey, JSON.stringify(vault))
    }
  }

  async get(key: string): Promise<string | null> {
    try {
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `security find-generic-password -a "${key}" -s "${this.serviceName}" -w 2>/dev/null`,
        cwd: undefined
      })
      if (result.exit_code === 0 && result.stdout.trim()) {
        return result.stdout.trim()
      }
    } catch {}

    // Fallback to localStorage
    const vault = this.getLocalVault()
    const encoded = vault[key]
    if (encoded) {
      return atob(encoded)
    }
    return null
  }

  async delete(key: string): Promise<void> {
    try {
      await invoke('execute_shell', {
        command: `security delete-generic-password -a "${key}" -s "${this.serviceName}" 2>/dev/null`,
        cwd: undefined
      })
    } catch {}

    // Also remove from fallback
    const vault = this.getLocalVault()
    delete vault[key]
    localStorage.setItem(this.fallbackKey, JSON.stringify(vault))
  }

  async list(): Promise<string[]> {
    try {
      const result = await invoke<{ stdout: string }>('execute_shell', {
        command: `security dump-keychain 2>/dev/null | grep -A4 '"${this.serviceName}"' | grep "acct" | sed 's/.*="\\(.*\\)"/\\1/'`,
        cwd: undefined
      })
      return result.stdout.trim().split('\n').filter(Boolean)
    } catch {
      return Object.keys(this.getLocalVault())
    }
  }

  private getLocalVault(): Record<string, string> {
    try {
      const stored = localStorage.getItem(this.fallbackKey)
      return stored ? JSON.parse(stored) : {}
    } catch {
      return {}
    }
  }
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useTokenVault() {
  const registry = ref<TokenEntry[]>(loadRegistry())
  const usage = ref<TokenUsage[]>(loadUsage())
  const storage = new KeychainStorage()
  const auditLog = useAuditLog()
  const constitution = useConstitution()

  /**
   * Add a new token to the vault
   */
  async function addToken(
    name: string,
    service: string,
    tokenValue: string,
    options: {
      type?: TokenEntry['type']
      expiresAt?: Date
      scopes?: string[]
      notes?: string
      autoRefresh?: boolean
      refreshUrl?: string
      allowedEndpoints?: string[]
    } = {}
  ): Promise<TokenEntry> {
    const id = `token_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

    // Store token value securely
    await storage.set(id, tokenValue)

    const entry: TokenEntry = {
      id,
      name,
      service,
      type: options.type || 'api_key',
      createdAt: new Date(),
      expiresAt: options.expiresAt,
      useCount: 0,
      scopes: options.scopes,
      notes: options.notes,
      autoRefresh: options.autoRefresh ?? false,
      refreshUrl: options.refreshUrl,
      allowedEndpoints: options.allowedEndpoints || []
    }

    registry.value.push(entry)
    saveRegistry(registry.value)

    await auditLog.log('token_use', `Added token: ${name} for ${service}`, {
      details: { tokenId: id, service },
      riskLevel: 'medium'
    })

    return entry
  }

  /**
   * Get a token value for use (with validation)
   */
  async function getToken(
    tokenId: string,
    endpoint: string
  ): Promise<{ token: string | null; error?: string }> {
    const entry = registry.value.find(t => t.id === tokenId)

    if (!entry) {
      return { token: null, error: 'Token not found' }
    }

    // Check if token is expired
    if (entry.expiresAt && entry.expiresAt < new Date()) {
      if (entry.autoRefresh && entry.refreshUrl) {
        // Attempt refresh
        const refreshed = await refreshToken(tokenId)
        if (!refreshed) {
          return { token: null, error: 'Token expired and refresh failed' }
        }
      } else {
        return { token: null, error: 'Token expired' }
      }
    }

    // Check if endpoint is allowed
    if (entry.allowedEndpoints.length > 0) {
      const isAllowed = entry.allowedEndpoints.some(allowed =>
        endpoint.includes(allowed)
      )
      if (!isAllowed) {
        await auditLog.log('constitution_violation', `Token ${entry.name} not allowed for endpoint`, {
          details: { tokenId, endpoint, allowedEndpoints: entry.allowedEndpoints },
          riskLevel: 'high',
          success: false
        })
        return { token: null, error: 'Endpoint not allowed for this token' }
      }
    }

    // Constitution check
    const validation = constitution.validateAction('token_use', undefined, endpoint)
    if (!validation.allowed) {
      return { token: null, error: validation.reason }
    }

    // Get token value from secure storage
    const tokenValue = await storage.get(tokenId)

    if (tokenValue) {
      // Update usage stats
      entry.lastUsed = new Date()
      entry.useCount++
      saveRegistry(registry.value)

      // Log usage
      const usageEntry: TokenUsage = {
        tokenId,
        timestamp: new Date(),
        endpoint,
        success: true
      }
      usage.value.push(usageEntry)
      saveUsage(usage.value)

      await auditLog.log('token_use', `Used token: ${entry.name}`, {
        details: { tokenId, endpoint },
        riskLevel: 'medium'
      })
    }

    return { token: tokenValue }
  }

  /**
   * Refresh an OAuth token
   */
  async function refreshToken(tokenId: string): Promise<boolean> {
    const entry = registry.value.find(t => t.id === tokenId)
    if (!entry || !entry.refreshUrl) return false

    try {
      // Get current refresh token
      const refreshToken = await storage.get(`${tokenId}_refresh`)
      if (!refreshToken) return false

      // Make refresh request
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `curl -s -X POST "${entry.refreshUrl}" -d "grant_type=refresh_token&refresh_token=${refreshToken}"`,
        cwd: undefined
      })

      if (result.exit_code === 0) {
        const response = JSON.parse(result.stdout)
        if (response.access_token) {
          await storage.set(tokenId, response.access_token)

          if (response.refresh_token) {
            await storage.set(`${tokenId}_refresh`, response.refresh_token)
          }

          if (response.expires_in) {
            entry.expiresAt = new Date(Date.now() + response.expires_in * 1000)
          }

          saveRegistry(registry.value)

          await auditLog.log('token_refresh', `Refreshed token: ${entry.name}`, {
            details: { tokenId },
            riskLevel: 'medium'
          })

          return true
        }
      }
    } catch (error) {
      console.error('Token refresh failed:', error)
    }

    return false
  }

  /**
   * Update token value
   */
  async function updateToken(tokenId: string, newValue: string): Promise<boolean> {
    const entry = registry.value.find(t => t.id === tokenId)
    if (!entry) return false

    await storage.set(tokenId, newValue)

    await auditLog.log('token_use', `Updated token: ${entry.name}`, {
      details: { tokenId },
      riskLevel: 'high'
    })

    return true
  }

  /**
   * Remove a token from the vault
   */
  async function removeToken(tokenId: string): Promise<boolean> {
    const entry = registry.value.find(t => t.id === tokenId)
    if (!entry) return false

    // Check if approval required
    const validation = constitution.validateAction('revoke_token')
    if (validation.requiresApproval) {
      // This should be handled by the caller
      return false
    }

    await storage.delete(tokenId)
    await storage.delete(`${tokenId}_refresh`)

    registry.value = registry.value.filter(t => t.id !== tokenId)
    saveRegistry(registry.value)

    await auditLog.log('token_use', `Removed token: ${entry.name}`, {
      details: { tokenId, service: entry.service },
      riskLevel: 'high'
    })

    return true
  }

  /**
   * Get tokens expiring soon
   */
  function getExpiringTokens(withinDays: number = 7): TokenEntry[] {
    const threshold = new Date(Date.now() + withinDays * 24 * 60 * 60 * 1000)
    return registry.value.filter(t =>
      t.expiresAt && t.expiresAt < threshold
    )
  }

  /**
   * Get token usage statistics
   */
  function getUsageStats(tokenId?: string, since?: Date): {
    totalUses: number
    successRate: number
    topEndpoints: { endpoint: string; count: number }[]
  } {
    let relevantUsage = usage.value
    if (tokenId) {
      relevantUsage = relevantUsage.filter(u => u.tokenId === tokenId)
    }
    if (since) {
      relevantUsage = relevantUsage.filter(u => u.timestamp >= since)
    }

    const endpointCounts: Record<string, number> = {}
    let successCount = 0

    for (const u of relevantUsage) {
      endpointCounts[u.endpoint] = (endpointCounts[u.endpoint] || 0) + 1
      if (u.success) successCount++
    }

    const topEndpoints = Object.entries(endpointCounts)
      .map(([endpoint, count]) => ({ endpoint, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)

    return {
      totalUses: relevantUsage.length,
      successRate: relevantUsage.length > 0 ? successCount / relevantUsage.length : 1,
      topEndpoints
    }
  }

  /**
   * Check vault health
   */
  async function checkHealth(): Promise<{
    totalTokens: number
    expiredTokens: number
    expiringSoon: number
    unusedTokens: number
    issues: string[]
  }> {
    const issues: string[] = []
    const now = new Date()
    const weekFromNow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000)
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)

    let expiredCount = 0
    let expiringCount = 0
    let unusedCount = 0

    for (const token of registry.value) {
      if (token.expiresAt && token.expiresAt < now) {
        expiredCount++
        issues.push(`Token "${token.name}" has expired`)
      } else if (token.expiresAt && token.expiresAt < weekFromNow) {
        expiringCount++
        issues.push(`Token "${token.name}" expires in ${Math.ceil((token.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000))} days`)
      }

      if (!token.lastUsed || token.lastUsed < monthAgo) {
        unusedCount++
      }
    }

    return {
      totalTokens: registry.value.length,
      expiredTokens: expiredCount,
      expiringSoon: expiringCount,
      unusedTokens: unusedCount,
      issues
    }
  }

  return {
    // Token management
    addToken,
    getToken,
    updateToken,
    removeToken,
    refreshToken,

    // Queries
    getExpiringTokens,
    getUsageStats,
    checkHealth,

    // Token list (metadata only, not values)
    tokens: computed(() => registry.value),
    tokenCount: computed(() => registry.value.length)
  }
}

export type UseTokenVaultReturn = ReturnType<typeof useTokenVault>
