/**
 * Security Settings Composable
 *
 * Manages security-related preferences including:
 * - AI Air-Gapped Mode (completely disable AI features)
 * - Clipboard permissions (OSC 52)
 * - Other security toggles
 */

import { ref, watch } from 'vue'

interface SecuritySettings {
  aiEnabled: boolean           // Master toggle for AI features
  clipboardWriteEnabled: boolean  // Allow terminal to write clipboard (OSC 52)
  clipboardWritePrompt: boolean   // Prompt before clipboard writes
}

const STORAGE_KEY = 'warp_open_security_settings'

// Default settings - security-conscious defaults
const defaultSettings: SecuritySettings = {
  aiEnabled: true,                  // AI enabled by default (local only)
  clipboardWriteEnabled: true,      // Allow clipboard writes
  clipboardWritePrompt: false,      // Don't prompt by default (too intrusive)
}

// Global reactive state
const settings = ref<SecuritySettings>({ ...defaultSettings })
const isLoaded = ref(false)

// Load settings from localStorage
function loadSettings(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      const parsed = JSON.parse(stored)
      settings.value = { ...defaultSettings, ...parsed }
    }
  } catch (e) {
    console.warn('[useSecuritySettings] Failed to load settings:', e)
    settings.value = { ...defaultSettings }
  }
  isLoaded.value = true
}

// Save settings to localStorage
function saveSettings(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings.value))
  } catch (e) {
    console.warn('[useSecuritySettings] Failed to save settings:', e)
  }
}

// Watch for changes and auto-save
watch(settings, () => {
  if (isLoaded.value) {
    saveSettings()
  }
}, { deep: true })

// Initialize on first import
if (!isLoaded.value) {
  loadSettings()
}

export function useSecuritySettings() {
  // Toggle AI enabled/disabled
  function toggleAI(): void {
    settings.value.aiEnabled = !settings.value.aiEnabled
    console.log('[useSecuritySettings] AI', settings.value.aiEnabled ? 'enabled' : 'disabled (air-gapped mode)')
  }

  // Set AI state explicitly
  function setAIEnabled(enabled: boolean): void {
    settings.value.aiEnabled = enabled
  }

  // Check if AI is enabled
  function isAIEnabled(): boolean {
    return settings.value.aiEnabled
  }

  // Toggle clipboard write permission
  function toggleClipboardWrite(): void {
    settings.value.clipboardWriteEnabled = !settings.value.clipboardWriteEnabled
  }

  // Set clipboard write permission
  function setClipboardWriteEnabled(enabled: boolean): void {
    settings.value.clipboardWriteEnabled = enabled
  }

  // Check if clipboard write is allowed
  function isClipboardWriteAllowed(): boolean {
    return settings.value.clipboardWriteEnabled
  }

  // Toggle clipboard write prompt
  function toggleClipboardPrompt(): void {
    settings.value.clipboardWritePrompt = !settings.value.clipboardWritePrompt
  }

  // Check if we should prompt for clipboard writes
  function shouldPromptForClipboard(): boolean {
    return settings.value.clipboardWriteEnabled && settings.value.clipboardWritePrompt
  }

  // Reset to defaults
  function resetToDefaults(): void {
    settings.value = { ...defaultSettings }
  }

  // Get all settings (for display in preferences UI)
  function getAllSettings(): SecuritySettings {
    return { ...settings.value }
  }

  return {
    settings,
    toggleAI,
    setAIEnabled,
    isAIEnabled,
    toggleClipboardWrite,
    setClipboardWriteEnabled,
    isClipboardWriteAllowed,
    toggleClipboardPrompt,
    shouldPromptForClipboard,
    resetToDefaults,
    getAllSettings,
  }
}

// Export types
export type { SecuritySettings }
