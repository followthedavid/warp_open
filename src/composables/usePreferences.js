import { ref, watch } from 'vue'

// Default preferences
const defaultPreferences = {
  terminal: {
    fontSize: 14,
    fontFamily: 'Menlo, Monaco, "Courier New", monospace',
    lineHeight: 1.2,
    cursorBlink: true,
    cursorStyle: 'block', // block, underline, bar
    scrollback: 5000,      // Increased for better experience
    fastScrollModifier: 'alt', // alt, ctrl, shift - for fast scrolling
    fastScrollSensitivity: 5,   // Multiplier for fast scroll
  },
  performance: {
    maxOutputBuffer: 10000,  // Max lines to keep in memory for search/replay
    batchWriteSize: 1000,    // Batch size for writing to terminal (reduces redraws)
    throttleInterval: 16,    // ms between batch writes (60fps)
    enableGPUAcceleration: true, // Use WebGL renderer when available
  },
  editor: {
    tabSize: 2,
    insertSpaces: true,
  },
  ui: {
    showTabBar: true,
    showScrollbar: true,
    compactMode: false,
  }
}

// Load preferences from localStorage
function loadPreferences() {
  try {
    const stored = localStorage.getItem('warp-preferences')
    if (stored) {
      const parsed = JSON.parse(stored)
      // Merge with defaults to ensure all keys exist
      return {
        terminal: { ...defaultPreferences.terminal, ...parsed.terminal },
        performance: { ...defaultPreferences.performance, ...parsed.performance },
        editor: { ...defaultPreferences.editor, ...parsed.editor },
        ui: { ...defaultPreferences.ui, ...parsed.ui },
      }
    }
  } catch (error) {
    console.error('Failed to load preferences:', error)
  }
  return defaultPreferences
}

// Reactive preferences
const preferences = ref(loadPreferences())

// Watch for changes and save to localStorage
watch(preferences, (newPrefs) => {
  try {
    localStorage.setItem('warp-preferences', JSON.stringify(newPrefs))
  } catch (error) {
    console.error('Failed to save preferences:', error)
  }
}, { deep: true })

export function usePreferences() {
  const updatePreference = (category, key, value) => {
    if (preferences.value[category] && key in preferences.value[category]) {
      preferences.value[category][key] = value
    }
  }

  const updatePreferences = (newPrefs) => {
    preferences.value = {
      ...preferences.value,
      ...newPrefs
    }
  }

  const resetPreferences = () => {
    preferences.value = { ...defaultPreferences }
  }

  const exportPreferences = () => {
    return JSON.stringify(preferences.value, null, 2)
  }

  const importPreferences = (jsonString) => {
    try {
      const imported = JSON.parse(jsonString)
      updatePreferences(imported)
      return true
    } catch (error) {
      console.error('Failed to import preferences:', error)
      return false
    }
  }

  return {
    preferences,
    updatePreference,
    updatePreferences,
    resetPreferences,
    exportPreferences,
    importPreferences,
    defaultPreferences
  }
}
