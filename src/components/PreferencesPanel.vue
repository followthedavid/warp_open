<template>
  <div v-if="isOpen" class="preferences-overlay" @click.self="close">
    <div class="preferences-panel">
      <div class="preferences-header">
        <h2>Preferences</h2>
        <button @click="close" class="close-btn">✕</button>
      </div>

      <div class="preferences-content">
        <!-- Terminal Settings -->
        <section class="preference-section">
          <h3>Terminal</h3>
          
          <div class="preference-item">
            <label for="fontSize">Font Size</label>
            <input 
              id="fontSize"
              type="number" 
              v-model.number="localPrefs.terminal.fontSize"
              min="8"
              max="32"
              @change="updatePrefs"
            />
            <span class="unit">px</span>
          </div>

          <div class="preference-item">
            <label for="fontFamily">Font Family</label>
            <select 
              id="fontFamily"
              v-model="localPrefs.terminal.fontFamily"
              @change="updatePrefs"
            >
              <option value="Menlo, Monaco, 'Courier New', monospace">Menlo / Monaco</option>
              <option value="'Fira Code', monospace">Fira Code</option>
              <option value="'JetBrains Mono', monospace">JetBrains Mono</option>
              <option value="'Source Code Pro', monospace">Source Code Pro</option>
              <option value="'Cascadia Code', monospace">Cascadia Code</option>
              <option value="monospace">System Monospace</option>
            </select>
          </div>

          <div class="preference-item">
            <label for="cursorStyle">Cursor Style</label>
            <select 
              id="cursorStyle"
              v-model="localPrefs.terminal.cursorStyle"
              @change="updatePrefs"
            >
              <option value="block">Block</option>
              <option value="underline">Underline</option>
              <option value="bar">Bar</option>
            </select>
          </div>

          <div class="preference-item">
            <label for="cursorBlink">Cursor Blink</label>
            <input 
              id="cursorBlink"
              type="checkbox"
              v-model="localPrefs.terminal.cursorBlink"
              @change="updatePrefs"
            />
          </div>

          <div class="preference-item">
            <label for="scrollback">Scrollback Lines</label>
            <input 
              id="scrollback"
              type="number"
              v-model.number="localPrefs.terminal.scrollback"
              min="100"
              max="10000"
              step="100"
              @change="updatePrefs"
            />
          </div>
        </section>

        <!-- UI Settings -->
        <section class="preference-section">
          <h3>Interface</h3>

          <div class="preference-item">
            <label for="showTabBar">Show Tab Bar</label>
            <input 
              id="showTabBar"
              type="checkbox"
              v-model="localPrefs.ui.showTabBar"
              @change="updatePrefs"
            />
          </div>

          <div class="preference-item">
            <label for="showScrollbar">Show Scrollbar</label>
            <input 
              id="showScrollbar"
              type="checkbox"
              v-model="localPrefs.ui.showScrollbar"
              @change="updatePrefs"
            />
          </div>

          <div class="preference-item">
            <label for="compactMode">Compact Mode</label>
            <input 
              id="compactMode"
              type="checkbox"
              v-model="localPrefs.ui.compactMode"
              @change="updatePrefs"
            />
          </div>
        </section>

        <!-- Actions -->
        <section class="preference-section">
          <h3>Actions</h3>
          
          <div class="preference-actions">
            <button @click="handleReset" class="action-btn reset">
              Reset to Defaults
            </button>
            <button @click="handleExport" class="action-btn export">
              Export Settings
            </button>
            <button @click="handleImport" class="action-btn import">
              Import Settings
            </button>
          </div>
        </section>
      </div>

      <div class="preferences-footer">
        <button @click="close" class="btn-primary">Done</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { usePreferences } from '../composables/usePreferences'

const props = defineProps({
  isOpen: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['close', 'preferences-changed'])

const { 
  preferences, 
  updatePreferences, 
  resetPreferences,
  exportPreferences,
  importPreferences 
} = usePreferences()

const localPrefs = ref(JSON.parse(JSON.stringify(preferences.value)))

watch(() => props.isOpen, (isOpen) => {
  if (isOpen) {
    localPrefs.value = JSON.parse(JSON.stringify(preferences.value))
  }
})

function updatePrefs() {
  updatePreferences(localPrefs.value)
  emit('preferences-changed', localPrefs.value)
}

function close() {
  emit('close')
}

function handleReset() {
  if (confirm('Reset all preferences to defaults?')) {
    resetPreferences()
    localPrefs.value = JSON.parse(JSON.stringify(preferences.value))
    emit('preferences-changed', localPrefs.value)
  }
}

function handleExport() {
  const json = exportPreferences()
  const blob = new Blob([json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'warp-preferences.json'
  a.click()
  URL.revokeObjectURL(url)
}

function handleImport() {
  const input = document.createElement('input')
  input.type = 'file'
  input.accept = 'application/json'
  input.onchange = (e) => {
    const file = e.target.files[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (event) => {
        if (importPreferences(event.target.result)) {
          localPrefs.value = JSON.parse(JSON.stringify(preferences.value))
          emit('preferences-changed', localPrefs.value)
          alert('Preferences imported successfully!')
        } else {
          alert('Failed to import preferences. Invalid file format.')
        }
      }
      reader.readAsText(file)
    }
  }
  input.click()
}
</script>

<style scoped>
.preferences-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(4px);
}

.preferences-panel {
  background: var(--bg-color);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  width: 90%;
  max-width: 600px;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
}

.preferences-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-color);
}

.preferences-header h2 {
  margin: 0;
  font-size: 18px;
  color: var(--text-color);
}

.close-btn {
  background: none;
  border: none;
  color: var(--text-color);
  font-size: 20px;
  cursor: pointer;
  width: 28px;
  height: 28px;
  border-radius: 4px;
  transition: background 0.2s;
}

.close-btn:hover {
  background: var(--border-color);
}

.preferences-content {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}

.preference-section {
  margin-bottom: 24px;
}

.preference-section h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  color: var(--active-tab-color);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.preference-item {
  display: flex;
  align-items: center;
  margin-bottom: 12px;
  gap: 12px;
}

.preference-item label {
  flex: 1;
  font-size: 13px;
  color: var(--text-color);
}

.preference-item input[type="number"],
.preference-item select {
  padding: 4px 8px;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  background: var(--bg-color);
  color: var(--text-color);
  font-size: 13px;
  width: 150px;
}

.preference-item input[type="checkbox"] {
  width: 16px;
  height: 16px;
  cursor: pointer;
}

.preference-item .unit {
  font-size: 12px;
  color: #888;
  width: 30px;
}

.preference-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.action-btn {
  padding: 8px 16px;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  background: var(--bg-color);
  color: var(--text-color);
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover {
  border-color: var(--active-tab-color);
  background: color-mix(in srgb, var(--active-tab-color) 10%, var(--bg-color));
}

.action-btn.reset {
  border-color: #cd3131;
  color: #cd3131;
}

.action-btn.reset:hover {
  background: rgba(205, 49, 49, 0.1);
}

.preferences-footer {
  padding: 16px 20px;
  border-top: 1px solid var(--border-color);
  display: flex;
  justify-content: flex-end;
}

.btn-primary {
  padding: 8px 24px;
  background: var(--active-tab-color);
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 14px;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-primary:hover {
  opacity: 0.9;
}

/* Scrollbar */
.preferences-content::-webkit-scrollbar {
  width: 8px;
}

.preferences-content::-webkit-scrollbar-track {
  background: var(--bg-color);
}

.preferences-content::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 4px;
}

.preferences-content::-webkit-scrollbar-thumb:hover {
  background: #555;
}
</style>
