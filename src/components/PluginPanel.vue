<template>
  <div class="plugin-panel" v-if="isVisible">
    <div class="panel-header">
      <h3>Plugins</h3>
      <button class="close-btn" @click="$emit('close')">×</button>
    </div>

    <div class="panel-content">
      <!-- Plugin List -->
      <div class="plugin-list">
        <div
          v-for="plugin in plugins"
          :key="plugin.id"
          class="plugin-item"
          :class="{ active: activePluginId === plugin.id }"
        >
          <div class="plugin-info" @click="togglePlugin(plugin.id)">
            <span class="plugin-name">{{ plugin.name }}</span>
            <span class="plugin-version">v{{ plugin.version }}</span>
          </div>
          <div class="plugin-actions">
            <label class="toggle-switch">
              <input
                type="checkbox"
                :checked="plugin.enabled"
                @change="toggleEnabled(plugin.id, $event)"
              />
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div v-if="plugins.length === 0" class="no-plugins">
          No plugins installed.
        </div>
      </div>

      <!-- Active Plugin Render Area -->
      <div v-if="activePluginId" class="plugin-render-area">
        <div class="render-header">
          <span>{{ activePluginName }}</span>
          <button @click="refreshPlugin" title="Refresh">↻</button>
        </div>
        <div ref="pluginContainer" class="plugin-container"></div>
      </div>

      <!-- Built-in Plugins -->
      <div class="builtin-section">
        <h4>Available Plugins</h4>
        <div class="builtin-list">
          <div class="builtin-item">
            <div class="builtin-info">
              <span class="builtin-name">Command Frequency Tracker</span>
              <span class="builtin-desc">Track your most-used commands</span>
            </div>
            <button
              v-if="!isCommandFrequencyLoaded"
              @click="loadCommandFrequencyPlugin"
              class="load-btn"
            >
              Load
            </button>
            <span v-else class="loaded-badge">Loaded</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import { pluginManager } from '../plugins/PluginManager'
import { CommandFrequencyPlugin } from '../plugins/demos/CommandFrequencyPlugin'
import type { PluginPermission } from '../plugins/types'

defineProps<{
  isVisible: boolean
}>()

defineEmits<{
  (e: 'close'): void
}>()

const plugins = computed(() => pluginManager.plugins.value)
const activePluginId = ref<string | null>(null)
const pluginContainer = ref<HTMLElement | null>(null)
const isCommandFrequencyLoaded = ref(false)

const activePluginName = computed(() => {
  if (!activePluginId.value) return ''
  const plugin = pluginManager.getPlugin(activePluginId.value)
  return plugin?.name || ''
})

function togglePlugin(pluginId: string) {
  if (activePluginId.value === pluginId) {
    activePluginId.value = null
  } else {
    activePluginId.value = pluginId
    nextTick(() => {
      renderActivePlugin()
    })
  }
}

function toggleEnabled(pluginId: string, event: Event) {
  const target = event.target as HTMLInputElement
  pluginManager.setPluginEnabled(pluginId, target.checked)
}

function renderActivePlugin() {
  if (!activePluginId.value || !pluginContainer.value) return
  pluginManager.renderPlugin(activePluginId.value, pluginContainer.value)
}

function refreshPlugin() {
  renderActivePlugin()
}

async function loadCommandFrequencyPlugin() {
  const permissions: PluginPermission[] = ['read-commands', 'read-output']
  const registration = await pluginManager.registerPlugin(CommandFrequencyPlugin, permissions)

  if (registration) {
    isCommandFrequencyLoaded.value = true
    activePluginId.value = registration.id
    nextTick(() => {
      renderActivePlugin()
    })
  }
}

// Re-render when visibility changes
watch(() => activePluginId.value, () => {
  nextTick(() => {
    renderActivePlugin()
  })
})

onMounted(() => {
  // Check if command frequency is already loaded
  isCommandFrequencyLoaded.value = plugins.value.some(
    p => p.name === 'Command Frequency Tracker'
  )
})
</script>

<style scoped>
.plugin-panel {
  position: fixed;
  right: 0;
  top: 0;
  bottom: 0;
  width: 320px;
  background: var(--bg-secondary, #1a1a2e);
  border-left: 1px solid var(--border-color, #333);
  display: flex;
  flex-direction: column;
  z-index: 100;
  box-shadow: -4px 0 12px rgba(0,0,0,0.3);
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #333);
}

.panel-header h3 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}

.close-btn {
  background: none;
  border: none;
  color: var(--text-secondary, #888);
  font-size: 20px;
  cursor: pointer;
  padding: 0;
  line-height: 1;
}

.close-btn:hover {
  color: var(--text-color, #fff);
}

.panel-content {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.plugin-list {
  padding: 12px;
  border-bottom: 1px solid var(--border-color, #333);
}

.plugin-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  margin-bottom: 8px;
  background: var(--bg-tertiary, #252540);
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.2s;
}

.plugin-item:hover {
  background: var(--bg-hover, #353555);
}

.plugin-item.active {
  background: var(--accent-color, #6366f1);
}

.plugin-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.plugin-name {
  font-size: 13px;
  font-weight: 500;
}

.plugin-version {
  font-size: 10px;
  color: var(--text-secondary, #888);
}

.plugin-item.active .plugin-version {
  color: rgba(255,255,255,0.7);
}

.toggle-switch {
  position: relative;
  width: 36px;
  height: 20px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: #444;
  border-radius: 20px;
  transition: 0.3s;
}

.slider:before {
  position: absolute;
  content: "";
  height: 14px;
  width: 14px;
  left: 3px;
  bottom: 3px;
  background: white;
  border-radius: 50%;
  transition: 0.3s;
}

input:checked + .slider {
  background: #4ade80;
}

input:checked + .slider:before {
  transform: translateX(16px);
}

.no-plugins {
  text-align: center;
  padding: 20px;
  color: var(--text-secondary, #888);
  font-size: 12px;
}

.plugin-render-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  border-bottom: 1px solid var(--border-color, #333);
}

.render-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: var(--bg-tertiary, #252540);
  font-size: 12px;
  font-weight: 500;
}

.render-header button {
  background: none;
  border: none;
  color: var(--text-secondary, #888);
  cursor: pointer;
  font-size: 14px;
}

.render-header button:hover {
  color: var(--text-color, #fff);
}

.plugin-container {
  flex: 1;
  overflow-y: auto;
  background: var(--bg-color, #0d0d1a);
}

.builtin-section {
  padding: 12px;
}

.builtin-section h4 {
  margin: 0 0 12px 0;
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary, #888);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.builtin-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.builtin-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  background: var(--bg-tertiary, #252540);
  border-radius: 6px;
}

.builtin-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.builtin-name {
  font-size: 12px;
  font-weight: 500;
}

.builtin-desc {
  font-size: 10px;
  color: var(--text-secondary, #888);
}

.load-btn {
  padding: 4px 12px;
  background: var(--accent-color, #6366f1);
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 11px;
  cursor: pointer;
  transition: background 0.2s;
}

.load-btn:hover {
  background: #5558e3;
}

.loaded-badge {
  font-size: 10px;
  color: #4ade80;
  padding: 4px 8px;
  background: rgba(74, 222, 128, 0.1);
  border-radius: 4px;
}
</style>
