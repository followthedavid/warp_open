<template>
  <Teleport to="body">
    <div v-if="isVisible" class="dev-console-overlay" @click="close">
      <div class="dev-console-panel" @click.stop>
        <div class="panel-header">
          <h3>Plugin Dev Console</h3>
          <div class="header-actions">
            <button class="clear-btn" @click="clearLogs" title="Clear logs">Clear</button>
            <button class="close-btn" @click="close">×</button>
          </div>
        </div>

        <div class="tabs-bar">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            class="tab-btn"
            :class="{ active: activeTab === tab.id }"
            @click="activeTab = tab.id"
          >
            {{ tab.label }}
            <span v-if="tab.count" class="tab-count">{{ tab.count }}</span>
          </button>
        </div>

        <div class="filter-bar">
          <select v-model="selectedPlugin" class="plugin-filter">
            <option value="">All Plugins</option>
            <option v-for="plugin in plugins" :key="plugin.id" :value="plugin.id">
              {{ plugin.name }}
            </option>
          </select>
          <select v-if="activeTab === 'logs'" v-model="logLevel" class="level-filter">
            <option value="">All Levels</option>
            <option value="error">Errors</option>
            <option value="warn">Warnings</option>
            <option value="info">Info</option>
            <option value="debug">Debug</option>
          </select>
        </div>

        <!-- Logs Tab -->
        <div v-if="activeTab === 'logs'" class="logs-container">
          <div v-if="filteredLogs.length === 0" class="empty-state">
            <span>No logs yet</span>
          </div>
          <div
            v-for="log in filteredLogs"
            :key="log.id"
            class="log-entry"
            :class="log.level"
          >
            <span class="log-time">{{ formatTime(log.timestamp) }}</span>
            <span class="log-plugin">{{ log.pluginName }}</span>
            <span class="log-level">{{ log.level.toUpperCase() }}</span>
            <span class="log-message">{{ log.message }}</span>
            <span v-if="log.args && log.args.length" class="log-args">
              {{ JSON.stringify(log.args) }}
            </span>
          </div>
        </div>

        <!-- Permissions Tab -->
        <div v-if="activeTab === 'permissions'" class="permissions-container">
          <div v-if="filteredGrants.length === 0" class="empty-state">
            <span>No permission grants recorded</span>
          </div>
          <div
            v-for="grant in filteredGrants"
            :key="`${grant.pluginId}-${grant.permission}-${grant.timestamp}`"
            class="grant-entry"
            :class="{ granted: grant.granted, denied: !grant.granted }"
          >
            <span class="grant-time">{{ formatTime(grant.timestamp) }}</span>
            <span class="grant-plugin">{{ grant.pluginName }}</span>
            <span class="grant-permission">{{ grant.permission }}</span>
            <span class="grant-status">{{ grant.granted ? 'GRANTED' : 'DENIED' }}</span>
            <span v-if="grant.reason" class="grant-reason">{{ grant.reason }}</span>
          </div>
        </div>

        <!-- Plugins Tab -->
        <div v-if="activeTab === 'plugins'" class="plugins-container">
          <div v-if="plugins.length === 0" class="empty-state">
            <span>No plugins registered</span>
          </div>
          <div
            v-for="plugin in plugins"
            :key="plugin.id"
            class="plugin-entry"
            :class="{ disabled: !plugin.enabled }"
          >
            <div class="plugin-header">
              <span class="plugin-name">{{ plugin.name }}</span>
              <span class="plugin-version">v{{ plugin.version }}</span>
              <span class="plugin-status">{{ plugin.enabled ? 'Enabled' : 'Disabled' }}</span>
            </div>
            <div class="plugin-meta">
              <span class="plugin-id">ID: {{ plugin.id }}</span>
              <span class="plugin-loaded">Loaded: {{ formatTime(plugin.loadedAt) }}</span>
            </div>
            <div class="plugin-permissions">
              <span class="perm-label">Permissions:</span>
              <span
                v-for="perm in plugin.permissions"
                :key="perm"
                class="perm-badge"
              >
                {{ perm }}
              </span>
              <span v-if="plugin.permissions.length === 0" class="no-perms">None</span>
            </div>
          </div>
        </div>

        <div class="panel-footer">
          <span class="footer-info">
            {{ plugins.length }} plugins | {{ devLogs.length }} logs | {{ permissionGrants.length }} grants
          </span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { pluginManager } from '../plugins/PluginManager'
import type { PluginDevLogEntry, PluginPermissionGrant, PluginRegistration } from '../plugins/types'

defineProps<{
  isVisible: boolean
}>()

const emit = defineEmits(['close'])

const activeTab = ref<'logs' | 'permissions' | 'plugins'>('logs')
const selectedPlugin = ref('')
const logLevel = ref('')

const { plugins, devLogs, permissionGrants, clearDevLogs, clearPermissionGrants } = pluginManager

const tabs = computed(() => [
  { id: 'logs' as const, label: 'Logs', count: devLogs.value.length },
  { id: 'permissions' as const, label: 'Permissions', count: permissionGrants.value.length },
  { id: 'plugins' as const, label: 'Plugins', count: plugins.value.length }
])

const filteredLogs = computed(() => {
  let logs = devLogs.value

  if (selectedPlugin.value) {
    logs = logs.filter(l => l.pluginId === selectedPlugin.value)
  }

  if (logLevel.value) {
    logs = logs.filter(l => l.level === logLevel.value)
  }

  return logs
})

const filteredGrants = computed(() => {
  if (selectedPlugin.value) {
    return permissionGrants.value.filter(g => g.pluginId === selectedPlugin.value)
  }
  return permissionGrants.value
})

function formatTime(timestamp: number): string {
  const date = new Date(timestamp)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function clearLogs() {
  if (activeTab.value === 'logs') {
    clearDevLogs()
  } else if (activeTab.value === 'permissions') {
    clearPermissionGrants()
  }
}

function close() {
  emit('close')
}
</script>

<style scoped>
.dev-console-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: flex-end;
  justify-content: center;
  z-index: 1100;
}

.dev-console-panel {
  background: #0f172a;
  border-radius: 12px 12px 0 0;
  width: 100%;
  max-width: 900px;
  height: 60vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 -8px 32px rgba(0, 0, 0, 0.5);
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid #1e293b;
}

.panel-header h3 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  color: #e2e8f0;
}

.header-actions {
  display: flex;
  gap: 8px;
}

.clear-btn {
  padding: 4px 12px;
  background: transparent;
  border: 1px solid #334155;
  border-radius: 4px;
  color: #94a3b8;
  font-size: 12px;
  cursor: pointer;
}

.clear-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.close-btn {
  width: 24px;
  height: 24px;
  border: none;
  background: transparent;
  color: #64748b;
  cursor: pointer;
  border-radius: 4px;
  font-size: 16px;
}

.close-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.tabs-bar {
  display: flex;
  gap: 4px;
  padding: 8px 16px;
  border-bottom: 1px solid #1e293b;
}

.tab-btn {
  padding: 6px 12px;
  background: transparent;
  border: none;
  border-radius: 4px;
  color: #94a3b8;
  font-size: 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
}

.tab-btn:hover {
  background: #1e293b;
}

.tab-btn.active {
  background: #3b82f620;
  color: #60a5fa;
}

.tab-count {
  background: #334155;
  padding: 1px 6px;
  border-radius: 10px;
  font-size: 10px;
}

.tab-btn.active .tab-count {
  background: #3b82f640;
}

.filter-bar {
  display: flex;
  gap: 8px;
  padding: 8px 16px;
  border-bottom: 1px solid #1e293b;
}

.plugin-filter,
.level-filter {
  padding: 4px 8px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 4px;
  color: #e2e8f0;
  font-size: 12px;
}

.logs-container,
.permissions-container,
.plugins-container {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
  font-family: 'Menlo', monospace;
  font-size: 11px;
}

.empty-state {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #64748b;
}

/* Log entries */
.log-entry {
  display: flex;
  gap: 8px;
  padding: 4px 8px;
  border-radius: 4px;
  margin-bottom: 2px;
  align-items: baseline;
}

.log-entry.error {
  background: #ef444420;
}

.log-entry.warn {
  background: #f59e0b20;
}

.log-entry.info {
  background: transparent;
}

.log-entry.debug {
  background: #64748b10;
}

.log-time {
  color: #64748b;
  flex-shrink: 0;
}

.log-plugin {
  color: #60a5fa;
  flex-shrink: 0;
  max-width: 100px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.log-level {
  flex-shrink: 0;
  font-weight: 600;
  width: 40px;
}

.log-entry.error .log-level { color: #ef4444; }
.log-entry.warn .log-level { color: #f59e0b; }
.log-entry.info .log-level { color: #10b981; }
.log-entry.debug .log-level { color: #64748b; }

.log-message {
  color: #e2e8f0;
  flex: 1;
  word-break: break-word;
}

.log-args {
  color: #94a3b8;
  font-size: 10px;
}

/* Permission grants */
.grant-entry {
  display: flex;
  gap: 8px;
  padding: 6px 8px;
  border-radius: 4px;
  margin-bottom: 4px;
  align-items: center;
}

.grant-entry.granted {
  background: #10b98120;
}

.grant-entry.denied {
  background: #ef444420;
}

.grant-time {
  color: #64748b;
  flex-shrink: 0;
}

.grant-plugin {
  color: #60a5fa;
  flex-shrink: 0;
}

.grant-permission {
  color: #f59e0b;
  font-weight: 500;
}

.grant-status {
  font-weight: 600;
}

.grant-entry.granted .grant-status { color: #10b981; }
.grant-entry.denied .grant-status { color: #ef4444; }

.grant-reason {
  color: #94a3b8;
  font-style: italic;
}

/* Plugin entries */
.plugin-entry {
  background: #1e293b;
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 8px;
}

.plugin-entry.disabled {
  opacity: 0.6;
}

.plugin-header {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 6px;
}

.plugin-name {
  font-size: 13px;
  font-weight: 600;
  color: #e2e8f0;
}

.plugin-version {
  color: #64748b;
}

.plugin-status {
  margin-left: auto;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 10px;
  background: #10b98120;
  color: #10b981;
}

.plugin-entry.disabled .plugin-status {
  background: #64748b20;
  color: #64748b;
}

.plugin-meta {
  display: flex;
  gap: 16px;
  font-size: 10px;
  color: #64748b;
  margin-bottom: 8px;
}

.plugin-permissions {
  display: flex;
  gap: 6px;
  align-items: center;
  flex-wrap: wrap;
}

.perm-label {
  color: #94a3b8;
  font-size: 11px;
}

.perm-badge {
  padding: 2px 6px;
  background: #3b82f620;
  border: 1px solid #3b82f640;
  border-radius: 4px;
  color: #60a5fa;
  font-size: 10px;
}

.no-perms {
  color: #64748b;
  font-style: italic;
  font-size: 11px;
}

.panel-footer {
  padding: 8px 16px;
  border-top: 1px solid #1e293b;
  font-size: 11px;
  color: #64748b;
}
</style>
