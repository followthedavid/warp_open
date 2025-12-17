<template>
  <div class="analytics-dashboard" v-if="isVisible">
    <div class="dashboard-header">
      <h2>Session Analytics</h2>
      <div class="header-actions">
        <button class="export-btn" @click="exportCSV" title="Export CSV">
          CSV
        </button>
        <button class="export-btn" @click="exportJSON" title="Export JSON">
          JSON
        </button>
        <button class="reset-btn" @click="confirmReset" title="Reset session">
          Reset
        </button>
        <button class="close-btn" @click="$emit('close')" title="Close">
          ×
        </button>
      </div>
    </div>

    <div class="dashboard-content">
      <!-- Summary Cards -->
      <div class="summary-cards">
        <div class="stat-card">
          <div class="stat-value">{{ sessionStats.totalCommands }}</div>
          <div class="stat-label">Total Commands</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{{ sessionStats.uniqueCommands }}</div>
          <div class="stat-label">Unique Commands</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{{ formatDuration(sessionStats.totalActiveTime) }}</div>
          <div class="stat-label">Active Time</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{{ sessionAge }}</div>
          <div class="stat-label">Session Age</div>
        </div>
      </div>

      <!-- Tab Navigation -->
      <div class="tab-nav">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          :class="['tab-btn', { active: activeTab === tab.id }]"
          @click="activeTab = tab.id"
        >
          {{ tab.label }}
        </button>
      </div>

      <!-- Tab Content -->
      <div class="tab-content">
        <!-- Most Used Commands -->
        <div v-if="activeTab === 'commands'" class="commands-section">
          <h3>Most Used Commands</h3>
          <div class="commands-list">
            <div
              v-for="(item, index) in mostUsedCommands"
              :key="item.command"
              class="command-item"
            >
              <span class="command-rank">#{{ index + 1 }}</span>
              <span class="command-name">{{ item.command }}</span>
              <div class="command-bar-container">
                <div
                  class="command-bar"
                  :style="{ width: getBarWidth(item.count) }"
                ></div>
              </div>
              <span class="command-count">{{ item.count }}</span>
            </div>
            <div v-if="mostUsedCommands.length === 0" class="no-data">
              No commands recorded yet
            </div>
          </div>
        </div>

        <!-- Activity Chart -->
        <div v-if="activeTab === 'activity'" class="activity-section">
          <h3>Commands Per Hour (Last 24h)</h3>
          <div class="chart-container">
            <div class="bar-chart">
              <div
                v-for="item in commandsPerHour"
                :key="item.hour"
                class="chart-bar-wrapper"
                :title="`${item.hour}: ${item.count} commands`"
              >
                <div
                  class="chart-bar"
                  :style="{ height: getChartBarHeight(item.count) }"
                ></div>
                <span class="chart-label">{{ formatHourLabel(item.hour) }}</span>
              </div>
            </div>
            <div v-if="commandsPerHour.length === 0" class="no-data">
              No activity data yet
            </div>
          </div>

          <h3 class="mt-4">Commands Per Day (Last 30d)</h3>
          <div class="chart-container">
            <div class="bar-chart days-chart">
              <div
                v-for="item in commandsByDay"
                :key="item.day"
                class="chart-bar-wrapper"
                :title="`${item.day}: ${item.count} commands`"
              >
                <div
                  class="chart-bar day-bar"
                  :style="{ height: getDayBarHeight(item.count) }"
                ></div>
                <span class="chart-label">{{ formatDayLabel(item.day) }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Pane Time Distribution -->
        <div v-if="activeTab === 'time'" class="time-section">
          <h3>Time Per Pane</h3>
          <div class="pane-time-list">
            <div
              v-for="item in paneTimeDistribution"
              :key="item.paneId"
              class="pane-time-item"
            >
              <div class="pane-info">
                <span class="pane-id">{{ truncateId(item.paneId) }}</span>
                <span class="pane-time">{{ item.minutes }}m ({{ item.percentage }}%)</span>
              </div>
              <div class="pane-bar-container">
                <div
                  class="pane-bar"
                  :style="{ width: `${item.percentage}%` }"
                ></div>
              </div>
            </div>
            <div v-if="paneTimeDistribution.length === 0" class="no-data">
              No pane time data yet
            </div>
          </div>
        </div>

        <!-- Recent Commands -->
        <div v-if="activeTab === 'history'" class="history-section">
          <h3>Recent Commands</h3>
          <div class="history-list">
            <div
              v-for="cmd in recentCommands"
              :key="cmd.timestamp + cmd.command"
              class="history-item"
            >
              <span class="history-time">{{ formatTimestamp(cmd.timestamp) }}</span>
              <span class="history-command">{{ cmd.command }}</span>
              <span v-if="cmd.exitCode !== undefined" :class="['history-exit', { error: cmd.exitCode !== 0 }]">
                {{ cmd.exitCode }}
              </span>
            </div>
            <div v-if="recentCommands.length === 0" class="no-data">
              No command history
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useAnalytics } from '../composables/useAnalytics'

defineProps<{
  isVisible: boolean
}>()

const emit = defineEmits<{
  (e: 'close'): void
}>()

const {
  mostUsedCommands,
  sessionStats,
  commandsPerHour,
  commandsByDay,
  paneTimeDistribution,
  recentCommands,
  exportToCSV,
  exportToJSON,
  resetSession
} = useAnalytics()

const activeTab = ref<'commands' | 'activity' | 'time' | 'history'>('commands')

const tabs = [
  { id: 'commands' as const, label: 'Commands' },
  { id: 'activity' as const, label: 'Activity' },
  { id: 'time' as const, label: 'Time' },
  { id: 'history' as const, label: 'History' }
]

const sessionAge = computed(() => {
  const ms = Date.now() - sessionStats.value.sessionStart
  const hours = Math.floor(ms / 3600000)
  const minutes = Math.floor((ms % 3600000) / 60000)

  if (hours > 24) {
    const days = Math.floor(hours / 24)
    return `${days}d ${hours % 24}h`
  }
  return `${hours}h ${minutes}m`
})

function formatDuration(ms: number): string {
  const minutes = Math.floor(ms / 60000)
  const hours = Math.floor(minutes / 60)

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`
  }
  return `${minutes}m`
}

function formatTimestamp(ts: number): string {
  const date = new Date(ts)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function formatHourLabel(hour: string): string {
  // Extract just the hour part
  const parts = hour.split(' ')
  return parts[1] || hour
}

function formatDayLabel(day: string): string {
  const date = new Date(day)
  return `${date.getMonth() + 1}/${date.getDate()}`
}

function truncateId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) + '...' : id
}

function getBarWidth(count: number): string {
  const maxCount = Math.max(...mostUsedCommands.value.map(c => c.count), 1)
  return `${(count / maxCount) * 100}%`
}

function getChartBarHeight(count: number): string {
  const maxCount = Math.max(...commandsPerHour.value.map(c => c.count), 1)
  return `${(count / maxCount) * 100}%`
}

function getDayBarHeight(count: number): string {
  const maxCount = Math.max(...commandsByDay.value.map(c => c.count), 1)
  return `${(count / maxCount) * 100}%`
}

function exportCSV() {
  const csv = exportToCSV()
  downloadFile(csv, 'analytics.csv', 'text/csv')
}

function exportJSON() {
  const json = exportToJSON()
  downloadFile(json, 'analytics.json', 'application/json')
}

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function confirmReset() {
  if (confirm('Reset session analytics? Historical data will be preserved.')) {
    resetSession()
  }
}
</script>

<style scoped>
.analytics-dashboard {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 90%;
  max-width: 800px;
  max-height: 80vh;
  background: #1a1f2e;
  border: 1px solid #334155;
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  z-index: 200;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  background: #0f172a;
  border-bottom: 1px solid #334155;
}

.dashboard-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: #e2e8f0;
}

.header-actions {
  display: flex;
  gap: 8px;
}

.export-btn,
.reset-btn {
  padding: 6px 12px;
  font-size: 11px;
  background: #1e293b;
  color: #94a3b8;
  border: 1px solid #334155;
  border-radius: 4px;
  cursor: pointer;
}

.export-btn:hover {
  background: #3b82f6;
  color: white;
  border-color: #3b82f6;
}

.reset-btn:hover {
  background: #ef4444;
  color: white;
  border-color: #ef4444;
}

.close-btn {
  width: 28px;
  height: 28px;
  padding: 0;
  font-size: 18px;
  background: transparent;
  color: #64748b;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.close-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.dashboard-content {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}

/* Summary Cards */
.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.stat-card {
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  padding: 16px;
  border-radius: 8px;
  text-align: center;
  border: 1px solid #334155;
}

.stat-value {
  font-size: 24px;
  font-weight: 700;
  color: #3b82f6;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 11px;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Tab Navigation */
.tab-nav {
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
  background: #0f172a;
  padding: 4px;
  border-radius: 8px;
}

.tab-btn {
  flex: 1;
  padding: 8px 16px;
  font-size: 12px;
  font-weight: 500;
  background: transparent;
  color: #64748b;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-btn:hover {
  color: #94a3b8;
}

.tab-btn.active {
  background: #3b82f6;
  color: white;
}

/* Commands Section */
.commands-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.command-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  background: #0f172a;
  border-radius: 6px;
}

.command-rank {
  font-size: 11px;
  color: #64748b;
  width: 24px;
}

.command-name {
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 13px;
  color: #e2e8f0;
  width: 120px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.command-bar-container {
  flex: 1;
  height: 8px;
  background: #1e293b;
  border-radius: 4px;
  overflow: hidden;
}

.command-bar {
  height: 100%;
  background: linear-gradient(90deg, #3b82f6, #8b5cf6);
  border-radius: 4px;
  transition: width 0.3s ease;
}

.command-count {
  font-size: 12px;
  color: #94a3b8;
  width: 40px;
  text-align: right;
}

/* Chart Styles */
.chart-container {
  background: #0f172a;
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
}

.bar-chart {
  display: flex;
  align-items: flex-end;
  gap: 4px;
  height: 150px;
}

.days-chart {
  height: 100px;
}

.chart-bar-wrapper {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  height: 100%;
}

.chart-bar {
  width: 100%;
  min-height: 4px;
  background: linear-gradient(180deg, #3b82f6, #1e40af);
  border-radius: 4px 4px 0 0;
  margin-top: auto;
  transition: height 0.3s ease;
}

.day-bar {
  background: linear-gradient(180deg, #10b981, #047857);
}

.chart-label {
  font-size: 9px;
  color: #64748b;
  margin-top: 4px;
  white-space: nowrap;
}

/* Time Section */
.pane-time-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.pane-time-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.pane-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.pane-id {
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
  color: #94a3b8;
}

.pane-time {
  font-size: 12px;
  color: #64748b;
}

.pane-bar-container {
  height: 8px;
  background: #1e293b;
  border-radius: 4px;
  overflow: hidden;
}

.pane-bar {
  height: 100%;
  background: linear-gradient(90deg, #10b981, #06b6d4);
  border-radius: 4px;
}

/* History Section */
.history-list {
  max-height: 400px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.history-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  background: #0f172a;
  border-radius: 4px;
  font-size: 12px;
}

.history-time {
  color: #64748b;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 11px;
  width: 50px;
  flex-shrink: 0;
}

.history-command {
  flex: 1;
  font-family: 'SF Mono', Monaco, monospace;
  color: #e2e8f0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.history-exit {
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 3px;
  background: rgba(16, 185, 129, 0.2);
  color: #10b981;
}

.history-exit.error {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

/* Utility */
.no-data {
  text-align: center;
  padding: 32px;
  color: #64748b;
  font-size: 13px;
}

h3 {
  font-size: 14px;
  font-weight: 600;
  color: #94a3b8;
  margin: 0 0 12px 0;
}

.mt-4 {
  margin-top: 20px;
}
</style>
