<template>
  <div class="daemon-panel">
    <div class="panel-header">
      <div class="header-left">
        <span class="panel-title">Personal AI Daemon</span>
        <span
          class="status-indicator"
          :class="status.healthStatus"
        >
          {{ status.running ? 'Running' : 'Stopped' }}
        </span>
      </div>
      <button class="close-btn" @click="$emit('close')">×</button>
    </div>

    <div class="panel-content">
      <!-- Status Overview -->
      <div class="status-overview">
        <div class="status-card">
          <div class="status-value">{{ status.tasksCompleted }}</div>
          <div class="status-label">Completed</div>
        </div>
        <div class="status-card">
          <div class="status-value">{{ status.tasksRunning }}</div>
          <div class="status-label">Running</div>
        </div>
        <div class="status-card">
          <div class="status-value">{{ status.approvalsWaiting }}</div>
          <div class="status-label">Awaiting</div>
        </div>
        <div class="status-card" :class="{ warning: status.tasksFailed > 0 }">
          <div class="status-value">{{ status.tasksFailed }}</div>
          <div class="status-label">Failed</div>
        </div>
      </div>

      <!-- Daemon Controls -->
      <div class="daemon-controls">
        <button
          v-if="!status.running"
          class="control-btn start"
          @click="$emit('start')"
        >
          Start Daemon
        </button>
        <button
          v-else
          class="control-btn stop"
          @click="$emit('stop')"
        >
          Stop Daemon
        </button>

        <div v-if="status.running" class="uptime">
          Started: {{ formatTime(status.startedAt) }}
        </div>
      </div>

      <!-- Next Task -->
      <div v-if="nextTask" class="next-task">
        <div class="section-title">Next Scheduled Task</div>
        <div class="task-preview">
          <span class="task-name">{{ nextTask.name }}</span>
          <span class="task-time">{{ formatRelativeTime(nextTask.nextRun) }}</span>
        </div>
      </div>

      <!-- Task List -->
      <div class="tasks-section">
        <div class="section-title">Scheduled Tasks</div>
        <div class="tasks-list">
          <div
            v-for="task in tasks"
            :key="task.id"
            class="task-item"
            :class="{ disabled: !task.enabled }"
          >
            <div class="task-header">
              <label class="task-toggle">
                <input
                  type="checkbox"
                  :checked="task.enabled"
                  @change="$emit('toggle-task', { id: task.id, enabled: !task.enabled })"
                />
                <span class="task-name">{{ task.name }}</span>
              </label>
              <button
                v-if="task.enabled"
                class="trigger-btn"
                @click="$emit('trigger-task', task.id)"
                title="Run now"
              >
                ▶
              </button>
            </div>
            <div class="task-details">
              <span class="task-schedule">
                {{ formatSchedule(task) }}
              </span>
              <span v-if="task.lastRun" class="task-last-run">
                Last: {{ formatRelativeTime(task.lastRun) }}
              </span>
            </div>
            <div class="task-stats">
              <span class="stat">{{ task.stats.successCount }}/{{ task.stats.runCount }} runs</span>
              <span v-if="task.stats.avgDuration" class="stat">
                ~{{ Math.round(task.stats.avgDuration / 1000) }}s avg
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Health Status -->
      <div class="health-section">
        <div class="section-title">System Health</div>
        <div class="health-indicator" :class="status.healthStatus">
          <span class="health-icon">
            {{ status.healthStatus === 'healthy' ? '✓' : status.healthStatus === 'degraded' ? '⚠' : '✗' }}
          </span>
          <span class="health-text">{{ status.healthStatus }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { DaemonStatus, ScheduledTask } from '../composables/useDaemonOrchestrator'

defineProps<{
  status: DaemonStatus
  tasks: ScheduledTask[]
  nextTask: ScheduledTask | null
}>()

defineEmits<{
  (e: 'close'): void
  (e: 'start'): void
  (e: 'stop'): void
  (e: 'trigger-task', taskId: string): void
  (e: 'toggle-task', payload: { id: string; enabled: boolean }): void
}>()

function formatTime(date?: Date): string {
  if (!date) return 'N/A'
  return new Date(date).toLocaleTimeString()
}

function formatRelativeTime(date: Date): string {
  const now = new Date()
  const d = new Date(date)
  const diff = d.getTime() - now.getTime()

  if (Math.abs(diff) < 60000) {
    return 'now'
  }

  const minutes = Math.round(diff / 60000)
  if (Math.abs(minutes) < 60) {
    return diff > 0 ? `in ${minutes}m` : `${-minutes}m ago`
  }

  const hours = Math.round(minutes / 60)
  if (Math.abs(hours) < 24) {
    return diff > 0 ? `in ${hours}h` : `${-hours}h ago`
  }

  const days = Math.round(hours / 24)
  return diff > 0 ? `in ${days}d` : `${-days}d ago`
}

function formatSchedule(task: ScheduledTask): string {
  if (task.cronPattern) {
    // Parse cron for display
    const parts = task.cronPattern.split(' ')
    if (parts.length >= 2) {
      const hour = parseInt(parts[1])
      return `Daily at ${hour}:00`
    }
    return task.cronPattern
  }
  if (task.intervalMinutes) {
    if (task.intervalMinutes >= 60) {
      return `Every ${task.intervalMinutes / 60}h`
    }
    return `Every ${task.intervalMinutes}m`
  }
  return 'Manual'
}
</script>

<style scoped>
.daemon-panel {
  position: fixed;
  right: 16px;
  top: 60px;
  width: 380px;
  max-height: calc(100vh - 100px);
  background: var(--warp-bg-surface);
  border: 1px solid var(--warp-border);
  border-radius: var(--warp-radius-lg);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  z-index: 100;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: var(--warp-bg-elevated);
  border-bottom: 1px solid var(--warp-border-subtle);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.panel-title {
  font-weight: 600;
  font-size: 14px;
}

.status-indicator {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 12px;
  font-weight: 500;
}

.status-indicator.healthy {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}

.status-indicator.degraded {
  background: rgba(245, 158, 11, 0.15);
  color: #f59e0b;
}

.status-indicator.unhealthy {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
}

.close-btn {
  background: transparent;
  border: none;
  color: var(--warp-text-tertiary);
  font-size: 20px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 4px;
}

.close-btn:hover {
  background: var(--warp-bg-hover);
  color: var(--warp-text-primary);
}

.panel-content {
  padding: 16px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* Status Overview */
.status-overview {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}

.status-card {
  background: var(--warp-bg-elevated);
  padding: 12px 8px;
  border-radius: 8px;
  text-align: center;
}

.status-card.warning {
  background: rgba(239, 68, 68, 0.1);
}

.status-value {
  font-size: 20px;
  font-weight: 600;
  color: var(--warp-text-primary);
}

.status-label {
  font-size: 10px;
  color: var(--warp-text-tertiary);
  text-transform: uppercase;
  margin-top: 4px;
}

/* Daemon Controls */
.daemon-controls {
  display: flex;
  align-items: center;
  gap: 12px;
}

.control-btn {
  flex: 1;
  padding: 10px 16px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
}

.control-btn.start {
  background: var(--warp-accent-primary);
  color: white;
}

.control-btn.start:hover {
  opacity: 0.9;
}

.control-btn.stop {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
}

.control-btn.stop:hover {
  background: rgba(239, 68, 68, 0.25);
}

.uptime {
  font-size: 11px;
  color: var(--warp-text-tertiary);
}

/* Next Task */
.next-task {
  background: var(--warp-bg-elevated);
  padding: 12px;
  border-radius: 8px;
}

.task-preview {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 8px;
}

.task-name {
  font-weight: 500;
  font-size: 13px;
}

.task-time {
  font-size: 12px;
  color: var(--warp-accent-primary);
  font-weight: 500;
}

/* Section Title */
.section-title {
  font-size: 11px;
  text-transform: uppercase;
  color: var(--warp-text-tertiary);
  letter-spacing: 0.5px;
  font-weight: 600;
}

/* Tasks List */
.tasks-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 12px;
}

.task-item {
  background: var(--warp-bg-elevated);
  padding: 12px;
  border-radius: 8px;
  transition: opacity 0.2s;
}

.task-item.disabled {
  opacity: 0.5;
}

.task-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.task-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.task-toggle input {
  cursor: pointer;
}

.task-toggle .task-name {
  font-weight: 500;
  font-size: 13px;
}

.trigger-btn {
  background: var(--warp-accent-primary);
  color: white;
  border: none;
  width: 24px;
  height: 24px;
  border-radius: 4px;
  font-size: 10px;
  cursor: pointer;
  opacity: 0.8;
}

.trigger-btn:hover {
  opacity: 1;
}

.task-details {
  display: flex;
  gap: 12px;
  margin-top: 6px;
  font-size: 11px;
  color: var(--warp-text-tertiary);
}

.task-stats {
  display: flex;
  gap: 12px;
  margin-top: 4px;
  font-size: 10px;
  color: var(--warp-text-quaternary, var(--warp-text-tertiary));
}

/* Health Section */
.health-section {
  margin-top: 8px;
}

.health-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  border-radius: 8px;
  margin-top: 8px;
}

.health-indicator.healthy {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.health-indicator.degraded {
  background: rgba(245, 158, 11, 0.1);
  color: #f59e0b;
}

.health-indicator.unhealthy {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}

.health-icon {
  font-size: 16px;
}

.health-text {
  font-weight: 500;
  font-size: 13px;
  text-transform: capitalize;
}
</style>
