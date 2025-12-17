<template>
  <div class="developer-dashboard">
    <!-- Header with Controls -->
    <div class="dashboard-header">
      <div class="header-left">
        <h1>🤖 Autonomous AI Developer</h1>
        <div class="status-indicator" :class="{ active: isActive }">
          <span class="status-dot"></span>
          {{ isActive ? 'Running' : 'Stopped' }}
        </div>
        <div class="status-indicator ollama-status" :class="{ active: ollamaAvailable }">
          <span class="status-dot"></span>
          Ollama {{ ollamaAvailable ? 'Running' : 'Offline' }}
        </div>
      </div>
      <div class="header-controls">
        <button
          v-if="!isActive"
          @click="startDeveloper"
          class="btn-start"
        >
          ▶ Start
        </button>
        <button
          v-else
          @click="stopDeveloper"
          class="btn-stop"
        >
          ⏹ Stop
        </button>
        <button @click="showAddGoal = true" class="btn-add">
          + Add Goal
        </button>
        <button @click="showAgentConsole = !showAgentConsole" class="btn-agent">
          🧭 Agent
        </button>
      </div>
    </div>

    <!-- Main Dashboard Grid -->
    <div class="dashboard-grid">
      <!-- Current Task Card -->
      <div class="card current-task">
        <h2>Current Task</h2>
        <div v-if="currentTask" class="task-details">
          <div class="task-header">
            <span class="priority-badge" :class="currentTask.priority">
              {{ currentTask.priority }}
            </span>
            <span class="status-badge" :class="currentTask.status">
              {{ currentTask.status }}
            </span>
          </div>
          <p class="task-description">{{ currentTask.description }}</p>
          <div v-if="currentTask.planId" class="task-progress">
            <div class="progress-label">Executing plan...</div>
            <div class="progress-bar">
              <div
                class="progress-fill"
                :style="{ width: `${taskProgress}%` }"
              ></div>
            </div>
            <div class="progress-text">{{ taskProgress }}% complete</div>
          </div>
          <div class="task-meta">
            Started: {{ formatTime(currentTask.createdAt) }}
          </div>
        </div>
        <div v-else class="no-task">
          <p>No active task</p>
          <p class="hint">Add a goal to get started</p>
        </div>
      </div>

      <!-- Goals Queue -->
      <div class="card goals-queue">
        <h2>Goals Queue ({{ pendingGoals.length }})</h2>
        <div class="goals-list">
          <div
            v-for="goal in pendingGoals"
            :key="goal.id"
            class="goal-item"
            :class="goal.priority"
          >
            <div class="goal-header">
              <span class="priority-badge" :class="goal.priority">
                {{ goal.priority }}
              </span>
              <button @click="removeGoal(goal.id)" class="btn-remove">×</button>
            </div>
            <p>{{ goal.description }}</p>
            <div class="goal-meta">
              Added: {{ formatTime(goal.createdAt) }}
            </div>
          </div>
          <div v-if="pendingGoals.length === 0" class="no-goals">
            No pending goals
          </div>
        </div>
      </div>

      <!-- Recent Learnings -->
      <div class="card learnings">
        <h2>Recent Learnings</h2>
        <div class="learnings-list">
          <div
            v-for="(learning, idx) in recentLearnings"
            :key="idx"
            class="learning-item"
            :class="learning.result"
          >
            <div class="learning-header">
              <span class="result-icon">
                {{ learning.result === 'success' ? '✅' : '❌' }}
              </span>
              <span class="learning-action">{{ learning.action }}</span>
            </div>
            <p class="learning-lesson">{{ learning.lesson }}</p>
            <div class="learning-time">{{ formatTime(learning.timestamp) }}</div>
          </div>
          <div v-if="recentLearnings.length === 0" class="no-learnings">
            No learnings yet
          </div>
        </div>
      </div>

      <!-- Live Logs -->
      <div class="card live-logs">
        <h2>Live Execution Logs</h2>
        <div class="logs-container" ref="logsContainer">
          <div
            v-for="(log, idx) in liveLogs"
            :key="idx"
            class="log-entry"
            :class="log.level"
          >
            <span class="log-time">{{ formatLogTime(log.timestamp) }}</span>
            <span class="log-message">{{ log.message }}</span>
          </div>
          <div v-if="liveLogs.length === 0" class="no-logs">
            Waiting for activity...
          </div>
        </div>
      </div>

      <!-- Statistics -->
      <div class="card statistics">
        <h2>Statistics</h2>
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-value">{{ stats.totalGoals }}</div>
            <div class="stat-label">Total Goals</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">{{ stats.completedGoals }}</div>
            <div class="stat-label">Completed</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">{{ stats.failedGoals }}</div>
            <div class="stat-label">Failed</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">{{ stats.successRate }}%</div>
            <div class="stat-label">Success Rate</div>
          </div>
        </div>
      </div>

      <!-- Completed Goals History -->
      <div class="card history">
        <h2>Recently Completed</h2>
        <div class="history-list">
          <div
            v-for="goal in completedGoals"
            :key="goal.id"
            class="history-item"
          >
            <div class="history-header">
              <span class="completion-icon">✓</span>
              <span class="history-description">{{ goal.description }}</span>
            </div>
            <div class="history-time">
              Completed: {{ formatTime(goal.completedAt!) }}
            </div>
          </div>
          <div v-if="completedGoals.length === 0" class="no-history">
            No completed goals yet
          </div>
        </div>
      </div>
    </div>

    <!-- Add Goal Modal -->
    <div v-if="showAddGoal" class="modal-overlay" @click="showAddGoal = false">
      <div class="modal-content" @click.stop>
        <h2>Add New Goal</h2>
        <textarea
          v-model="newGoalDescription"
          placeholder="Describe what you want the AI to work on..."
          class="goal-input"
        ></textarea>
        <div class="priority-selector">
          <label>Priority:</label>
          <select v-model="newGoalPriority">
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
        <div class="modal-actions">
          <button @click="addGoal" class="btn-primary">Add Goal</button>
          <button @click="showAddGoal = false" class="btn-secondary">Cancel</button>
        </div>
      </div>
    </div>

    <!-- Agent Console Panel -->
    <AgentConsole v-if="showAgentConsole" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue';
import { autonomousDeveloper } from '../agents/autonomousDeveloper';
import AgentConsole from './AgentConsole.vue';

// State
const showAgentConsole = ref(false);
const isActive = ref(false);
const currentTask = ref<any>(null);
const goals = ref<any[]>([]);
const learnings = ref<any[]>([]);
const liveLogs = ref<Array<{ timestamp: Date; message: string; level: string }>>([]);
const showAddGoal = ref(false);
const newGoalDescription = ref('');
const newGoalPriority = ref<'low' | 'medium' | 'high' | 'critical'>('medium');
const logsContainer = ref<HTMLElement | null>(null);

// Ollama connection status
const ollamaAvailable = ref(false);

// Check if Ollama is running
async function checkOllama() {
  try {
    const response = await fetch('http://localhost:11434/api/tags');
    ollamaAvailable.value = response.ok;
  } catch {
    ollamaAvailable.value = false;
  }
}

// Computed
const pendingGoals = computed(() =>
  goals.value.filter(g => g.status === 'pending')
);

const completedGoals = computed(() =>
  goals.value
    .filter(g => g.status === 'completed')
    .slice(-5)
    .reverse()
);

const recentLearnings = computed(() =>
  learnings.value.slice(-10).reverse()
);

const taskProgress = computed(() => {
  // Calculate progress based on current task's plan
  // This is a simplified version
  if (!currentTask.value || !currentTask.value.planId) return 0;

  // In real implementation, would check plan step completion
  return Math.floor(Math.random() * 100); // Placeholder
});

const stats = computed(() => {
  const total = goals.value.length;
  const completed = goals.value.filter(g => g.status === 'completed').length;
  const failed = goals.value.filter(g => g.status === 'failed').length;
  const successRate = total > 0 ? Math.round((completed / total) * 100) : 0;

  return {
    totalGoals: total,
    completedGoals: completed,
    failedGoals: failed,
    successRate,
  };
});

// Methods
function startDeveloper() {
  autonomousDeveloper.start();
  isActive.value = true;
  addLog('System started', 'info');
}

function stopDeveloper() {
  autonomousDeveloper.stop();
  isActive.value = false;
  addLog('System stopped', 'info');
}

function addGoal() {
  if (!newGoalDescription.value.trim()) return;

  autonomousDeveloper.addGoal(newGoalDescription.value, newGoalPriority.value);
  addLog(`New goal added: ${newGoalDescription.value}`, 'success');

  newGoalDescription.value = '';
  newGoalPriority.value = 'medium';
  showAddGoal.value = false;

  refreshData();
}

function removeGoal(goalId: string) {
  // Implementation would remove from autonomousDeveloper
  addLog(`Goal removed`, 'warning');
  refreshData();
}

function addLog(message: string, level: 'info' | 'success' | 'warning' | 'error' = 'info') {
  liveLogs.value.push({
    timestamp: new Date(),
    message,
    level,
  });

  // Keep only last 100 logs
  if (liveLogs.value.length > 100) {
    liveLogs.value = liveLogs.value.slice(-100);
  }

  // Auto-scroll to bottom
  nextTick(() => {
    if (logsContainer.value) {
      logsContainer.value.scrollTop = logsContainer.value.scrollHeight;
    }
  });
}

function refreshData() {
  goals.value = autonomousDeveloper.getGoals();
  learnings.value = autonomousDeveloper.getLearnings();
  currentTask.value = autonomousDeveloper.getCurrentTask();
  isActive.value = autonomousDeveloper.isActive();
}

function formatTime(date: Date | string): string {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatLogTime(date: Date): string {
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

// Auto-refresh data
let refreshInterval: NodeJS.Timeout;

onMounted(() => {
  refreshData();
  checkOllama();

  // Refresh every 2 seconds
  refreshInterval = setInterval(() => {
    refreshData();
    checkOllama();
  }, 2000);

  addLog('Dashboard initialized', 'info');
});

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
});
</script>

<style scoped>
.developer-dashboard {
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: var(--bg-primary);
  color: var(--text-primary);
  overflow: hidden;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.header-left h1 {
  margin: 0;
  font-size: 24px;
  font-weight: 600;
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  background: var(--bg-tertiary);
  border-radius: 20px;
  font-size: 13px;
  color: var(--text-secondary);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #6b7280;
}

.status-indicator.active .status-dot {
  background: #10b981;
  animation: pulse 2s infinite;
}

.ollama-status.active .status-dot {
  background: #10b981;
}

.ollama-status:not(.active) {
  color: #ef4444;
}

.ollama-status:not(.active) .status-dot {
  background: #ef4444;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.header-controls {
  display: flex;
  gap: 12px;
}

.btn-start, .btn-stop, .btn-add {
  padding: 10px 20px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-start {
  background: var(--success-color);
  color: white;
}

.btn-start:hover {
  background: var(--success-hover);
}

.btn-stop {
  background: var(--error-color);
  color: white;
}

.btn-stop:hover {
  opacity: 0.9;
}

.btn-add {
  background: var(--primary-color);
  color: white;
}

.btn-add:hover {
  background: var(--primary-hover);
}

/* Dashboard Grid */
.dashboard-grid {
  flex: 1;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  grid-template-rows: auto auto auto;
  gap: 20px;
  padding: 20px;
  overflow-y: auto;
}

.card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 20px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.card h2 {
  margin: 0 0 16px 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.current-task {
  grid-column: span 2;
}

.goals-queue {
  grid-row: span 2;
}

.live-logs {
  grid-column: span 2;
  grid-row: span 2;
}

/* Current Task */
.task-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.task-header {
  display: flex;
  gap: 8px;
}

.priority-badge, .status-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.priority-badge.low { background: #e5e7eb; color: #374151; }
.priority-badge.medium { background: #dbeafe; color: #1e40af; }
.priority-badge.high { background: #fef3c7; color: #92400e; }
.priority-badge.critical { background: #fee2e2; color: #991b1b; }

.status-badge.pending { background: #f3f4f6; color: #6b7280; }
.status-badge.planning { background: #dbeafe; color: #1e40af; }
.status-badge.executing { background: #fef3c7; color: #92400e; }
.status-badge.completed { background: #d1fae5; color: #065f46; }
.status-badge.failed { background: #fee2e2; color: #991b1b; }

.task-description {
  font-size: 15px;
  color: var(--text-primary);
  margin: 0;
}

.task-progress {
  margin-top: 8px;
}

.progress-label {
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 8px;
}

.progress-bar {
  height: 8px;
  background: var(--bg-tertiary);
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--primary-color);
  transition: width 0.3s ease;
}

.progress-text {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
  text-align: right;
}

.task-meta {
  font-size: 12px;
  color: var(--text-tertiary);
}

.no-task {
  text-align: center;
  padding: 40px 20px;
  color: var(--text-secondary);
}

.no-task .hint {
  font-size: 13px;
  color: var(--text-tertiary);
}

/* Goals List */
.goals-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-height: 500px;
  overflow-y: auto;
}

.goal-item {
  padding: 12px;
  background: var(--bg-tertiary);
  border-radius: 6px;
  border-left: 3px solid var(--border-color);
}

.goal-item.critical { border-left-color: #ef4444; }
.goal-item.high { border-left-color: #f59e0b; }
.goal-item.medium { border-left-color: #3b82f6; }
.goal-item.low { border-left-color: #6b7280; }

.goal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.btn-remove {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-size: 20px;
  cursor: pointer;
  padding: 0 4px;
}

.btn-remove:hover {
  color: var(--error-color);
}

.goal-item p {
  margin: 0 0 8px 0;
  font-size: 14px;
}

.goal-meta {
  font-size: 11px;
  color: var(--text-tertiary);
}

/* Learnings */
.learnings-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-height: 300px;
  overflow-y: auto;
}

.learning-item {
  padding: 12px;
  background: var(--bg-tertiary);
  border-radius: 6px;
}

.learning-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.result-icon {
  font-size: 14px;
}

.learning-action {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.learning-lesson {
  margin: 0 0 8px 0;
  font-size: 13px;
  color: var(--text-secondary);
}

.learning-time {
  font-size: 11px;
  color: var(--text-tertiary);
}

/* Live Logs */
.logs-container {
  flex: 1;
  overflow-y: auto;
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 12px;
  line-height: 1.6;
  background: var(--bg-primary);
  padding: 12px;
  border-radius: 4px;
}

.log-entry {
  display: flex;
  gap: 12px;
  padding: 4px 0;
}

.log-time {
  color: var(--text-tertiary);
  flex-shrink: 0;
}

.log-message {
  color: var(--text-primary);
}

.log-entry.success .log-message {
  color: var(--success-color);
}

.log-entry.warning .log-message {
  color: #f59e0b;
}

.log-entry.error .log-message {
  color: var(--error-color);
}

/* Statistics */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

.stat-item {
  text-align: center;
}

.stat-value {
  font-size: 32px;
  font-weight: 700;
  color: var(--primary-color);
  margin-bottom: 4px;
}

.stat-label {
  font-size: 12px;
  color: var(--text-secondary);
  text-transform: uppercase;
}

/* History */
.history-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-height: 300px;
  overflow-y: auto;
}

.history-item {
  padding: 12px;
  background: var(--bg-tertiary);
  border-radius: 6px;
  border-left: 3px solid var(--success-color);
}

.history-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.completion-icon {
  color: var(--success-color);
  font-weight: 700;
}

.history-description {
  font-size: 14px;
  color: var(--text-primary);
}

.history-time {
  font-size: 11px;
  color: var(--text-tertiary);
}

/* Modal */
.modal-overlay {
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
}

.modal-content {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 24px;
  width: 500px;
  max-width: 90vw;
}

.modal-content h2 {
  margin: 0 0 16px 0;
  font-size: 18px;
}

.goal-input {
  width: 100%;
  min-height: 100px;
  padding: 12px;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  color: var(--text-primary);
  font-size: 14px;
  font-family: inherit;
  resize: vertical;
  margin-bottom: 16px;
}

.priority-selector {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.priority-selector label {
  font-size: 14px;
  color: var(--text-secondary);
}

.priority-selector select {
  padding: 8px 12px;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  color: var(--text-primary);
  font-size: 14px;
}

.modal-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

.btn-primary, .btn-secondary {
  padding: 10px 20px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
}

.btn-primary {
  background: var(--primary-color);
  color: white;
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.no-goals, .no-learnings, .no-history, .no-logs {
  text-align: center;
  padding: 20px;
  color: var(--text-tertiary);
  font-size: 13px;
}
</style>
