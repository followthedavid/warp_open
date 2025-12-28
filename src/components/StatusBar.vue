<template>
  <footer class="status-bar">
    <!-- Left: Git & CWD -->
    <div class="status-left">
      <!-- Git Branch -->
      <div v-if="gitBranch" class="status-item status-git">
        <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M6 3v12M18 9a3 3 0 100 6 3 3 0 000-6zM6 21a3 3 0 100-6 3 3 0 000 6zM18 12a9 9 0 01-9 9" stroke-linecap="round"/>
        </svg>
        <span class="git-branch">{{ gitBranch }}</span>
        <span v-if="gitDirty" class="git-dirty" title="Uncommitted changes">*</span>
      </div>

      <!-- Current Working Directory -->
      <div class="status-item status-cwd" :title="currentDirectory">
        <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span>{{ displayPath }}</span>
      </div>
    </div>

    <!-- Center: Notifications -->
    <div class="status-center">
      <div v-if="activeNotification" class="status-notification" :class="activeNotification.type">
        {{ activeNotification.message }}
      </div>
    </div>

    <!-- Right: AI & Recording Status -->
    <div class="status-right">
      <!-- Recording Indicator -->
      <div v-if="isRecording" class="status-item status-recording">
        <span class="recording-dot"></span>
        <span>{{ isPaused ? 'Paused' : 'Recording' }}</span>
      </div>

      <!-- AI Status -->
      <div class="status-item status-ai" :class="{ active: aiEnabled }">
        <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2a2 2 0 012 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 017 7h1a1 1 0 011 1v3a1 1 0 01-1 1h-1v1a2 2 0 01-2 2H5a2 2 0 01-2-2v-1H2a1 1 0 01-1-1v-3a1 1 0 011-1h1a7 7 0 017-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 012-2z" stroke-linecap="round"/>
          <circle cx="9" cy="13" r="1"/>
          <circle cx="15" cy="13" r="1"/>
          <path d="M9 17h6"/>
        </svg>
        <span>{{ aiEnabled ? 'AI Active' : 'AI Off' }}</span>
      </div>

      <!-- Model Info -->
      <div v-if="aiEnabled && modelName" class="status-item status-model" :title="modelName">
        <span>{{ shortModelName }}</span>
      </div>

      <!-- Ollama Connection -->
      <div class="status-item status-connection" :class="{ connected: ollamaConnected }">
        <span class="connection-dot"></span>
        <span>{{ ollamaConnected ? 'Ollama' : 'Offline' }}</span>
      </div>
    </div>
  </footer>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'

// Props
const props = defineProps<{
  currentDirectory?: string
  gitBranch?: string | null
  gitDirty?: boolean
  aiEnabled?: boolean
  modelName?: string
  isRecording?: boolean
  isPaused?: boolean
}>()

// Ollama connection state
const ollamaConnected = ref(false)

// Notification state
const activeNotification = ref<{ message: string; type: 'info' | 'success' | 'warning' | 'error' } | null>(null)

// Display path (shortened for UI)
const displayPath = computed(() => {
  const path = props.currentDirectory || '~'
  const homePrefix = '/Users/'

  if (path.startsWith(homePrefix)) {
    const afterHome = path.substring(homePrefix.length)
    const parts = afterHome.split('/')
    if (parts.length > 1) {
      return '~/' + parts.slice(1).join('/')
    }
    return '~'
  }

  return path
})

// Short model name
const shortModelName = computed(() => {
  const name = props.modelName || ''
  // Extract just the model name without version/size
  const parts = name.split(':')
  return parts[0] || name
})

// Check Ollama connection
async function checkOllamaConnection() {
  try {
    const response = await fetch('http://localhost:11434/api/tags')
    ollamaConnected.value = response.ok
  } catch {
    ollamaConnected.value = false
  }
}

// Polling interval
let connectionCheckInterval: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  checkOllamaConnection()
  connectionCheckInterval = setInterval(checkOllamaConnection, 10000) // Check every 10s
})

onUnmounted(() => {
  if (connectionCheckInterval) {
    clearInterval(connectionCheckInterval)
  }
})

// Expose method to show notifications
function showNotification(message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info', duration = 3000) {
  activeNotification.value = { message, type }
  setTimeout(() => {
    activeNotification.value = null
  }, duration)
}

defineExpose({ showNotification })
</script>

<style scoped>
.status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 24px;
  padding: 0 var(--warp-space-3);
  background: var(--warp-bg-surface);
  border-top: 1px solid var(--warp-border-subtle);
  font-size: var(--warp-text-xs);
  color: var(--warp-text-tertiary);
  user-select: none;
}

.status-left,
.status-center,
.status-right {
  display: flex;
  align-items: center;
  gap: var(--warp-space-4);
}

.status-center {
  flex: 1;
  justify-content: center;
}

.status-item {
  display: flex;
  align-items: center;
  gap: var(--warp-space-1);
}

.status-icon {
  width: 12px;
  height: 12px;
  opacity: 0.7;
}

/* Git Status */
.status-git {
  color: var(--warp-accent-secondary);
}

.git-branch {
  max-width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.git-dirty {
  color: var(--warp-warning);
  font-weight: var(--warp-weight-bold);
}

/* CWD */
.status-cwd {
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Notification */
.status-notification {
  padding: 2px var(--warp-space-2);
  border-radius: var(--warp-radius-sm);
  animation: warp-fade-in 0.2s ease;
}

.status-notification.info {
  background: var(--warp-info-bg);
  color: var(--warp-info);
}

.status-notification.success {
  background: var(--warp-success-bg);
  color: var(--warp-success);
}

.status-notification.warning {
  background: var(--warp-warning-bg);
  color: var(--warp-warning);
}

.status-notification.error {
  background: var(--warp-error-bg);
  color: var(--warp-error);
}

/* Recording Indicator */
.status-recording {
  color: var(--warp-error);
}

.recording-dot {
  width: 6px;
  height: 6px;
  border-radius: var(--warp-radius-full);
  background: var(--warp-error);
  animation: warp-pulse 1s ease-in-out infinite;
}

/* AI Status */
.status-ai {
  color: var(--warp-text-tertiary);
}

.status-ai.active {
  color: var(--warp-success);
}

.status-ai.active .status-icon {
  opacity: 1;
}

/* Model */
.status-model {
  color: var(--warp-accent-primary);
  font-family: var(--warp-font-mono);
}

/* Connection Status */
.status-connection {
  color: var(--warp-text-disabled);
}

.status-connection.connected {
  color: var(--warp-text-tertiary);
}

.connection-dot {
  width: 6px;
  height: 6px;
  border-radius: var(--warp-radius-full);
  background: var(--warp-text-disabled);
}

.status-connection.connected .connection-dot {
  background: var(--warp-success);
}

/* Hover effects */
.status-item {
  cursor: default;
  padding: 2px var(--warp-space-1);
  border-radius: var(--warp-radius-sm);
  transition: background var(--warp-transition-fast);
}

.status-item:hover {
  background: var(--warp-bg-hover);
}
</style>
