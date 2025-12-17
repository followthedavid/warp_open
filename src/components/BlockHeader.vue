<template>
  <div class="block-header" @click="$emit('toggle')">
    <div class="header-left">
      <span class="collapse-icon">{{ collapsed ? '▶' : '▼' }}</span>
      <span :class="['exit-indicator', exitStatusClass]">{{ exitStatusIcon }}</span>
      <span class="command-text">{{ command || '(command)' }}</span>
    </div>
    <div class="header-right" @click.stop>
      <span v-if="duration !== null" class="duration">{{ formattedDuration }}</span>
      <span class="timestamp">{{ formattedTime }}</span>
      <button @click="$emit('rerun')" class="action-btn" title="Rerun command">
        ↻
      </button>
      <button @click="$emit('copy')" class="action-btn" title="Copy output">
        📋
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  command: string
  exitCode: number | null
  duration: number | null
  startTime: number
  collapsed: boolean
}>()

defineEmits<{
  toggle: []
  rerun: []
  copy: []
}>()

const exitStatusClass = computed(() => {
  if (props.exitCode === null) return 'running'
  return props.exitCode === 0 ? 'success' : 'error'
})

const exitStatusIcon = computed(() => {
  if (props.exitCode === null) return '●'
  return props.exitCode === 0 ? '✓' : '✗'
})

const formattedDuration = computed(() => {
  if (props.duration === null) return ''
  if (props.duration < 1000) return `${props.duration}ms`
  return `${(props.duration / 1000).toFixed(2)}s`
})

const formattedTime = computed(() => {
  const date = new Date(props.startTime)
  return date.toLocaleTimeString('en-US', { 
    hour: '2-digit', 
    minute: '2-digit',
    second: '2-digit'
  })
})
</script>

<style scoped>
.block-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 14px;
  background: #2a2a2a;
  cursor: pointer;
  user-select: none;
  transition: background 0.15s ease;
}

.block-header:hover {
  background: #333;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
  min-width: 0;
}

.collapse-icon {
  color: #888;
  font-size: 12px;
  width: 16px;
  transition: transform 0.2s ease;
}

.exit-indicator {
  font-size: 14px;
  font-weight: bold;
}

.exit-indicator.running {
  color: #ffa500;
  animation: pulse 1.5s ease-in-out infinite;
}

.exit-indicator.success {
  color: #4caf50;
}

.exit-indicator.error {
  color: #f44336;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.command-text {
  color: #d4d4d4;
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}

.duration {
  color: #888;
  font-size: 12px;
  font-family: monospace;
}

.timestamp {
  color: #666;
  font-size: 11px;
  font-family: monospace;
}

.action-btn {
  background: transparent;
  border: 1px solid #444;
  color: #999;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.15s ease;
}

.action-btn:hover {
  background: #444;
  color: #fff;
  border-color: #666;
}

.action-btn:active {
  transform: scale(0.95);
}
</style>
