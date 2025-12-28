<template>
  <div :class="['message-bubble', `message-${role}`, { 'is-tool-call': isToolCall, 'is-tool-result': isToolResult }]">
    <div class="message-header">
      <span class="message-role">
        <span v-if="isToolCall" class="tool-icon">🔧</span>
        <span v-else-if="isToolResult" class="tool-icon">📋</span>
        {{ roleLabel }}
      </span>
      <span class="message-time">{{ formattedTime }}</span>
    </div>
    <div class="message-content">
      <div v-if="isToolCall" class="tool-call-display">
        <div class="tool-name">{{ toolInfo.tool }}</div>
        <pre>{{ JSON.stringify(toolInfo.args, null, 2) }}</pre>
      </div>
      <div v-else-if="isToolResult" class="tool-result-display">
        <div class="result-label">{{ toolResultLabel }}</div>
        <pre>{{ toolResultContent }}</pre>
      </div>
      <pre v-else-if="isCode">{{ content }}<span v-if="streaming" class="streaming-cursor">▋</span></pre>
      <span v-else>{{ content }}<span v-if="streaming" class="streaming-cursor">▋</span></span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'

const props = defineProps<{
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: number | Date
  streaming?: boolean
}>()

// Debug logging
watch(() => props.content, (newContent) => {
  console.log(`[MessageBubble] Content changed for ${props.role}:`, newContent?.length || 0, 'chars')
}, { immediate: true })

const roleLabel = computed(() => {
  switch (props.role) {
    case 'user': return 'You'
    case 'assistant': return 'AI'
    case 'system': return 'System'
    default: return 'Unknown'
  }
})

const formattedTime = computed(() => {
  const date = props.timestamp instanceof Date ? props.timestamp : new Date(props.timestamp)
  return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
})

const isCode = computed(() => {
  return props.content.includes('\n') || props.content.startsWith('$')
})

const isToolCall = computed(() => {
  return props.role === 'assistant' && props.content.trim().startsWith('{') && props.content.includes('"tool"')
})

const isToolResult = computed(() => {
  return props.role === 'system' && props.content.startsWith('[Tool executed:')
})

const toolInfo = computed(() => {
  if (!isToolCall.value) return null
  try {
    return JSON.parse(props.content.trim())
  } catch {
    return null
  }
})

const toolResultLabel = computed(() => {
  if (!isToolResult.value) return ''
  const match = props.content.match(/\[Tool executed: ([^\]]+)\]/)
  return match ? match[1] : 'Tool Result'
})

const toolResultContent = computed(() => {
  if (!isToolResult.value) return props.content
  // Extract content after "Result:\n"
  const parts = props.content.split('Result:\n')
  return parts.length > 1 ? parts[1] : props.content
})
</script>

<style scoped>
.message-bubble {
  margin: 8px 0;
  padding: 12px;
  border-radius: 8px;
  max-width: 85%;
  animation: slideIn 0.2s ease-out;
}

@keyframes slideIn {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.message-user {
  background-color: #0084ff;
  color: white;
  margin-left: auto;
  border-bottom-right-radius: 4px;
}

.message-assistant {
  background-color: #2d2d2d;
  color: #e0e0e0;
  margin-right: auto;
  border-bottom-left-radius: 4px;
}

.message-system {
  background-color: #3a3a3a;
  color: #a0a0a0;
  margin: 8px auto;
  text-align: center;
  font-size: 0.9em;
  max-width: 70%;
}

.message-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 4px;
  font-size: 0.85em;
  opacity: 0.8;
}

.message-role {
  font-weight: 600;
}

.message-time {
  font-size: 0.9em;
}

.message-content {
  line-height: 1.4;
  word-wrap: break-word;
}

.message-content pre {
  background-color: rgba(0, 0, 0, 0.3);
  padding: 8px;
  border-radius: 4px;
  overflow-x: auto;
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 0.9em;
  margin: 4px 0 0 0;
}

.message-user .message-content pre {
  background-color: rgba(0, 0, 0, 0.2);
}

/* Tool call styling */
.is-tool-call {
  border-left: 3px solid #ffa500;
}

.is-tool-result {
  border-left: 3px solid #00bfff;
}

.tool-icon {
  margin-right: 4px;
  font-size: 1.1em;
}

.tool-call-display .tool-name {
  font-weight: 600;
  color: #ffa500;
  margin-bottom: 8px;
  font-size: 1.1em;
}

.tool-result-display .result-label {
  font-weight: 600;
  color: #00bfff;
  margin-bottom: 8px;
  font-size: 0.95em;
}

.tool-call-display pre,
.tool-result-display pre {
  background-color: rgba(0, 0, 0, 0.4);
  border-radius: 4px;
  padding: 10px;
  font-size: 0.85em;
  max-height: 400px;
  overflow-y: auto;
}

/* Streaming cursor animation */
.streaming-cursor {
  display: inline-block;
  animation: blink 0.7s infinite;
  color: #00ff00;
  font-weight: bold;
}

@keyframes blink {
  0%, 50% { opacity: 1; }
  51%, 100% { opacity: 0; }
}
</style>
