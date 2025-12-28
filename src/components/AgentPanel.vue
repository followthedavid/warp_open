<template>
  <div class="agent-panel">
    <div class="agent-header">
      <div class="header-left">
        <span class="agent-icon">🤖</span>
        <h3>AI Assistant</h3>
        <span :class="['status-indicator', { processing: isProcessing }]">
          {{ isProcessing ? 'Thinking...' : 'Ready' }}
        </span>
      </div>
      <div class="header-actions">
        <select v-model="selectedModel" class="model-select">
          <option value="qwen2.5-coder:1.5b">Qwen2.5 Coder 1.5B (Fast)</option>
          <option value="tinydolphin:1.1b">TinyDolphin 1.1B (Uncensored)</option>
          <option value="coder-uncensored:latest">Coder Uncensored 1.5B</option>
          <option value="stablelm2:1.6b">StableLM2 1.6B</option>
        </select>
        <button @click="clearChat" class="action-btn" title="Clear chat">
          🗑️
        </button>
        <button @click="handleUndo" class="action-btn" title="Undo last action">
          ↩️
        </button>
        <button v-if="isProcessing" @click="handleStop" class="action-btn stop-btn" title="Stop">
          ⏹️
        </button>
      </div>
    </div>

    <div class="messages-container" ref="messagesContainer">
      <div v-if="messages.length === 0" class="welcome-message">
        <div class="welcome-icon">✨</div>
        <h4>Welcome to AI Assistant</h4>
        <p>I can help you with:</p>
        <ul>
          <li>📁 Reading and editing files</li>
          <li>💻 Running shell commands</li>
          <li>🔍 Searching code</li>
          <li>📝 Explaining code</li>
        </ul>
        <div class="suggestions">
          <button @click="sendSuggestion('List files in the current directory')">
            List files
          </button>
          <button @click="sendSuggestion('Show me the contents of package.json')">
            Read package.json
          </button>
          <button @click="sendSuggestion('Find all TypeScript files')">
            Find *.ts files
          </button>
        </div>
      </div>

      <div
        v-for="msg in messages"
        :key="msg.id"
        :class="['message', msg.role]"
      >
        <div class="message-header">
          <span class="role-icon">{{ getRoleIcon(msg.role) }}</span>
          <span class="role-name">{{ getRoleName(msg.role) }}</span>
          <span class="timestamp">{{ formatTime(msg.timestamp) }}</span>
        </div>
        <div class="message-content">
          <div v-if="msg.toolCall" class="tool-call">
            <div class="tool-header">
              <span class="tool-icon">🔧</span>
              <span class="tool-name">{{ msg.toolCall.tool }}</span>
              <span :class="['tool-status', msg.toolCall.result?.success ? 'success' : 'error']">
                {{ msg.toolCall.result?.success ? '✓' : '✗' }}
              </span>
            </div>
            <div class="tool-params">
              <code v-for="(value, key) in msg.toolCall.params" :key="key">
                {{ key }}: {{ truncate(String(value), 100) }}
              </code>
            </div>
            <div v-if="msg.toolCall.result" class="tool-result">
              <pre v-if="msg.toolCall.result.output">{{ truncate(msg.toolCall.result.output, 500) }}</pre>
              <pre v-if="msg.toolCall.result.error" class="error">{{ msg.toolCall.result.error }}</pre>
            </div>
          </div>
          <div v-else class="text-content">
            <pre>{{ msg.content }}</pre>
          </div>
        </div>
      </div>

      <div v-if="isProcessing" class="processing-indicator">
        <span class="spinner"></span>
        <span>Processing...</span>
      </div>
    </div>

    <div class="input-container">
      <textarea
        v-model="inputText"
        @keydown="handleKeydown"
        placeholder="Ask me anything... (Shift+Enter for new line)"
        class="message-input"
        rows="2"
        :disabled="isProcessing"
      ></textarea>
      <button
        @click="sendMessage"
        :disabled="!inputText.trim() || isProcessing"
        class="send-btn"
      >
        {{ isProcessing ? '⏳' : '➤' }}
      </button>
    </div>

    <div class="context-bar">
      <span class="context-label">Context:</span>
      <span class="context-item">📂 {{ context.cwd }}</span>
      <span v-if="context.recentFiles.length > 0" class="context-item">
        📄 {{ context.recentFiles.length }} recent files
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'
import { useAgentMode } from '../composables/useAgentMode'

const props = defineProps<{
  paneId: string
}>()

const {
  messages,
  isProcessing,
  context,
  model,
  processMessage,
  updateContext,
  clearMessages,
  undo,
  stop,
  stats
} = useAgentMode(props.paneId)

const inputText = ref('')
const messagesContainer = ref<HTMLElement | null>(null)
const selectedModel = ref(model.value)

watch(selectedModel, (newModel) => {
  model.value = newModel
})

watch(messages, async () => {
  await nextTick()
  scrollToBottom()
}, { deep: true })

function scrollToBottom(): void {
  if (messagesContainer.value) {
    messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
  }
}

function sendMessage(): void {
  if (!inputText.value.trim() || isProcessing.value) return
  const text = inputText.value.trim()
  inputText.value = ''
  processMessage(text)
}

function sendSuggestion(text: string): void {
  inputText.value = text
  sendMessage()
}

function handleKeydown(event: KeyboardEvent): void {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault()
    sendMessage()
  }
}

function clearChat(): void {
  clearMessages()
}

async function handleUndo(): Promise<void> {
  const result = await undo()
  if (!result.success) {
    console.log('Undo failed:', result.message)
  }
}

function handleStop(): void {
  stop()
}

function getRoleIcon(role: string): string {
  switch (role) {
    case 'user': return '👤'
    case 'assistant': return '🤖'
    case 'tool': return '🔧'
    case 'system': return '⚙️'
    default: return '💬'
  }
}

function getRoleName(role: string): string {
  switch (role) {
    case 'user': return 'You'
    case 'assistant': return 'Assistant'
    case 'tool': return 'Tool'
    case 'system': return 'System'
    default: return role
  }
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text
  return text.slice(0, maxLen) + '...'
}
</script>

<style scoped>
.agent-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #1a1a3a;
  color: #e0e0e0;
}

.agent-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: #252545;
  border-bottom: 1px solid #3a3a5a;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.agent-icon {
  font-size: 20px;
}

.agent-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.status-indicator {
  padding: 4px 10px;
  background: #22c55e20;
  color: #22c55e;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 500;
}

.status-indicator.processing {
  background: #f59e0b20;
  color: #f59e0b;
}

.header-actions {
  display: flex;
  gap: 8px;
}

.model-select {
  padding: 6px 10px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  color: #a0a0c0;
  font-size: 12px;
  cursor: pointer;
}

.action-btn {
  padding: 6px 10px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s;
}

.action-btn:hover {
  background: #3a3a5a;
}

.action-btn.stop-btn {
  background: #ef444420;
  border-color: #ef4444;
}

.action-btn.stop-btn:hover {
  background: #ef444440;
}

.messages-container {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
}

.welcome-message {
  text-align: center;
  padding: 32px;
  color: #8080a0;
}

.welcome-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.welcome-message h4 {
  margin: 0 0 8px;
  font-size: 18px;
  color: #e0e0e0;
}

.welcome-message p {
  margin: 0 0 16px;
}

.welcome-message ul {
  list-style: none;
  padding: 0;
  margin: 0 0 24px;
  text-align: left;
  display: inline-block;
}

.welcome-message li {
  padding: 4px 0;
}

.suggestions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
}

.suggestions button {
  padding: 8px 14px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 16px;
  cursor: pointer;
  font-size: 12px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.suggestions button:hover {
  background: #3a3a5a;
  color: #e0e0e0;
  border-color: #6366f1;
}

.message {
  margin-bottom: 16px;
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.message-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.role-icon {
  font-size: 14px;
}

.role-name {
  font-size: 12px;
  font-weight: 600;
  color: #a0a0c0;
}

.timestamp {
  font-size: 10px;
  color: #6060a0;
}

.message-content {
  padding: 12px;
  background: #252545;
  border-radius: 8px;
  border-left: 3px solid #3a3a5a;
}

.message.user .message-content {
  border-left-color: #6366f1;
}

.message.assistant .message-content {
  border-left-color: #22c55e;
}

.message.tool .message-content {
  border-left-color: #f59e0b;
}

.text-content pre {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 13px;
  white-space: pre-wrap;
  word-break: break-word;
}

.tool-call {
  font-size: 12px;
}

.tool-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.tool-name {
  font-weight: 600;
  color: #f59e0b;
}

.tool-status {
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 10px;
}

.tool-status.success {
  background: #22c55e20;
  color: #22c55e;
}

.tool-status.error {
  background: #ef444420;
  color: #ef4444;
}

.tool-params {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-bottom: 8px;
}

.tool-params code {
  background: #1a1a3a;
  padding: 4px 8px;
  border-radius: 4px;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 11px;
  color: #a0a0c0;
}

.tool-result {
  background: #1a1a3a;
  border-radius: 6px;
  padding: 8px;
  max-height: 200px;
  overflow-y: auto;
}

.tool-result pre {
  margin: 0;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 11px;
  color: #a0a0c0;
  white-space: pre-wrap;
  word-break: break-word;
}

.tool-result pre.error {
  color: #ef4444;
}

.processing-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  color: #f59e0b;
  font-size: 13px;
}

.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid #f59e0b40;
  border-top-color: #f59e0b;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.input-container {
  display: flex;
  gap: 8px;
  padding: 12px 16px;
  background: #252545;
  border-top: 1px solid #3a3a5a;
}

.message-input {
  flex: 1;
  padding: 10px 14px;
  background: #1a1a3a;
  border: 1px solid #3a3a5a;
  border-radius: 8px;
  color: #e0e0e0;
  font-family: inherit;
  font-size: 13px;
  resize: none;
  outline: none;
}

.message-input:focus {
  border-color: #6366f1;
}

.message-input:disabled {
  opacity: 0.6;
}

.send-btn {
  padding: 0 16px;
  background: #6366f1;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  font-size: 18px;
  color: white;
  transition: all 0.2s;
}

.send-btn:hover:not(:disabled) {
  background: #5558dd;
}

.send-btn:disabled {
  background: #3a3a5a;
  cursor: not-allowed;
}

.context-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  background: #1a1a3a;
  border-top: 1px solid #252545;
  font-size: 11px;
  color: #6060a0;
}

.context-label {
  color: #8080a0;
}

.context-item {
  padding: 2px 8px;
  background: #252545;
  border-radius: 4px;
}
</style>
