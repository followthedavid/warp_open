<template>
  <div class="ai-chat-tab">
    <div class="tab-header">
      <div class="header-left">
        <label class="model-label">Model:</label>
        <select v-model="selectedModel" @change="handleModelChange" class="model-selector">
          <option v-for="model in availableModels" :key="model" :value="model">
            {{ model }}
          </option>
        </select>

        <label class="model-label" style="margin-left: 16px;">AI Mode:</label>
        <select v-model="aiMode" @change="handleModeChange" class="model-selector mode-selector">
          <option value="local">🏠 Local Only</option>
          <option value="agent">🤖 Agent (Claude-level)</option>
          <option value="claude" :disabled="!isClaudeConfigured">☁️ Claude Only</option>
          <option value="auto" :disabled="!isClaudeConfigured">🎯 Auto (Orchestrate)</option>
          <option value="hybrid" :disabled="!isClaudeConfigured">🔄 Hybrid (Escalate)</option>
        </select>

        <label class="execution-toggle">
          <input type="checkbox" v-model="executionMode" @change="handleExecutionModeChange" />
          <span class="toggle-label">⚡ Code Execution</span>
        </label>

        <span class="agent-indicator" :class="{ online: agentBridge.connected }" style="margin-left: 16px;">
          🧭 {{ agentBridge.connected ? 'Agent' : 'Agent Off' }}
        </span>
      </div>
      <button @click="showClaudeSettings = !showClaudeSettings" class="settings-btn" :class="{ 'claude-configured': isClaudeConfigured }">
        {{ isClaudeConfigured ? '✓' : '⚙️' }} Claude API
      </button>
      <button @click="showPlan = !showPlan" class="settings-btn">
        📋 Plan
      </button>
      <button @click="showDebug = !showDebug" class="settings-btn">
        🐛 Debug
      </button>
    </div>
    <div class="messages-container" ref="messagesContainer">
      <div v-for="msg in messages" :key="msg.id" class="message-wrapper">
        <MessageBubble
          :role="msg.role"
          :content="msg.content"
          :timestamp="msg.timestamp"
          :streaming="msg.streaming"
        />

        <!-- Show execution steps if present -->
        <ExecutionSteps
          v-if="msg.executionTask"
          :task="msg.executionTask"
        />

        <!-- Escalation button for hybrid mode -->
        <button
          v-if="aiMode === 'hybrid' && msg.role === 'assistant' && !msg.streaming"
          @click="handleEscalate(msg.id)"
          class="escalate-btn"
        >
          ⬆️ Escalate to Claude
        </button>
      </div>
      <div v-if="isThinking" class="thinking-indicator">
        <span class="dot"></span>
        <span class="dot"></span>
        <span class="dot"></span>
      </div>
    </div>
    <AutonomySettings v-if="showSettings" @close="showSettings = false" />

    <!-- Claude API Settings Panel -->
    <div v-if="showClaudeSettings" class="claude-settings-panel">
      <div class="settings-header">
        <strong>Claude API Configuration</strong>
        <button @click="showClaudeSettings = false" class="close-btn">✕</button>
      </div>
      <div class="settings-body">
        <label class="settings-label">API Key:</label>
        <input
          v-model="claudeApiKey"
          type="password"
          class="settings-input"
          placeholder="sk-ant-api03-..."
        />
        <div class="settings-help">
          Get your API key from <a href="https://console.anthropic.com/" target="_blank">console.anthropic.com</a>
        </div>
        <button @click="saveClaudeSettings" class="save-btn">Save & Initialize</button>
        <div v-if="claudeError" class="error-message">{{ claudeError }}</div>
        <div v-if="isClaudeConfigured" class="success-message">✓ Claude API configured</div>
      </div>
    </div>

    <!-- Plan Panel -->
    <div v-if="showPlan" class="plan-panel-container">
      <div class="panel-header">
        <strong>Execution Plan</strong>
        <button @click="showPlan = false" class="close-btn">✕</button>
      </div>
      <PlanPanel />
    </div>

    <div v-if="showDebug" class="debug-panel">
      <div class="debug-header">
        <strong>Debug Logs</strong>
        <button @click="showDebug = false" class="close-debug">✕</button>
      </div>
      <div class="debug-logs">
        <div v-for="(log, idx) in debugLogs" :key="idx" class="debug-log">{{ log }}</div>
      </div>
    </div>
    <BatchPanel />
    <InputArea @send="handleSend" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import MessageBubble from './MessageBubble.vue'
import InputArea from './InputArea.vue'
import BatchPanel from './BatchPanel.vue'
import AutonomySettings from './AutonomySettings.vue'
import PlanPanel from './PlanPanel.vue'
import ExecutionSteps from './ExecutionSteps.vue'
import { useTabs, type Tab } from '../composables/useTabs'
import { useAI } from '../composables/useAI'
import { useCodeExecution } from '../composables/useCodeExecution'
import { useAgentBridge } from '../composables/useAgentBridge'

const props = defineProps<{
  tab: Tab
}>()

const { sendMessage } = useTabs()
const { getSession, sendPromptRouted, escalateToClaude, availableModels, refreshModels, setModel, claude, addMessage } = useAI()
const { parseTaskFromMessage, executeTask, getTaskSummary } = useCodeExecution()
const agentBridge = useAgentBridge()

const messagesContainer = ref<HTMLElement | null>(null)
const showSettings = ref(false)
const showDebug = ref(false)  // Hide debug panel by default now
const showClaudeSettings = ref(false)
const showPlan = ref(false)
const selectedModel = ref('qwen2.5-coder:1.5b')
const aiMode = ref<'local' | 'agent' | 'claude' | 'auto' | 'hybrid'>('local')
const claudeApiKey = ref('')
const claudeError = ref('')
const executionMode = ref(true) // Default to ON so code execution works out of the box

const isClaudeConfigured = computed(() => claude.isClaudeAvailable.value)

// Get AI session for this tab
const aiSession = computed(() => getSession(props.tab.id))

// Use messages from AI session ONLY - don't mix with tab messages
const messages = computed(() => {
  const aiMessages = aiSession.value?.messages || []
  const filtered = aiMessages.filter(msg => msg.role !== 'system')
  console.log(`[COMPUTED] messages computed, total: ${aiMessages.length}, filtered: ${filtered.length}`)
  return filtered
})

const isThinking = computed(() => aiSession.value?.isThinking || props.tab.is_thinking || false)

const debugLogs = computed(() => aiSession.value?.debugLogs || [])

// Load available models on mount
onMounted(async () => {
  await refreshModels()
  // Set initial model if session exists
  if (aiSession.value) {
    selectedModel.value = aiSession.value.model
  }
})

// Watch messages for debugging
watch(messages, (newMessages, oldMessages) => {
  console.log(`[WATCH] Messages changed! Count: ${newMessages.length}`)
  console.log('[WATCH] Messages:', newMessages.map(m => ({ role: m.role, contentLength: m.content?.length || 0 })))
  if (newMessages.length < (oldMessages?.length || 0)) {
    console.warn('[WATCH] ⚠️ MESSAGES DECREASED! Was:', oldMessages?.length, 'Now:', newMessages.length)
  }
}, { deep: true })

// Scroll to bottom when messages change
watch([messages, isThinking], () => {
  nextTick(() => {
    if (messagesContainer.value) {
      messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
    }
  })
}, { deep: true })

async function handleSend(message: string) {
  console.log('[AIChatTab] handleSend called, executionMode:', executionMode.value)
  // If execution mode is enabled, check if this is an actionable task
  if (executionMode.value) {
    console.log('[AIChatTab] Parsing task from message:', message)
    const taskDescription = await parseTaskFromMessage(message)
    console.log('[AIChatTab] Task description:', taskDescription)

    if (taskDescription) {
      // This is an actionable request - execute it!
      console.log('[AIChatTab] ✅ Executing task:', taskDescription)

      // Add user message
      addMessage(props.tab.id, {
        role: 'user',
        content: message,
      })

      // Create assistant message for execution and get reference to it
      const assistantMessage = addMessage(props.tab.id, {
        role: 'assistant',
        content: `Executing: ${taskDescription}`,
        isExecuting: true,
      })

      // Execute the task with live updates
      try {
        const task = await executeTask(assistantMessage.id, taskDescription, (steps) => {
          // Update the message with current execution steps
          console.log('[AIChatTab] Step update:', steps.length, 'steps')
          assistantMessage.executionTask = {
            id: assistantMessage.id,
            messageId: assistantMessage.id,
            description: taskDescription,
            status: 'running',
            createdAt: new Date(),
            steps: [...steps]
          }
        })

        // Update final result
        assistantMessage.executionTask = task
        assistantMessage.isExecuting = false
        assistantMessage.content = getTaskSummary(task)

        console.log('[AIChatTab] Task completed:', task.status)
      } catch (error) {
        assistantMessage.content = `❌ Execution failed: ${String(error)}`
        assistantMessage.isExecuting = false
        console.error('[AIChatTab] Execution error:', error)
      }

      return
    }
  }

  // Normal conversational mode - use routed sending
  await sendPromptRouted(props.tab.id, message, selectedModel.value)
}

function handleExecutionModeChange() {
  const session = getSession(props.tab.id)
  session.executionMode = executionMode.value
  console.log('[AIChatTab] Execution mode:', executionMode.value ? 'enabled' : 'disabled')
}

function handleModelChange() {
  setModel(props.tab.id, selectedModel.value)
}

function handleModeChange() {
  claude.setAIMode(aiMode.value)
  const session = getSession(props.tab.id)
  session.aiMode = aiMode.value
  console.log('[AIChatTab] AI mode changed to:', aiMode.value)
}

function handleEscalate(messageId: string) {
  escalateToClaude(props.tab.id, messageId)
}

function saveClaudeSettings() {
  claudeError.value = ''

  if (!claudeApiKey.value || !claudeApiKey.value.startsWith('sk-ant-')) {
    claudeError.value = 'Invalid API key format'
    return
  }

  try {
    claude.initClaude({
      apiKey: claudeApiKey.value,
      model: 'claude-sonnet-4-5-20250929'
    })
    showClaudeSettings.value = false
    console.log('[AIChatTab] Claude configured successfully')
  } catch (error) {
    claudeError.value = `Failed to initialize: ${error}`
  }
}

// Scroll to bottom on mount
nextTick(() => {
  if (messagesContainer.value) {
    messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
  }
})
</script>

<style scoped>
.ai-chat-tab {
  display: flex;
  flex-direction: column;
  height: 100%;
  background-color: #1e1e1e;
}

.tab-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px;
  background: #1a1a1a;
  border-bottom: 1px solid rgba(255,255,255,0.1);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.model-label {
  color: #d4d4d4;
  font-size: 12px;
  font-weight: 500;
}

.model-selector {
  background: #2d2d2d;
  color: #d4d4d4;
  border: 1px solid #444;
  border-radius: 4px;
  padding: 4px 8px;
  font-size: 12px;
  cursor: pointer;
}

.model-selector:hover {
  border-color: #4a9eff;
}

.settings-btn {
  padding: 6px 12px;
  background: #2d2d2d;
  color: #d4d4d4;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.settings-btn:hover {
  background: #4a9eff;
}

.messages-container {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.messages-container::-webkit-scrollbar {
  width: 8px;
}

.messages-container::-webkit-scrollbar-track {
  background: #1e1e1e;
}

.messages-container::-webkit-scrollbar-thumb {
  background: #404040;
  border-radius: 4px;
}

.messages-container::-webkit-scrollbar-thumb:hover {
  background: #505050;
}

.thinking-indicator {
  display: flex;
  gap: 4px;
  padding: 12px;
  margin-right: auto;
  background-color: #2d2d2d;
  border-radius: 8px;
  max-width: fit-content;
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: #666;
  animation: thinking 1.4s infinite;
}

.dot:nth-child(2) {
  animation-delay: 0.2s;
}

.dot:nth-child(3) {
  animation-delay: 0.4s;
}

@keyframes thinking {
  0%, 60%, 100% {
    opacity: 0.3;
    transform: scale(0.8);
  }
  30% {
    opacity: 1;
    transform: scale(1);
  }
}

.message-wrapper {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.detected-commands {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding-left: 8px;
}

.command-suggestion {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background-color: #2a2a2a;
  border-left: 3px solid #4a9eff;
  border-radius: 4px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  max-width: fit-content;
}

.command-suggestion code {
  color: #d4d4d4;
  font-size: 13px;
  background: none;
  padding: 0;
}

.run-btn {
  background-color: #4a9eff;
  color: white;
  border: none;
  padding: 4px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 4px;
}

.run-btn:hover {
  background-color: #6db3ff;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(74, 158, 255, 0.3);
}

.run-btn:active {
  transform: translateY(0);
}

.plan-panel-container {
  position: fixed;
  top: 50px;
  right: 20px;
  width: 600px;
  height: calc(100vh - 150px);
  background: #1a1a1a;
  border: 1px solid #4a9eff;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
  z-index: 1000;
  display: flex;
  flex-direction: column;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: #252525;
  border-bottom: 1px solid #4a9eff;
  border-radius: 8px 8px 0 0;
  color: #4a9eff;
  font-size: 14px;
  font-weight: 600;
}

.debug-panel {
  position: fixed;
  bottom: 80px;
  right: 20px;
  width: 500px;
  max-height: 400px;
  background: #1a1a1a;
  border: 1px solid #4a9eff;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
  z-index: 1000;
}

.debug-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: #252525;
  border-bottom: 1px solid #4a9eff;
  border-radius: 8px 8px 0 0;
  color: #4a9eff;
  font-size: 13px;
}

.close-debug {
  background: none;
  border: none;
  color: #999;
  cursor: pointer;
  font-size: 16px;
  padding: 0;
  width: 20px;
  height: 20px;
}

.close-debug:hover {
  color: #fff;
}

.debug-logs {
  padding: 8px;
  max-height: 350px;
  overflow-y: auto;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  font-size: 11px;
  line-height: 1.4;
}

.debug-log {
  color: #d4d4d4;
  padding: 2px 0;
  white-space: pre-wrap;
  word-break: break-all;
}

.debug-logs::-webkit-scrollbar {
  width: 6px;
}

.debug-logs::-webkit-scrollbar-track {
  background: #1a1a1a;
}

.debug-logs::-webkit-scrollbar-thumb {
  background: #404040;
  border-radius: 3px;
}

.debug-logs::-webkit-scrollbar-thumb:hover {
  background: #505050;
}

.escalate-btn {
  margin-top: 8px;
  padding: 6px 12px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  transition: all 0.2s;
  align-self: flex-start;
}

.escalate-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

.claude-settings-panel {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 500px;
  background: #1a1a1a;
  border: 1px solid #4a9eff;
  border-radius: 8px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
  z-index: 1000;
}

.settings-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  background: #252525;
  border-bottom: 1px solid #4a9eff;
  border-radius: 8px 8px 0 0;
  color: #4a9eff;
}

.settings-body {
  padding: 20px;
}

.settings-label {
  display: block;
  color: #d4d4d4;
  font-size: 14px;
  margin-bottom: 8px;
}

.settings-input {
  width: 100%;
  padding: 10px;
  background: #2d2d2d;
  border: 1px solid #444;
  border-radius: 4px;
  color: #d4d4d4;
  font-size: 14px;
  font-family: 'Monaco', 'Courier New', monospace;
  margin-bottom: 8px;
}

.settings-input:focus {
  outline: none;
  border-color: #4a9eff;
}

.settings-help {
  color: #888;
  font-size: 12px;
  margin-bottom: 16px;
}

.settings-help a {
  color: #4a9eff;
  text-decoration: none;
}

.settings-help a:hover {
  text-decoration: underline;
}

.save-btn {
  padding: 10px 20px;
  background: #4a9eff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  width: 100%;
}

.save-btn:hover {
  background: #6db3ff;
}

.close-btn {
  background: none;
  border: none;
  color: #999;
  cursor: pointer;
  font-size: 18px;
  padding: 0;
  width: 24px;
  height: 24px;
}

.close-btn:hover {
  color: #fff;
}

.error-message {
  margin-top: 12px;
  padding: 10px;
  background: rgba(255, 0, 0, 0.1);
  border: 1px solid rgba(255, 0, 0, 0.3);
  border-radius: 4px;
  color: #ff6b6b;
  font-size: 13px;
}

.success-message {
  margin-top: 12px;
  padding: 10px;
  background: rgba(0, 255, 0, 0.1);
  border: 1px solid rgba(0, 255, 0, 0.3);
  border-radius: 4px;
  color: #51cf66;
  font-size: 13px;
}

.claude-configured {
  background: linear-gradient(135deg, #51cf66 0%, #37b679 100%) !important;
  color: white !important;
}

.mode-selector {
  min-width: 200px;
}

.mode-selector option:disabled {
  color: #666;
}

.execution-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-left: 16px;
  cursor: pointer;
  user-select: none;
}

.execution-toggle input[type="checkbox"] {
  cursor: pointer;
  width: 16px;
  height: 16px;
}

.toggle-label {
  color: #d4d4d4;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
}

.execution-toggle:hover .toggle-label {
  color: #4a9eff;
}
</style>
