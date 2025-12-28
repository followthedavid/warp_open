<template>
  <div v-if="isVisible" class="ai-overlay" @click.stop>
    <div class="ai-header">
      <span class="ai-label">AI Assistant</span>
      <span class="ai-context">{{ contextLabel }}</span>
      <button
        v-if="timeline.length > 0"
        class="ai-clear"
        @click="clearTimeline"
        title="Clear history"
      >
        Clear
      </button>
      <button class="ai-close" @click="$emit('close')" title="Close (Esc)">×</button>
    </div>

    <!-- Suggestions Panel -->
    <div v-if="activeSuggestions.length > 0 && showSuggestions" class="suggestions-panel">
      <div class="suggestions-header">
        <span class="suggestions-label">
          <span class="suggestions-icon">💡</span>
          Suggestions
          <span v-if="isGeneratingSuggestions" class="generating-indicator">...</span>
        </span>
        <div class="suggestions-actions">
          <button class="dismiss-all-btn" @click="dismissAllSuggestions" title="Dismiss all">
            Clear
          </button>
          <button class="toggle-suggestions-btn" @click="toggleSuggestionsPanel" title="Hide suggestions">
            ▾
          </button>
        </div>
      </div>
      <div class="suggestions-list">
        <div
          v-for="suggestion in activeSuggestions"
          :key="suggestion.id"
          :class="['suggestion-item', `type-${suggestion.type}`]"
        >
          <span class="suggestion-type-badge">{{ getSuggestionBadge(suggestion.type) }}</span>
          <span class="suggestion-text">{{ suggestion.text }}</span>
          <div class="suggestion-actions">
            <button
              v-if="suggestion.command"
              class="use-btn"
              @click="useSuggestion(suggestion)"
              title="Copy command"
            >
              📋
            </button>
            <button
              class="ask-btn"
              @click="askAboutSuggestion(suggestion)"
              title="Ask about this"
            >
              ?
            </button>
            <button
              class="dismiss-btn"
              @click="dismissSuggestion(suggestion.id)"
              title="Dismiss"
            >
              ×
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Collapsed suggestions indicator -->
    <div v-else-if="activeSuggestions.length > 0 && !showSuggestions" class="suggestions-collapsed" @click="toggleSuggestionsPanel">
      <span>💡 {{ activeSuggestions.length }} suggestion{{ activeSuggestions.length > 1 ? 's' : '' }}</span>
      <span class="expand-icon">▸</span>
    </div>

    <div class="ai-content" ref="contentRef">
      <!-- Timeline View -->
      <div v-if="timeline.length > 0" class="ai-timeline">
        <div
          v-for="(entry, index) in timeline"
          :key="entry.id"
          :class="['timeline-entry', { collapsed: entry.collapsed }]"
        >
          <div class="entry-header" @click="toggleEntry(index)">
            <span class="entry-time">{{ formatTime(entry.timestamp) }}</span>
            <span class="entry-preview">{{ truncate(entry.query, 40) }}</span>
            <span class="entry-toggle">{{ entry.collapsed ? '▸' : '▾' }}</span>
          </div>

          <div v-if="!entry.collapsed" class="entry-content">
            <div class="entry-query">
              <span class="query-label">You:</span>
              {{ entry.query }}
            </div>

            <div v-if="entry.isLoading" class="entry-loading">
              <span class="loading-dots">Thinking...</span>
            </div>

            <div v-else-if="entry.response" class="entry-response">
              <span class="response-label">AI:</span>
              <div class="response-text" v-html="formatResponse(entry.response)"></div>

              <div v-if="entry.suggestedCommand" class="suggestion-box">
                <code>{{ entry.suggestedCommand }}</code>
                <button class="copy-btn" @click="copyCommand(entry.suggestedCommand)" title="Copy to clipboard">
                  Copy
                </button>
              </div>
            </div>

            <div v-else-if="entry.error" class="entry-error">
              {{ entry.error }}
            </div>
          </div>
        </div>
      </div>

      <!-- Empty state -->
      <div v-else class="ai-placeholder">
        <div class="placeholder-icon">🤖</div>
        <div class="placeholder-text">Ask questions about your terminal</div>
        <div class="placeholder-hint">
          Context: working directory + recent output
        </div>
      </div>

      <!-- Currently loading indicator at bottom -->
      <div v-if="currentlyLoading" class="loading-indicator">
        <span class="loading-dots">Processing...</span>
      </div>
    </div>

    <div class="ai-input-area">
      <input
        ref="inputRef"
        v-model="userInput"
        @keydown.enter="sendQuery"
        @keydown.esc="$emit('close')"
        @keydown.up="recallPreviousQuery"
        placeholder="Ask about this terminal..."
        class="ai-input"
        :disabled="currentlyLoading"
      />
      <button class="ai-send" @click="sendQuery" :disabled="currentlyLoading || !userInput.trim()">
        Send
      </button>
    </div>

    <!-- Quick actions -->
    <div v-if="timeline.length === 0" class="quick-actions">
      <button class="quick-btn" @click="quickQuery('What command should I run?')">
        💡 Suggest command
      </button>
      <button class="quick-btn" @click="quickQuery('Explain this error')">
        🔍 Explain error
      </button>
      <button class="quick-btn" @click="quickQuery('How do I fix this?')">
        🔧 How to fix
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { sanitizeHtml } from '../utils/sanitize'

interface TimelineEntry {
  id: string
  timestamp: number
  query: string
  response: string
  suggestedCommand: string
  error: string
  isLoading: boolean
  collapsed: boolean
  context: {
    cwd: string
    recentOutput: string
  }
}

interface Suggestion {
  id: string
  type: 'next_step' | 'fix' | 'explain' | 'optimize'
  text: string
  command?: string
  timestamp: number
  dismissed: boolean
}

const props = defineProps<{
  isVisible: boolean
  cwd: string | undefined
  recentOutput: string | undefined
  paneId: string
  lastCommand?: string
}>()

const emit = defineEmits(['close'])

const userInput = ref('')
const timeline = ref<TimelineEntry[]>([])
const inputRef = ref<HTMLInputElement | null>(null)
const contentRef = ref<HTMLElement | null>(null)
const queryHistory = ref<string[]>([])
const historyIndex = ref(-1)

// Suggestions system
const suggestions = ref<Suggestion[]>([])
const showSuggestions = ref(true)
const isGeneratingSuggestions = ref(false)
const lastProcessedCommand = ref<string | null>(null)

// Suggestions storage key
const suggestionsKey = computed(() => `ai-suggestions-${props.paneId}`)

// Per-pane timeline storage key
const storageKey = computed(() => `ai-timeline-${props.paneId}`)

// Load timeline from localStorage on mount
function loadTimeline() {
  try {
    const stored = localStorage.getItem(storageKey.value)
    if (stored) {
      const parsed = JSON.parse(stored)
      // Restore but mark all as not loading
      timeline.value = parsed.map((e: TimelineEntry) => ({
        ...e,
        isLoading: false,
        collapsed: true // Collapse old entries on load
      }))
    }
  } catch (e) {
    console.warn('[AIOverlay] Failed to load timeline:', e)
  }
}

// Save timeline to localStorage
function saveTimeline() {
  try {
    // Only save last 20 entries
    const toSave = timeline.value.slice(-20).map(e => ({
      ...e,
      isLoading: false // Never persist loading state
    }))
    localStorage.setItem(storageKey.value, JSON.stringify(toSave))
  } catch (e) {
    console.warn('[AIOverlay] Failed to save timeline:', e)
  }
}

const currentlyLoading = computed(() =>
  timeline.value.some(e => e.isLoading)
)

const contextLabel = computed(() => {
  if (props.cwd) {
    const parts = props.cwd.split('/')
    return parts.slice(-2).join('/') || props.cwd
  }
  return 'Terminal'
})

function formatTime(timestamp: number): string {
  const date = new Date(timestamp)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? text.slice(0, maxLength) + '...' : text
}

function formatResponse(text: string): string {
  // Simple markdown-lite formatting with DOMPurify sanitization for XSS protection
  const html = text
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br>')
  return sanitizeHtml(html)
}

function toggleEntry(index: number) {
  timeline.value[index].collapsed = !timeline.value[index].collapsed
}

function clearTimeline() {
  timeline.value = []
  localStorage.removeItem(storageKey.value)
}

function recallPreviousQuery(event: KeyboardEvent) {
  if (queryHistory.value.length === 0) return
  event.preventDefault()

  if (historyIndex.value < queryHistory.value.length - 1) {
    historyIndex.value++
    userInput.value = queryHistory.value[queryHistory.value.length - 1 - historyIndex.value]
  }
}

// Focus input when overlay becomes visible
watch(() => props.isVisible, (visible) => {
  if (visible) {
    loadTimeline()
    nextTick(() => {
      inputRef.value?.focus()
      scrollToBottom()
    })
  }
})

// Watch paneId changes to load correct timeline
watch(() => props.paneId, () => {
  loadTimeline()
})

function scrollToBottom() {
  nextTick(() => {
    if (contentRef.value) {
      contentRef.value.scrollTop = contentRef.value.scrollHeight
    }
  })
}

function quickQuery(query: string) {
  userInput.value = query
  sendQuery()
}

async function sendQuery() {
  const query = userInput.value.trim()
  if (!query || currentlyLoading.value) return

  // Add to history
  queryHistory.value.push(query)
  historyIndex.value = -1
  userInput.value = ''

  // Create new timeline entry
  const entry: TimelineEntry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    query,
    response: '',
    suggestedCommand: '',
    error: '',
    isLoading: true,
    collapsed: false,
    context: {
      cwd: props.cwd || 'unknown',
      recentOutput: (props.recentOutput || '').slice(-2000)
    }
  }

  // Collapse previous entries
  timeline.value.forEach(e => { e.collapsed = true })

  timeline.value.push(entry)
  scrollToBottom()

  try {
    // Use Ollama for local AI
    const aiResponse = await invoke<string>('query_ollama', {
      prompt: buildPrompt(entry.context, query),
      model: 'qwen2.5-coder:1.5b',
    })

    entry.response = aiResponse
    entry.isLoading = false

    // Extract command suggestion if present
    const cmdMatch = aiResponse.match(/```(?:bash|sh)?\s*\n([^\n]+)\n```/)
    if (cmdMatch) {
      entry.suggestedCommand = cmdMatch[1].trim()
    }

  } catch (error) {
    console.error('[AIOverlay] Query failed:', error)
    entry.error = error instanceof Error ? error.message : 'AI query failed'
    entry.isLoading = false
  }

  saveTimeline()
  scrollToBottom()
}

function buildPrompt(context: { cwd: string; recentOutput: string }, query: string): string {
  return `You are an AI assistant helping with terminal tasks.

Working directory: ${context.cwd}

Recent terminal output:
\`\`\`
${context.recentOutput || '(no recent output)'}
\`\`\`

User's question: ${query}

Provide a helpful, concise response. If suggesting a command, wrap it in \`\`\`bash code block.`
}

async function copyCommand(command: string) {
  if (!command) return
  try {
    await navigator.clipboard.writeText(command)
  } catch (err) {
    console.error('[AIOverlay] Copy failed:', err)
  }
}

// Suggestions functions
function loadSuggestions() {
  try {
    const stored = localStorage.getItem(suggestionsKey.value)
    if (stored) {
      suggestions.value = JSON.parse(stored).filter((s: Suggestion) => !s.dismissed)
    }
  } catch (e) {
    suggestions.value = []
  }
}

function saveSuggestions() {
  try {
    localStorage.setItem(suggestionsKey.value, JSON.stringify(suggestions.value.slice(-10)))
  } catch (e) {}
}

function dismissSuggestion(id: string) {
  const suggestion = suggestions.value.find(s => s.id === id)
  if (suggestion) {
    suggestion.dismissed = true
    saveSuggestions()
  }
}

function dismissAllSuggestions() {
  suggestions.value.forEach(s => { s.dismissed = true })
  saveSuggestions()
}

function toggleSuggestionsPanel() {
  showSuggestions.value = !showSuggestions.value
}

const activeSuggestions = computed(() =>
  suggestions.value.filter(s => !s.dismissed).slice(-5)
)

// Generate suggestions based on last command
async function generateSuggestions() {
  if (!props.lastCommand || props.lastCommand === lastProcessedCommand.value) {
    return
  }

  lastProcessedCommand.value = props.lastCommand
  isGeneratingSuggestions.value = true

  try {
    const prompt = buildSuggestionPrompt(props.lastCommand)
    const response = await invoke<string>('query_ollama', {
      prompt,
      model: 'qwen2.5-coder:1.5b',
    })

    // Parse suggestions from response
    const newSuggestions = parseSuggestions(response)
    if (newSuggestions.length > 0) {
      suggestions.value = [...suggestions.value.filter(s => !s.dismissed), ...newSuggestions]
      saveSuggestions()
    }
  } catch (error) {
    console.warn('[AIOverlay] Failed to generate suggestions:', error)
  } finally {
    isGeneratingSuggestions.value = false
  }
}

function buildSuggestionPrompt(lastCommand: string): string {
  const output = (props.recentOutput || '').slice(-1000)
  return `You are an AI assistant analyzing terminal commands.

Working directory: ${props.cwd || 'unknown'}
Last command executed: ${lastCommand}

Recent output:
\`\`\`
${output}
\`\`\`

Based on this context, provide 2-3 brief, actionable suggestions. Format as:
1. [TYPE] Suggestion text | command: \`actual_command\`

Where TYPE is one of: NEXT, FIX, EXPLAIN, OPTIMIZE

Example:
1. [NEXT] Run tests | command: \`npm test\`
2. [FIX] Add missing dependency | command: \`npm install lodash\`

Keep suggestions concise (under 50 chars). Only suggest if relevant.`
}

function parseSuggestions(response: string): Suggestion[] {
  const suggestions: Suggestion[] = []
  const lines = response.split('\n')

  for (const line of lines) {
    const match = line.match(/^\d+\.\s*\[(\w+)\]\s*(.+?)(?:\s*\|\s*command:\s*`([^`]+)`)?$/i)
    if (match) {
      const typeMap: Record<string, Suggestion['type']> = {
        'NEXT': 'next_step',
        'FIX': 'fix',
        'EXPLAIN': 'explain',
        'OPTIMIZE': 'optimize',
      }
      const type = typeMap[match[1].toUpperCase()] || 'next_step'
      suggestions.push({
        id: `sug-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        type,
        text: match[2].trim(),
        command: match[3]?.trim(),
        timestamp: Date.now(),
        dismissed: false,
      })
    }
  }

  return suggestions.slice(0, 3)
}

function useSuggestion(suggestion: Suggestion) {
  if (suggestion.command) {
    copyCommand(suggestion.command)
  }
  dismissSuggestion(suggestion.id)
}

function askAboutSuggestion(suggestion: Suggestion) {
  userInput.value = `Tell me more about: ${suggestion.text}`
  sendQuery()
}

function getSuggestionBadge(type: Suggestion['type']): string {
  const badges: Record<Suggestion['type'], string> = {
    'next_step': 'NEXT',
    'fix': 'FIX',
    'explain': 'INFO',
    'optimize': 'OPT',
  }
  return badges[type] || 'TIP'
}

// Watch for lastCommand changes to generate suggestions
watch(() => props.lastCommand, (newCmd) => {
  if (newCmd && props.isVisible) {
    generateSuggestions()
  }
})

// Load suggestions on mount
watch(() => props.isVisible, (visible) => {
  if (visible) {
    loadSuggestions()
    if (props.lastCommand && props.lastCommand !== lastProcessedCommand.value) {
      generateSuggestions()
    }
  }
})
</script>

<style scoped>
.ai-overlay {
  position: absolute;
  right: 8px;
  top: 8px;
  width: 400px;
  max-width: calc(100% - 16px);
  max-height: calc(100% - 16px);
  background: #1a1f2e;
  border: 1px solid #3b82f6;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
  z-index: 100;
  overflow: hidden;
}

.ai-header {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  background: #0f172a;
  border-bottom: 1px solid #334155;
  gap: 8px;
}

.ai-label {
  font-weight: 600;
  color: #3b82f6;
  font-size: 13px;
}

.ai-context {
  flex: 1;
  font-size: 11px;
  color: #64748b;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ai-clear {
  padding: 2px 8px;
  font-size: 10px;
  background: transparent;
  color: #64748b;
  border: 1px solid #334155;
  border-radius: 4px;
  cursor: pointer;
}

.ai-clear:hover {
  background: #334155;
  color: #e2e8f0;
}

.ai-close {
  width: 20px;
  height: 20px;
  border: none;
  background: transparent;
  color: #64748b;
  cursor: pointer;
  border-radius: 4px;
  font-size: 16px;
  line-height: 1;
}

.ai-close:hover {
  background: #334155;
  color: #f1f5f9;
}

.ai-content {
  flex: 1;
  overflow-y: auto;
  min-height: 120px;
  max-height: 400px;
}

/* Timeline styles */
.ai-timeline {
  padding: 8px;
}

.timeline-entry {
  background: #0f172a;
  border-radius: 6px;
  margin-bottom: 8px;
  overflow: hidden;
}

.timeline-entry:last-child {
  margin-bottom: 0;
}

.entry-header {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  gap: 8px;
  cursor: pointer;
  border-bottom: 1px solid transparent;
}

.timeline-entry:not(.collapsed) .entry-header {
  border-bottom-color: #334155;
}

.entry-header:hover {
  background: rgba(255, 255, 255, 0.03);
}

.entry-time {
  font-size: 10px;
  color: #64748b;
  font-family: 'SF Mono', Monaco, monospace;
}

.entry-preview {
  flex: 1;
  font-size: 12px;
  color: #94a3b8;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.entry-toggle {
  font-size: 10px;
  color: #64748b;
}

.entry-content {
  padding: 12px;
}

.entry-query {
  font-size: 12px;
  color: #e2e8f0;
  margin-bottom: 12px;
  padding-left: 12px;
  border-left: 2px solid #3b82f6;
}

.query-label, .response-label {
  font-size: 10px;
  font-weight: 600;
  color: #64748b;
  text-transform: uppercase;
  display: block;
  margin-bottom: 4px;
}

.entry-response {
  font-size: 13px;
  color: #e2e8f0;
  line-height: 1.5;
}

.entry-loading {
  color: #64748b;
  padding: 8px 0;
}

.entry-error {
  color: #ef4444;
  font-size: 12px;
  padding: 8px;
  background: rgba(239, 68, 68, 0.1);
  border-radius: 4px;
}

.response-text :deep(code) {
  background: #1e293b;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
  color: #10b981;
}

.suggestion-box {
  margin-top: 12px;
  padding: 8px;
  background: #1e293b;
  border-radius: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.suggestion-box code {
  flex: 1;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
  color: #10b981;
  overflow-x: auto;
}

.copy-btn {
  padding: 4px 8px;
  font-size: 11px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  flex-shrink: 0;
}

.copy-btn:hover {
  background: #2563eb;
}

/* Loading indicator */
.loading-indicator {
  text-align: center;
  padding: 12px;
  color: #64748b;
  font-size: 12px;
}

.loading-dots {
  animation: pulse 1.5s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 0.5; }
  50% { opacity: 1; }
}

/* Empty state */
.ai-placeholder {
  text-align: center;
  padding: 32px 16px;
}

.placeholder-icon {
  font-size: 32px;
  margin-bottom: 12px;
}

.placeholder-text {
  color: #94a3b8;
  font-size: 14px;
  margin-bottom: 8px;
}

.placeholder-hint {
  color: #64748b;
  font-size: 11px;
}

/* Input area */
.ai-input-area {
  display: flex;
  padding: 8px;
  background: #0f172a;
  border-top: 1px solid #334155;
  gap: 8px;
}

.ai-input {
  flex: 1;
  padding: 8px 12px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 6px;
  color: #e2e8f0;
  font-size: 13px;
  outline: none;
}

.ai-input:focus {
  border-color: #3b82f6;
}

.ai-input:disabled {
  opacity: 0.6;
}

.ai-send {
  padding: 8px 16px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
}

.ai-send:hover:not(:disabled) {
  background: #2563eb;
}

.ai-send:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Quick actions */
.quick-actions {
  display: flex;
  gap: 8px;
  padding: 8px;
  background: #0f172a;
  border-top: 1px solid #334155;
  flex-wrap: wrap;
}

.quick-btn {
  padding: 6px 10px;
  font-size: 11px;
  background: #1e293b;
  color: #94a3b8;
  border: 1px solid #334155;
  border-radius: 4px;
  cursor: pointer;
}

.quick-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

/* Suggestions Panel Styles */
.suggestions-panel {
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  border-bottom: 1px solid #334155;
  padding: 8px;
}

.suggestions-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.suggestions-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  font-weight: 600;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.suggestions-icon {
  font-size: 12px;
}

.generating-indicator {
  color: #3b82f6;
  animation: pulse 1s infinite;
}

.suggestions-actions {
  display: flex;
  gap: 4px;
}

.dismiss-all-btn,
.toggle-suggestions-btn {
  padding: 2px 6px;
  font-size: 10px;
  background: transparent;
  color: #64748b;
  border: 1px solid #334155;
  border-radius: 4px;
  cursor: pointer;
}

.dismiss-all-btn:hover,
.toggle-suggestions-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.suggestions-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.suggestion-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  background: rgba(15, 23, 42, 0.6);
  border-radius: 6px;
  border-left: 3px solid #64748b;
}

.suggestion-item.type-next_step {
  border-left-color: #10b981;
}

.suggestion-item.type-fix {
  border-left-color: #f59e0b;
}

.suggestion-item.type-explain {
  border-left-color: #3b82f6;
}

.suggestion-item.type-optimize {
  border-left-color: #8b5cf6;
}

.suggestion-type-badge {
  font-size: 9px;
  font-weight: 700;
  padding: 2px 5px;
  border-radius: 3px;
  background: #334155;
  color: #94a3b8;
  flex-shrink: 0;
}

.type-next_step .suggestion-type-badge {
  background: rgba(16, 185, 129, 0.2);
  color: #10b981;
}

.type-fix .suggestion-type-badge {
  background: rgba(245, 158, 11, 0.2);
  color: #f59e0b;
}

.type-explain .suggestion-type-badge {
  background: rgba(59, 130, 246, 0.2);
  color: #3b82f6;
}

.type-optimize .suggestion-type-badge {
  background: rgba(139, 92, 246, 0.2);
  color: #8b5cf6;
}

.suggestion-text {
  flex: 1;
  font-size: 12px;
  color: #e2e8f0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.suggestion-actions {
  display: flex;
  gap: 4px;
  flex-shrink: 0;
}

.use-btn,
.ask-btn,
.dismiss-btn {
  width: 22px;
  height: 22px;
  padding: 0;
  font-size: 11px;
  background: #1e293b;
  color: #94a3b8;
  border: 1px solid #334155;
  border-radius: 4px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
}

.use-btn:hover {
  background: #10b981;
  color: white;
  border-color: #10b981;
}

.ask-btn:hover {
  background: #3b82f6;
  color: white;
  border-color: #3b82f6;
}

.dismiss-btn:hover {
  background: #ef4444;
  color: white;
  border-color: #ef4444;
}

/* Collapsed suggestions indicator */
.suggestions-collapsed {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 12px;
  background: #1e293b;
  border-bottom: 1px solid #334155;
  font-size: 11px;
  color: #64748b;
  cursor: pointer;
}

.suggestions-collapsed:hover {
  background: #334155;
  color: #94a3b8;
}

.expand-icon {
  font-size: 10px;
}
</style>
