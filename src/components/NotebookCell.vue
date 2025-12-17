<template>
  <div
    :class="['notebook-cell', cell.type, { active: isActive, collapsed: cell.collapsed }]"
    @click="$emit('select', cell.id)"
  >
    <div class="cell-gutter">
      <span v-if="cell.type === 'code'" class="execution-count">
        [{{ cell.executionCount || ' ' }}]
      </span>
      <span v-else class="cell-type-icon">
        {{ cell.type === 'markdown' ? '📝' : '📄' }}
      </span>
    </div>

    <div class="cell-content">
      <div class="cell-header">
        <div class="cell-actions">
          <button
            v-if="cell.type === 'code'"
            @click.stop="$emit('execute', cell.id)"
            :disabled="isExecuting"
            class="action-btn run"
            title="Run cell (Shift+Enter)"
          >
            {{ isExecuting ? '⏳' : '▶' }}
          </button>
          <button
            @click.stop="$emit('toggle-collapse', cell.id)"
            class="action-btn"
            :title="cell.collapsed ? 'Expand' : 'Collapse'"
          >
            {{ cell.collapsed ? '▼' : '▲' }}
          </button>
          <button
            @click.stop="$emit('move', cell.id, 'up')"
            class="action-btn"
            title="Move up"
          >
            ↑
          </button>
          <button
            @click.stop="$emit('move', cell.id, 'down')"
            class="action-btn"
            title="Move down"
          >
            ↓
          </button>
          <button
            @click.stop="$emit('delete', cell.id)"
            class="action-btn danger"
            title="Delete cell"
          >
            ×
          </button>
        </div>
        <div v-if="cell.startTime && cell.endTime" class="cell-timing">
          {{ formatDuration(cell.endTime - cell.startTime) }}
        </div>
      </div>

      <div v-show="!cell.collapsed" class="cell-body">
        <textarea
          v-if="isActive && cell.type !== 'output'"
          ref="editorRef"
          v-model="editContent"
          @input="onInput"
          @keydown="onKeydown"
          :placeholder="getPlaceholder()"
          class="cell-editor"
          :class="cell.type"
          rows="3"
        ></textarea>
        <div v-else class="cell-display" :class="cell.type">
          <pre v-if="cell.type === 'code'"><code>{{ cell.content || '# Empty cell' }}</code></pre>
          <div v-else-if="cell.type === 'markdown'" class="markdown-content" v-html="renderedMarkdown"></div>
          <pre v-else>{{ cell.content }}</pre>
        </div>

        <div v-if="cell.type === 'code' && (cell.output || cell.error)" class="cell-output">
          <div v-if="cell.error" class="output-error">
            <pre>{{ cell.error }}</pre>
          </div>
          <div v-if="cell.output" class="output-content">
            <pre>{{ cell.output }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import type { NotebookCell } from '../composables/useNotebook'
import { sanitizeMarkdown } from '../utils/sanitize'

const props = defineProps<{
  cell: NotebookCell
  isActive: boolean
  isExecuting: boolean
}>()

const emit = defineEmits<{
  select: [id: string]
  execute: [id: string]
  update: [id: string, content: string]
  delete: [id: string]
  move: [id: string, direction: 'up' | 'down']
  'toggle-collapse': [id: string]
  'add-below': [id: string, type: 'code' | 'markdown']
}>()

const editorRef = ref<HTMLTextAreaElement | null>(null)
const editContent = ref(props.cell.content)

watch(() => props.cell.content, (newContent) => {
  editContent.value = newContent
})

watch(() => props.isActive, async (active) => {
  if (active && props.cell.type !== 'output') {
    await nextTick()
    editorRef.value?.focus()
  }
})

onMounted(() => {
  if (props.isActive && editorRef.value) {
    editorRef.value.focus()
  }
})

const renderedMarkdown = computed(() => {
  // Simple markdown rendering with DOMPurify sanitization for XSS protection
  let html = props.cell.content
    .replace(/^### (.*$)/gm, '<h3>$1</h3>')
    .replace(/^## (.*$)/gm, '<h2>$1</h2>')
    .replace(/^# (.*$)/gm, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br>')
  return sanitizeMarkdown(html)
})

function getPlaceholder(): string {
  return props.cell.type === 'code'
    ? 'Enter shell command...'
    : 'Enter markdown text...'
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

function onInput(): void {
  emit('update', props.cell.id, editContent.value)
  autoResize()
}

function autoResize(): void {
  if (editorRef.value) {
    editorRef.value.style.height = 'auto'
    editorRef.value.style.height = editorRef.value.scrollHeight + 'px'
  }
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Enter' && event.shiftKey) {
    event.preventDefault()
    if (props.cell.type === 'code') {
      emit('execute', props.cell.id)
    }
  } else if (event.key === 'b' && (event.metaKey || event.ctrlKey)) {
    event.preventDefault()
    emit('add-below', props.cell.id, 'code')
  } else if (event.key === 'm' && (event.metaKey || event.ctrlKey)) {
    event.preventDefault()
    emit('add-below', props.cell.id, 'markdown')
  }
}
</script>

<style scoped>
.notebook-cell {
  display: flex;
  gap: 8px;
  padding: 8px;
  border: 1px solid transparent;
  border-radius: 8px;
  margin-bottom: 8px;
  background: #1e1e3e;
  transition: all 0.2s ease;
}

.notebook-cell:hover {
  border-color: #3a3a5a;
}

.notebook-cell.active {
  border-color: #6366f1;
  background: #252545;
}

.notebook-cell.collapsed {
  padding-bottom: 4px;
}

.cell-gutter {
  width: 50px;
  flex-shrink: 0;
  text-align: right;
  padding-right: 8px;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
  color: #6060a0;
}

.execution-count {
  color: #6366f1;
}

.cell-content {
  flex: 1;
  min-width: 0;
}

.cell-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
  opacity: 0;
  transition: opacity 0.2s;
}

.notebook-cell:hover .cell-header,
.notebook-cell.active .cell-header {
  opacity: 1;
}

.cell-actions {
  display: flex;
  gap: 4px;
}

.action-btn {
  width: 24px;
  height: 24px;
  border: none;
  background: #2a2a4a;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.action-btn:hover {
  background: #3a3a5a;
  color: #e0e0e0;
}

.action-btn.run {
  background: #22c55e20;
  color: #22c55e;
}

.action-btn.run:hover {
  background: #22c55e40;
}

.action-btn.danger:hover {
  background: #ef444420;
  color: #ef4444;
}

.cell-timing {
  font-size: 11px;
  color: #6060a0;
}

.cell-body {
  /* Body styles */
}

.cell-editor {
  width: 100%;
  background: #1a1a3a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  padding: 12px;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 13px;
  color: #e0e0e0;
  resize: none;
  outline: none;
  min-height: 60px;
}

.cell-editor:focus {
  border-color: #6366f1;
}

.cell-editor.markdown {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}

.cell-display {
  padding: 12px;
  background: #1a1a3a;
  border-radius: 6px;
}

.cell-display pre {
  margin: 0;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 13px;
  color: #e0e0e0;
  white-space: pre-wrap;
  word-break: break-word;
}

.cell-display code {
  color: #a78bfa;
}

.markdown-content {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 14px;
  color: #c0c0e0;
  line-height: 1.6;
}

.markdown-content h1, .markdown-content h2, .markdown-content h3 {
  margin: 0 0 8px;
  color: #e0e0e0;
}

.markdown-content code {
  background: #2a2a4a;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
}

.cell-output {
  margin-top: 8px;
  border-top: 1px solid #3a3a5a;
  padding-top: 8px;
}

.output-content pre {
  margin: 0;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
  color: #a0a0c0;
  white-space: pre-wrap;
  max-height: 300px;
  overflow-y: auto;
}

.output-error {
  margin-bottom: 8px;
}

.output-error pre {
  margin: 0;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
  color: #ef4444;
  white-space: pre-wrap;
}
</style>
