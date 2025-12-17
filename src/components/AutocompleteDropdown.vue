<template>
  <Teleport to="body">
    <div
      v-if="isVisible && suggestions.length > 0"
      class="autocomplete-dropdown"
      :style="dropdownStyle"
    >
      <div class="dropdown-header">
        <span class="header-title">Suggestions</span>
        <span class="header-hint">Tab to accept, Esc to dismiss</span>
      </div>
      <div class="suggestions-list" ref="listRef">
        <div
          v-for="(suggestion, index) in suggestions"
          :key="suggestion.id"
          :class="['suggestion-item', { selected: index === selectedIndex }]"
          @click="$emit('select', suggestion)"
          @mouseenter="$emit('hover', index)"
        >
          <span class="suggestion-icon">{{ suggestion.icon || getDefaultIcon(suggestion.type) }}</span>
          <div class="suggestion-content">
            <span class="suggestion-text">
              <span v-html="highlightMatch(suggestion.text, query)"></span>
            </span>
            <span v-if="suggestion.description" class="suggestion-desc">
              {{ suggestion.description }}
            </span>
          </div>
          <span :class="['suggestion-type', `type-${suggestion.type}`]">
            {{ suggestion.type }}
          </span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'
import type { Suggestion } from '../composables/useAutocomplete'

const props = defineProps<{
  isVisible: boolean
  suggestions: Suggestion[]
  selectedIndex: number
  query: string
  position: { x: number; y: number }
}>()

defineEmits<{
  select: [suggestion: Suggestion]
  hover: [index: number]
}>()

const listRef = ref<HTMLElement | null>(null)

const dropdownStyle = computed(() => ({
  left: `${props.position.x}px`,
  top: `${props.position.y}px`,
}))

function getDefaultIcon(type: string): string {
  switch (type) {
    case 'command': return '⌘'
    case 'path': return '📁'
    case 'flag': return '🏳️'
    case 'git': return ''
    case 'env': return '🔧'
    case 'history': return '⏱'
    case 'snippet': return '📝'
    default: return '•'
  }
}

function highlightMatch(text: string, query: string): string {
  if (!query) return escapeHtml(text)

  const lowerText = text.toLowerCase()
  const lowerQuery = query.toLowerCase()
  const index = lowerText.indexOf(lowerQuery)

  if (index === -1) return escapeHtml(text)

  const before = escapeHtml(text.slice(0, index))
  const match = escapeHtml(text.slice(index, index + query.length))
  const after = escapeHtml(text.slice(index + query.length))

  return `${before}<span class="highlight">${match}</span>${after}`
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// Scroll selected item into view
watch(() => props.selectedIndex, async (index) => {
  await nextTick()
  if (listRef.value) {
    const items = listRef.value.querySelectorAll('.suggestion-item')
    const selected = items[index] as HTMLElement
    if (selected) {
      selected.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    }
  }
})
</script>

<style scoped>
.autocomplete-dropdown {
  position: fixed;
  z-index: 10000;
  min-width: 300px;
  max-width: 500px;
  max-height: 320px;
  background: #1e1e2e;
  border: 1px solid #45475a;
  border-radius: 8px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  overflow: hidden;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.dropdown-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: #181825;
  border-bottom: 1px solid #45475a;
}

.header-title {
  font-size: 11px;
  font-weight: 600;
  color: #cdd6f4;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.header-hint {
  font-size: 10px;
  color: #6c7086;
}

.suggestions-list {
  max-height: 260px;
  overflow-y: auto;
}

.suggestion-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  cursor: pointer;
  transition: background 0.1s ease;
}

.suggestion-item:hover,
.suggestion-item.selected {
  background: #313244;
}

.suggestion-item.selected {
  border-left: 3px solid #89b4fa;
  padding-left: 9px;
}

.suggestion-icon {
  font-size: 16px;
  width: 24px;
  text-align: center;
  flex-shrink: 0;
}

.suggestion-content {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.suggestion-text {
  font-size: 13px;
  color: #cdd6f4;
  font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.suggestion-text :deep(.highlight) {
  color: #89b4fa;
  font-weight: 600;
}

.suggestion-desc {
  font-size: 11px;
  color: #6c7086;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.suggestion-type {
  font-size: 9px;
  font-weight: 600;
  text-transform: uppercase;
  padding: 2px 6px;
  border-radius: 4px;
  flex-shrink: 0;
}

.type-command {
  background: rgba(137, 180, 250, 0.2);
  color: #89b4fa;
}

.type-path {
  background: rgba(166, 227, 161, 0.2);
  color: #a6e3a1;
}

.type-flag {
  background: rgba(249, 226, 175, 0.2);
  color: #f9e2af;
}

.type-git {
  background: rgba(245, 194, 231, 0.2);
  color: #f5c2e7;
}

.type-env {
  background: rgba(148, 226, 213, 0.2);
  color: #94e2d5;
}

.type-history {
  background: rgba(180, 190, 254, 0.2);
  color: #b4befe;
}

.type-snippet {
  background: rgba(250, 179, 135, 0.2);
  color: #fab387;
}

/* Scrollbar */
.suggestions-list::-webkit-scrollbar {
  width: 6px;
}

.suggestions-list::-webkit-scrollbar-track {
  background: transparent;
}

.suggestions-list::-webkit-scrollbar-thumb {
  background: #45475a;
  border-radius: 3px;
}

.suggestions-list::-webkit-scrollbar-thumb:hover {
  background: #585b70;
}
</style>
