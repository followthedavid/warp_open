<template>
  <div class="ai-command-search" :class="{ expanded: isExpanded }">
    <div class="search-header" @click="toggleExpand">
      <span class="search-icon">🔮</span>
      <input
        v-model="searchQuery"
        @input="onInput"
        @keydown="onKeydown"
        @focus="isExpanded = true"
        placeholder="Describe what you want to do..."
        class="search-input"
        ref="inputRef"
      />
      <button
        v-if="searchQuery"
        @click.stop="clearSearch"
        class="clear-btn"
      >
        ×
      </button>
      <span v-if="isSearching" class="search-spinner"></span>
    </div>

    <div v-if="isExpanded" class="search-body">
      <div v-if="suggestions.length > 0" class="suggestions-list">
        <div
          v-for="(suggestion, index) in suggestions"
          :key="suggestion.id"
          :class="['suggestion-item', { selected: selectedIndex === index, dangerous: suggestion.dangerous }]"
          @click="selectSuggestion(suggestion)"
          @mouseenter="selectedIndex = index"
        >
          <div class="suggestion-header">
            <code class="suggestion-command">{{ suggestion.command }}</code>
            <span v-if="suggestion.dangerous" class="danger-badge">⚠️ Caution</span>
          </div>
          <div class="suggestion-description">{{ suggestion.description }}</div>
          <div v-if="suggestion.explanation" class="suggestion-explanation">
            {{ suggestion.explanation }}
          </div>
          <div class="suggestion-actions">
            <button @click.stop="copyCommand(suggestion.command)" class="action-btn">
              📋 Copy
            </button>
            <button @click.stop="insertCommand(suggestion.command)" class="action-btn primary">
              ➤ Insert
            </button>
          </div>
        </div>
      </div>

      <div v-else-if="searchQuery && !isSearching" class="no-results">
        <span class="no-results-icon">🤔</span>
        <p>No suggestions found. Try rephrasing your query.</p>
      </div>

      <div v-else-if="!searchQuery" class="search-hints">
        <h4>Try asking:</h4>
        <div class="hint-chips">
          <button
            v-for="hint in hints"
            :key="hint"
            @click="searchFor(hint)"
            class="hint-chip"
          >
            {{ hint }}
          </button>
        </div>

        <div v-if="recentSearches.length > 0" class="recent-searches">
          <h4>Recent:</h4>
          <div class="recent-list">
            <button
              v-for="recent in recentSearches"
              :key="recent"
              @click="searchFor(recent)"
              class="recent-item"
            >
              🕐 {{ recent }}
            </button>
          </div>
        </div>
      </div>

      <div v-if="error" class="error-message">
        {{ error }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useAICommandSearch, type CommandSuggestion } from '../composables/useAICommandSearch'

const emit = defineEmits<{
  'insert-command': [command: string]
  'execute-command': [command: string]
}>()

const {
  isSearching,
  suggestions,
  error,
  search,
  getRecentSearches,
  clearResults
} = useAICommandSearch()

const searchQuery = ref('')
const isExpanded = ref(false)
const selectedIndex = ref(0)
const inputRef = ref<HTMLInputElement | null>(null)

const hints = [
  'find large files',
  'list open ports',
  'check disk space',
  'kill process by name',
  'search for text in files',
  'compress a folder',
  'show running containers'
]

const recentSearches = computed(() => getRecentSearches())

let debounceTimeout: ReturnType<typeof setTimeout> | null = null

watch(suggestions, () => {
  selectedIndex.value = 0
})

function onInput(): void {
  if (debounceTimeout) clearTimeout(debounceTimeout)
  debounceTimeout = setTimeout(() => {
    if (searchQuery.value.trim()) {
      search(searchQuery.value)
    } else {
      clearResults()
    }
  }, 300)
}

function onKeydown(event: KeyboardEvent): void {
  if (!isExpanded.value) return

  switch (event.key) {
    case 'ArrowDown':
      event.preventDefault()
      if (selectedIndex.value < suggestions.value.length - 1) {
        selectedIndex.value++
      }
      break
    case 'ArrowUp':
      event.preventDefault()
      if (selectedIndex.value > 0) {
        selectedIndex.value--
      }
      break
    case 'Enter':
      event.preventDefault()
      if (suggestions.value.length > 0) {
        selectSuggestion(suggestions.value[selectedIndex.value])
      }
      break
    case 'Escape':
      isExpanded.value = false
      break
    case 'Tab':
      if (suggestions.value.length > 0) {
        event.preventDefault()
        insertCommand(suggestions.value[selectedIndex.value].command)
      }
      break
  }
}

function selectSuggestion(suggestion: CommandSuggestion): void {
  insertCommand(suggestion.command)
}

function insertCommand(command: string): void {
  emit('insert-command', command)
  isExpanded.value = false
  searchQuery.value = ''
  clearResults()
}

function copyCommand(command: string): void {
  navigator.clipboard.writeText(command)
}

function clearSearch(): void {
  searchQuery.value = ''
  clearResults()
}

function searchFor(query: string): void {
  searchQuery.value = query
  search(query)
}

function toggleExpand(): void {
  if (!isExpanded.value) {
    isExpanded.value = true
    inputRef.value?.focus()
  }
}

function handleClickOutside(event: MouseEvent): void {
  const target = event.target as HTMLElement
  if (!target.closest('.ai-command-search')) {
    isExpanded.value = false
  }
}

onMounted(() => {
  document.addEventListener('click', handleClickOutside)
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
  if (debounceTimeout) clearTimeout(debounceTimeout)
})
</script>

<style scoped>
.ai-command-search {
  position: relative;
  background: #252545;
  border: 1px solid #3a3a5a;
  border-radius: 12px;
  overflow: hidden;
  transition: all 0.2s ease;
}

.ai-command-search.expanded {
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}

.search-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  cursor: text;
}

.search-icon {
  font-size: 18px;
}

.search-input {
  flex: 1;
  background: transparent;
  border: none;
  font-size: 14px;
  color: #e0e0e0;
  outline: none;
}

.search-input::placeholder {
  color: #6060a0;
}

.clear-btn {
  width: 24px;
  height: 24px;
  border: none;
  background: #3a3a5a;
  border-radius: 50%;
  cursor: pointer;
  font-size: 14px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.clear-btn:hover {
  background: #4a4a6a;
  color: #e0e0e0;
}

.search-spinner {
  width: 18px;
  height: 18px;
  border: 2px solid #6366f140;
  border-top-color: #6366f1;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.search-body {
  border-top: 1px solid #3a3a5a;
  padding: 12px;
  max-height: 400px;
  overflow-y: auto;
}

.suggestions-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.suggestion-item {
  padding: 12px;
  background: #1e1e3e;
  border: 1px solid #3a3a5a;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.suggestion-item:hover,
.suggestion-item.selected {
  border-color: #6366f1;
  background: #2a2a4a;
}

.suggestion-item.dangerous {
  border-color: #f59e0b40;
}

.suggestion-item.dangerous.selected {
  border-color: #f59e0b;
}

.suggestion-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.suggestion-command {
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 13px;
  color: #a78bfa;
  background: #1a1a3a;
  padding: 4px 8px;
  border-radius: 4px;
}

.danger-badge {
  font-size: 11px;
  color: #f59e0b;
}

.suggestion-description {
  font-size: 13px;
  color: #e0e0e0;
  margin-bottom: 4px;
}

.suggestion-explanation {
  font-size: 12px;
  color: #8080a0;
  margin-bottom: 8px;
}

.suggestion-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.action-btn {
  padding: 6px 12px;
  background: #3a3a5a;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.action-btn:hover {
  background: #4a4a6a;
  color: #e0e0e0;
}

.action-btn.primary {
  background: #6366f1;
  color: white;
}

.action-btn.primary:hover {
  background: #5558dd;
}

.no-results {
  text-align: center;
  padding: 24px;
  color: #8080a0;
}

.no-results-icon {
  font-size: 32px;
  display: block;
  margin-bottom: 8px;
}

.search-hints h4,
.recent-searches h4 {
  margin: 0 0 12px;
  font-size: 12px;
  font-weight: 500;
  color: #8080a0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.hint-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}

.hint-chip {
  padding: 6px 12px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 16px;
  cursor: pointer;
  font-size: 12px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.hint-chip:hover {
  background: #3a3a5a;
  color: #e0e0e0;
  border-color: #6366f1;
}

.recent-searches {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #3a3a5a;
}

.recent-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.recent-item {
  padding: 8px 12px;
  background: transparent;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #a0a0c0;
  text-align: left;
  transition: all 0.2s;
}

.recent-item:hover {
  background: #2a2a4a;
  color: #e0e0e0;
}

.error-message {
  padding: 12px;
  background: #ef444420;
  border: 1px solid #ef444440;
  border-radius: 8px;
  color: #ef4444;
  font-size: 13px;
  margin-top: 12px;
}
</style>
