<template>
  <Teleport to="body">
    <div v-if="isVisible" class="command-palette-overlay" @click="close">
      <div class="command-palette" @click.stop>
        <div class="palette-header">
          <input
            ref="inputRef"
            v-model="query"
            @input="filterCommands"
            @keydown="handleKeydown"
            placeholder="Type a command..."
            class="palette-input"
            autocomplete="off"
            spellcheck="false"
          />
        </div>
        <div class="palette-results" ref="resultsRef">
          <!-- Recent commands section -->
          <div v-if="!query && recentCommands.length > 0" class="results-section">
            <div class="section-header">Recent</div>
            <div
              v-for="(cmd, index) in recentCommands"
              :key="'recent-' + cmd.id"
              class="palette-item"
              :class="{ selected: index === selectedIndex }"
              @click="executeCommand(cmd)"
              @mouseenter="selectedIndex = index"
            >
              <span class="item-icon">{{ cmd.icon }}</span>
              <span class="item-label">{{ cmd.label }}</span>
              <span class="item-shortcut" v-if="cmd.shortcut">{{ cmd.shortcut }}</span>
            </div>
          </div>
          <!-- All commands section (when no query) -->
          <div v-if="!query" class="results-section">
            <div class="section-header">All Commands</div>
          </div>
          <!-- Filtered/All commands -->
          <div
            v-for="(result, index) in filteredCommands"
            :key="result.command.id"
            class="palette-item"
            :class="{ selected: getActualIndex(index) === selectedIndex }"
            @click="executeCommand(result.command)"
            @mouseenter="selectedIndex = getActualIndex(index)"
          >
            <span class="item-icon">{{ result.command.icon }}</span>
            <span class="item-label" v-html="result.highlighted"></span>
            <span class="item-category">{{ result.command.category }}</span>
            <span class="item-shortcut" v-if="result.command.shortcut">{{ result.command.shortcut }}</span>
          </div>
          <div v-if="filteredCommands.length === 0 && query" class="palette-empty">
            No matching commands
          </div>
        </div>
        <div class="palette-footer">
          <span class="footer-hint">
            <kbd>↑↓</kbd> navigate
            <kbd>↵</kbd> select
            <kbd>esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'

interface Command {
  id: string
  label: string
  icon: string
  shortcut?: string
  category: string
  action: () => void
}

interface FuzzyResult {
  command: Command
  score: number
  highlighted: string
  matchedIndices: number[]
}

const props = defineProps<{
  isVisible: boolean
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'execute', command: string): void
  // Tab actions
  (e: 'new-terminal'): void
  (e: 'new-editor'): void
  (e: 'new-ai'): void
  (e: 'close-tab'): void
  // Pane actions
  (e: 'split-vertical'): void
  (e: 'split-horizontal'): void
  (e: 'toggle-ai-overlay'): void
  // Navigation
  (e: 'next-tab'): void
  (e: 'prev-tab'): void
  (e: 'next-pane'): void
  (e: 'prev-pane'): void
  // UI
  (e: 'toggle-sidebar'): void
  (e: 'show-shortcuts'): void
  (e: 'open-preferences'): void
  (e: 'open-folder'): void
  (e: 'global-search'): void
}>()

const query = ref('')
const selectedIndex = ref(0)
const inputRef = ref<HTMLInputElement | null>(null)
const resultsRef = ref<HTMLElement | null>(null)

// Recent commands storage
const RECENT_STORAGE_KEY = 'warp_open_recent_commands'
const MAX_RECENT = 5
const recentCommandIds = ref<string[]>(loadRecentCommands())

function loadRecentCommands(): string[] {
  try {
    const stored = localStorage.getItem(RECENT_STORAGE_KEY)
    return stored ? JSON.parse(stored) : []
  } catch {
    return []
  }
}

function saveRecentCommands(ids: string[]) {
  try {
    localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(ids.slice(0, MAX_RECENT)))
  } catch {
    // Ignore storage errors
  }
}

function addToRecent(commandId: string) {
  // Remove if already exists, then add to front
  const filtered = recentCommandIds.value.filter(id => id !== commandId)
  recentCommandIds.value = [commandId, ...filtered].slice(0, MAX_RECENT)
  saveRecentCommands(recentCommandIds.value)
}

// All available commands
const commands: Command[] = [
  // Tabs
  { id: 'new-terminal', label: 'New Terminal', icon: '>', shortcut: '⌘T', category: 'Tabs', action: () => emit('new-terminal') },
  { id: 'new-editor', label: 'New Editor', icon: '✎', shortcut: '', category: 'Tabs', action: () => emit('new-editor') },
  { id: 'new-ai', label: 'New AI Chat', icon: '◉', shortcut: '', category: 'Tabs', action: () => emit('new-ai') },
  { id: 'close-tab', label: 'Close Tab', icon: '✕', shortcut: '⌘W', category: 'Tabs', action: () => emit('close-tab') },
  { id: 'next-tab', label: 'Next Tab', icon: '→', shortcut: '⌘⇧]', category: 'Tabs', action: () => emit('next-tab') },
  { id: 'prev-tab', label: 'Previous Tab', icon: '←', shortcut: '⌘⇧[', category: 'Tabs', action: () => emit('prev-tab') },

  // Panes
  { id: 'split-vertical', label: 'Split Pane Vertically', icon: '┃', shortcut: '⌘⇧D', category: 'Panes', action: () => emit('split-vertical') },
  { id: 'split-horizontal', label: 'Split Pane Horizontally', icon: '━', shortcut: '⌘⇧E', category: 'Panes', action: () => emit('split-horizontal') },
  { id: 'next-pane', label: 'Next Pane', icon: '⇥', shortcut: '⌥→', category: 'Panes', action: () => emit('next-pane') },
  { id: 'prev-pane', label: 'Previous Pane', icon: '⇤', shortcut: '⌥←', category: 'Panes', action: () => emit('prev-pane') },

  // AI
  { id: 'toggle-ai', label: 'Toggle AI Overlay', icon: '◉', shortcut: '⌘⇧A', category: 'AI', action: () => emit('toggle-ai-overlay') },

  // Search
  { id: 'global-search', label: 'Search Tabs & Panes', icon: '🔍', shortcut: '⌘⇧F', category: 'Search', action: () => emit('global-search') },

  // UI
  { id: 'toggle-sidebar', label: 'Toggle Sidebar', icon: '☰', shortcut: '⌘B', category: 'View', action: () => emit('toggle-sidebar') },
  { id: 'show-shortcuts', label: 'Show Keyboard Shortcuts', icon: '⌨', shortcut: '⌘/', category: 'Help', action: () => emit('show-shortcuts') },
  { id: 'preferences', label: 'Open Preferences', icon: '⚙', shortcut: '⌘,', category: 'Settings', action: () => emit('open-preferences') },
  { id: 'open-folder', label: 'Open Folder', icon: '📁', shortcut: '⌘O', category: 'File', action: () => emit('open-folder') },
]

// Get recent commands as Command objects
const recentCommands = computed(() => {
  return recentCommandIds.value
    .map(id => commands.find(c => c.id === id))
    .filter((c): c is Command => c !== undefined)
})

// Fuzzy search implementation
function fuzzyMatch(pattern: string, text: string): { score: number; matchedIndices: number[] } | null {
  const patternLower = pattern.toLowerCase()
  const textLower = text.toLowerCase()

  let patternIdx = 0
  let textIdx = 0
  const matchedIndices: number[] = []
  let score = 0
  let consecutiveBonus = 0
  let lastMatchIdx = -2

  while (patternIdx < patternLower.length && textIdx < textLower.length) {
    if (patternLower[patternIdx] === textLower[textIdx]) {
      matchedIndices.push(textIdx)

      // Scoring
      // Base match score
      score += 10

      // Consecutive match bonus
      if (textIdx === lastMatchIdx + 1) {
        consecutiveBonus += 5
        score += consecutiveBonus
      } else {
        consecutiveBonus = 0
      }

      // Start of word bonus
      if (textIdx === 0 || text[textIdx - 1] === ' ' || text[textIdx - 1] === '-' || text[textIdx - 1] === '_') {
        score += 15
      }

      // Exact case match bonus
      if (pattern[patternIdx] === text[textIdx]) {
        score += 2
      }

      lastMatchIdx = textIdx
      patternIdx++
    }
    textIdx++
  }

  // All pattern characters must be found
  if (patternIdx !== patternLower.length) {
    return null
  }

  // Penalty for longer strings (prefer shorter matches)
  score -= (text.length - matchedIndices.length) * 0.5

  return { score, matchedIndices }
}

// Highlight matched characters in text
function highlightMatches(text: string, matchedIndices: number[]): string {
  if (matchedIndices.length === 0) return escapeHtml(text)

  let result = ''
  let lastIdx = 0

  for (const idx of matchedIndices) {
    // Add text before match
    result += escapeHtml(text.slice(lastIdx, idx))
    // Add highlighted character
    result += `<mark class="fuzzy-match">${escapeHtml(text[idx])}</mark>`
    lastIdx = idx + 1
  }

  // Add remaining text
  result += escapeHtml(text.slice(lastIdx))

  return result
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

const filteredCommands = computed((): FuzzyResult[] => {
  if (!query.value.trim()) {
    // Return all commands with no highlighting
    return commands.map(cmd => ({
      command: cmd,
      score: 0,
      highlighted: cmd.label,
      matchedIndices: []
    }))
  }

  const q = query.value.trim()
  const results: FuzzyResult[] = []

  for (const cmd of commands) {
    // Try matching against label, category, and id
    const labelMatch = fuzzyMatch(q, cmd.label)
    const categoryMatch = fuzzyMatch(q, cmd.category)
    const idMatch = fuzzyMatch(q, cmd.id)

    // Use the best match
    const bestMatch = [labelMatch, categoryMatch, idMatch]
      .filter((m): m is NonNullable<typeof m> => m !== null)
      .sort((a, b) => b.score - a.score)[0]

    if (bestMatch) {
      // Boost recently used commands
      const recentIdx = recentCommandIds.value.indexOf(cmd.id)
      const recentBonus = recentIdx !== -1 ? (MAX_RECENT - recentIdx) * 5 : 0

      results.push({
        command: cmd,
        score: bestMatch.score + recentBonus,
        highlighted: labelMatch ? highlightMatches(cmd.label, labelMatch.matchedIndices) : cmd.label,
        matchedIndices: labelMatch?.matchedIndices || []
      })
    }
  }

  // Sort by score descending
  return results.sort((a, b) => b.score - a.score)
})

// Calculate actual index accounting for recent commands section
function getActualIndex(filteredIndex: number): number {
  if (!query.value && recentCommands.value.length > 0) {
    return recentCommands.value.length + filteredIndex
  }
  return filteredIndex
}

// Get total selectable items count
const totalSelectableItems = computed(() => {
  if (!query.value && recentCommands.value.length > 0) {
    return recentCommands.value.length + filteredCommands.value.length
  }
  return filteredCommands.value.length
})

function filterCommands() {
  selectedIndex.value = 0
}

function handleKeydown(e: KeyboardEvent) {
  const maxIndex = totalSelectableItems.value - 1

  switch (e.key) {
    case 'ArrowDown':
      e.preventDefault()
      selectedIndex.value = Math.min(selectedIndex.value + 1, maxIndex)
      scrollToSelected()
      break
    case 'ArrowUp':
      e.preventDefault()
      selectedIndex.value = Math.max(selectedIndex.value - 1, 0)
      scrollToSelected()
      break
    case 'Enter':
      e.preventDefault()
      executeSelectedCommand()
      break
    case 'Escape':
      e.preventDefault()
      close()
      break
  }
}

function executeSelectedCommand() {
  // Determine which command is selected
  if (!query.value && recentCommands.value.length > 0) {
    // Check if selection is in recent commands
    if (selectedIndex.value < recentCommands.value.length) {
      executeCommand(recentCommands.value[selectedIndex.value])
      return
    }
    // Otherwise, selection is in filtered commands
    const filteredIdx = selectedIndex.value - recentCommands.value.length
    if (filteredCommands.value[filteredIdx]) {
      executeCommand(filteredCommands.value[filteredIdx].command)
    }
  } else {
    // No recent section, use filtered commands directly
    if (filteredCommands.value[selectedIndex.value]) {
      executeCommand(filteredCommands.value[selectedIndex.value].command)
    }
  }
}

function scrollToSelected() {
  nextTick(() => {
    const results = resultsRef.value
    if (!results) return
    const selected = results.querySelector('.selected') as HTMLElement
    if (selected) {
      selected.scrollIntoView({ block: 'nearest' })
    }
  })
}

function executeCommand(cmd: Command) {
  // Add to recent commands
  addToRecent(cmd.id)
  cmd.action()
  emit('execute', cmd.id)
  close()
}

function close() {
  query.value = ''
  selectedIndex.value = 0
  emit('close')
}

// Focus input when palette opens
watch(() => props.isVisible, (visible) => {
  if (visible) {
    nextTick(() => {
      inputRef.value?.focus()
    })
  }
})
</script>

<style scoped>
.command-palette-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 15vh;
  z-index: 1000;
  backdrop-filter: blur(2px);
}

.command-palette {
  width: 560px;
  max-width: 90vw;
  background: #1a1f2e;
  border: 1px solid #334155;
  border-radius: 12px;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  overflow: hidden;
}

.palette-header {
  padding: 16px;
  border-bottom: 1px solid #334155;
}

.palette-input {
  width: 100%;
  padding: 12px 16px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 8px;
  color: #e2e8f0;
  font-size: 16px;
  outline: none;
}

.palette-input:focus {
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
}

.palette-input::placeholder {
  color: #64748b;
}

.palette-results {
  max-height: 400px;
  overflow-y: auto;
  padding: 8px;
}

.palette-item {
  display: flex;
  align-items: center;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  gap: 12px;
}

.palette-item:hover,
.palette-item.selected {
  background: #334155;
}

.item-icon {
  width: 24px;
  text-align: center;
  font-size: 14px;
  color: #64748b;
}

.item-label {
  flex: 1;
  color: #e2e8f0;
  font-size: 14px;
}

.item-shortcut {
  font-size: 12px;
  color: #64748b;
  font-family: 'SF Mono', Monaco, monospace;
  padding: 2px 6px;
  background: #0f172a;
  border-radius: 4px;
}

.palette-empty {
  padding: 24px;
  text-align: center;
  color: #64748b;
  font-size: 14px;
}

/* Section headers for Recent/All Commands */
.results-section {
  margin-bottom: 4px;
}

.section-header {
  font-size: 11px;
  font-weight: 600;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 8px 12px 4px;
}

/* Category label */
.item-category {
  font-size: 11px;
  color: #64748b;
  margin-left: auto;
  margin-right: 8px;
}

/* Fuzzy match highlighting */
:deep(.fuzzy-match) {
  background: #3b82f620;
  color: #60a5fa;
  font-weight: 600;
  border-radius: 2px;
  padding: 0 1px;
}

.palette-footer {
  padding: 12px 16px;
  border-top: 1px solid #334155;
  background: #0f172a;
}

.footer-hint {
  font-size: 12px;
  color: #64748b;
}

.footer-hint kbd {
  display: inline-block;
  padding: 2px 6px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 4px;
  font-family: inherit;
  margin: 0 4px;
}

/* Scrollbar styling */
.palette-results::-webkit-scrollbar {
  width: 8px;
}

.palette-results::-webkit-scrollbar-track {
  background: transparent;
}

.palette-results::-webkit-scrollbar-thumb {
  background: #334155;
  border-radius: 4px;
}

.palette-results::-webkit-scrollbar-thumb:hover {
  background: #475569;
}
</style>
