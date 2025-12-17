<template>
  <Teleport to="body">
    <div v-if="isVisible" class="search-overlay" @click="close">
      <div class="search-panel" @click.stop>
        <div class="search-header">
          <div class="search-input-wrapper">
            <input
              ref="inputRef"
              v-model="query"
              @input="search"
              @keydown="handleKeydown"
              placeholder="Search tabs, panes, output..."
              class="search-input"
              autocomplete="off"
              spellcheck="false"
            />
            <div v-if="searchHistory.length > 0 && showHistory" class="search-history">
              <div
                v-for="(item, idx) in searchHistory"
                :key="idx"
                class="history-item"
                :class="{ selected: historyIndex === idx }"
                @click="useHistoryItem(item)"
              >
                <span class="history-icon">⏱</span>
                {{ item }}
              </div>
            </div>
          </div>
          <span class="search-hint">{{ results.length }} results</span>
        </div>

        <!-- Search Options -->
        <div class="search-options">
          <label class="option-toggle" title="Use Regular Expression">
            <input type="checkbox" v-model="useRegex" @change="search" />
            <span class="option-label">.*</span>
            <span class="option-text">Regex</span>
          </label>
          <label class="option-toggle" title="Case Sensitive">
            <input type="checkbox" v-model="caseSensitive" @change="search" />
            <span class="option-label">Aa</span>
            <span class="option-text">Match Case</span>
          </label>
          <div class="scope-selector">
            <span class="scope-label">Scope:</span>
            <select v-model="searchScope" @change="search" class="scope-select">
              <option value="all">All</option>
              <option value="tabs">Tabs Only</option>
              <option value="cwds">Directories</option>
              <option value="output">Output Only</option>
              <option value="snapshots">Snapshots</option>
            </select>
          </div>
        </div>

        <div class="search-results" ref="resultsRef">
          <div
            v-for="(result, index) in results"
            :key="result.id"
            class="result-item"
            :class="{ selected: index === selectedIndex }"
            @click="selectResult(result)"
            @mouseenter="selectedIndex = index"
          >
            <div class="result-icon">{{ result.icon }}</div>
            <div class="result-content">
              <div class="result-title" v-html="result.highlightedTitle"></div>
              <div class="result-meta">
                <span class="result-type">{{ result.type }}</span>
                <span v-if="result.context" class="result-context">{{ result.context }}</span>
              </div>
              <div v-if="result.preview" class="result-preview" v-html="result.highlightedPreview"></div>
            </div>
          </div>

          <div v-if="results.length === 0 && query" class="no-results">
            No matching results
          </div>

          <div v-if="!query" class="search-placeholder">
            <div class="placeholder-text">Type to search across:</div>
            <ul class="placeholder-list">
              <li>Tab names</li>
              <li>Working directories</li>
              <li>Recent terminal output</li>
            </ul>
          </div>
        </div>

        <div class="search-footer">
          <span class="footer-hint">
            <kbd>↑↓</kbd> navigate
            <kbd>↵</kbd> jump to
            <kbd>esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'

interface SearchResult {
  id: string
  type: 'tab' | 'pane' | 'output'
  icon: string
  title: string
  highlightedTitle: string
  context?: string
  preview?: string
  highlightedPreview?: string
  tabId: string
  paneId?: string
  score: number
}

interface LayoutNode {
  type: 'leaf' | 'split'
  paneId?: string
  cwd?: string
  ptyId?: number
  direction?: 'horizontal' | 'vertical'
  ratio?: number
  first?: LayoutNode
  second?: LayoutNode
}

interface Tab {
  id: string
  kind: string
  name: string
  layout?: LayoutNode
  activePaneId?: string
}

interface Pane {
  paneId: string
  cwd?: string
  ptyId: number
}

interface Snapshot {
  id: string
  name: string
  description?: string
  tags?: string[]
}

const props = defineProps<{
  isVisible: boolean
  tabs: Tab[]
  paneCwds: Map<string, string>
  paneOutputs: Map<string, string>
  snapshots?: Snapshot[]
}>()

const emit = defineEmits(['close', 'jump-to-tab', 'jump-to-pane', 'jump-to-snapshot'])

const query = ref('')
const selectedIndex = ref(0)
const inputRef = ref<HTMLInputElement | null>(null)
const resultsRef = ref<HTMLElement | null>(null)
const results = ref<SearchResult[]>([])

// Enhanced search options
const useRegex = ref(false)
const caseSensitive = ref(false)
const searchScope = ref<'all' | 'tabs' | 'cwds' | 'output' | 'snapshots'>('all')

// Search history
const HISTORY_KEY = 'warp_search_history'
const MAX_HISTORY = 10
const searchHistory = ref<string[]>([])
const showHistory = ref(false)
const historyIndex = ref(-1)

// Load search history
function loadHistory() {
  try {
    const stored = localStorage.getItem(HISTORY_KEY)
    if (stored) {
      searchHistory.value = JSON.parse(stored)
    }
  } catch (e) {
    searchHistory.value = []
  }
}

// Save to history
function saveToHistory(q: string) {
  if (!q.trim()) return

  // Remove if exists, add to front
  const idx = searchHistory.value.indexOf(q)
  if (idx !== -1) {
    searchHistory.value.splice(idx, 1)
  }
  searchHistory.value.unshift(q)

  // Limit size
  while (searchHistory.value.length > MAX_HISTORY) {
    searchHistory.value.pop()
  }

  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(searchHistory.value))
  } catch (e) {}
}

// Use history item
function useHistoryItem(item: string) {
  query.value = item
  showHistory.value = false
  historyIndex.value = -1
  search()
}

loadHistory()

// Fuzzy match implementation
function fuzzyMatch(pattern: string, text: string): { score: number; indices: number[] } | null {
  const patternLower = caseSensitive.value ? pattern : pattern.toLowerCase()
  const textLower = caseSensitive.value ? text : text.toLowerCase()

  let patternIdx = 0
  let textIdx = 0
  const indices: number[] = []
  let score = 0
  let consecutiveBonus = 0
  let lastMatchIdx = -2

  while (patternIdx < patternLower.length && textIdx < textLower.length) {
    if (patternLower[patternIdx] === textLower[textIdx]) {
      indices.push(textIdx)
      score += 10
      if (textIdx === lastMatchIdx + 1) {
        consecutiveBonus += 5
        score += consecutiveBonus
      } else {
        consecutiveBonus = 0
      }
      if (textIdx === 0 || /[\s\-_/]/.test(text[textIdx - 1])) {
        score += 15
      }
      lastMatchIdx = textIdx
      patternIdx++
    }
    textIdx++
  }

  if (patternIdx !== patternLower.length) return null
  return { score, indices }
}

// Regex match with timeout protection
function regexMatch(pattern: string, text: string): { score: number; indices: number[] } | null {
  try {
    const flags = caseSensitive.value ? 'g' : 'gi'
    const regex = new RegExp(pattern, flags)

    // Set a timeout to prevent catastrophic backtracking
    const startTime = Date.now()
    const MAX_TIME = 100 // 100ms max

    const match = regex.exec(text)
    if (Date.now() - startTime > MAX_TIME) {
      console.warn('[GlobalSearch] Regex timeout')
      return null
    }

    if (!match) return null

    // Get match indices
    const indices: number[] = []
    const matchStart = match.index
    for (let i = 0; i < match[0].length; i++) {
      indices.push(matchStart + i)
    }

    return {
      score: 50 + (match[0].length * 2), // Score based on match length
      indices,
    }
  } catch (e) {
    // Invalid regex
    return null
  }
}

// Combined match function
function matchText(pattern: string, text: string): { score: number; indices: number[] } | null {
  if (useRegex.value) {
    return regexMatch(pattern, text)
  }
  return fuzzyMatch(pattern, text)
}

// Highlight matched characters
function highlight(text: string, indices: number[]): string {
  if (indices.length === 0) return escapeHtml(text)
  let result = ''
  let lastIdx = 0
  for (const idx of indices) {
    result += escapeHtml(text.slice(lastIdx, idx))
    result += `<mark class="search-match">${escapeHtml(text[idx])}</mark>`
    lastIdx = idx + 1
  }
  result += escapeHtml(text.slice(lastIdx))
  return result
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

// Get all panes from a layout
function getPanesFromLayout(node: LayoutNode | undefined): Pane[] {
  if (!node) return []
  if (node.type === 'leaf') {
    return [{ paneId: node.paneId || '', cwd: node.cwd, ptyId: node.ptyId || 0 }]
  }
  return [...getPanesFromLayout(node.first), ...getPanesFromLayout(node.second)]
}

function search() {
  selectedIndex.value = 0
  showHistory.value = false

  if (!query.value.trim()) {
    results.value = []
    return
  }

  const q = query.value.trim()
  const searchResults: SearchResult[] = []
  const scope = searchScope.value

  // Search tabs
  if (scope === 'all' || scope === 'tabs') {
    for (const tab of props.tabs) {
      const tabMatch = matchText(q, tab.name)
      if (tabMatch) {
        searchResults.push({
          id: `tab-${tab.id}`,
          type: 'tab',
          icon: tab.kind === 'terminal' ? '>' : tab.kind === 'ai' ? '◉' : '✎',
          title: tab.name,
          highlightedTitle: highlight(tab.name, tabMatch.indices),
          context: tab.kind,
          tabId: tab.id,
          score: tabMatch.score + 20
        })
      }
    }
  }

  // Search panes (CWDs and output)
  for (const tab of props.tabs) {
    if (tab.kind === 'terminal' && tab.layout) {
      const panes = getPanesFromLayout(tab.layout)
      for (const pane of panes) {
        // Search CWD
        if (scope === 'all' || scope === 'cwds') {
          const cwd = props.paneCwds.get(pane.paneId) || pane.cwd
          if (cwd) {
            const cwdMatch = matchText(q, cwd)
            if (cwdMatch) {
              searchResults.push({
                id: `cwd-${pane.paneId}`,
                type: 'pane',
                icon: '📁',
                title: cwd.split('/').pop() || cwd,
                highlightedTitle: highlight(cwd.split('/').pop() || cwd, []),
                context: `in ${tab.name}`,
                preview: cwd,
                highlightedPreview: highlight(cwd, cwdMatch.indices),
                tabId: tab.id,
                paneId: pane.paneId,
                score: cwdMatch.score
              })
            }
          }
        }

        // Search recent output
        if (scope === 'all' || scope === 'output') {
          const output = props.paneOutputs.get(pane.paneId)
          if (output) {
            const lines = output.split('\n').filter(l => l.trim())
            let matchCount = 0
            for (const line of lines.slice(-50)) { // Last 50 lines
              if (matchCount >= 3) break // Max 3 matches per pane
              const outputMatch = matchText(q, line)
              if (outputMatch) {
                searchResults.push({
                  id: `output-${pane.paneId}-${matchCount}-${Date.now()}`,
                  type: 'output',
                  icon: '📄',
                  title: truncate(line, 60),
                  highlightedTitle: highlight(truncate(line, 60), outputMatch.indices),
                  context: `in ${tab.name}`,
                  tabId: tab.id,
                  paneId: pane.paneId,
                  score: outputMatch.score - 10
                })
                matchCount++
              }
            }
          }
        }
      }
    }
  }

  // Search snapshots
  if ((scope === 'all' || scope === 'snapshots') && props.snapshots) {
    for (const snapshot of props.snapshots) {
      const nameMatch = matchText(q, snapshot.name)
      const descMatch = snapshot.description ? matchText(q, snapshot.description) : null
      const tagMatch = snapshot.tags?.some(t => matchText(q, t))

      if (nameMatch || descMatch || tagMatch) {
        searchResults.push({
          id: `snapshot-${snapshot.id}`,
          type: 'tab', // Use 'tab' type for now
          icon: '📸',
          title: snapshot.name,
          highlightedTitle: nameMatch ? highlight(snapshot.name, nameMatch.indices) : escapeHtml(snapshot.name),
          context: 'snapshot',
          preview: snapshot.description,
          highlightedPreview: descMatch && snapshot.description ? highlight(snapshot.description, descMatch.indices) : snapshot.description,
          tabId: snapshot.id, // Store snapshot ID
          score: (nameMatch?.score || 0) + (descMatch?.score || 0) + (tagMatch ? 20 : 0)
        })
      }
    }
  }

  // Sort by score descending
  results.value = searchResults.sort((a, b) => b.score - a.score).slice(0, 30)
}

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) + '...' : text
}

function handleKeydown(e: KeyboardEvent) {
  // Handle history navigation when input is empty or focused
  if (!query.value && searchHistory.value.length > 0) {
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      showHistory.value = true
      historyIndex.value = Math.min(historyIndex.value + 1, searchHistory.value.length - 1)
      if (historyIndex.value >= 0) {
        query.value = searchHistory.value[historyIndex.value]
      }
      return
    }
    if (e.key === 'ArrowDown' && historyIndex.value >= 0) {
      e.preventDefault()
      historyIndex.value--
      if (historyIndex.value >= 0) {
        query.value = searchHistory.value[historyIndex.value]
      } else {
        query.value = ''
        showHistory.value = false
      }
      return
    }
  }

  switch (e.key) {
    case 'ArrowDown':
      e.preventDefault()
      selectedIndex.value = Math.min(selectedIndex.value + 1, results.value.length - 1)
      scrollToSelected()
      break
    case 'ArrowUp':
      e.preventDefault()
      selectedIndex.value = Math.max(selectedIndex.value - 1, 0)
      scrollToSelected()
      break
    case 'Enter':
      e.preventDefault()
      if (results.value[selectedIndex.value]) {
        saveToHistory(query.value)
        selectResult(results.value[selectedIndex.value])
      }
      break
    case 'Escape':
      e.preventDefault()
      if (showHistory.value) {
        showHistory.value = false
        historyIndex.value = -1
      } else {
        close()
      }
      break
  }
}

function scrollToSelected() {
  nextTick(() => {
    const container = resultsRef.value
    if (!container) return
    const selected = container.querySelector('.selected') as HTMLElement
    if (selected) {
      selected.scrollIntoView({ block: 'nearest' })
    }
  })
}

function selectResult(result: SearchResult) {
  if (result.paneId) {
    emit('jump-to-pane', { tabId: result.tabId, paneId: result.paneId })
  } else {
    emit('jump-to-tab', result.tabId)
  }
  close()
}

function close() {
  query.value = ''
  selectedIndex.value = 0
  results.value = []
  emit('close')
}

watch(() => props.isVisible, (visible) => {
  if (visible) {
    nextTick(() => {
      inputRef.value?.focus()
    })
  }
})
</script>

<style scoped>
.search-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 10vh;
  z-index: 1000;
  backdrop-filter: blur(2px);
}

.search-panel {
  width: 600px;
  max-width: 90vw;
  background: #1a1f2e;
  border: 1px solid #334155;
  border-radius: 12px;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  overflow: hidden;
}

.search-header {
  display: flex;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid #334155;
  gap: 12px;
}

.search-input {
  flex: 1;
  padding: 12px 16px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 8px;
  color: #e2e8f0;
  font-size: 16px;
  outline: none;
}

.search-input:focus {
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
}

.search-input-wrapper {
  flex: 1;
  position: relative;
}

.search-hint {
  font-size: 12px;
  color: #64748b;
  white-space: nowrap;
}

/* Search History */
.search-history {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  margin-top: 4px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 6px;
  overflow: hidden;
  z-index: 10;
}

.history-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  cursor: pointer;
  font-size: 13px;
  color: #94a3b8;
}

.history-item:hover,
.history-item.selected {
  background: #334155;
  color: #e2e8f0;
}

.history-icon {
  font-size: 11px;
  opacity: 0.6;
}

/* Search Options */
.search-options {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 8px 16px;
  border-bottom: 1px solid #334155;
  background: #0f172a;
}

.option-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 12px;
  color: #64748b;
  transition: color 0.2s;
}

.option-toggle:hover {
  color: #94a3b8;
}

.option-toggle input {
  display: none;
}

.option-toggle input:checked + .option-label {
  background: #3b82f6;
  color: white;
}

.option-label {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 20px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  font-family: 'SF Mono', Monaco, monospace;
}

.option-text {
  font-size: 11px;
}

.scope-selector {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-left: auto;
}

.scope-label {
  font-size: 11px;
  color: #64748b;
}

.scope-select {
  padding: 4px 8px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 4px;
  color: #e2e8f0;
  font-size: 11px;
  cursor: pointer;
}

.scope-select:focus {
  outline: none;
  border-color: #3b82f6;
}

.search-results {
  max-height: 400px;
  overflow-y: auto;
  padding: 8px;
}

.result-item {
  display: flex;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  gap: 12px;
}

.result-item:hover,
.result-item.selected {
  background: #334155;
}

.result-icon {
  width: 24px;
  text-align: center;
  font-size: 14px;
  color: #64748b;
  flex-shrink: 0;
  padding-top: 2px;
}

.result-content {
  flex: 1;
  min-width: 0;
}

.result-title {
  color: #e2e8f0;
  font-size: 14px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.result-meta {
  display: flex;
  gap: 8px;
  margin-top: 2px;
  font-size: 11px;
  color: #64748b;
}

.result-type {
  text-transform: capitalize;
}

.result-preview {
  margin-top: 4px;
  font-size: 12px;
  color: #94a3b8;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  font-family: 'SF Mono', Monaco, monospace;
}

:deep(.search-match) {
  background: #3b82f620;
  color: #60a5fa;
  font-weight: 600;
  border-radius: 2px;
  padding: 0 1px;
}

.no-results {
  padding: 32px;
  text-align: center;
  color: #64748b;
  font-size: 14px;
}

.search-placeholder {
  padding: 24px;
  text-align: center;
}

.placeholder-text {
  color: #94a3b8;
  font-size: 14px;
  margin-bottom: 12px;
}

.placeholder-list {
  list-style: none;
  padding: 0;
  margin: 0;
  color: #64748b;
  font-size: 13px;
}

.placeholder-list li {
  padding: 4px 0;
}

.search-footer {
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

/* Scrollbar */
.search-results::-webkit-scrollbar {
  width: 8px;
}

.search-results::-webkit-scrollbar-track {
  background: transparent;
}

.search-results::-webkit-scrollbar-thumb {
  background: #334155;
  border-radius: 4px;
}
</style>
