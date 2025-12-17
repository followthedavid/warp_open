<template>
  <Teleport to="body">
    <div v-if="isVisible" class="snapshots-overlay" @click="close">
      <div class="snapshots-panel" @click.stop>
        <div class="panel-header">
          <h3>Workspace Snapshots</h3>
          <button class="close-btn" @click="close">×</button>
        </div>

        <div class="panel-actions">
          <button class="save-btn" @click="handleSaveSnapshot">
            📸 Save Current Workspace
          </button>
        </div>

        <!-- Search and Filter Bar -->
        <div class="search-filter-bar" v-if="snapshots.length > 0">
          <div class="search-input-wrapper">
            <input
              type="text"
              v-model="localSearchQuery"
              @input="handleSearch"
              placeholder="Search snapshots..."
              class="search-input"
            />
            <button
              v-if="localSearchQuery || selectedTags.length > 0 || dateFilter !== 'all'"
              class="clear-search-btn"
              @click="handleClearFilters"
              title="Clear filters"
            >
              ✕
            </button>
          </div>
          <div class="tags-filter" v-if="allTags.length > 0">
            <span class="filter-label">Tags:</span>
            <button
              v-for="tag in allTags"
              :key="tag"
              class="tag-filter-btn"
              :class="{ active: selectedTags.includes(tag) }"
              @click="toggleTagFilter(tag)"
            >
              {{ tag }}
            </button>
          </div>
          <div class="date-filter">
            <span class="filter-label">Date:</span>
            <button
              v-for="option in dateFilterOptions"
              :key="option.value"
              class="date-filter-btn"
              :class="{ active: dateFilter === option.value }"
              @click="setDateFilter(option.value)"
            >
              {{ option.label }}
            </button>
          </div>
        </div>

        <div class="snapshots-list" v-if="displaySnapshots.length > 0">
          <div
            v-for="snapshot in displaySnapshots"
            :key="snapshot.id"
            class="snapshot-item"
          >
            <div class="snapshot-info">
              <div class="snapshot-name">{{ snapshot.name }}</div>
              <div class="snapshot-meta">
                <span class="snapshot-time">{{ formatTimestamp(snapshot.timestamp) }}</span>
                <span class="snapshot-tabs">{{ snapshot.tabs.length }} tabs</span>
              </div>
              <div v-if="snapshot.description" class="snapshot-desc">
                {{ snapshot.description }}
              </div>
              <!-- Tags Display -->
              <div class="snapshot-tags" v-if="snapshot.tags && snapshot.tags.length > 0">
                <span
                  v-for="tag in snapshot.tags"
                  :key="tag"
                  class="tag"
                  @click="toggleTagFilter(tag)"
                >
                  {{ tag }}
                  <button class="tag-remove" @click.stop="handleRemoveTag(snapshot, tag)" title="Remove tag">×</button>
                </span>
              </div>
            </div>
            <div class="snapshot-actions">
              <button class="action-btn restore" @click="handleRestore(snapshot)" title="Restore this snapshot">
                ↩ Restore
              </button>
              <button class="action-btn tag" @click="handleAddTag(snapshot)" title="Add tag">
                🏷️
              </button>
              <button class="action-btn export" @click="handleExport(snapshot)" title="Export">
                ⬇
              </button>
              <button class="action-btn rename" @click="handleRename(snapshot)" title="Rename">
                ✏️
              </button>
              <button class="action-btn delete" @click="handleDelete(snapshot)" title="Delete">
                🗑️
              </button>
            </div>
          </div>
        </div>

        <div v-else-if="snapshots.length > 0 && displaySnapshots.length === 0" class="empty-state">
          <div class="empty-icon">🔍</div>
          <div class="empty-text">No matching snapshots</div>
          <div class="empty-hint">
            Try a different search or clear filters
          </div>
        </div>

        <div v-else class="empty-state">
          <div class="empty-icon">📷</div>
          <div class="empty-text">No snapshots yet</div>
          <div class="empty-hint">
            Save your current workspace to restore it later
          </div>
        </div>

        <div class="panel-footer">
          <span class="snapshot-count">
            {{ displaySnapshots.length }}{{ displaySnapshots.length !== snapshots.length ? ` of ${snapshots.length}` : '' }}
            snapshot{{ snapshots.length !== 1 ? 's' : '' }}
          </span>
          <div class="footer-actions">
            <button class="import-btn" @click="triggerImport" title="Import snapshots">
              Import
            </button>
            <button v-if="snapshots.length > 0" class="export-btn" @click="handleExportAll" title="Export all snapshots">
              Export All
            </button>
            <button v-if="snapshots.length > 0" class="clear-btn" @click="handleClearAll">
              Clear All
            </button>
          </div>
          <input
            ref="fileInput"
            type="file"
            accept=".json"
            style="display: none"
            @change="handleFileSelect"
          />
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useSnapshots, type Snapshot } from '../composables/useSnapshots'

const props = defineProps<{
  isVisible: boolean
}>()

const emit = defineEmits(['close', 'save', 'restore'])

const {
  snapshots,
  filteredSnapshots,
  deleteSnapshot,
  renameSnapshot,
  clearAllSnapshots,
  formatTimestamp,
  exportSnapshot,
  exportAllSnapshots,
  importSnapshots,
  // Tags
  addTag,
  removeTag,
  allTags,
  // Search/Filter
  searchQuery,
  selectedTags,
  dateFilter,
  setSearchQuery,
  setDateFilter,
  toggleTagFilter,
  clearFilters
} = useSnapshots()

const fileInput = ref<HTMLInputElement | null>(null)
const localSearchQuery = ref('')

// Date filter options
const dateFilterOptions = [
  { value: 'all' as const, label: 'All' },
  { value: 'today' as const, label: 'Today' },
  { value: 'week' as const, label: 'Week' },
  { value: 'month' as const, label: 'Month' }
]

// Sync local search with composable
watch(localSearchQuery, (value) => {
  setSearchQuery(value)
})

// Display either filtered or all snapshots
const displaySnapshots = computed(() => {
  if (localSearchQuery.value || selectedTags.value.length > 0 || dateFilter.value !== 'all') {
    return filteredSnapshots.value
  }
  return snapshots.value
})

function close() {
  emit('close')
}

function handleSaveSnapshot() {
  const name = prompt('Name this snapshot:', `Workspace ${new Date().toLocaleString()}`)
  if (name) {
    emit('save', name)
  }
}

function handleRestore(snapshot: Snapshot) {
  if (confirm(`Restore "${snapshot.name}"?\n\nThis will replace your current workspace.`)) {
    emit('restore', snapshot)
    close()
  }
}

function handleRename(snapshot: Snapshot) {
  const newName = prompt('Rename snapshot:', snapshot.name)
  if (newName && newName !== snapshot.name) {
    renameSnapshot(snapshot.id, newName)
  }
}

function handleDelete(snapshot: Snapshot) {
  if (confirm(`Delete "${snapshot.name}"?`)) {
    deleteSnapshot(snapshot.id)
  }
}

function handleClearAll() {
  if (confirm('Delete all snapshots? This cannot be undone.')) {
    clearAllSnapshots()
  }
}

function handleExport(snapshot: Snapshot) {
  exportSnapshot(snapshot.id)
}

function handleExportAll() {
  exportAllSnapshots()
}

function triggerImport() {
  fileInput.value?.click()
}

async function handleFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  const result = await importSnapshots(file)

  if (result.success) {
    alert(`Successfully imported ${result.imported} snapshot(s)`)
  } else if (result.errors.length > 0) {
    alert(`Import failed:\n${result.errors.join('\n')}`)
  }

  // Reset file input
  input.value = ''
}

// Tag handlers
function handleAddTag(snapshot: Snapshot) {
  const tag = prompt('Add tag:', '')
  if (tag && tag.trim()) {
    addTag(snapshot.id, tag.trim().toLowerCase())
  }
}

function handleRemoveTag(snapshot: Snapshot, tag: string) {
  removeTag(snapshot.id, tag)
}

function handleSearch() {
  setSearchQuery(localSearchQuery.value)
}

function handleClearFilters() {
  localSearchQuery.value = ''
  clearFilters()
}
</script>

<style scoped>
.snapshots-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.snapshots-panel {
  background: #1a1f2e;
  border-radius: 12px;
  width: 500px;
  max-width: 90vw;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid #334155;
}

.panel-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: #e2e8f0;
}

.close-btn {
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  color: #64748b;
  cursor: pointer;
  border-radius: 6px;
  font-size: 18px;
}

.close-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.panel-actions {
  padding: 16px 20px;
  border-bottom: 1px solid #334155;
}

.save-btn {
  width: 100%;
  padding: 12px;
  background: linear-gradient(135deg, #3b82f6, #6366f1);
  border: none;
  border-radius: 8px;
  color: white;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.save-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
}

.snapshots-list {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
}

.snapshot-item {
  background: #0f172a;
  border-radius: 8px;
  padding: 12px 16px;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.snapshot-item:last-child {
  margin-bottom: 0;
}

.snapshot-info {
  flex: 1;
  min-width: 0;
}

.snapshot-name {
  font-size: 14px;
  font-weight: 500;
  color: #e2e8f0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.snapshot-meta {
  display: flex;
  gap: 12px;
  margin-top: 4px;
  font-size: 12px;
  color: #64748b;
}

.snapshot-desc {
  font-size: 11px;
  color: #94a3b8;
  margin-top: 4px;
}

.snapshot-actions {
  display: flex;
  gap: 6px;
  flex-shrink: 0;
}

.action-btn {
  padding: 6px 10px;
  font-size: 12px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn.restore {
  background: #10b98120;
  color: #10b981;
}

.action-btn.restore:hover {
  background: #10b98140;
}

.action-btn.rename,
.action-btn.delete {
  background: transparent;
  color: #64748b;
  padding: 6px;
}

.action-btn.rename:hover,
.action-btn.delete:hover {
  background: #334155;
  color: #e2e8f0;
}

.action-btn.delete:hover {
  color: #ef4444;
}

.empty-state {
  padding: 48px 24px;
  text-align: center;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.empty-text {
  font-size: 16px;
  color: #94a3b8;
  margin-bottom: 8px;
}

.empty-hint {
  font-size: 13px;
  color: #64748b;
}

.panel-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  border-top: 1px solid #334155;
  font-size: 12px;
  color: #64748b;
}

.footer-actions {
  display: flex;
  gap: 8px;
}

.import-btn,
.export-btn {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid #334155;
  border-radius: 4px;
  color: #94a3b8;
  cursor: pointer;
  font-size: 11px;
}

.import-btn:hover,
.export-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.action-btn.export {
  background: transparent;
  color: #64748b;
  padding: 6px;
}

.action-btn.export:hover {
  background: #334155;
  color: #3b82f6;
}

.clear-btn {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid #334155;
  border-radius: 4px;
  color: #ef4444;
  cursor: pointer;
  font-size: 11px;
}

.clear-btn:hover {
  background: #ef444420;
  border-color: #ef4444;
}

/* Search and Filter Bar */
.search-filter-bar {
  padding: 12px 20px;
  border-bottom: 1px solid #334155;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.search-input-wrapper {
  position: relative;
  display: flex;
  align-items: center;
}

.search-input {
  flex: 1;
  padding: 8px 32px 8px 12px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 6px;
  color: #e2e8f0;
  font-size: 13px;
  outline: none;
}

.search-input:focus {
  border-color: #3b82f6;
}

.search-input::placeholder {
  color: #64748b;
}

.clear-search-btn {
  position: absolute;
  right: 8px;
  width: 20px;
  height: 20px;
  border: none;
  background: transparent;
  color: #64748b;
  cursor: pointer;
  border-radius: 4px;
  font-size: 12px;
}

.clear-search-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.tags-filter {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.filter-label {
  font-size: 11px;
  color: #64748b;
  margin-right: 4px;
}

.tag-filter-btn {
  padding: 3px 8px;
  font-size: 11px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 12px;
  color: #94a3b8;
  cursor: pointer;
  transition: all 0.15s;
}

.tag-filter-btn:hover {
  border-color: #3b82f6;
  color: #e2e8f0;
}

.tag-filter-btn.active {
  background: #3b82f620;
  border-color: #3b82f6;
  color: #60a5fa;
}

/* Tags on Snapshot Items */
.snapshot-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 6px;
}

.tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 6px;
  font-size: 10px;
  background: #3b82f620;
  border: 1px solid #3b82f640;
  border-radius: 10px;
  color: #60a5fa;
  cursor: pointer;
  transition: all 0.15s;
}

.tag:hover {
  background: #3b82f640;
}

.tag-remove {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 12px;
  height: 12px;
  padding: 0;
  border: none;
  background: transparent;
  color: #60a5fa;
  cursor: pointer;
  border-radius: 50%;
  font-size: 10px;
  line-height: 1;
  opacity: 0.6;
}

.tag-remove:hover {
  opacity: 1;
  background: #3b82f640;
}

.action-btn.tag {
  background: transparent;
  color: #64748b;
  padding: 6px;
}

.action-btn.tag:hover {
  background: #334155;
  color: #f59e0b;
}

/* Date Filter */
.date-filter {
  display: flex;
  align-items: center;
  gap: 6px;
}

.date-filter-btn {
  padding: 4px 10px;
  font-size: 11px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 4px;
  color: #94a3b8;
  cursor: pointer;
  transition: all 0.15s;
}

.date-filter-btn:hover {
  border-color: #10b981;
  color: #e2e8f0;
}

.date-filter-btn.active {
  background: #10b98120;
  border-color: #10b981;
  color: #10b981;
}
</style>
