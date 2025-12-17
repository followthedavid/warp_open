<template>
  <div class="notebook-panel">
    <div class="notebook-header">
      <div class="notebook-tabs">
        <button
          v-for="nb in notebooks"
          :key="nb.id"
          :class="['tab', { active: activeNotebook?.id === nb.id }]"
          @click="openNotebook(nb.id)"
        >
          <span class="tab-name">{{ nb.name }}</span>
          <button class="tab-close" @click.stop="confirmDelete(nb.id)">×</button>
        </button>
        <button class="tab new-tab" @click="createNew">+ New</button>
      </div>
      <div class="notebook-actions">
        <button @click="executeAll" :disabled="isExecuting || !activeNotebook" class="action-btn">
          ▶▶ Run All
        </button>
        <button @click="clearOutputs" :disabled="!activeNotebook" class="action-btn">
          Clear Outputs
        </button>
        <div class="export-dropdown">
          <button class="action-btn" :disabled="!activeNotebook">
            Export ▾
          </button>
          <div class="dropdown-menu">
            <button @click="exportAs('json')">JSON</button>
            <button @click="exportAs('markdown')">Markdown</button>
            <button @click="exportAs('script')">Shell Script</button>
          </div>
        </div>
      </div>
    </div>

    <div v-if="activeNotebook" class="notebook-content">
      <div class="notebook-info">
        <input
          v-model="notebookName"
          @blur="saveNotebookName"
          @keydown.enter="saveNotebookName"
          class="notebook-name-input"
          placeholder="Notebook name..."
        />
        <span class="notebook-meta">
          {{ activeNotebook.cells.length }} cells •
          Updated {{ formatDate(activeNotebook.metadata.updatedAt) }}
        </span>
      </div>

      <div class="cells-container">
        <NotebookCell
          v-for="cell in activeNotebook.cells"
          :key="cell.id"
          :cell="cell"
          :isActive="activeCellId === cell.id"
          :isExecuting="isExecuting && activeCellId === cell.id"
          @select="selectCell"
          @execute="executeCell"
          @update="handleUpdate"
          @delete="deleteCell"
          @move="moveCell"
          @toggle-collapse="toggleCollapse"
          @add-below="addCellBelow"
        />

        <div class="add-cell-buttons">
          <button @click="addCell('code')" class="add-btn">
            + Code
          </button>
          <button @click="addCell('markdown')" class="add-btn">
            + Markdown
          </button>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <div class="empty-icon">📓</div>
      <h3>No Notebook Open</h3>
      <p>Create a new notebook or select an existing one</p>
      <button @click="createNew" class="create-btn">Create Notebook</button>
    </div>

    <!-- Delete confirmation modal -->
    <div v-if="deleteConfirmId" class="modal-overlay" @click="deleteConfirmId = null">
      <div class="modal" @click.stop>
        <h3>Delete Notebook?</h3>
        <p>This action cannot be undone.</p>
        <div class="modal-actions">
          <button @click="deleteConfirmId = null" class="btn secondary">Cancel</button>
          <button @click="confirmDeleteNotebook" class="btn danger">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useNotebook } from '../composables/useNotebook'
import NotebookCell from './NotebookCell.vue'

const {
  notebooks,
  activeNotebook,
  activeCellId,
  isExecuting,
  createNotebook,
  openNotebook,
  closeNotebook,
  deleteNotebook,
  renameNotebook,
  addCell: addCellComposable,
  updateCell,
  deleteCell: deleteCellComposable,
  moveCell: moveCellComposable,
  toggleCollapse: toggleCollapseComposable,
  selectCell: selectCellComposable,
  executeCell: executeCellComposable,
  executeAll: executeAllComposable,
  clearOutputs: clearOutputsComposable,
  exportToJson,
  exportToMarkdown,
  exportToScript
} = useNotebook()

const notebookName = ref('')
const deleteConfirmId = ref<string | null>(null)

watch(activeNotebook, (nb) => {
  if (nb) {
    notebookName.value = nb.name
  }
}, { immediate: true })

function createNew(): void {
  const nb = createNotebook()
  openNotebook(nb.id)
  addCellComposable('code')
}

function saveNotebookName(): void {
  if (activeNotebook.value && notebookName.value.trim()) {
    renameNotebook(activeNotebook.value.id, notebookName.value.trim())
  }
}

function selectCell(id: string): void {
  selectCellComposable(id)
}

function executeCell(id: string): void {
  executeCellComposable(id)
}

function handleUpdate(id: string, content: string): void {
  updateCell(id, { content })
}

function deleteCell(id: string): void {
  deleteCellComposable(id)
}

function moveCell(id: string, direction: 'up' | 'down'): void {
  moveCellComposable(id, direction)
}

function toggleCollapse(id: string): void {
  toggleCollapseComposable(id)
}

function addCell(type: 'code' | 'markdown'): void {
  addCellComposable(type)
}

function addCellBelow(id: string, type: 'code' | 'markdown'): void {
  addCellComposable(type, '', id)
}

function executeAll(): void {
  executeAllComposable()
}

function clearOutputs(): void {
  clearOutputsComposable()
}

function confirmDelete(id: string): void {
  deleteConfirmId.value = id
}

function confirmDeleteNotebook(): void {
  if (deleteConfirmId.value) {
    deleteNotebook(deleteConfirmId.value)
    deleteConfirmId.value = null
  }
}

function exportAs(format: 'json' | 'markdown' | 'script'): void {
  if (!activeNotebook.value) return

  let content: string
  let filename: string
  let mimeType: string

  switch (format) {
    case 'json':
      content = exportToJson()
      filename = `${activeNotebook.value.name}.json`
      mimeType = 'application/json'
      break
    case 'markdown':
      content = exportToMarkdown()
      filename = `${activeNotebook.value.name}.md`
      mimeType = 'text/markdown'
      break
    case 'script':
      content = exportToScript()
      filename = `${activeNotebook.value.name}.sh`
      mimeType = 'text/x-shellscript'
      break
  }

  // Create download
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function formatDate(timestamp: number): string {
  const date = new Date(timestamp)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}
</script>

<style scoped>
.notebook-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #1a1a3a;
  color: #e0e0e0;
}

.notebook-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: #252545;
  border-bottom: 1px solid #3a3a5a;
}

.notebook-tabs {
  display: flex;
  gap: 4px;
  overflow-x: auto;
  max-width: 60%;
}

.tab {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #a0a0c0;
  white-space: nowrap;
  transition: all 0.2s;
}

.tab:hover {
  background: #3a3a5a;
  color: #e0e0e0;
}

.tab.active {
  background: #6366f1;
  border-color: #6366f1;
  color: white;
}

.tab-close {
  width: 18px;
  height: 18px;
  border: none;
  background: transparent;
  border-radius: 50%;
  cursor: pointer;
  font-size: 14px;
  color: inherit;
  opacity: 0.6;
  transition: all 0.2s;
}

.tab-close:hover {
  background: rgba(0, 0, 0, 0.2);
  opacity: 1;
}

.new-tab {
  background: transparent;
  border-style: dashed;
}

.notebook-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
  padding: 6px 12px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.action-btn:hover:not(:disabled) {
  background: #3a3a5a;
  color: #e0e0e0;
}

.action-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.export-dropdown {
  position: relative;
}

.dropdown-menu {
  position: absolute;
  top: 100%;
  right: 0;
  margin-top: 4px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  overflow: hidden;
  display: none;
  z-index: 100;
}

.export-dropdown:hover .dropdown-menu {
  display: block;
}

.dropdown-menu button {
  display: block;
  width: 100%;
  padding: 8px 16px;
  background: none;
  border: none;
  text-align: left;
  cursor: pointer;
  font-size: 12px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.dropdown-menu button:hover {
  background: #3a3a5a;
  color: #e0e0e0;
}

.notebook-content {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
}

.notebook-info {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid #3a3a5a;
}

.notebook-name-input {
  flex: 1;
  background: transparent;
  border: none;
  font-size: 20px;
  font-weight: 600;
  color: #e0e0e0;
  outline: none;
}

.notebook-name-input:focus {
  border-bottom: 2px solid #6366f1;
}

.notebook-meta {
  font-size: 12px;
  color: #6060a0;
}

.cells-container {
  /* Container for cells */
}

.add-cell-buttons {
  display: flex;
  gap: 8px;
  margin-top: 16px;
  padding: 16px;
  border: 2px dashed #3a3a5a;
  border-radius: 8px;
  justify-content: center;
}

.add-btn {
  padding: 8px 16px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #a0a0c0;
  transition: all 0.2s;
}

.add-btn:hover {
  background: #3a3a5a;
  color: #e0e0e0;
  border-color: #6366f1;
}

.empty-state {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: #6060a0;
}

.empty-icon {
  font-size: 64px;
  margin-bottom: 16px;
}

.empty-state h3 {
  margin: 0 0 8px;
  font-size: 18px;
  color: #a0a0c0;
}

.empty-state p {
  margin: 0 0 24px;
  font-size: 14px;
}

.create-btn {
  padding: 12px 24px;
  background: #6366f1;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  color: white;
  transition: all 0.2s;
}

.create-btn:hover {
  background: #5558dd;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal {
  background: #252545;
  border: 1px solid #3a3a5a;
  border-radius: 12px;
  padding: 24px;
  min-width: 300px;
}

.modal h3 {
  margin: 0 0 8px;
  font-size: 18px;
}

.modal p {
  margin: 0 0 24px;
  color: #a0a0c0;
}

.modal-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s;
}

.btn.secondary {
  background: #3a3a5a;
  color: #e0e0e0;
}

.btn.secondary:hover {
  background: #4a4a6a;
}

.btn.danger {
  background: #ef4444;
  color: white;
}

.btn.danger:hover {
  background: #dc2626;
}
</style>
