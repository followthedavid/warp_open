<template>
  <div class="workflow-panel">
    <div class="panel-header">
      <h2>Workflows</h2>
      <div class="header-actions">
        <button @click="showCreateModal = true" class="btn-primary">
          + New
        </button>
      </div>
    </div>

    <div class="search-bar">
      <input
        v-model="searchInput"
        type="text"
        placeholder="Search workflows..."
        @input="workflows.setSearch(searchInput)"
      />
    </div>

    <div class="categories">
      <button
        v-for="cat in workflows.categories.value"
        :key="cat.id"
        :class="['category-btn', { active: workflows.selectedCategory.value === cat.id }]"
        @click="workflows.setCategory(workflows.selectedCategory.value === cat.id ? null : cat.id)"
      >
        <span class="cat-icon">{{ cat.icon }}</span>
        <span class="cat-name">{{ cat.name }}</span>
        <span class="cat-count">{{ cat.count }}</span>
      </button>
    </div>

    <div class="workflow-sections">
      <div v-if="workflows.favoriteWorkflows.value.length > 0" class="section">
        <h3>Favorites</h3>
        <div class="workflow-grid">
          <WorkflowCard
            v-for="wf in workflows.favoriteWorkflows.value"
            :key="wf.id"
            :workflow="wf"
            @execute="executeWorkflow"
            @toggle-favorite="workflows.toggleFavorite"
            @edit="editWorkflow"
            @delete="confirmDelete"
          />
        </div>
      </div>

      <div v-if="workflows.recentWorkflows.value.length > 0 && !workflows.selectedCategory.value && !searchInput" class="section">
        <h3>Recent</h3>
        <div class="workflow-grid">
          <WorkflowCard
            v-for="wf in workflows.recentWorkflows.value.slice(0, 4)"
            :key="wf.id"
            :workflow="wf"
            @execute="executeWorkflow"
            @toggle-favorite="workflows.toggleFavorite"
            @edit="editWorkflow"
            @delete="confirmDelete"
          />
        </div>
      </div>

      <div class="section">
        <h3>{{ workflows.selectedCategory.value ? getCategoryName(workflows.selectedCategory.value) : 'All Workflows' }}</h3>
        <div v-if="workflows.workflows.value.length > 0" class="workflow-grid">
          <WorkflowCard
            v-for="wf in workflows.workflows.value"
            :key="wf.id"
            :workflow="wf"
            @execute="executeWorkflow"
            @toggle-favorite="workflows.toggleFavorite"
            @edit="editWorkflow"
            @delete="confirmDelete"
          />
        </div>
        <div v-else class="empty-state">
          <p>No workflows found</p>
          <button @click="showCreateModal = true" class="btn-secondary">Create your first workflow</button>
        </div>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <Teleport to="body">
      <div v-if="showCreateModal || editingWorkflow" class="modal-overlay" @click="closeModals">
        <div class="modal" @click.stop>
          <div class="modal-header">
            <h3>{{ editingWorkflow ? 'Edit Workflow' : 'Create Workflow' }}</h3>
            <button class="close-btn" @click="closeModals">×</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label>Name</label>
              <input v-model="formData.name" type="text" placeholder="My Workflow" />
            </div>
            <div class="form-group">
              <label>Description</label>
              <input v-model="formData.description" type="text" placeholder="What does this workflow do?" />
            </div>
            <div class="form-group">
              <label>Command</label>
              <textarea v-model="formData.command" placeholder="git commit -m &quot;{{message}}&quot;" rows="3"></textarea>
              <small>Use {'{{param}}'} for parameters</small>
            </div>
            <div class="form-group">
              <label>Category</label>
              <select v-model="formData.category">
                <option v-for="cat in workflows.categories.value" :key="cat.id" :value="cat.id">
                  {{ cat.icon }} {{ cat.name }}
                </option>
              </select>
            </div>
            <div class="form-group">
              <label>Tags (comma-separated)</label>
              <input v-model="formData.tagsInput" type="text" placeholder="git, commit, useful" />
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn-secondary" @click="closeModals">Cancel</button>
            <button class="btn-primary" @click="saveWorkflow">
              {{ editingWorkflow ? 'Save Changes' : 'Create Workflow' }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Execute Modal -->
    <Teleport to="body">
      <div v-if="executingWorkflow" class="modal-overlay" @click="executingWorkflow = null">
        <div class="modal execute-modal" @click.stop>
          <div class="modal-header">
            <h3>{{ executingWorkflow.icon || '' }} {{ executingWorkflow.name }}</h3>
            <button class="close-btn" @click="executingWorkflow = null">×</button>
          </div>
          <div class="modal-body">
            <p class="workflow-desc">{{ executingWorkflow.description }}</p>

            <div v-if="executingWorkflow.parameters.length > 0" class="params-form">
              <div v-for="param in executingWorkflow.parameters" :key="param.name" class="form-group">
                <label>
                  {{ param.name }}
                  <span v-if="param.required" class="required">*</span>
                </label>
                <small v-if="param.description">{{ param.description }}</small>

                <select v-if="param.type === 'select'" v-model="paramValues[param.name]">
                  <option v-for="opt in param.options" :key="opt" :value="opt">{{ opt || '(none)' }}</option>
                </select>
                <input
                  v-else
                  v-model="paramValues[param.name]"
                  :type="param.type === 'number' ? 'number' : 'text'"
                  :placeholder="param.defaultValue"
                />
              </div>
            </div>

            <div class="preview-section">
              <label>Preview:</label>
              <code class="command-preview">{{ previewCommand }}</code>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn-secondary" @click="executingWorkflow = null">Cancel</button>
            <button class="btn-primary" @click="runWorkflow">
              Run Command
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useWorkflows, type Workflow } from '../composables/useWorkflows'
import WorkflowCard from './WorkflowCard.vue'

const emit = defineEmits<{
  execute: [command: string]
}>()

const workflows = useWorkflows()
const searchInput = ref('')
const showCreateModal = ref(false)
const editingWorkflow = ref<Workflow | null>(null)
const executingWorkflow = ref<Workflow | null>(null)
const paramValues = ref<Record<string, string>>({})

const formData = ref({
  name: '',
  description: '',
  command: '',
  category: 'custom',
  tagsInput: '',
})

const previewCommand = computed(() => {
  if (!executingWorkflow.value) return ''
  return workflows.buildCommand(executingWorkflow.value, paramValues.value)
})

function getCategoryName(id: string): string {
  const cat = workflows.categories.value.find(c => c.id === id)
  return cat ? cat.name : id
}

function executeWorkflow(workflow: Workflow): void {
  executingWorkflow.value = workflow
  // Initialize param values with defaults
  paramValues.value = {}
  for (const param of workflow.parameters) {
    paramValues.value[param.name] = param.defaultValue || ''
  }
}

function runWorkflow(): void {
  if (!executingWorkflow.value) return

  const command = workflows.buildCommand(executingWorkflow.value, paramValues.value)
  workflows.recordUsage(executingWorkflow.value.id)
  emit('execute', command)
  executingWorkflow.value = null
}

function editWorkflow(workflow: Workflow): void {
  if (workflow.isBuiltin) return

  editingWorkflow.value = workflow
  formData.value = {
    name: workflow.name,
    description: workflow.description,
    command: workflow.command,
    category: workflow.category,
    tagsInput: workflow.tags.join(', '),
  }
}

function confirmDelete(workflow: Workflow): void {
  if (workflow.isBuiltin) return
  if (confirm(`Delete "${workflow.name}"?`)) {
    workflows.deleteWorkflow(workflow.id)
  }
}

function closeModals(): void {
  showCreateModal.value = false
  editingWorkflow.value = null
  formData.value = {
    name: '',
    description: '',
    command: '',
    category: 'custom',
    tagsInput: '',
  }
}

function saveWorkflow(): void {
  const params = workflows.extractParameters(formData.value.command)
  const parameters = params.map(name => ({
    name,
    required: true,
    type: 'string' as const,
  }))

  const tags = formData.value.tagsInput
    .split(',')
    .map(t => t.trim())
    .filter(t => t)

  if (editingWorkflow.value) {
    workflows.updateWorkflow(editingWorkflow.value.id, {
      name: formData.value.name,
      description: formData.value.description,
      command: formData.value.command,
      category: formData.value.category,
      tags,
      parameters,
    })
  } else {
    workflows.createWorkflow({
      name: formData.value.name,
      description: formData.value.description,
      command: formData.value.command,
      category: formData.value.category,
      tags,
      parameters,
      isFavorite: false,
    })
  }

  closeModals()
}
</script>

<style scoped>
.workflow-panel {
  height: 100%;
  display: flex;
  flex-direction: column;
  background: #1a1a2e;
  color: #e0e0e0;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid #2a2a4a;
}

.panel-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.btn-primary {
  background: #6366f1;
  color: white;
  border: none;
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
}

.btn-primary:hover {
  background: #5558e8;
}

.btn-secondary {
  background: #3a3a5a;
  color: #e0e0e0;
  border: none;
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
}

.btn-secondary:hover {
  background: #4a4a6a;
}

.search-bar {
  padding: 12px 20px;
}

.search-bar input {
  width: 100%;
  padding: 10px 14px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 8px;
  color: #e0e0e0;
  font-size: 14px;
}

.search-bar input:focus {
  outline: none;
  border-color: #6366f1;
}

.categories {
  display: flex;
  gap: 8px;
  padding: 0 20px 12px;
  flex-wrap: wrap;
}

.category-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 20px;
  color: #a0a0c0;
  cursor: pointer;
  font-size: 12px;
  transition: all 0.2s;
}

.category-btn:hover {
  border-color: #6366f1;
}

.category-btn.active {
  background: #6366f1;
  border-color: #6366f1;
  color: white;
}

.cat-count {
  background: rgba(255, 255, 255, 0.2);
  padding: 2px 6px;
  border-radius: 10px;
  font-size: 10px;
}

.workflow-sections {
  flex: 1;
  overflow-y: auto;
  padding: 0 20px 20px;
}

.section {
  margin-bottom: 24px;
}

.section h3 {
  font-size: 14px;
  font-weight: 600;
  color: #8080a0;
  margin: 0 0 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.workflow-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #6060a0;
}

.empty-state p {
  margin-bottom: 16px;
}

/* Modal styles */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10000;
}

.modal {
  width: 500px;
  max-width: 90vw;
  max-height: 90vh;
  background: #1e1e3a;
  border: 1px solid #3a3a5a;
  border-radius: 12px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid #3a3a5a;
}

.modal-header h3 {
  margin: 0;
  font-size: 16px;
}

.close-btn {
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  color: #8080a0;
  font-size: 20px;
  cursor: pointer;
  border-radius: 4px;
}

.close-btn:hover {
  background: #3a3a5a;
  color: #e0e0e0;
}

.modal-body {
  padding: 20px;
  flex: 1;
  overflow-y: auto;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding: 16px 20px;
  border-top: 1px solid #3a3a5a;
}

.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: #a0a0c0;
  margin-bottom: 6px;
}

.form-group small {
  display: block;
  font-size: 11px;
  color: #6060a0;
  margin-top: 4px;
}

.form-group input,
.form-group textarea,
.form-group select {
  width: 100%;
  padding: 10px 12px;
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 6px;
  color: #e0e0e0;
  font-size: 14px;
}

.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus {
  outline: none;
  border-color: #6366f1;
}

.form-group textarea {
  font-family: 'SF Mono', Monaco, monospace;
  resize: vertical;
}

.required {
  color: #ef4444;
}

.workflow-desc {
  color: #8080a0;
  font-size: 13px;
  margin-bottom: 16px;
}

.params-form {
  margin-bottom: 16px;
}

.preview-section {
  background: #0a0a1a;
  border-radius: 8px;
  padding: 12px;
}

.preview-section label {
  display: block;
  font-size: 11px;
  color: #6060a0;
  margin-bottom: 8px;
  text-transform: uppercase;
}

.command-preview {
  display: block;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 13px;
  color: #a6e3a1;
  word-break: break-all;
}

.execute-modal {
  width: 560px;
}
</style>
