<template>
  <div class="env-editor">
    <!-- Header -->
    <div class="env-editor__header">
      <h3 class="env-editor__title">Environment Variables</h3>
      <div class="env-editor__controls">
        <input
          v-model="searchText"
          type="text"
          class="env-editor__search"
          placeholder="Search..."
        />
        <button class="env-editor__btn env-editor__btn--add" @click="showAddModal = true">
          + Add
        </button>
        <button class="env-editor__btn env-editor__btn--refresh" @click="loadEnvVars">
          ↻
        </button>
        <button class="env-editor__btn env-editor__btn--close" @click="emit('close')">×</button>
      </div>
    </div>

    <!-- Filter tabs -->
    <div class="env-editor__tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        class="env-editor__tab"
        :class="{ 'env-editor__tab--active': activeTab === tab.id }"
        @click="activeTab = tab.id"
      >
        {{ tab.label }} ({{ getTabCount(tab.id) }})
      </button>
    </div>

    <!-- Variable list -->
    <div class="env-editor__list">
      <div
        v-for="variable in filteredVariables"
        :key="variable.key"
        class="env-editor__item"
        :class="{ 'env-editor__item--modified': variable.modified }"
      >
        <div class="env-editor__key" :title="variable.key">
          {{ variable.key }}
        </div>
        <div class="env-editor__value-wrapper">
          <input
            v-if="editingKey === variable.key"
            v-model="editValue"
            type="text"
            class="env-editor__input"
            @keyup.enter="saveEdit(variable.key)"
            @keyup.escape="cancelEdit"
            @blur="saveEdit(variable.key)"
            ref="editInput"
          />
          <span v-else class="env-editor__value" :title="variable.value" @dblclick="startEdit(variable)">
            {{ truncateValue(variable.value) }}
          </span>
        </div>
        <div class="env-editor__actions">
          <button
            class="env-editor__action-btn"
            @click="copyValue(variable.value)"
            title="Copy value"
          >
            📋
          </button>
          <button
            class="env-editor__action-btn"
            @click="startEdit(variable)"
            title="Edit"
          >
            ✏️
          </button>
          <button
            v-if="variable.canDelete"
            class="env-editor__action-btn env-editor__action-btn--delete"
            @click="deleteVariable(variable.key)"
            title="Delete"
          >
            🗑️
          </button>
        </div>
      </div>

      <div v-if="filteredVariables.length === 0" class="env-editor__empty">
        {{ searchText ? 'No matching variables' : 'No environment variables' }}
      </div>
    </div>

    <!-- Add Modal -->
    <div v-if="showAddModal" class="env-editor__modal-overlay" @click.self="showAddModal = false">
      <div class="env-editor__modal">
        <h4 class="env-editor__modal-title">Add Environment Variable</h4>
        <div class="env-editor__modal-field">
          <label>Name</label>
          <input
            v-model="newVarKey"
            type="text"
            class="env-editor__modal-input"
            placeholder="VARIABLE_NAME"
            @input="newVarKey = newVarKey.toUpperCase().replace(/[^A-Z0-9_]/g, '')"
          />
        </div>
        <div class="env-editor__modal-field">
          <label>Value</label>
          <textarea
            v-model="newVarValue"
            class="env-editor__modal-textarea"
            placeholder="Variable value"
            rows="3"
          ></textarea>
        </div>
        <div class="env-editor__modal-actions">
          <button class="env-editor__btn" @click="showAddModal = false">Cancel</button>
          <button
            class="env-editor__btn env-editor__btn--primary"
            @click="addVariable"
            :disabled="!newVarKey"
          >
            Add Variable
          </button>
        </div>
      </div>
    </div>

    <!-- Status message -->
    <div v-if="statusMessage" class="env-editor__status" :class="`env-editor__status--${statusType}`">
      {{ statusMessage }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

// Emits
const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'change', key: string, value: string): void;
}>();

// Types
interface EnvVariable {
  key: string;
  value: string;
  category: 'system' | 'path' | 'user' | 'shell' | 'custom';
  canDelete: boolean;
  modified?: boolean;
}

// State
const variables = ref<EnvVariable[]>([]);
const searchText = ref('');
const activeTab = ref<'all' | 'system' | 'path' | 'user' | 'shell' | 'custom'>('all');
const editingKey = ref<string | null>(null);
const editValue = ref('');
const showAddModal = ref(false);
const newVarKey = ref('');
const newVarValue = ref('');
const statusMessage = ref('');
const statusType = ref<'success' | 'error'>('success');

// Tabs
const tabs = [
  { id: 'all' as const, label: 'All' },
  { id: 'path' as const, label: 'Path' },
  { id: 'shell' as const, label: 'Shell' },
  { id: 'user' as const, label: 'User' },
  { id: 'custom' as const, label: 'Custom' },
];

// Computed
const filteredVariables = computed(() => {
  let filtered = variables.value;

  // Filter by tab
  if (activeTab.value !== 'all') {
    filtered = filtered.filter(v => v.category === activeTab.value);
  }

  // Filter by search
  if (searchText.value) {
    const search = searchText.value.toLowerCase();
    filtered = filtered.filter(
      v => v.key.toLowerCase().includes(search) || v.value.toLowerCase().includes(search)
    );
  }

  return filtered;
});

// Methods
function getTabCount(tabId: string): number {
  if (tabId === 'all') return variables.value.length;
  return variables.value.filter(v => v.category === tabId).length;
}

function categorizeVariable(key: string): EnvVariable['category'] {
  const pathVars = ['PATH', 'MANPATH', 'INFOPATH', 'LIBRARY_PATH', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH'];
  const shellVars = ['SHELL', 'TERM', 'TERM_PROGRAM', 'COLORTERM', 'SHLVL', 'PS1', 'PS2', 'PROMPT'];
  const userVars = ['USER', 'HOME', 'LOGNAME', 'USERNAME', 'USERPROFILE'];
  const systemVars = ['LANG', 'LC_ALL', 'LC_CTYPE', 'PWD', 'OLDPWD', 'TMPDIR', 'TEMP', 'TMP'];

  if (pathVars.includes(key)) return 'path';
  if (shellVars.includes(key)) return 'shell';
  if (userVars.includes(key)) return 'user';
  if (systemVars.includes(key)) return 'system';

  return 'custom';
}

function truncateValue(value: string, maxLength: number = 60): string {
  if (value.length <= maxLength) return value;
  return value.substring(0, maxLength) + '...';
}

async function loadEnvVars() {
  if (!isTauri || !invoke) return;

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: 'env | sort',
    });

    const lines = result.stdout.split('\n');
    const parsed: EnvVariable[] = [];

    for (const line of lines) {
      if (!line.trim()) continue;

      const eqIndex = line.indexOf('=');
      if (eqIndex === -1) continue;

      const key = line.substring(0, eqIndex);
      const value = line.substring(eqIndex + 1);
      const category = categorizeVariable(key);

      parsed.push({
        key,
        value,
        category,
        canDelete: category === 'custom',
      });
    }

    variables.value = parsed;
  } catch (e) {
    console.error('[EnvEditor] Error loading env vars:', e);
    showStatus('Error loading environment variables', 'error');
  }
}

function startEdit(variable: EnvVariable) {
  editingKey.value = variable.key;
  editValue.value = variable.value;

  nextTick(() => {
    const input = document.querySelector('.env-editor__input') as HTMLInputElement;
    if (input) input.focus();
  });
}

function cancelEdit() {
  editingKey.value = null;
  editValue.value = '';
}

async function saveEdit(key: string) {
  if (!editingKey.value) return;

  const variable = variables.value.find(v => v.key === key);
  if (!variable) return;

  if (editValue.value === variable.value) {
    cancelEdit();
    return;
  }

  try {
    if (isTauri && invoke) {
      await invoke('execute_shell', {
        command: `export ${key}="${editValue.value.replace(/"/g, '\\"')}"`,
      });

      variable.value = editValue.value;
      variable.modified = true;
      emit('change', key, editValue.value);
      showStatus(`Updated ${key}`, 'success');
    }
  } catch (e) {
    console.error('[EnvEditor] Error saving:', e);
    showStatus(`Error updating ${key}`, 'error');
  }

  cancelEdit();
}

async function addVariable() {
  if (!newVarKey.value) return;

  try {
    if (isTauri && invoke) {
      await invoke('execute_shell', {
        command: `export ${newVarKey.value}="${newVarValue.value.replace(/"/g, '\\"')}"`,
      });

      variables.value.push({
        key: newVarKey.value,
        value: newVarValue.value,
        category: 'custom',
        canDelete: true,
        modified: true,
      });

      emit('change', newVarKey.value, newVarValue.value);
      showStatus(`Added ${newVarKey.value}`, 'success');
    }
  } catch (e) {
    console.error('[EnvEditor] Error adding:', e);
    showStatus('Error adding variable', 'error');
  }

  newVarKey.value = '';
  newVarValue.value = '';
  showAddModal.value = false;
}

async function deleteVariable(key: string) {
  try {
    if (isTauri && invoke) {
      await invoke('execute_shell', {
        command: `unset ${key}`,
      });

      const index = variables.value.findIndex(v => v.key === key);
      if (index >= 0) {
        variables.value.splice(index, 1);
      }

      showStatus(`Deleted ${key}`, 'success');
    }
  } catch (e) {
    console.error('[EnvEditor] Error deleting:', e);
    showStatus(`Error deleting ${key}`, 'error');
  }
}

function copyValue(value: string) {
  navigator.clipboard.writeText(value);
  showStatus('Copied to clipboard', 'success');
}

function showStatus(message: string, type: 'success' | 'error') {
  statusMessage.value = message;
  statusType.value = type;

  setTimeout(() => {
    statusMessage.value = '';
  }, 3000);
}

// Lifecycle
onMounted(() => {
  loadEnvVars();
});

// Expose
defineExpose({
  refresh: loadEnvVars,
});
</script>

<style scoped>
.env-editor {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--panel-bg, #1e1e2e);
  color: var(--panel-fg, #cdd6f4);
  font-size: 13px;
}

.env-editor__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.env-editor__title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}

.env-editor__controls {
  display: flex;
  align-items: center;
  gap: 8px;
}

.env-editor__search {
  padding: 4px 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--border-color, #45475a);
  border-radius: 4px;
  color: inherit;
  font-size: 12px;
  width: 150px;
}

.env-editor__search:focus {
  outline: none;
  border-color: var(--accent-color, #89b4fa);
}

.env-editor__btn {
  padding: 4px 10px;
  background: var(--button-bg, #45475a);
  border: none;
  border-radius: 4px;
  color: inherit;
  cursor: pointer;
  font-size: 12px;
}

.env-editor__btn:hover {
  background: var(--button-hover, #585b70);
}

.env-editor__btn--add {
  background: var(--success-bg, #a6e3a133);
  color: var(--success-color, #a6e3a1);
}

.env-editor__btn--primary {
  background: var(--accent-color, #89b4fa);
  color: var(--panel-bg, #1e1e2e);
}

.env-editor__btn--primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.env-editor__tabs {
  display: flex;
  gap: 4px;
  padding: 8px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
  overflow-x: auto;
}

.env-editor__tab {
  padding: 4px 12px;
  background: transparent;
  border: none;
  border-radius: 4px;
  color: var(--muted-color, #9399b2);
  cursor: pointer;
  font-size: 12px;
  white-space: nowrap;
}

.env-editor__tab:hover {
  background: var(--tab-hover, #313244);
  color: var(--panel-fg, #cdd6f4);
}

.env-editor__tab--active {
  background: var(--tab-active, #45475a);
  color: var(--panel-fg, #cdd6f4);
}

.env-editor__list {
  flex: 1;
  overflow: auto;
  padding: 8px 0;
}

.env-editor__item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.env-editor__item:hover {
  background: var(--item-hover, #313244);
}

.env-editor__item--modified {
  border-left: 3px solid var(--accent-color, #89b4fa);
}

.env-editor__key {
  width: 200px;
  font-family: monospace;
  font-weight: 500;
  color: var(--key-color, #89dceb);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex-shrink: 0;
}

.env-editor__value-wrapper {
  flex: 1;
  min-width: 0;
}

.env-editor__value {
  font-family: monospace;
  font-size: 12px;
  color: var(--value-color, #cdd6f4);
  cursor: pointer;
  word-break: break-all;
}

.env-editor__input {
  width: 100%;
  padding: 4px 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--accent-color, #89b4fa);
  border-radius: 4px;
  color: inherit;
  font-family: monospace;
  font-size: 12px;
}

.env-editor__input:focus {
  outline: none;
}

.env-editor__actions {
  display: flex;
  gap: 4px;
  opacity: 0;
  transition: opacity 0.15s ease;
}

.env-editor__item:hover .env-editor__actions {
  opacity: 1;
}

.env-editor__action-btn {
  padding: 2px 4px;
  background: transparent;
  border: none;
  cursor: pointer;
  font-size: 12px;
  opacity: 0.7;
}

.env-editor__action-btn:hover {
  opacity: 1;
}

.env-editor__action-btn--delete:hover {
  color: var(--danger-color, #f38ba8);
}

.env-editor__empty {
  padding: 24px;
  text-align: center;
  color: var(--muted-color, #6c7086);
}

.env-editor__modal-overlay {
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

.env-editor__modal {
  background: var(--modal-bg, #1e1e2e);
  border: 1px solid var(--border-color, #313244);
  border-radius: 8px;
  padding: 20px;
  width: 400px;
  max-width: 90%;
}

.env-editor__modal-title {
  margin: 0 0 16px 0;
  font-size: 16px;
}

.env-editor__modal-field {
  margin-bottom: 12px;
}

.env-editor__modal-field label {
  display: block;
  margin-bottom: 4px;
  font-size: 12px;
  color: var(--label-color, #9399b2);
}

.env-editor__modal-input,
.env-editor__modal-textarea {
  width: 100%;
  padding: 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--border-color, #45475a);
  border-radius: 4px;
  color: inherit;
  font-family: monospace;
  font-size: 13px;
  box-sizing: border-box;
}

.env-editor__modal-input:focus,
.env-editor__modal-textarea:focus {
  outline: none;
  border-color: var(--accent-color, #89b4fa);
}

.env-editor__modal-textarea {
  resize: vertical;
}

.env-editor__modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 16px;
}

.env-editor__status {
  position: absolute;
  bottom: 16px;
  left: 50%;
  transform: translateX(-50%);
  padding: 8px 16px;
  border-radius: 4px;
  font-size: 12px;
  animation: fadeIn 0.2s ease;
}

.env-editor__status--success {
  background: var(--success-bg, #a6e3a133);
  color: var(--success-color, #a6e3a1);
}

.env-editor__status--error {
  background: var(--error-bg, #f38ba833);
  color: var(--error-color, #f38ba8);
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateX(-50%) translateY(10px); }
  to { opacity: 1; transform: translateX(-50%) translateY(0); }
}
</style>
