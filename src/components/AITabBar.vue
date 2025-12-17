<template>
  <div class="tab-bar">
    <draggable
      v-model="tabs"
      item-key="id"
      class="tabs-container"
      :animation="200"
      handle=".tab-drag-handle"
      ghost-class="tab-ghost"
    >
      <template #item="{ element: tab }">
        <div
          :class="['tab', { active: tab.id === activeTabId }]"
          @click="switchTab(tab.id)"
        >
          <span class="tab-drag-handle" title="Drag to reorder">⋮⋮</span>
          <input
            v-if="editingTabId === tab.id"
            v-model="editingName"
            @blur="finishRename"
            @keyup.enter="finishRename"
            @keyup.esc="cancelRename"
            @click.stop
            ref="renameInput"
            class="tab-rename-input"
          />
          <span v-else class="tab-name" @dblclick.stop="startRename(tab.id)" title="Double-click to rename">{{ tab.name }}</span>
          <button
            v-if="tabs.length > 1"
            @click.stop="closeTab(tab.id)"
            class="close-btn"
            title="Close tab"
          >
            ×
          </button>
        </div>
      </template>
    </draggable>
    <button @click="addTab" class="new-tab-btn" title="New AI tab">
      +
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref, nextTick, computed } from 'vue'
import draggable from 'vuedraggable'
import { state, createTab, removeTab, renameTab, reorderTabs, type AITab } from '../composables/useAITabs'

interface Props {
  tabs: AITab[]
  activeTabId: number | null
}

const props = defineProps<Props>()
const emit = defineEmits<{
  'set-active-tab': [id: number]
}>()

const tabs = computed({
  get: () => state.tabs,
  set: (value) => {
    reorderTabs(value)
  }
})
const activeTabId = computed(() => props.activeTabId)

const editingTabId = ref<number | null>(null)
const editingName = ref('')
const renameInput = ref<HTMLInputElement | null>(null)

function addTab() {
  createTab()
}

function closeTab(id: number) {
  removeTab(id)
}

function switchTab(id: number) {
  emit('set-active-tab', id)
}

function startRename(tabId: number) {
  const tab = tabs.value.find(t => t.id === tabId)
  if (!tab) return
  
  editingTabId.value = tabId
  editingName.value = tab.name
  
  nextTick(() => {
    if (renameInput.value) {
      renameInput.value.focus()
      renameInput.value.select()
    }
  })
}

function finishRename() {
  if (editingTabId.value !== null && editingName.value.trim()) {
    renameTab(editingTabId.value, editingName.value.trim())
  }
  editingTabId.value = null
  editingName.value = ''
}

function cancelRename() {
  editingTabId.value = null
  editingName.value = ''
}
</script>

<style scoped>
.tab-bar {
  display: flex;
  align-items: center;
  background-color: #2d2d2d;
  border-bottom: 1px solid #404040;
  padding: 4px 8px;
  gap: 8px;
  min-height: 44px;
}

.tabs-container {
  display: flex;
  flex: 1;
  gap: 4px;
  overflow-x: auto;
  overflow-y: hidden;
  align-items: center;
}

.tabs-container::-webkit-scrollbar {
  height: 4px;
}

.tabs-container::-webkit-scrollbar-track {
  background: transparent;
}

.tabs-container::-webkit-scrollbar-thumb {
  background: #404040;
  border-radius: 2px;
}

.tab {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 8px 8px 4px;
  background-color: #1e1e1e;
  border-radius: 6px 6px 0 0;
  cursor: pointer;
  user-select: none;
  transition: background-color 0.2s;
  white-space: nowrap;
  min-width: 120px;
  max-width: 200px;
}

.tab-drag-handle {
  cursor: grab;
  opacity: 0.4;
  font-size: 12px;
  line-height: 1;
  padding: 0 2px;
  transition: opacity 0.2s;
}

.tab:hover .tab-drag-handle {
  opacity: 0.8;
}

.tab-drag-handle:active {
  cursor: grabbing;
}

.tab-ghost {
  opacity: 0.5;
  background-color: #0084ff;
}

.tab:hover {
  background-color: #252525;
}

.tab.active {
  background-color: #1e1e1e;
  border-bottom: 2px solid #0084ff;
}

.tab-name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  color: #e0e0e0;
  font-size: 13px;
}

.tab.active .tab-name {
  color: #ffffff;
  font-weight: 500;
}

.tab-rename-input {
  flex: 1;
  background: transparent;
  border: 1px solid #0084ff;
  border-radius: 3px;
  padding: 2px 4px;
  color: #ffffff;
  font-size: 13px;
  outline: none;
}

.close-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  background: transparent;
  border: none;
  border-radius: 3px;
  color: #999;
  font-size: 20px;
  line-height: 1;
  cursor: pointer;
  transition: all 0.2s;
  padding: 0;
}

.close-btn:hover {
  background-color: #ff4444;
  color: white;
}

.new-tab-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  background-color: #0084ff;
  border: none;
  border-radius: 6px;
  color: white;
  font-size: 20px;
  font-weight: 300;
  cursor: pointer;
  transition: background-color 0.2s;
  flex-shrink: 0;
}

.new-tab-btn:hover {
  background-color: #0073e6;
}

.new-tab-btn:active {
  background-color: #0062cc;
}
</style>
