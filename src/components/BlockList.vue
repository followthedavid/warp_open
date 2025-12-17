<template>
  <div class="block-list">
    <div class="block-toolbar" v-if="blocks.length > 0">
      <span class="block-count">{{ blocks.length }} command{{ blocks.length !== 1 ? 's' : '' }}</span>
      <div class="toolbar-actions">
        <button @click="$emit('collapseAll')" class="toolbar-btn" title="Collapse all">
          ▼ Collapse
        </button>
        <button @click="$emit('expandAll')" class="toolbar-btn" title="Expand all">
          ▶ Expand
        </button>
        <button @click="$emit('exportJson')" class="toolbar-btn" title="Export as JSON">
          📄 Export
        </button>
        <button @click="$emit('exportScript')" class="toolbar-btn" title="Export as script">
          📜 Script
        </button>
        <button @click="$emit('clearAll')" class="toolbar-btn danger" title="Clear all blocks">
          🗑️ Clear
        </button>
      </div>
    </div>

    <div class="blocks-container">
      <TransitionGroup name="block">
        <CommandBlock
          v-for="block in blocks"
          :key="block.id"
          :block="block"
          @toggle="$emit('toggle', $event)"
          @rerun="$emit('rerun', $event)"
          @copy="$emit('copy', $event)"
        />
      </TransitionGroup>
    </div>

    <div v-if="blocks.length === 0" class="empty-state">
      <span class="empty-icon">📦</span>
      <p>No commands yet</p>
      <p class="empty-hint">Commands you run will appear here as blocks</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import CommandBlock from './CommandBlock.vue'
import type { CommandBlock as CommandBlockType } from '../composables/useBlocks'

defineProps<{
  blocks: CommandBlockType[]
}>()

defineEmits<{
  toggle: [blockId: string]
  rerun: [blockId: string]
  copy: [blockId: string]
  collapseAll: []
  expandAll: []
  exportJson: []
  exportScript: []
  clearAll: []
}>()
</script>

<style scoped>
.block-list {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.block-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: #252525;
  border-bottom: 1px solid #3a3a3a;
  flex-shrink: 0;
}

.block-count {
  color: #888;
  font-size: 12px;
  font-weight: 500;
}

.toolbar-actions {
  display: flex;
  gap: 8px;
}

.toolbar-btn {
  background: transparent;
  border: 1px solid #444;
  color: #aaa;
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 11px;
  transition: all 0.15s ease;
}

.toolbar-btn:hover {
  background: #333;
  color: #fff;
  border-color: #555;
}

.toolbar-btn.danger:hover {
  background: rgba(244, 67, 54, 0.2);
  border-color: #f44336;
  color: #f44336;
}

.blocks-container {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
}

/* Transition animations */
.block-enter-active {
  animation: slideIn 0.3s ease-out;
}

.block-leave-active {
  animation: slideOut 0.2s ease-in;
}

@keyframes slideIn {
  from {
    opacity: 0;
    transform: translateY(-20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes slideOut {
  from {
    opacity: 1;
    transform: translateY(0);
  }
  to {
    opacity: 0;
    transform: translateY(20px);
  }
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #666;
  text-align: center;
  padding: 40px;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
  opacity: 0.5;
}

.empty-state p {
  margin: 4px 0;
}

.empty-hint {
  font-size: 12px;
  color: #555;
}

/* Scrollbar */
.blocks-container::-webkit-scrollbar {
  width: 8px;
}

.blocks-container::-webkit-scrollbar-track {
  background: #1a1a1a;
}

.blocks-container::-webkit-scrollbar-thumb {
  background: #404040;
  border-radius: 4px;
}

.blocks-container::-webkit-scrollbar-thumb:hover {
  background: #505050;
}
</style>
