<template>
  <div class="project-tree">
    <div class="tree-header">
      <div class="title">
        <span>Project</span>
        <small v-if="projectRoot" class="path">{{ projectRoot }}</small>
      </div>
      <button class="refresh-btn" @click="$emit('refresh')" data-testid="refresh-project-tree">
        ⟳
      </button>
    </div>

    <div v-if="isLoading" class="empty-tree">Loading files…</div>
    <div v-else-if="!tree?.length" class="empty-tree">
      <p>No files yet.</p>
      <small>Select “Open Folder” to choose a workspace.</small>
    </div>

    <ul v-else class="tree-scroll">
      <ProjectTreeNode
        v-for="node in tree"
        :key="node.path"
        :node="node"
        :expanded="expanded"
        @open-file="$emit('open-file', $event)"
      />
    </ul>
  </div>
</template>

<script setup lang="ts">
import { reactive } from 'vue'
import type { FileNode } from '../composables/useProject'
import ProjectTreeNode from './ProjectTreeNode.vue'

defineProps<{
  tree: FileNode[]
  projectRoot: string | null
  isLoading?: boolean
}>()

defineEmits(['open-file', 'refresh'])

const expanded = reactive(new Set<string>())
</script>

<style scoped>
.project-tree {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #0d111c;
  border-right: 1px solid rgba(255, 255, 255, 0.05);
}

.tree-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

.title {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 14px;
}

.path {
  font-size: 11px;
  color: #8d98b3;
}

.refresh-btn {
  background: #182032;
  border: none;
  color: #d1d5db;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
}

.tree-scroll {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
}

.tree-node {
  padding-left: 8px;
}

.node-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  cursor: pointer;
  border-radius: 4px;
  color: #cfd8f3;
  font-size: 13px;
}

.node-row:hover {
  background: rgba(255, 255, 255, 0.05);
}

.children {
  padding-left: 14px;
}

.empty-tree {
  margin: auto;
  text-align: center;
  color: #9ca3af;
  padding: 0 12px;
}
</style>

