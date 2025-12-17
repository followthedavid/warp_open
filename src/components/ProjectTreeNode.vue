<template>
  <li class="tree-node">
    <div
      class="node-row"
      :class="node.kind"
      :data-testid="`tree-node-${node.name}`"
      @click.stop="handleClick"
    >
      <span class="icon">
        <template v-if="node.kind === 'dir'">
          {{ isOpen ? '📂' : '📁' }}
        </template>
        <template v-else>📄</template>
      </span>
      <span class="name">{{ node.name }}</span>
    </div>
    <ul v-if="node.kind === 'dir' && node.children && isOpen" class="children">
      <ProjectTreeNode
        v-for="child in node.children"
        :key="child.path"
        :node="child"
        :expanded="expanded"
        @open-file="$emit('open-file', $event)"
      />
    </ul>
  </li>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { FileNode } from '../composables/useProject'

defineOptions({ name: 'ProjectTreeNode' })

const props = defineProps<{
  node: FileNode
  expanded: Set<string>
}>()

const emit = defineEmits<{
  (event: 'open-file', path: string): void
}>()

const isOpen = computed(() => props.expanded.has(props.node.path))

function handleClick() {
  if (props.node.kind === 'dir') {
    if (props.expanded.has(props.node.path)) {
      props.expanded.delete(props.node.path)
    } else {
      props.expanded.add(props.node.path)
    }
  } else {
    emit('open-file', props.node.path)
  }
}
</script>

<style scoped>
.tree-node {
  list-style: none;
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
</style>

