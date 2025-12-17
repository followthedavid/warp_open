<template>
  <div class="split-pane-container" :class="{ 'single-pane': isSinglePane }">
    <LayoutRenderer
      v-if="layout"
      :node="layout"
      :activePaneId="activePaneId"
      @pane-focus="handlePaneFocus"
      @cwd-change="$emit('cwd-change', $event)"
      @title-change="$emit('title-change', $event)"
      @output-change="$emit('output-change', $event)"
      @command-executed="$emit('command-executed', $event)"
      @resize="handleResize"
    />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import LayoutRenderer from './LayoutRenderer.vue'
import type { LayoutNode } from '../composables/useTabs'

const props = defineProps<{
  layout: LayoutNode | undefined
  activePaneId: string | undefined
  tabId: string
}>()

const emit = defineEmits(['pane-focus', 'cwd-change', 'title-change', 'output-change', 'command-executed', 'resize'])

const isSinglePane = computed(() => {
  return props.layout?.type === 'leaf'
})

function handlePaneFocus(paneId: string) {
  emit('pane-focus', paneId)
}

function handleResize(event: { nodeId: string; ratio: number }) {
  emit('resize', { tabId: props.tabId, ...event })
}
</script>

<style scoped>
.split-pane-container {
  width: 100%;
  height: 100%;
  display: flex;
  overflow: hidden;
}

.single-pane {
  /* No special styling needed for single pane */
}
</style>
