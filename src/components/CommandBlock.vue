<template>
  <div :class="['command-block', { collapsed, running: isRunning, success: exitCode === 0 && !isRunning, error: exitCode !== null && exitCode !== 0 }]">
    <BlockHeader
      :command="block.command"
      :exitCode="block.exitCode"
      :duration="block.duration"
      :startTime="block.startTime"
      :collapsed="block.collapsed"
      @toggle="$emit('toggle', block.id)"
      @rerun="$emit('rerun', block.id)"
      @copy="$emit('copy', block.id)"
    />
    <BlockBody
      v-if="!block.collapsed"
      :output="block.output"
      :outputType="block.outputType"
    />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import BlockHeader from './BlockHeader.vue'
import BlockBody from './BlockBody.vue'
import type { CommandBlock } from '../composables/useBlocks'

const props = defineProps<{
  block: CommandBlock
}>()

defineEmits<{
  toggle: [blockId: string]
  rerun: [blockId: string]
  copy: [blockId: string]
}>()

const collapsed = computed(() => props.block.collapsed)
const exitCode = computed(() => props.block.exitCode)
const isRunning = computed(() => props.block.isRunning)
</script>

<style scoped>
.command-block {
  margin: 8px 0;
  border-radius: 8px;
  background: #1e1e1e;
  border: 1px solid #3a3a3a;
  overflow: hidden;
  transition: all 0.2s ease;
}

.command-block:hover {
  border-color: #4a4a4a;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

.command-block.collapsed {
  opacity: 0.7;
}

.command-block.success {
  border-left: 3px solid #4caf50;
}

.command-block.error {
  border-left: 3px solid #f44336;
}

.command-block.running {
  border-left: 3px solid #ffa500;
  animation: runningPulse 2s ease-in-out infinite;
}

@keyframes runningPulse {
  0%, 100% { border-left-color: #ffa500; }
  50% { border-left-color: #ff8c00; }
}
</style>
