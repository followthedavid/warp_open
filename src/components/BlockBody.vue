<template>
  <div :class="['block-body', `output-${outputType}`]">
    <div v-if="outputType === 'json'" class="json-output">
      <pre class="output-content json">{{ formattedJson }}</pre>
    </div>
    <div v-else-if="outputType === 'diff'" class="diff-output">
      <div v-for="(line, idx) in diffLines" :key="idx" :class="getDiffLineClass(line)">
        {{ line }}
      </div>
    </div>
    <div v-else-if="outputType === 'error'" class="error-output">
      <pre class="output-content error">{{ output }}</pre>
    </div>
    <pre v-else class="output-content">{{ output }}</pre>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  output: string
  outputType?: 'plain' | 'error' | 'json' | 'table' | 'diff'
}>()

const formattedJson = computed(() => {
  if (props.outputType !== 'json') return props.output
  try {
    const parsed = JSON.parse(props.output.trim())
    return JSON.stringify(parsed, null, 2)
  } catch {
    return props.output
  }
})

const diffLines = computed(() => {
  return props.output.split('\n')
})

function getDiffLineClass(line: string): string {
  if (line.startsWith('+') && !line.startsWith('+++')) return 'diff-add'
  if (line.startsWith('-') && !line.startsWith('---')) return 'diff-remove'
  if (line.startsWith('@@')) return 'diff-range'
  if (line.startsWith('diff') || line.startsWith('---') || line.startsWith('+++')) return 'diff-header'
  return 'diff-context'
}
</script>

<style scoped>
.block-body {
  padding: 12px 14px;
  background: #1a1a1a;
  border-top: 1px solid #2a2a2a;
  animation: expandBody 0.2s ease-out;
  overflow: hidden;
  max-height: 500px;
  overflow-y: auto;
}

@keyframes expandBody {
  from {
    opacity: 0;
    max-height: 0;
  }
  to {
    opacity: 1;
    max-height: 500px;
  }
}

.output-content {
  margin: 0;
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.5;
  color: #d4d4d4;
  white-space: pre-wrap;
  word-wrap: break-word;
  overflow-x: auto;
}

/* Error output styling */
.output-error .error-output {
  background: rgba(244, 67, 54, 0.1);
  border-left: 3px solid #f44336;
  padding-left: 12px;
}

.output-content.error {
  color: #ef9a9a;
}

/* JSON output styling */
.output-json .json-output {
  background: rgba(33, 150, 243, 0.05);
}

.output-content.json {
  color: #81d4fa;
}

/* Diff output styling */
.diff-output {
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.5;
}

.diff-add {
  background: rgba(76, 175, 80, 0.2);
  color: #a5d6a7;
  padding: 1px 4px;
}

.diff-remove {
  background: rgba(244, 67, 54, 0.2);
  color: #ef9a9a;
  padding: 1px 4px;
}

.diff-range {
  color: #64b5f6;
  background: rgba(100, 181, 246, 0.1);
  padding: 1px 4px;
}

.diff-header {
  color: #b0bec5;
  font-weight: bold;
  padding: 2px 4px;
}

.diff-context {
  color: #9e9e9e;
  padding: 1px 4px;
}

/* Scrollbar styling */
.block-body::-webkit-scrollbar,
.output-content::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

.block-body::-webkit-scrollbar-track,
.output-content::-webkit-scrollbar-track {
  background: #1a1a1a;
}

.block-body::-webkit-scrollbar-thumb,
.output-content::-webkit-scrollbar-thumb {
  background: #404040;
  border-radius: 4px;
}

.block-body::-webkit-scrollbar-thumb:hover,
.output-content::-webkit-scrollbar-thumb:hover {
  background: #505050;
}
</style>
