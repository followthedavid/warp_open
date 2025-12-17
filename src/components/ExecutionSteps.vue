<template>
  <div class="execution-steps">
    <div class="execution-header">
      <span class="execution-icon">⚡</span>
      <span class="execution-title">{{ task.description }}</span>
      <span class="execution-status" :class="task.status">
        {{ statusText }}
      </span>
    </div>

    <div class="steps-list">
      <div
        v-for="step in task.steps"
        :key="step.id"
        class="execution-step"
        :class="step.status"
      >
        <div class="step-header">
          <span class="step-icon">{{ getStepIcon(step) }}</span>
          <span class="step-title">{{ step.title }}</span>
          <span class="step-status-badge" :class="step.status">
            {{ step.status }}
          </span>
        </div>

        <div v-if="shouldShowContent(step)" class="step-content">
          <pre v-if="step.type === 'file_read' || step.type === 'command'">{{ step.content }}</pre>
          <div v-else-if="step.type === 'thinking'" class="thinking-content">
            {{ step.content }}
          </div>
          <code v-else>{{ step.content }}</code>
        </div>

        <div v-if="step.error" class="step-error">
          ❌ Error: {{ step.error }}
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { ExecutionTask, ExecutionStep } from '../composables/useCodeExecution';

const props = defineProps<{
  task: ExecutionTask;
}>();

const statusText = computed(() => {
  switch (props.task.status) {
    case 'running': return '⟳ Executing...';
    case 'completed': return '✓ Completed';
    case 'failed': return '✗ Failed';
    default: return '○ Pending';
  }
});

function getStepIcon(step: ExecutionStep): string {
  if (step.status === 'running') return '⟳';
  if (step.status === 'completed') return '✓';
  if (step.status === 'failed') return '✗';

  switch (step.type) {
    case 'thinking': return '💭';
    case 'file_read': return '📖';
    case 'file_write': return '📝';
    case 'command': return '⚙️';
    default: return '○';
  }
}

function shouldShowContent(step: ExecutionStep): boolean {
  return step.status === 'completed' || step.status === 'failed' || step.status === 'running';
}
</script>

<style scoped>
.execution-steps {
  background: #2a2a2a;
  border-left: 3px solid #4a9eff;
  border-radius: 6px;
  padding: 12px;
  margin: 8px 0;
}

.execution-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid #404040;
}

.execution-icon {
  font-size: 16px;
}

.execution-title {
  flex: 1;
  color: #d4d4d4;
  font-weight: 500;
  font-size: 14px;
}

.execution-status {
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 3px;
  font-weight: 500;
}

.execution-status.running {
  background: rgba(74, 158, 255, 0.2);
  color: #4a9eff;
}

.execution-status.completed {
  background: rgba(81, 207, 102, 0.2);
  color: #51cf66;
}

.execution-status.failed {
  background: rgba(255, 107, 107, 0.2);
  color: #ff6b6b;
}

.steps-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.execution-step {
  background: #1e1e1e;
  border-radius: 4px;
  padding: 8px;
  transition: all 0.2s;
}

.execution-step.running {
  border-left: 2px solid #4a9eff;
  animation: pulse 2s infinite;
}

.execution-step.completed {
  border-left: 2px solid #51cf66;
}

.execution-step.failed {
  border-left: 2px solid #ff6b6b;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}

.step-header {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 4px;
}

.step-icon {
  font-size: 14px;
  width: 20px;
  text-align: center;
}

.step-title {
  flex: 1;
  color: #d4d4d4;
  font-size: 13px;
}

.step-status-badge {
  font-size: 10px;
  text-transform: uppercase;
  padding: 2px 6px;
  border-radius: 2px;
  opacity: 0.7;
}

.step-status-badge.running {
  background: rgba(74, 158, 255, 0.2);
  color: #4a9eff;
}

.step-status-badge.completed {
  background: rgba(81, 207, 102, 0.2);
  color: #51cf66;
}

.step-status-badge.failed {
  background: rgba(255, 107, 107, 0.2);
  color: #ff6b6b;
}

.step-content {
  margin-top: 6px;
  padding: 8px;
  background: #1a1a1a;
  border-radius: 3px;
  font-size: 12px;
}

.step-content pre {
  margin: 0;
  padding: 0;
  color: #d4d4d4;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  white-space: pre-wrap;
  word-break: break-all;
}

.step-content code {
  color: #d4d4d4;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
}

.thinking-content {
  color: #aaa;
  font-style: italic;
}

.step-error {
  margin-top: 6px;
  padding: 6px 8px;
  background: rgba(255, 107, 107, 0.1);
  border: 1px solid rgba(255, 107, 107, 0.3);
  border-radius: 3px;
  color: #ff6b6b;
  font-size: 12px;
}
</style>
