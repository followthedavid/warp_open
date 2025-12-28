<template>
  <div class="execution-steps">
    <div class="execution-header">
      <span class="execution-icon">⚡</span>
      <span class="execution-title">{{ task.description }}</span>
      <span class="execution-status" :class="task.status">
        {{ statusText }}
      </span>
    </div>

    <!-- Approval Controls -->
    <div v-if="hasPendingSteps && !autoMode" class="approval-controls">
      <div class="approval-message">
        <span class="approval-icon">🔐</span>
        <span>Review and approve {{ pendingSteps.length }} step(s) before execution</span>
      </div>
      <div class="approval-buttons">
        <button @click="approveAll" class="btn-approve-all">
          ▶ Run All ({{ pendingSteps.length }})
        </button>
        <button @click="enableAutoMode" class="btn-auto-mode">
          ⚡ Auto Mode
        </button>
      </div>
    </div>

    <!-- Auto Mode Indicator -->
    <div v-if="autoMode" class="auto-mode-indicator">
      <span>⚡ Auto-executing...</span>
      <button @click="disableAutoMode" class="btn-pause">⏸ Pause</button>
    </div>

    <div class="steps-list">
      <div
        v-for="(step, index) in task.steps"
        :key="step.id"
        class="execution-step"
        :class="[step.status, { 'awaiting-approval': step.status === 'pending' && !autoMode }]"
      >
        <div class="step-header">
          <span class="step-number">{{ index + 1 }}</span>
          <span class="step-icon">{{ getStepIcon(step) }}</span>
          <span class="step-title">{{ step.title }}</span>
          <span class="step-status-badge" :class="step.status">
            {{ step.status === 'pending' && !autoMode ? 'awaiting approval' : step.status }}
          </span>
        </div>

        <!-- Show command preview for pending steps -->
        <div v-if="step.status === 'pending'" class="step-preview">
          <div class="preview-label">Command to execute:</div>
          <pre class="preview-command">{{ step.content }}</pre>

          <!-- Confidence indicator -->
          <div v-if="step._meta" class="confidence-indicator">
            <span class="confidence-bar" :style="{ width: (step._meta.confidence * 100) + '%' }"></span>
            <span class="confidence-text">
              {{ Math.round(step._meta.confidence * 100) }}% confidence
              <span v-if="step._meta.safe" class="safe-badge">✓ Safe</span>
              <span v-else class="review-badge">⚠ Review</span>
            </span>
          </div>

          <!-- Step-level approval button -->
          <div v-if="!autoMode" class="step-actions">
            <button @click="$emit('approve-step', step.id)" class="btn-run-step">
              ▶ Run This Step
            </button>
            <button @click="$emit('skip-step', step.id)" class="btn-skip-step">
              ⏭ Skip
            </button>
            <button @click="$emit('edit-step', step.id)" class="btn-edit-step">
              ✏️ Edit
            </button>
          </div>
        </div>

        <!-- Show content for running/completed steps -->
        <div v-if="shouldShowContent(step)" class="step-content">
          <pre v-if="step.type === 'file_read' || step.type === 'command'">{{ step.content }}</pre>
          <div v-else-if="step.type === 'thinking'" class="thinking-content">
            {{ step.content }}
          </div>
          <code v-else>{{ step.content }}</code>
        </div>

        <div v-if="step.error" class="step-error">
          <div class="error-header">❌ Error</div>
          <pre class="error-content">{{ step.error }}</pre>
          <div class="error-actions">
            <button @click="$emit('retry-step', step.id)" class="btn-retry">
              🔄 Retry
            </button>
            <button @click="$emit('skip-step', step.id)" class="btn-skip">
              ⏭ Skip
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Summary -->
    <div v-if="task.status === 'completed'" class="execution-summary success">
      ✓ All {{ task.steps.length }} steps completed successfully
    </div>
    <div v-else-if="task.status === 'failed'" class="execution-summary failed">
      ✗ Execution failed - {{ failedSteps.length }} step(s) failed
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import type { ExecutionTask, ExecutionStep } from '../composables/useCodeExecution';

const props = defineProps<{
  task: ExecutionTask;
}>();

const emit = defineEmits<{
  (e: 'approve-step', stepId: string): void;
  (e: 'approve-all'): void;
  (e: 'skip-step', stepId: string): void;
  (e: 'edit-step', stepId: string): void;
  (e: 'retry-step', stepId: string): void;
  (e: 'enable-auto-mode'): void;
  (e: 'disable-auto-mode'): void;
}>();

const autoMode = ref(false);

const statusText = computed(() => {
  switch (props.task.status) {
    case 'running': return '⟳ Executing...';
    case 'completed': return '✓ Completed';
    case 'failed': return '✗ Failed';
    default: return '○ Pending';
  }
});

const pendingSteps = computed(() =>
  props.task.steps.filter(s => s.status === 'pending')
);

const failedSteps = computed(() =>
  props.task.steps.filter(s => s.status === 'failed')
);

const hasPendingSteps = computed(() => pendingSteps.value.length > 0);

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

function approveAll() {
  emit('approve-all');
}

function enableAutoMode() {
  autoMode.value = true;
  emit('enable-auto-mode');
}

function disableAutoMode() {
  autoMode.value = false;
  emit('disable-auto-mode');
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

/* Approval Controls */
.approval-controls {
  background: rgba(255, 193, 7, 0.1);
  border: 1px solid rgba(255, 193, 7, 0.3);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 12px;
}

.approval-message {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #ffc107;
  font-size: 13px;
  margin-bottom: 10px;
}

.approval-icon {
  font-size: 16px;
}

.approval-buttons {
  display: flex;
  gap: 8px;
}

.btn-approve-all {
  background: #51cf66;
  color: #000;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 600;
  font-size: 13px;
  transition: all 0.2s;
}

.btn-approve-all:hover {
  background: #40c057;
  transform: translateY(-1px);
}

.btn-auto-mode {
  background: #4a9eff;
  color: #fff;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 600;
  font-size: 13px;
}

.btn-auto-mode:hover {
  background: #339af0;
}

/* Auto Mode Indicator */
.auto-mode-indicator {
  background: rgba(74, 158, 255, 0.1);
  border: 1px solid rgba(74, 158, 255, 0.3);
  border-radius: 6px;
  padding: 8px 12px;
  margin-bottom: 12px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: #4a9eff;
  font-size: 13px;
}

.btn-pause {
  background: transparent;
  border: 1px solid #4a9eff;
  color: #4a9eff;
  padding: 4px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.steps-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.execution-step {
  background: #1e1e1e;
  border-radius: 4px;
  padding: 10px;
  transition: all 0.2s;
}

.execution-step.awaiting-approval {
  border: 1px dashed rgba(255, 193, 7, 0.5);
  background: rgba(255, 193, 7, 0.05);
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

.step-number {
  background: #3a3a3a;
  color: #888;
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 10px;
  min-width: 20px;
  text-align: center;
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

.step-status-badge.pending {
  background: rgba(255, 193, 7, 0.2);
  color: #ffc107;
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

/* Step Preview */
.step-preview {
  margin-top: 8px;
  padding: 10px;
  background: #1a1a1a;
  border-radius: 4px;
}

.preview-label {
  font-size: 11px;
  color: #888;
  margin-bottom: 6px;
  text-transform: uppercase;
}

.preview-command {
  margin: 0;
  padding: 8px;
  background: #0d0d0d;
  border-radius: 3px;
  color: #00ff00;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}

/* Confidence Indicator */
.confidence-indicator {
  margin-top: 8px;
  position: relative;
  background: #0d0d0d;
  border-radius: 3px;
  padding: 6px 8px;
}

.confidence-bar {
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  background: rgba(81, 207, 102, 0.2);
  border-radius: 3px;
  transition: width 0.3s;
}

.confidence-text {
  position: relative;
  font-size: 11px;
  color: #888;
  display: flex;
  align-items: center;
  gap: 8px;
}

.safe-badge {
  background: rgba(81, 207, 102, 0.2);
  color: #51cf66;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 10px;
}

.review-badge {
  background: rgba(255, 193, 7, 0.2);
  color: #ffc107;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 10px;
}

/* Step Actions */
.step-actions {
  display: flex;
  gap: 8px;
  margin-top: 10px;
}

.btn-run-step {
  background: #51cf66;
  color: #000;
  border: none;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 600;
  font-size: 12px;
}

.btn-run-step:hover {
  background: #40c057;
}

.btn-skip-step, .btn-edit-step {
  background: transparent;
  border: 1px solid #555;
  color: #888;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.btn-skip-step:hover, .btn-edit-step:hover {
  border-color: #888;
  color: #d4d4d4;
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

/* Error Handling */
.step-error {
  margin-top: 8px;
  padding: 10px;
  background: rgba(255, 107, 107, 0.1);
  border: 1px solid rgba(255, 107, 107, 0.3);
  border-radius: 4px;
}

.error-header {
  color: #ff6b6b;
  font-weight: 600;
  margin-bottom: 6px;
}

.error-content {
  margin: 0;
  padding: 8px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 3px;
  color: #ff8787;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  font-size: 11px;
  white-space: pre-wrap;
}

.error-actions {
  display: flex;
  gap: 8px;
  margin-top: 10px;
}

.btn-retry {
  background: #4a9eff;
  color: #fff;
  border: none;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.btn-skip {
  background: transparent;
  border: 1px solid #555;
  color: #888;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

/* Summary */
.execution-summary {
  margin-top: 12px;
  padding: 10px;
  border-radius: 4px;
  text-align: center;
  font-weight: 500;
  font-size: 13px;
}

.execution-summary.success {
  background: rgba(81, 207, 102, 0.1);
  color: #51cf66;
  border: 1px solid rgba(81, 207, 102, 0.3);
}

.execution-summary.failed {
  background: rgba(255, 107, 107, 0.1);
  color: #ff6b6b;
  border: 1px solid rgba(255, 107, 107, 0.3);
}
</style>
