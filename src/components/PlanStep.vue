<template>
  <div class="plan-step" :class="stepClasses">
    <div class="step-header" @click="toggleExpanded">
      <!-- Status Icon -->
      <div class="step-status-icon" :class="`status-${step.status}`">
        <span v-if="step.status === 'pending'">⏸</span>
        <span v-else-if="step.status === 'awaitingApproval'">⏳</span>
        <span v-else-if="step.status === 'executing'">⚡</span>
        <span v-else-if="step.status === 'completed'">✓</span>
        <span v-else-if="step.status === 'rolledBack'">↩</span>
      </div>

      <!-- Step Info -->
      <div class="step-info">
        <div class="step-title-row">
          <span class="step-number">{{ index + 1 }}.</span>
          <h4 class="step-title">{{ step.title }}</h4>
          <span v-if="step.tool" class="step-tool">{{ step.tool }}</span>
          <span v-if="step.escalated" class="step-badge escalated">Escalated</span>
        </div>
        <p v-if="step.description" class="step-description">
          {{ step.description }}
        </p>
        <div v-if="step.timestamp" class="step-meta">
          <span class="step-time">
            {{ formatTime(step.timestamp) }}
          </span>
        </div>
      </div>

      <!-- Expand/Collapse Icon -->
      <div v-if="hasSubsteps" class="expand-icon">
        <span :class="{ expanded: isExpanded }">▼</span>
      </div>
    </div>

    <!-- Step Actions -->
    <div v-if="showActions" class="step-actions">
      <button
        v-if="step.status === 'awaitingApproval'"
        @click.stop="handleApprove"
        class="btn-approve"
      >
        Approve
      </button>
      <button
        v-if="canEscalate"
        @click.stop="handleEscalate"
        class="btn-escalate"
      >
        Escalate to Claude
      </button>
      <button
        v-if="step.status === 'executing'"
        class="btn-status executing"
        disabled
      >
        Executing...
      </button>
    </div>

    <!-- Step Output -->
    <div v-if="step.output && isExpanded" class="step-output">
      <div class="output-label">Output:</div>
      <pre>{{ step.output }}</pre>
    </div>

    <!-- Step Error -->
    <div v-if="step.error && isExpanded" class="step-error">
      <div class="error-label">Error:</div>
      <pre>{{ step.error }}</pre>
    </div>

    <!-- Substeps (Recursive) -->
    <div v-if="hasSubsteps && isExpanded" class="substeps">
      <PlanStep
        v-for="(substep, subIndex) in step.substeps"
        :key="substep.id"
        :step="substep"
        :plan-id="planId"
        :index="subIndex"
        :is-current="false"
        :depth="depth + 1"
        @approve="$emit('approve', $event)"
        @escalate="$emit('escalate', $event)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import type { PlanStep as PlanStepType } from '../agents/types';

interface Props {
  step: PlanStepType;
  planId: string;
  index: number;
  isCurrent: boolean;
  depth?: number;
}

const props = withDefaults(defineProps<Props>(), {
  depth: 0,
});

const emit = defineEmits<{
  approve: [stepId: string];
  escalate: [stepId: string];
}>();

const isExpanded = ref(true);

const hasSubsteps = computed(() => {
  return props.step.substeps && props.step.substeps.length > 0;
});

const stepClasses = computed(() => ({
  'is-current': props.isCurrent,
  'has-substeps': hasSubsteps.value,
  'is-expanded': isExpanded.value,
  [`depth-${props.depth}`]: true,
}));

const showActions = computed(() => {
  return (
    props.step.status === 'awaitingApproval' ||
    props.step.status === 'executing' ||
    canEscalate.value
  );
});

const canEscalate = computed(() => {
  return (
    !props.step.escalated &&
    (props.step.status === 'executing' || props.step.status === 'completed')
  );
});

function toggleExpanded() {
  if (hasSubsteps.value) {
    isExpanded.value = !isExpanded.value;
  }
}

function handleApprove() {
  emit('approve', props.step.id);
}

function handleEscalate() {
  emit('escalate', props.step.id);
}

function formatTime(timestamp: Date): string {
  return new Date(timestamp).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}
</script>

<style scoped>
.plan-step {
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  transition: all 0.2s;
}

.plan-step.is-current {
  border-color: var(--primary-color);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
}

.plan-step.depth-1 {
  margin-left: 24px;
  border-left: 2px solid var(--border-color);
}

.plan-step.depth-2 {
  margin-left: 48px;
  border-left: 2px solid var(--border-color);
}

/* Step Header */
.step-header {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  cursor: pointer;
}

.step-header:hover {
  opacity: 0.9;
}

.step-status-icon {
  flex-shrink: 0;
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  font-size: 14px;
  font-weight: 600;
}

.status-pending {
  background: var(--status-pending-bg, #f3f4f6);
  color: var(--status-pending-text, #6b7280);
}

.status-awaitingApproval {
  background: var(--status-warning-bg, #fef3c7);
  color: var(--status-warning-text, #92400e);
  animation: pulse 2s infinite;
}

.status-executing {
  background: var(--status-progress-bg, #dbeafe);
  color: var(--status-progress-text, #1e40af);
  animation: spin 1s linear infinite;
}

.status-completed {
  background: var(--status-success-bg, #d1fae5);
  color: var(--status-success-text, #065f46);
}

.status-rolledBack {
  background: var(--status-error-bg, #fee2e2);
  color: var(--status-error-text, #991b1b);
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* Step Info */
.step-info {
  flex: 1;
  min-width: 0;
}

.step-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.step-number {
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 600;
}

.step-title {
  margin: 0;
  color: var(--text-primary);
  font-size: 15px;
  font-weight: 600;
  flex: 1;
}

.step-tool {
  padding: 2px 8px;
  background: var(--bg-tertiary);
  border-radius: 4px;
  font-size: 11px;
  color: var(--text-secondary);
  text-transform: uppercase;
  font-weight: 500;
}

.step-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
}

.step-badge.escalated {
  background: var(--primary-bg, #eff6ff);
  color: var(--primary-color, #3b82f6);
}

.step-description {
  margin: 4px 0 0 0;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.5;
}

.step-meta {
  margin-top: 8px;
  display: flex;
  gap: 12px;
}

.step-time {
  font-size: 12px;
  color: var(--text-tertiary);
  font-family: 'Monaco', 'Menlo', monospace;
}

/* Expand Icon */
.expand-icon {
  flex-shrink: 0;
  color: var(--text-secondary);
  transition: transform 0.2s;
}

.expand-icon span.expanded {
  transform: rotate(180deg);
  display: inline-block;
}

/* Step Actions */
.step-actions {
  margin-top: 12px;
  display: flex;
  gap: 8px;
  padding-left: 40px;
}

.step-actions button {
  padding: 6px 14px;
  border: none;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-approve {
  background: var(--success-color, #10b981);
  color: white;
}

.btn-approve:hover {
  background: var(--success-hover, #059669);
}

.btn-escalate {
  background: var(--primary-color, #3b82f6);
  color: white;
}

.btn-escalate:hover {
  background: var(--primary-hover, #2563eb);
}

.btn-status {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  cursor: not-allowed;
  opacity: 0.7;
}

.btn-status.executing {
  animation: pulse 1.5s infinite;
}

/* Step Output */
.step-output,
.step-error {
  margin-top: 12px;
  padding: 12px;
  border-radius: 6px;
  margin-left: 40px;
}

.step-output {
  background: var(--bg-tertiary);
  border-left: 3px solid var(--success-color, #10b981);
}

.step-error {
  background: var(--error-bg, #fef2f2);
  border-left: 3px solid var(--error-color, #ef4444);
}

.output-label,
.error-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  margin-bottom: 8px;
  color: var(--text-secondary);
}

.step-output pre,
.step-error pre {
  margin: 0;
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.step-output pre {
  color: var(--text-primary);
}

.step-error pre {
  color: var(--error-text, #991b1b);
}

/* Substeps */
.substeps {
  margin-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
</style>
