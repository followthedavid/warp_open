<template>
  <div class="plan-panel">
    <div v-if="!currentPlan" class="no-plan">
      <p>No active execution plan</p>
      <div class="plan-menu">
        <button @click="showPlanMenu = !showPlanMenu" class="btn-primary">
          Create New Plan ▼
        </button>
        <div v-if="showPlanMenu" class="plan-dropdown">
          <button @click="createNewPlan" class="dropdown-item">
            Empty Plan
          </button>
          <button @click="createMasterPlan" class="dropdown-item">
            Master Upgrade Plan
          </button>
          <button @click="createJWTPlan" class="dropdown-item">
            JWT Refactor Example
          </button>
        </div>
      </div>
    </div>

    <div v-else class="plan-container">
      <!-- Plan Header -->
      <div class="plan-header">
        <div class="plan-info">
          <h2>{{ currentPlan.title }}</h2>
          <p v-if="currentPlan.description" class="plan-description">
            {{ currentPlan.description }}
          </p>
          <div class="plan-meta">
            <span class="plan-status" :class="`status-${currentPlan.status}`">
              {{ currentPlan.status }}
            </span>
            <span class="plan-progress">
              {{ currentPlan.currentStepIndex }} / {{ currentPlan.steps.length }} steps
            </span>
          </div>
        </div>
        <div class="plan-actions">
          <button @click="deletePlan(currentPlan.id)" class="btn-secondary">
            Delete Plan
          </button>
        </div>
      </div>

      <!-- Steps List -->
      <div class="steps-container">
        <h3>Execution Steps</h3>
        <div class="steps-list">
          <PlanStep
            v-for="(step, index) in currentPlan.steps"
            :key="step.id"
            :step="step"
            :plan-id="currentPlan.id"
            :index="index"
            :is-current="index === currentPlan.currentStepIndex"
            @approve="handleApprove"
            @escalate="handleEscalate"
          />
        </div>
      </div>

      <!-- Logs Panel -->
      <div class="logs-panel">
        <div class="logs-header">
          <h3>Execution Logs</h3>
          <button @click="toggleLogs" class="btn-text">
            {{ showLogs ? 'Hide' : 'Show' }}
          </button>
        </div>
        <div v-if="showLogs" class="logs-content">
          <div
            v-for="(log, index) in currentPlan.logs"
            :key="index"
            class="log-entry"
          >
            {{ log }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { usePlan } from '../composables/usePlan';
import PlanStep from './PlanStep.vue';
import { generateMasterPlan, generateJWTRefactorPlan } from '../agents/steps';

const {
  currentPlan,
  createPlan,
  addStep,
  approveStep,
  escalateStep,
  deletePlan,
} = usePlan();

const showLogs = ref(true);
const showPlanMenu = ref(false);

function createNewPlan() {
  const plan = createPlan(
    'New Execution Plan',
    'Enter plan description here'
  );

  // Add some example steps
  addStep(plan.id, 'Example Step 1', {
    description: 'This is an example step',
    requiresApproval: true,
  });

  showPlanMenu.value = false;
}

function createMasterPlan() {
  const plan = createPlan(
    'Ultimate AI Terminal Autonomous Upgrade',
    'Integrate full autonomous execution, hybrid AI orchestration, file & git operations, rollback, and self-improvement modules.'
  );

  // Add all master plan steps
  const steps = generateMasterPlan(plan.id);
  steps.forEach(step => {
    const { id, ...stepData } = step;
    Object.assign(plan.steps, [step]);
  });

  showPlanMenu.value = false;
}

function createJWTPlan() {
  const plan = createPlan(
    'Refactor Authentication System',
    'Migrate from session-based auth to JWT with full automated tests'
  );

  // Add JWT refactor steps
  const steps = generateJWTRefactorPlan();
  steps.forEach(step => {
    Object.assign(plan.steps, [step]);
  });

  showPlanMenu.value = false;
}

function toggleLogs() {
  showLogs.value = !showLogs.value;
}

async function handleApprove(stepId: string) {
  if (!currentPlan.value) return;
  await approveStep(currentPlan.value.id, stepId);
}

async function handleEscalate(stepId: string) {
  if (!currentPlan.value) return;
  await escalateStep(currentPlan.value.id, stepId);
}
</script>

<style scoped>
.plan-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--bg-secondary);
  border-radius: 8px;
  overflow: hidden;
}

.no-plan {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  gap: 16px;
  color: var(--text-secondary);
}

.plan-menu {
  position: relative;
}

.plan-dropdown {
  position: absolute;
  top: 100%;
  left: 0;
  margin-top: 8px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  min-width: 200px;
  z-index: 10;
}

.dropdown-item {
  width: 100%;
  padding: 10px 16px;
  background: transparent;
  color: var(--text-primary);
  border: none;
  text-align: left;
  cursor: pointer;
  transition: background 0.2s;
  font-size: 14px;
}

.dropdown-item:hover {
  background: var(--bg-hover);
}

.dropdown-item:first-child {
  border-radius: 6px 6px 0 0;
}

.dropdown-item:last-child {
  border-radius: 0 0 6px 6px;
}

.plan-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

/* Plan Header */
.plan-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 20px;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border-color);
}

.plan-info h2 {
  margin: 0 0 8px 0;
  color: var(--text-primary);
  font-size: 20px;
  font-weight: 600;
}

.plan-description {
  margin: 0 0 12px 0;
  color: var(--text-secondary);
  font-size: 14px;
}

.plan-meta {
  display: flex;
  gap: 12px;
  align-items: center;
}

.plan-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  text-transform: uppercase;
}

.status-pending {
  background: var(--status-pending-bg, #fef3c7);
  color: var(--status-pending-text, #92400e);
}

.status-inProgress {
  background: var(--status-progress-bg, #dbeafe);
  color: var(--status-progress-text, #1e40af);
}

.status-completed {
  background: var(--status-success-bg, #d1fae5);
  color: var(--status-success-text, #065f46);
}

.status-rolledBack {
  background: var(--status-error-bg, #fee2e2);
  color: var(--status-error-text, #991b1b);
}

.plan-progress {
  font-size: 13px;
  color: var(--text-secondary);
}

.plan-actions {
  display: flex;
  gap: 8px;
}

/* Steps Container */
.steps-container {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}

.steps-container h3 {
  margin: 0 0 16px 0;
  color: var(--text-primary);
  font-size: 16px;
  font-weight: 600;
}

.steps-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* Logs Panel */
.logs-panel {
  border-top: 1px solid var(--border-color);
  background: var(--bg-tertiary);
}

.logs-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 20px;
}

.logs-header h3 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.logs-content {
  max-height: 200px;
  overflow-y: auto;
  padding: 0 20px 12px;
}

.log-entry {
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 12px;
  color: var(--text-secondary);
  padding: 4px 0;
  line-height: 1.5;
}

/* Buttons */
.btn-primary {
  padding: 10px 20px;
  background: var(--primary-color, #3b82f6);
  color: white;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.2s;
}

.btn-primary:hover {
  background: var(--primary-hover, #2563eb);
}

.btn-secondary {
  padding: 8px 16px;
  background: transparent;
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: var(--bg-hover);
  border-color: var(--border-hover);
}

.btn-text {
  padding: 4px 8px;
  background: transparent;
  color: var(--primary-color);
  border: none;
  font-size: 13px;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-text:hover {
  opacity: 0.8;
}
</style>
