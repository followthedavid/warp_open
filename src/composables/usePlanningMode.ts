/**
 * Planning Mode System
 * Creates structured plans before execution, similar to Claude Code's planning feature.
 * Plans are saved to ~/.warp_open/plans/ for review and resumption.
 */

import { ref, computed } from 'vue';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export interface PlanStep {
  id: string;
  description: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';
  result?: string;
  error?: string;
  startedAt?: number;
  completedAt?: number;
}

export interface Plan {
  id: string;
  name: string;
  description: string;
  goal: string;
  steps: PlanStep[];
  status: 'draft' | 'approved' | 'executing' | 'completed' | 'failed' | 'paused';
  createdAt: number;
  updatedAt: number;
  approvedAt?: number;
  completedAt?: number;
  filePath?: string;
  context?: Record<string, unknown>;
}

export interface PlanningModeState {
  isActive: boolean;
  currentPlan: Plan | null;
  currentStepIndex: number;
  autoExecute: boolean;
}

// State
const state = ref<PlanningModeState>({
  isActive: false,
  currentPlan: null,
  currentStepIndex: -1,
  autoExecute: false,
});

const plans = ref<Plan[]>([]);
const plansDirectory = '~/.warp_open/plans';

function generatePlanId(): string {
  return `plan_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

function generateStepId(): string {
  return `step_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`;
}

export function usePlanningMode() {
  const isActive = computed(() => state.value.isActive);
  const currentPlan = computed(() => state.value.currentPlan);
  const currentStep = computed(() => {
    if (!state.value.currentPlan || state.value.currentStepIndex < 0) return null;
    return state.value.currentPlan.steps[state.value.currentStepIndex];
  });
  const progress = computed(() => {
    if (!state.value.currentPlan) return 0;
    const completed = state.value.currentPlan.steps.filter(
      s => s.status === 'completed' || s.status === 'skipped'
    ).length;
    return (completed / state.value.currentPlan.steps.length) * 100;
  });

  async function enterPlanningMode(goal: string): Promise<Plan> {
    const plan: Plan = {
      id: generatePlanId(),
      name: goal.slice(0, 50),
      description: '',
      goal,
      steps: [],
      status: 'draft',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    state.value.isActive = true;
    state.value.currentPlan = plan;
    state.value.currentStepIndex = -1;

    console.log('[PlanningMode] Entered planning mode for:', goal);
    return plan;
  }

  function addStep(description: string): PlanStep | null {
    if (!state.value.currentPlan) return null;

    const step: PlanStep = {
      id: generateStepId(),
      description,
      status: 'pending',
    };

    state.value.currentPlan.steps.push(step);
    state.value.currentPlan.updatedAt = Date.now();

    return step;
  }

  function updateStep(stepId: string, description: string): void {
    if (!state.value.currentPlan) return;

    const step = state.value.currentPlan.steps.find(s => s.id === stepId);
    if (step) {
      step.description = description;
      state.value.currentPlan.updatedAt = Date.now();
    }
  }

  function removeStep(stepId: string): void {
    if (!state.value.currentPlan) return;

    const index = state.value.currentPlan.steps.findIndex(s => s.id === stepId);
    if (index >= 0) {
      state.value.currentPlan.steps.splice(index, 1);
      state.value.currentPlan.updatedAt = Date.now();
    }
  }

  function reorderSteps(fromIndex: number, toIndex: number): void {
    if (!state.value.currentPlan) return;

    const steps = state.value.currentPlan.steps;
    const [removed] = steps.splice(fromIndex, 1);
    steps.splice(toIndex, 0, removed);
    state.value.currentPlan.updatedAt = Date.now();
  }

  async function savePlan(): Promise<string | null> {
    if (!state.value.currentPlan || !invoke) return null;

    const plan = state.value.currentPlan;
    const filename = `${plan.id}.md`;
    const markdown = generatePlanMarkdown(plan);

    try {
      await invoke('execute_shell', {
        command: 'mkdir -p ~/.warp_open/plans',
      });

      await invoke('write_file', {
        path: `~/.warp_open/plans/${filename}`,
        content: markdown,
      });

      plan.filePath = `~/.warp_open/plans/${filename}`;
      console.log('[PlanningMode] Saved plan to:', plan.filePath);
      return plan.filePath;
    } catch (error) {
      console.error('[PlanningMode] Failed to save plan:', error);
      return null;
    }
  }

  function generatePlanMarkdown(plan: Plan): string {
    const statusEmoji: Record<string, string> = {
      pending: '⬜',
      in_progress: '🔄',
      completed: '✅',
      failed: '❌',
      skipped: '⏭️',
    };

    let md = `# Plan: ${plan.name}\n\n`;
    md += `**Goal:** ${plan.goal}\n\n`;
    md += `**Status:** ${plan.status}\n`;
    md += `**Created:** ${new Date(plan.createdAt).toISOString()}\n`;
    md += `**Updated:** ${new Date(plan.updatedAt).toISOString()}\n\n`;

    if (plan.description) {
      md += `## Description\n\n${plan.description}\n\n`;
    }

    md += `## Steps\n\n`;
    plan.steps.forEach((step, index) => {
      const emoji = statusEmoji[step.status] || '⬜';
      md += `${index + 1}. ${emoji} ${step.description}\n`;
      if (step.result) {
        md += `   - Result: ${step.result}\n`;
      }
      if (step.error) {
        md += `   - Error: ${step.error}\n`;
      }
    });

    md += `\n---\n`;
    md += `*Plan ID: ${plan.id}*\n`;

    return md;
  }

  function approvePlan(): void {
    if (!state.value.currentPlan) return;

    state.value.currentPlan.status = 'approved';
    state.value.currentPlan.approvedAt = Date.now();
    state.value.currentPlan.updatedAt = Date.now();

    console.log('[PlanningMode] Plan approved');
  }

  async function startExecution(): Promise<void> {
    if (!state.value.currentPlan) return;
    if (state.value.currentPlan.status !== 'approved') {
      console.error('[PlanningMode] Plan must be approved before execution');
      return;
    }

    state.value.currentPlan.status = 'executing';
    state.value.currentStepIndex = 0;
    state.value.currentPlan.updatedAt = Date.now();

    if (state.value.currentPlan.steps.length > 0) {
      state.value.currentPlan.steps[0].status = 'in_progress';
      state.value.currentPlan.steps[0].startedAt = Date.now();
    }

    console.log('[PlanningMode] Started execution');
  }

  function completeCurrentStep(result?: string): void {
    if (!state.value.currentPlan || state.value.currentStepIndex < 0) return;

    const step = state.value.currentPlan.steps[state.value.currentStepIndex];
    if (step) {
      step.status = 'completed';
      step.result = result;
      step.completedAt = Date.now();
    }

    state.value.currentStepIndex++;

    if (state.value.currentStepIndex < state.value.currentPlan.steps.length) {
      const nextStep = state.value.currentPlan.steps[state.value.currentStepIndex];
      nextStep.status = 'in_progress';
      nextStep.startedAt = Date.now();
    } else {
      state.value.currentPlan.status = 'completed';
      state.value.currentPlan.completedAt = Date.now();
      console.log('[PlanningMode] Plan completed');
    }

    state.value.currentPlan.updatedAt = Date.now();
    savePlan();
  }

  function failCurrentStep(error: string): void {
    if (!state.value.currentPlan || state.value.currentStepIndex < 0) return;

    const step = state.value.currentPlan.steps[state.value.currentStepIndex];
    if (step) {
      step.status = 'failed';
      step.error = error;
      step.completedAt = Date.now();
    }

    state.value.currentPlan.status = 'failed';
    state.value.currentPlan.updatedAt = Date.now();
    savePlan();

    console.log('[PlanningMode] Step failed:', error);
  }

  function skipCurrentStep(reason?: string): void {
    if (!state.value.currentPlan || state.value.currentStepIndex < 0) return;

    const step = state.value.currentPlan.steps[state.value.currentStepIndex];
    if (step) {
      step.status = 'skipped';
      step.result = reason || 'Skipped by user';
      step.completedAt = Date.now();
    }

    state.value.currentStepIndex++;

    if (state.value.currentStepIndex < state.value.currentPlan.steps.length) {
      const nextStep = state.value.currentPlan.steps[state.value.currentStepIndex];
      nextStep.status = 'in_progress';
      nextStep.startedAt = Date.now();
    } else {
      state.value.currentPlan.status = 'completed';
      state.value.currentPlan.completedAt = Date.now();
    }

    state.value.currentPlan.updatedAt = Date.now();
    savePlan();
  }

  function pauseExecution(): void {
    if (!state.value.currentPlan) return;

    state.value.currentPlan.status = 'paused';
    state.value.currentPlan.updatedAt = Date.now();
    savePlan();

    console.log('[PlanningMode] Execution paused');
  }

  function resumeExecution(): void {
    if (!state.value.currentPlan || state.value.currentPlan.status !== 'paused') return;

    state.value.currentPlan.status = 'executing';
    state.value.currentPlan.updatedAt = Date.now();

    console.log('[PlanningMode] Execution resumed');
  }

  function exitPlanningMode(): void {
    if (state.value.currentPlan && state.value.currentPlan.status === 'draft') {
      savePlan();
    }

    state.value.isActive = false;
    state.value.currentPlan = null;
    state.value.currentStepIndex = -1;

    console.log('[PlanningMode] Exited planning mode');
  }

  async function loadPlan(planId: string): Promise<Plan | null> {
    if (!invoke) return null;

    try {
      const content = await invoke<string>('read_file', {
        path: `~/.warp_open/plans/${planId}.md`,
      });

      return parsePlanMarkdown(content, planId);
    } catch (error) {
      console.error('[PlanningMode] Failed to load plan:', error);
      return null;
    }
  }

  function parsePlanMarkdown(content: string, planId: string): Plan {
    const lines = content.split('\n');
    const plan: Plan = {
      id: planId,
      name: '',
      description: '',
      goal: '',
      steps: [],
      status: 'draft',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    let inSteps = false;

    for (const line of lines) {
      if (line.startsWith('# Plan:')) {
        plan.name = line.replace('# Plan:', '').trim();
      } else if (line.startsWith('**Goal:**')) {
        plan.goal = line.replace('**Goal:**', '').trim();
      } else if (line.startsWith('**Status:**')) {
        plan.status = line.replace('**Status:**', '').trim() as Plan['status'];
      } else if (line === '## Steps') {
        inSteps = true;
      } else if (inSteps && /^\d+\./.test(line)) {
        const description = line.replace(/^\d+\.\s*[⬜🔄✅❌⏭️]\s*/, '').trim();
        const status = line.includes('✅') ? 'completed' :
                      line.includes('❌') ? 'failed' :
                      line.includes('🔄') ? 'in_progress' :
                      line.includes('⏭️') ? 'skipped' : 'pending';
        plan.steps.push({
          id: generateStepId(),
          description,
          status,
        });
      }
    }

    return plan;
  }

  async function listPlans(): Promise<Plan[]> {
    if (!invoke) return [];

    try {
      const result = await invoke<Array<{ path: string }>>('glob_files', {
        pattern: '*.md',
        path: '~/.warp_open/plans',
      });

      const loadedPlans: Plan[] = [];
      for (const file of result) {
        const planId = file.path.split('/').pop()?.replace('.md', '');
        if (planId) {
          const plan = await loadPlan(planId);
          if (plan) loadedPlans.push(plan);
        }
      }

      plans.value = loadedPlans;
      return loadedPlans;
    } catch {
      return [];
    }
  }

  async function deletePlan(planId: string): Promise<boolean> {
    if (!invoke) return false;

    try {
      await invoke('execute_shell', {
        command: `rm ~/.warp_open/plans/${planId}.md`,
      });

      const index = plans.value.findIndex(p => p.id === planId);
      if (index >= 0) plans.value.splice(index, 1);

      return true;
    } catch {
      return false;
    }
  }

  function generatePlanFromGoal(goal: string, context?: string): string {
    return `Create a detailed implementation plan for: ${goal}

${context ? `Context:\n${context}\n\n` : ''}

Please provide:
1. A list of specific, actionable steps
2. Files that need to be created or modified
3. Any dependencies between steps
4. Potential challenges and how to address them

Format each step as a clear, single action that can be executed independently.
Number each step and be specific about what needs to be done.`;
  }

  return {
    isActive,
    currentPlan,
    currentStep,
    progress,
    plans: computed(() => plans.value),

    enterPlanningMode,
    exitPlanningMode,
    approvePlan,

    addStep,
    updateStep,
    removeStep,
    reorderSteps,

    startExecution,
    completeCurrentStep,
    failCurrentStep,
    skipCurrentStep,
    pauseExecution,
    resumeExecution,

    savePlan,
    loadPlan,
    listPlans,
    deletePlan,

    generatePlanMarkdown,
    generatePlanFromGoal,
  };
}
