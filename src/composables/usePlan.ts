/**
 * Autonomous execution plan management composable
 * Handles plan creation, step execution, approval, escalation, and rollback
 */

import { ref, computed } from 'vue';
import { v4 as uuidv4 } from 'uuid';
import type { ExecutionPlan, PlanStep, StepStatus } from '../agents/types';
import { useAI } from './useAI';

// Active plans storage
const activePlans = ref<Map<string, ExecutionPlan>>(new Map());
const currentPlanId = ref<string | null>(null);

export function usePlan() {
  const ai = useAI();

  // Get current active plan
  const currentPlan = computed(() => {
    if (!currentPlanId.value) return null;
    return activePlans.value.get(currentPlanId.value) || null;
  });

  // Create a new execution plan
  function createPlan(title: string, description?: string): ExecutionPlan {
    const plan: ExecutionPlan = {
      id: uuidv4(),
      title,
      description,
      steps: [],
      currentStepIndex: 0,
      status: 'pending',
      logs: [],
      createdAt: new Date(),
    };

    activePlans.value.set(plan.id, plan);
    currentPlanId.value = plan.id;

    addLog(plan.id, `Plan created: ${title}`);
    console.log('[Plan] Created new plan:', plan.id);

    return plan;
  }

  // Add a step to the plan
  function addStep(
    planId: string,
    title: string,
    options?: {
      description?: string;
      tool?: PlanStep['tool'];
      toolParams?: Record<string, any>;
      requiresApproval?: boolean;
      substeps?: PlanStep[];
    }
  ): PlanStep {
    const plan = activePlans.value.get(planId);
    if (!plan) {
      throw new Error(`Plan ${planId} not found`);
    }

    const step: PlanStep = {
      id: uuidv4(),
      title,
      description: options?.description,
      status: 'pending',
      tool: options?.tool,
      toolParams: options?.toolParams,
      requiresApproval: options?.requiresApproval ?? true,
      substeps: options?.substeps,
    };

    plan.steps.push(step);
    addLog(planId, `Added step: ${title}`);
    console.log('[Plan] Added step:', step.id, title);

    return step;
  }

  // Add a log entry to the plan
  function addLog(planId: string, message: string) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    const timestamp = new Date().toLocaleTimeString();
    plan.logs.push(`[${timestamp}] ${message}`);
  }

  // Update step status
  function updateStepStatus(planId: string, stepId: string, status: StepStatus) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    const step = findStep(plan.steps, stepId);
    if (step) {
      step.status = status;
      addLog(planId, `Step "${step.title}" status: ${status}`);
    }
  }

  // Find a step by ID (recursive search through substeps)
  function findStep(steps: PlanStep[], stepId: string): PlanStep | null {
    for (const step of steps) {
      if (step.id === stepId) return step;
      if (step.substeps) {
        const found = findStep(step.substeps, stepId);
        if (found) return found;
      }
    }
    return null;
  }

  // Approve a step
  async function approveStep(planId: string, stepId: string) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    const step = findStep(plan.steps, stepId);
    if (!step) return;

    step.approved = true;
    step.status = 'executing';
    addLog(planId, `Step "${step.title}" approved`);

    // Execute the step
    await executeStep(planId, stepId);
  }

  // Execute a single step
  async function executeStep(planId: string, stepId: string) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    const step = findStep(plan.steps, stepId);
    if (!step) return;

    addLog(planId, `Executing step: ${step.title}`);
    step.status = 'executing';
    step.timestamp = new Date();

    try {
      // Execute substeps first if they exist
      if (step.substeps && step.substeps.length > 0) {
        for (const substep of step.substeps) {
          if (substep.requiresApproval && !substep.approved) {
            // Wait for approval
            substep.status = 'awaitingApproval';
            addLog(planId, `Substep "${substep.title}" awaiting approval`);
            return; // Exit and wait for manual approval
          }
          await executeStep(planId, substep.id);
        }
      }

      // Execute the main step based on tool type
      let output = '';

      switch (step.tool) {
        case 'ollama':
          output = await executeOllamaStep(planId, step);
          break;
        case 'claude':
          output = await executeClaudeStep(planId, step);
          break;
        case 'command':
          output = await executeCommandStep(planId, step);
          break;
        case 'read_file':
          output = await executeReadFile(planId, step);
          break;
        case 'write_file':
          output = await executeWriteFile(planId, step);
          break;
        case 'git':
          output = await executeGitCommand(planId, step);
          break;
        default:
          output = 'Step executed (tool not specified)';
      }

      step.output = output;
      step.status = 'completed';
      addLog(planId, `Step "${step.title}" completed`);

      // Move to next step
      moveToNextStep(planId);

    } catch (error) {
      step.error = String(error);
      step.status = 'rolledBack';
      addLog(planId, `Step "${step.title}" failed: ${error}`);

      // Trigger rollback
      await rollbackPlan(planId);
    }
  }

  // Execute step using Ollama
  async function executeOllamaStep(planId: string, step: PlanStep): Promise<string> {
    addLog(planId, `[Ollama] Executing: ${step.title}`);

    // Use the AI composable to query Ollama
    const session = ai.getSession(planId);

    // Build prompt based on step
    const prompt = step.description || step.title;

    // For now, return a simulated result
    // In production, this would call actual Ollama
    return `Ollama executed: ${prompt}`;
  }

  // Execute step using Claude
  async function executeClaudeStep(planId: string, step: PlanStep): Promise<string> {
    addLog(planId, `[Claude] Executing: ${step.title}`);

    if (!ai.claude.isClaudeAvailable.value) {
      throw new Error('Claude not configured');
    }

    const prompt = step.description || step.title;
    const response = await ai.claude.queryClaude(prompt);

    return response;
  }

  // Execute command/shell operation
  async function executeCommandStep(planId: string, step: PlanStep): Promise<string> {
    const command = step.toolParams?.command || step.title;
    const workingDir = step.toolParams?.workingDir;

    addLog(planId, `[Command] Executing: ${command}`);

    try {
      const { executeCommand } = await import('../utils/commandOps');
      const result = await executeCommand(command, workingDir);

      if (result.exitCode !== 0) {
        throw new Error(`Command failed with exit code ${result.exitCode}: ${result.stderr}`);
      }

      return result.stdout || 'Command executed successfully';
    } catch (error) {
      throw new Error(`Failed to execute command: ${error}`);
    }
  }

  // Execute file read operation
  async function executeReadFile(planId: string, step: PlanStep): Promise<string> {
    const path = step.toolParams?.path || '';
    addLog(planId, `[ReadFile] Reading: ${path}`);

    try {
      const { readFile } = await import('../utils/fileOps');
      const content = await readFile(path);
      return content;
    } catch (error) {
      throw new Error(`Failed to read file ${path}: ${error}`);
    }
  }

  // Execute file write operation
  async function executeWriteFile(planId: string, step: PlanStep): Promise<string> {
    const path = step.toolParams?.path || '';
    const content = step.toolParams?.content || '';

    addLog(planId, `[WriteFile] Writing to: ${path}`);

    try {
      const { writeFile, createSnapshot } = await import('../utils/fileOps');

      // Create snapshot before writing
      const snapshot = await createSnapshot(path);
      if (snapshot) {
        step.snapshotBefore = snapshot;
      }

      await writeFile(path, content);
      return `Wrote ${content.length} bytes to ${path}`;
    } catch (error) {
      throw new Error(`Failed to write file ${path}: ${error}`);
    }
  }

  // Execute git command
  async function executeGitCommand(planId: string, step: PlanStep): Promise<string> {
    const command = step.toolParams?.command || '';
    const repoPath = step.toolParams?.repoPath;

    addLog(planId, `[Git] Executing: ${command}`);

    try {
      const gitOps = await import('../utils/gitOps');

      // Parse git command and execute appropriate function
      if (command.includes('status')) {
        const result = await gitOps.gitStatus(repoPath);
        if (!result.success) throw new Error(result.error);
        return result.output;
      } else if (command.includes('commit')) {
        const messageMatch = command.match(/-m\s+"(.+?)"/);
        const message = messageMatch ? messageMatch[1] : 'Automated commit';
        const result = await gitOps.gitCommit(message, repoPath);
        if (!result.success) throw new Error(result.error);
        return result.output;
      } else if (command.includes('push')) {
        const result = await gitOps.gitPush('origin', undefined, repoPath);
        if (!result.success) throw new Error(result.error);
        return result.output;
      } else if (command.includes('pull')) {
        const result = await gitOps.gitPull('origin', undefined, repoPath);
        if (!result.success) throw new Error(result.error);
        return result.output;
      } else if (command.includes('add')) {
        const result = await gitOps.gitAdd('.', repoPath);
        if (!result.success) throw new Error(result.error);
        return result.output;
      } else if (command.includes('diff')) {
        return await gitOps.gitDiff(undefined, repoPath);
      } else {
        // Fallback to command execution
        const { executeCommand } = await import('../utils/commandOps');
        const result = await executeCommand(`git ${command}`, repoPath);
        return result.stdout;
      }
    } catch (error) {
      throw new Error(`Git command failed: ${error}`);
    }
  }

  // Escalate step to Claude
  async function escalateStep(planId: string, stepId: string) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    const step = findStep(plan.steps, stepId);
    if (!step) return;

    addLog(planId, `Escalating step to Claude: ${step.title}`);
    step.escalated = true;

    if (!ai.claude.isClaudeAvailable.value) {
      addLog(planId, 'Claude not available for escalation');
      return;
    }

    // Ask Claude to review and improve the step
    const prompt = `Review and improve this execution step:\nTitle: ${step.title}\nDescription: ${step.description}\nCurrent output: ${step.output}`;
    const response = await ai.claude.queryClaude(prompt);

    step.output = response;
    addLog(planId, `Claude escalation completed for: ${step.title}`);
  }

  // Move to the next step in the plan
  function moveToNextStep(planId: string) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    plan.currentStepIndex++;

    if (plan.currentStepIndex >= plan.steps.length) {
      // Plan completed
      plan.status = 'completed';
      addLog(planId, 'Plan execution completed');
    } else {
      // Check if next step requires approval
      const nextStep = plan.steps[plan.currentStepIndex];
      if (nextStep.requiresApproval) {
        nextStep.status = 'awaitingApproval';
        addLog(planId, `Next step awaiting approval: ${nextStep.title}`);
      } else {
        // Auto-execute if no approval required
        executeStep(planId, nextStep.id);
      }
    }
  }

  // Rollback the entire plan
  async function rollbackPlan(planId: string) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    addLog(planId, 'Rolling back plan...');
    plan.status = 'rolledBack';

    // Rollback all completed steps in reverse order
    for (let i = plan.steps.length - 1; i >= 0; i--) {
      const step = plan.steps[i];
      if (step.status === 'completed') {
        await rollbackStep(planId, step.id);
      }
    }

    addLog(planId, 'Plan rollback completed');
  }

  // Rollback a single step
  async function rollbackStep(planId: string, stepId: string) {
    const plan = activePlans.value.get(planId);
    if (!plan) return;

    const step = findStep(plan.steps, stepId);
    if (!step) return;

    addLog(planId, `Rolling back step: ${step.title}`);

    // Restore from snapshot if available
    if (step.snapshotBefore && step.toolParams?.path) {
      try {
        const { restoreSnapshot } = await import('../utils/fileOps');
        await restoreSnapshot(step.toolParams.path, step.snapshotBefore);
        addLog(planId, `Restored snapshot for: ${step.title}`);
      } catch (error) {
        addLog(planId, `Failed to restore snapshot: ${error}`);
      }
    }

    step.status = 'rolledBack';

    // Rollback substeps
    if (step.substeps) {
      for (const substep of step.substeps.slice().reverse()) {
        await rollbackStep(planId, substep.id);
      }
    }
  }

  // Delete a plan
  function deletePlan(planId: string) {
    activePlans.value.delete(planId);
    if (currentPlanId.value === planId) {
      currentPlanId.value = null;
    }
    console.log('[Plan] Deleted plan:', planId);
  }

  // Set active plan
  function setActivePlan(planId: string | null) {
    currentPlanId.value = planId;
  }

  return {
    activePlans,
    currentPlan,
    currentPlanId,
    createPlan,
    addStep,
    addLog,
    approveStep,
    executeStep,
    escalateStep,
    rollbackPlan,
    rollbackStep,
    deletePlan,
    setActivePlan,
    updateStepStatus,
    findStep,
  };
}
