/**
 * Autonomous AI Developer with Perpetual Memory
 * Self-generates plans, executes code changes, learns from results
 * Integrated with perpetual logging for continuous learning
 */

import { ref } from 'vue';
import { v4 as uuidv4 } from 'uuid';
import type { ExecutionPlan, PlanStep } from './types';
import { usePlan } from '../composables/usePlan';
import { useClaude } from '../composables/useClaude';
import {
  appendPerpetualLog,
  getRelevantContext,
  getAllPerpetualLogs,
  getLogStatistics,
} from '../utils/perpetualLog';

interface DeveloperGoal {
  id: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'pending' | 'planning' | 'executing' | 'completed' | 'failed';
  createdAt: Date;
  completedAt?: Date;
  planId?: string;
  error?: string;
}

interface LearningEntry {
  timestamp: Date;
  action: string;
  result: 'success' | 'failure';
  lesson: string;
  context: string;
}

class AutonomousDeveloper {
  private goals = ref<DeveloperGoal[]>([]);
  private learnings = ref<LearningEntry[]>([]);
  private isRunning = ref(false);
  private currentTask = ref<DeveloperGoal | null>(null);
  private loopInterval: NodeJS.Timeout | null = null;
  private claude = useClaude();

  constructor() {
    this.loadState();
  }

  /**
   * Add a high-level goal for the AI to work on
   */
  addGoal(description: string, priority: DeveloperGoal['priority'] = 'medium'): DeveloperGoal {
    const goal: DeveloperGoal = {
      id: uuidv4(),
      description,
      priority,
      status: 'pending',
      createdAt: new Date(),
    };

    this.goals.value.push(goal);
    this.saveState();

    // Log to perpetual memory
    appendPerpetualLog({
      type: 'goal',
      content: `New goal: ${description} [Priority: ${priority}]`,
      status: 'pending',
      goalId: goal.id,
    });

    console.log(`[AI Developer] New goal added: ${description}`);
    return goal;
  }

  /**
   * Start the autonomous development loop
   */
  async start(): Promise<void> {
    if (this.isRunning.value) {
      console.log('[AI Developer] Already running');
      return;
    }

    this.isRunning.value = true;
    console.log('[AI Developer] Starting autonomous development loop');

    appendPerpetualLog({
      type: 'success',
      content: 'Autonomous developer started',
      status: 'executed',
    });

    // Main loop
    this.loopInterval = setInterval(() => this.executeLoop(), 5000);

    // Immediate first execution
    await this.executeLoop();
  }

  /**
   * Main execution loop
   */
  private async executeLoop(): Promise<void> {
    if (!this.isRunning.value) return;

    try {
      // Get next goal
      const goal = this.getNextGoal();

      if (!goal) {
        console.log('[AI Developer] No pending goals');
        return;
      }

      this.currentTask.value = goal;
      goal.status = 'planning';
      this.saveState();

      // Generate plan
      console.log(`[AI Developer] Planning: ${goal.description}`);
      const plan = await this.generatePlanForGoal(goal);

      if (!plan) {
        goal.status = 'failed';
        goal.error = 'Failed to generate plan';
        this.saveState();

        appendPerpetualLog({
          type: 'error',
          content: `Plan generation failed for: ${goal.description}`,
          status: 'failed',
          goalId: goal.id,
        });

        return;
      }

      goal.planId = plan.id;
      goal.status = 'executing';
      this.saveState();

      // Execute plan
      console.log(`[AI Developer] Executing plan: ${plan.title}`);
      const success = await this.executePlan(plan, goal);

      if (success) {
        goal.status = 'completed';
        goal.completedAt = new Date();

        appendPerpetualLog({
          type: 'success',
          content: `Completed goal: ${goal.description}`,
          status: 'completed',
          goalId: goal.id,
          planId: plan.id,
        });

        // Self-reflection
        await this.selfReflect(goal, plan);
      } else {
        goal.status = 'failed';
        goal.error = 'Plan execution failed';

        appendPerpetualLog({
          type: 'error',
          content: `Failed goal: ${goal.description}. Error: ${goal.error}`,
          status: 'failed',
          goalId: goal.id,
        });
      }

      this.saveState();
      this.currentTask.value = null;

    } catch (error) {
      console.error('[AI Developer] Loop error:', error);

      appendPerpetualLog({
        type: 'error',
        content: `Loop error: ${String(error)}`,
        status: 'failed',
      });
    }
  }

  /**
   * Stop the autonomous loop
   */
  stop(): void {
    this.isRunning.value = false;

    if (this.loopInterval) {
      clearInterval(this.loopInterval);
      this.loopInterval = null;
    }

    appendPerpetualLog({
      type: 'success',
      content: 'Autonomous developer stopped',
      status: 'executed',
    });

    console.log('[AI Developer] Stopped');
  }

  /**
   * Generate execution plan using perpetual memory context
   */
  private async generatePlanForGoal(goal: DeveloperGoal): Promise<ExecutionPlan | null> {
    const { createPlan } = usePlan();

    try {
      // Get relevant context from perpetual log
      const context = await getRelevantContext(goal.description, 30, [
        'plan',
        'reflection',
        'improvement',
      ]);

      // Get recent learnings
      const recentLearnings = this.learnings.value
        .slice(-10)
        .map(l => `- ${l.action}: ${l.lesson}`)
        .join('\n');

      // Build prompt for Claude
      const prompt = `
You are an autonomous AI developer. Generate a detailed execution plan.

GOAL: ${goal.description}
PRIORITY: ${goal.priority}

RELEVANT PAST EXPERIENCE:
${context}

RECENT LEARNINGS:
${recentLearnings}

Generate a JSON array of steps. Each step:
- title: Brief description
- tool: [read_file, write_file, command, git, ollama, claude]
- description: Detailed explanation
- toolParams: { path?, command?, content? }
- requiresApproval: boolean
- substeps: (optional) nested steps array

Output ONLY valid JSON array.
`;

      // Call Claude or Ollama
      const response = await this.claudeReasoning(prompt);

      // Parse response
      const stepsData = JSON.parse(response);

      // Create plan
      const plan = createPlan(
        `Auto: ${goal.description}`,
        `Autonomous plan for: ${goal.description}`
      );

      // Add steps
      stepsData.forEach((stepData: any) => {
        plan.steps.push({
          id: uuidv4(),
          status: 'pending',
          ...stepData,
        });
      });

      // Log plan generation
      appendPerpetualLog({
        type: 'plan',
        content: `Generated plan with ${plan.steps.length} steps for: ${goal.description}`,
        status: 'approved',
        goalId: goal.id,
        planId: plan.id,
        metadata: { stepCount: plan.steps.length },
      });

      return plan;

    } catch (error) {
      console.error('[AI Developer] Plan generation failed:', error);
      return null;
    }
  }

  /**
   * Execute plan with logging
   */
  private async executePlan(plan: ExecutionPlan, goal: DeveloperGoal): Promise<boolean> {
    const { executeStep } = usePlan();

    try {
      for (const step of plan.steps) {
        console.log(`[AI Developer] Executing: ${step.title}`);

        // Log step start
        appendPerpetualLog({
          type: 'step',
          content: `Executing step: ${step.title}`,
          status: 'pending',
          planId: plan.id,
          stepId: step.id,
          goalId: goal.id,
        });

        // Auto-approve low-risk operations
        if (step.requiresApproval && !step.approved) {
          if (this.isLowRisk(step)) {
            step.approved = true;
          } else {
            // High-risk, needs human approval
            step.status = 'awaitingApproval';

            appendPerpetualLog({
              type: 'step',
              content: `Awaiting approval for: ${step.title}`,
              status: 'pending',
              stepId: step.id,
            });

            return false; // Pause execution
          }
        }

        // Execute step
        await executeStep(plan.id, step.id);

        // Log result
        if (step.status === 'completed') {
          appendPerpetualLog({
            type: 'step',
            content: `Completed: ${step.title}\nOutput: ${step.output}`,
            status: 'completed',
            stepId: step.id,
          });
        } else if (step.status === 'rolledBack') {
          appendPerpetualLog({
            type: 'error',
            content: `Failed and rolled back: ${step.title}\nError: ${step.error}`,
            status: 'failed',
            stepId: step.id,
          });

          return false;
        }
      }

      plan.status = 'completed';
      return true;

    } catch (error) {
      console.error('[AI Developer] Execution failed:', error);
      plan.status = 'rolledBack';
      return false;
    }
  }

  /**
   * Self-reflection and improvement generation
   */
  private async selfReflect(goal: DeveloperGoal, plan: ExecutionPlan): Promise<void> {
    try {
      // Get recent context
      const context = await getRelevantContext('code improvements', 10);

      const prompt = `
You completed this goal: ${goal.description}

Steps executed:
${plan.steps.map(s => `- ${s.title}: ${s.status}`).join('\n')}

Past learnings:
${context}

Suggest 1-3 improvement tasks based on this work.
Focus on: code quality, performance, testing, documentation, security.

Output JSON array:
[
  { "description": "...", "priority": "low|medium|high" }
]
`;

      const response = await this.claudeReasoning(prompt);
      const improvements = JSON.parse(response);

      console.log(`[AI Developer] Generated ${improvements.length} improvements`);

      // Add improvement goals
      improvements.forEach((imp: any) => {
        this.addGoal(imp.description, imp.priority || 'low');

        appendPerpetualLog({
          type: 'improvement',
          content: `Improvement suggested: ${imp.description}`,
          status: 'pending',
        });
      });

      // Record learning
      this.recordLearning(
        `Completed: ${goal.description}`,
        'success',
        `Generated ${improvements.length} follow-up improvements`,
        JSON.stringify(plan.steps.map(s => s.title))
      );

      // Log reflection
      appendPerpetualLog({
        type: 'reflection',
        content: `Reflected on goal: ${goal.description}. Generated ${improvements.length} improvements.`,
        status: 'completed',
        goalId: goal.id,
      });

    } catch (error) {
      console.error('[AI Developer] Reflection failed:', error);
    }
  }

  /**
   * Record a learning entry
   */
  private recordLearning(
    action: string,
    result: 'success' | 'failure',
    lesson: string,
    context: string
  ): void {
    this.learnings.value.push({
      timestamp: new Date(),
      action,
      result,
      lesson,
      context,
    });

    // Keep only last 100
    if (this.learnings.value.length > 100) {
      this.learnings.value = this.learnings.value.slice(-100);
    }

    this.saveState();
  }

  /**
   * Get next goal by priority
   */
  private getNextGoal(): DeveloperGoal | null {
    const pending = this.goals.value.filter(g => g.status === 'pending');
    if (pending.length === 0) return null;

    const priorityOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };

    pending.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);
    return pending[0];
  }

  /**
   * Check if step is low-risk (auto-approvable)
   */
  private isLowRisk(step: PlanStep): boolean {
    return step.tool === 'read_file' ||
           step.tool === 'ollama' ||
           step.tool === 'claude';
  }

  /**
   * AI reasoning call - uses Ollama (local) instead of Claude
   */
  private async claudeReasoning(prompt: string): Promise<string> {
    console.log('[AI Developer] Ollama reasoning:', prompt.substring(0, 100));

    try {
      // Use Ollama locally instead of Claude API
      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'qwen2.5-coder:1.5b',
          prompt: prompt,
          stream: false
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data.response || '[]';

    } catch (error) {
      console.error('[AI Developer] Ollama reasoning failed:', error);
      appendPerpetualLog({
        type: 'error',
        content: `Ollama reasoning failed: ${String(error)}. Is Ollama running?`,
        status: 'failed',
      });
      return '[]'; // Fallback on error
    }
  }

  // Persistence
  private loadState(): void {
    // In browser mode, use localStorage instead of files
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const goalsData = localStorage.getItem('ai_developer_goals');
        if (goalsData) {
          const data = JSON.parse(goalsData);
          this.goals.value = data.map((g: any) => ({
            ...g,
            createdAt: new Date(g.createdAt),
            completedAt: g.completedAt ? new Date(g.completedAt) : undefined,
          }));
        }

        const learningsData = localStorage.getItem('ai_developer_learnings');
        if (learningsData) {
          const data = JSON.parse(learningsData);
          this.learnings.value = data.map((l: any) => ({
            ...l,
            timestamp: new Date(l.timestamp),
          }));
        }
      } catch (error) {
        console.error('[AI Developer] Failed to load state from localStorage:', error);
      }
    }
  }

  private saveState(): void {
    // In browser mode, use localStorage instead of files
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        localStorage.setItem(
          'ai_developer_goals',
          JSON.stringify(this.goals.value)
        );

        localStorage.setItem(
          'ai_developer_learnings',
          JSON.stringify(this.learnings.value)
        );
      } catch (error) {
        console.error('[AI Developer] Failed to save state to localStorage:', error);
      }
    }
  }

  // Public API
  getGoals(): DeveloperGoal[] {
    return this.goals.value;
  }

  getLearnings(): LearningEntry[] {
    return this.learnings.value;
  }

  getCurrentTask(): DeveloperGoal | null {
    return this.currentTask.value;
  }

  isActive(): boolean {
    return this.isRunning.value;
  }

  getStatistics() {
    return getLogStatistics();
  }
}

// Singleton instance
export const autonomousDeveloper = new AutonomousDeveloper();
