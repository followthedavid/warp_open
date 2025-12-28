/**
 * Orchestrator - Task queue and state machine
 *
 * Manages the agent execution flow by:
 * - Breaking complex tasks into steps
 * - Managing execution state
 * - Coordinating between components
 * - Handling retries and escalation
 */

import { invoke } from '@tauri-apps/api/tauri';
import { ContextManager } from './ContextManager';
import { ConstrainedOutput, type AgentAction } from './ConstrainedOutput';
import { Verifier } from './Verifier';
import { RecoveryHandler } from './RecoveryHandler';

export type TaskState =
  | 'pending'
  | 'planning'
  | 'executing'
  | 'verifying'
  | 'waiting_user'
  | 'completed'
  | 'failed'
  | 'paused';

export interface Task {
  id: string;
  description: string;
  state: TaskState;
  steps: TaskStep[];
  currentStepIndex: number;
  createdAt: number;
  updatedAt: number;
  error?: string;
  result?: string;
}

export interface TaskStep {
  id: string;
  description: string;
  action?: AgentAction;
  state: 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';
  output?: string;
  error?: string;
  retryCount: number;
}

export interface OrchestratorConfig {
  maxRetries: number;
  maxStepsPerTask: number;
  stepTimeout: number;
  model: string;
  onStateChange?: (task: Task) => void;
  onStepComplete?: (step: TaskStep, task: Task) => void;
  onUserInput?: (question: string) => Promise<string>;
}

export class Orchestrator {
  private contextManager: ContextManager;
  private constrainedOutput: ConstrainedOutput;
  private verifier: Verifier;
  private recoveryHandler: RecoveryHandler;
  private config: OrchestratorConfig;
  private currentTask: Task | null = null;
  private taskQueue: Task[] = [];
  private isRunning: boolean = false;
  private isPaused: boolean = false;

  constructor(config: Partial<OrchestratorConfig> = {}) {
    this.config = {
      maxRetries: config.maxRetries ?? 3,
      maxStepsPerTask: config.maxStepsPerTask ?? 20,
      stepTimeout: config.stepTimeout ?? 30000,
      model: config.model ?? 'qwen2.5-coder:1.5b',
      onStateChange: config.onStateChange,
      onStepComplete: config.onStepComplete,
      onUserInput: config.onUserInput
    };

    this.contextManager = new ContextManager();
    this.constrainedOutput = new ConstrainedOutput({ model: this.config.model });
    this.verifier = new Verifier();
    this.recoveryHandler = new RecoveryHandler();
  }

  /**
   * Create a new task
   */
  createTask(description: string): Task {
    const task: Task = {
      id: `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      description,
      state: 'pending',
      steps: [],
      currentStepIndex: 0,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    this.taskQueue.push(task);
    return task;
  }

  /**
   * Start executing the task queue
   */
  async start(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;
    this.isPaused = false;

    while (this.taskQueue.length > 0 && this.isRunning && !this.isPaused) {
      const task = this.taskQueue.shift()!;
      await this.executeTask(task);
    }

    this.isRunning = false;
  }

  /**
   * Pause execution
   */
  pause(): void {
    this.isPaused = true;
    if (this.currentTask) {
      this.currentTask.state = 'paused';
      this.notifyStateChange(this.currentTask);
    }
  }

  /**
   * Resume execution
   */
  async resume(): Promise<void> {
    if (!this.isPaused) return;
    this.isPaused = false;

    if (this.currentTask && this.currentTask.state === 'paused') {
      this.currentTask.state = 'executing';
      await this.continueTask(this.currentTask);
    }

    await this.start();
  }

  /**
   * Stop execution
   */
  stop(): void {
    this.isRunning = false;
    this.isPaused = false;
    if (this.currentTask) {
      this.currentTask.state = 'failed';
      this.currentTask.error = 'Execution stopped by user';
      this.notifyStateChange(this.currentTask);
    }
  }

  /**
   * Execute a single task
   */
  private async executeTask(task: Task): Promise<void> {
    this.currentTask = task;
    task.state = 'planning';
    task.updatedAt = Date.now();
    this.notifyStateChange(task);

    try {
      // Initialize context
      this.contextManager.clear();
      this.contextManager.setTask(task.description);

      // Planning phase - break down the task
      await this.planTask(task);

      // Execution phase
      task.state = 'executing';
      this.notifyStateChange(task);
      await this.continueTask(task);

    } catch (e) {
      task.state = 'failed';
      task.error = e instanceof Error ? e.message : 'Unknown error';
      this.notifyStateChange(task);
    }

    this.currentTask = null;
  }

  /**
   * Plan the task by breaking it into steps
   */
  private async planTask(task: Task): Promise<void> {
    const planPrompt = `You are planning a coding task. Break it into simple steps.

Task: ${task.description}

List 3-7 concrete steps to complete this task. Each step should be a single action.
Format as JSON array: ["step 1 description", "step 2 description", ...]

Only output the JSON array, nothing else.`;

    try {
      const response = await invoke<string>('query_ollama', {
        prompt: planPrompt,
        model: this.config.model
      });

      // Parse steps
      const stepsMatch = response.match(/\[[\s\S]*\]/);
      if (stepsMatch) {
        const steps = JSON.parse(stepsMatch[0]) as string[];
        task.steps = steps.slice(0, this.config.maxStepsPerTask).map((desc, i) => ({
          id: `step_${i}`,
          description: desc,
          state: 'pending' as const,
          retryCount: 0
        }));
      } else {
        // Fallback: create a single step
        task.steps = [{
          id: 'step_0',
          description: task.description,
          state: 'pending',
          retryCount: 0
        }];
      }
    } catch (e) {
      // Planning failed, create single step
      task.steps = [{
        id: 'step_0',
        description: task.description,
        state: 'pending',
        retryCount: 0
      }];
    }
  }

  /**
   * Continue executing task steps
   */
  private async continueTask(task: Task): Promise<void> {
    while (task.currentStepIndex < task.steps.length && !this.isPaused) {
      const step = task.steps[task.currentStepIndex];

      if (step.state === 'completed' || step.state === 'skipped') {
        task.currentStepIndex++;
        continue;
      }

      step.state = 'in_progress';
      task.updatedAt = Date.now();

      try {
        await this.executeStep(step, task);
        step.state = 'completed';
        this.contextManager.completeStep(step.description);
        this.config.onStepComplete?.(step, task);
      } catch (e) {
        step.error = e instanceof Error ? e.message : 'Unknown error';

        if (step.retryCount < this.config.maxRetries) {
          step.retryCount++;
          this.contextManager.addError(step.error);
          continue; // Retry the step
        } else {
          step.state = 'failed';
          task.state = 'failed';
          task.error = `Step failed after ${this.config.maxRetries} retries: ${step.error}`;
          this.notifyStateChange(task);
          return;
        }
      }

      task.currentStepIndex++;
      task.updatedAt = Date.now();
    }

    if (task.currentStepIndex >= task.steps.length) {
      task.state = 'completed';
      task.result = 'All steps completed successfully';
      this.notifyStateChange(task);
    }
  }

  /**
   * Execute a single step
   */
  private async executeStep(step: TaskStep, task: Task): Promise<void> {
    // Build context-aware prompt
    const prompt = this.contextManager.buildPrompt(step.description);

    // Get constrained action from model
    const result = await this.constrainedOutput.queryConstrained(prompt);

    if (!result.valid || !result.action) {
      throw new Error(result.error || 'Failed to get valid action');
    }

    step.action = result.action;

    // Handle special actions
    if (result.action.action === 'think') {
      step.output = result.action.thought;
      await this.contextManager.addMessage({
        role: 'assistant',
        content: result.action.thought || '',
        timestamp: Date.now()
      });
      return;
    }

    if (result.action.action === 'done') {
      step.output = result.action.content || 'Task completed';
      return;
    }

    if (result.action.action === 'ask') {
      if (this.config.onUserInput) {
        task.state = 'waiting_user';
        this.notifyStateChange(task);
        const answer = await this.config.onUserInput(result.action.question || '');
        await this.contextManager.addMessage({
          role: 'user',
          content: answer,
          timestamp: Date.now()
        });
        task.state = 'executing';
        this.notifyStateChange(task);
      }
      return;
    }

    // Verify action before execution
    task.state = 'verifying';
    this.notifyStateChange(task);

    const verification = await this.verifier.verify(result.action);

    if (!verification.valid) {
      throw new Error(`Verification failed: ${verification.errors.join(', ')}`);
    }

    if (verification.warnings.length > 0) {
      console.warn('Verification warnings:', verification.warnings);
    }

    // Execute with recovery
    task.state = 'executing';
    this.notifyStateChange(task);

    const execResult = await this.recoveryHandler.executeWithRecovery(
      result.action,
      (action) => this.executeAction(action),
      this.contextManager.getState()
    );

    if (!execResult.success) {
      throw new Error(execResult.error);
    }

    step.output = execResult.output;

    // Add to context
    await this.contextManager.addMessage({
      role: 'assistant',
      content: `Executed: ${result.action.action} - ${execResult.output?.slice(0, 200) || 'Success'}`,
      timestamp: Date.now()
    });
  }

  /**
   * Execute an action
   */
  private async executeAction(action: AgentAction): Promise<string> {
    switch (action.action) {
      case 'read':
        return await invoke<string>('read_file', { path: action.path });

      case 'write':
        await invoke<void>('write_file', { path: action.path, content: action.content });
        return `Wrote ${action.content?.length || 0} bytes to ${action.path}`;

      case 'edit':
        const content = await invoke<string>('read_file', { path: action.path });
        if (!content.includes(action.oldContent || '')) {
          throw new Error('oldContent not found in file');
        }
        const newContent = content.replace(action.oldContent || '', action.newContent || '');
        await invoke<void>('write_file', { path: action.path, content: newContent });
        return `Edited ${action.path}`;

      case 'bash':
        return await invoke<string>('execute_shell', {
          command: action.command
        });

      case 'search':
        const files = await invoke<string[]>('grep_files', {
          pattern: action.pattern,
          path: action.path || '.'
        });
        return files.join('\n');

      default:
        return 'No-op';
    }
  }

  /**
   * Notify state change
   */
  private notifyStateChange(task: Task): void {
    this.config.onStateChange?.(task);
  }

  /**
   * Get current task
   */
  getCurrentTask(): Task | null {
    return this.currentTask;
  }

  /**
   * Get task queue
   */
  getQueue(): Task[] {
    return [...this.taskQueue];
  }

  /**
   * Get execution stats
   */
  getStats(): {
    isRunning: boolean;
    isPaused: boolean;
    queueLength: number;
    currentTask: string | null;
    recoveryStats: ReturnType<RecoveryHandler['getStats']>;
  } {
    return {
      isRunning: this.isRunning,
      isPaused: this.isPaused,
      queueLength: this.taskQueue.length,
      currentTask: this.currentTask?.description || null,
      recoveryStats: this.recoveryHandler.getStats()
    };
  }
}

export default Orchestrator;
