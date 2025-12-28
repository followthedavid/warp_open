/**
 * ScaffoldedAgent - Unified agent combining all scaffolding components
 *
 * This is the main entry point that coordinates:
 * - ContextManager: Sliding window context
 * - ConstrainedOutput: JSON schema enforcement
 * - Verifier: Syntax and safety checking
 * - RecoveryHandler: Checkpoint and rollback
 * - Orchestrator: Task queue and state machine
 * - ModelRouter: Intelligent model selection
 * - PatternCache: Reusable code patterns
 *
 * Designed to make small local models (1-3B params) capable of
 * complex multi-step coding tasks with safeguards.
 */

import { ref, computed, type Ref } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';

import { ContextManager, type ContextState } from './ContextManager';
import { ConstrainedOutput, type AgentAction, type ValidationResult } from './ConstrainedOutput';
import { Verifier, type VerificationResult } from './Verifier';
import { RecoveryHandler, type ActionRecord } from './RecoveryHandler';
import { Orchestrator, type Task, type TaskState } from './Orchestrator';
import { ModelRouter, type TaskType, type RoutingResult } from './ModelRouter';
import { PatternCache, type PatternMatch, type CodePattern } from './PatternCache';

export interface AgentConfig {
  defaultModel: string;
  maxRetries: number;
  maxStepsPerTask: number;
  stepTimeout: number;
  usePatternCache: boolean;
  preferLocalModels: boolean;
  autoVerify: boolean;
  autoRecover: boolean;
}

export interface AgentMessage {
  id: string;
  role: 'user' | 'assistant' | 'system' | 'action';
  content: string;
  timestamp: number;
  action?: AgentAction;
  verification?: VerificationResult;
  patternUsed?: string;
}

export interface AgentStats {
  tasksCompleted: number;
  tasksFailed: number;
  actionsExecuted: number;
  patternsUsed: number;
  rollbacks: number;
  avgResponseTime: number;
}

export class ScaffoldedAgent {
  // Core components
  private contextManager: ContextManager;
  private constrainedOutput: ConstrainedOutput;
  private verifier: Verifier;
  private recoveryHandler: RecoveryHandler;
  private orchestrator: Orchestrator;
  private modelRouter: ModelRouter;
  private patternCache: PatternCache;

  // Configuration
  private config: AgentConfig;

  // State
  private messages: Ref<AgentMessage[]>;
  private currentModel: Ref<string>;
  private isProcessing: Ref<boolean>;
  private currentTask: Ref<Task | null>;
  private stats: AgentStats;

  // Event callbacks
  private onMessage?: (message: AgentMessage) => void;
  private onStateChange?: (state: TaskState) => void;
  private onUserInput?: (question: string) => Promise<string>;

  constructor(config: Partial<AgentConfig> = {}) {
    this.config = {
      defaultModel: config.defaultModel ?? 'qwen2.5-coder:1.5b',
      maxRetries: config.maxRetries ?? 3,
      maxStepsPerTask: config.maxStepsPerTask ?? 20,
      stepTimeout: config.stepTimeout ?? 30000,
      usePatternCache: config.usePatternCache ?? true,
      preferLocalModels: config.preferLocalModels ?? true,
      autoVerify: config.autoVerify ?? true,
      autoRecover: config.autoRecover ?? true
    };

    // Initialize components
    this.contextManager = new ContextManager({
      summarizeModel: 'tinydolphin:1.1b'
    });

    this.constrainedOutput = new ConstrainedOutput({
      model: this.config.defaultModel,
      maxRetries: this.config.maxRetries
    });

    this.verifier = new Verifier();
    this.recoveryHandler = new RecoveryHandler();

    this.orchestrator = new Orchestrator({
      maxRetries: this.config.maxRetries,
      maxStepsPerTask: this.config.maxStepsPerTask,
      stepTimeout: this.config.stepTimeout,
      model: this.config.defaultModel,
      onStateChange: (task) => this.handleTaskStateChange(task),
      onStepComplete: (step, task) => this.handleStepComplete(step, task),
      onUserInput: (q) => this.handleUserInputRequest(q)
    });

    this.modelRouter = new ModelRouter();
    this.patternCache = new PatternCache();

    // Initialize state
    this.messages = ref([]);
    this.currentModel = ref(this.config.defaultModel);
    this.isProcessing = ref(false);
    this.currentTask = ref(null);
    this.stats = {
      tasksCompleted: 0,
      tasksFailed: 0,
      actionsExecuted: 0,
      patternsUsed: 0,
      rollbacks: 0,
      avgResponseTime: 0
    };

    // Load pattern cache
    this.patternCache.load();
  }

  /**
   * Process a user message/request
   */
  async process(input: string): Promise<string> {
    const startTime = Date.now();
    this.isProcessing.value = true;

    // Add user message
    this.addMessage({
      role: 'user',
      content: input
    });

    try {
      // Route to appropriate model
      const routing = await this.modelRouter.route(input, {
        preferLocal: this.config.preferLocalModels
      });

      this.currentModel.value = routing.model;
      this.addMessage({
        role: 'system',
        content: `Using model: ${routing.model} (${routing.reason})`
      });

      // Check for pattern matches first
      if (this.config.usePatternCache) {
        const matches = this.patternCache.findMatches(input);
        if (matches.length > 0 && matches[0].confidence > 0.7) {
          const result = await this.usePattern(matches[0], input);
          if (result) {
            this.updateStats(startTime, true);
            return result;
          }
        }
      }

      // Create and execute task
      const task = this.orchestrator.createTask(input);
      this.currentTask.value = task;

      await this.orchestrator.start();

      // Get result
      const result = task.result || 'Task completed';

      this.addMessage({
        role: 'assistant',
        content: result
      });

      this.updateStats(startTime, task.state === 'completed');
      return result;

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      this.addMessage({
        role: 'system',
        content: `Error: ${errorMsg}`
      });

      this.updateStats(startTime, false);
      throw error;

    } finally {
      this.isProcessing.value = false;
      this.currentTask.value = null;
    }
  }

  /**
   * Execute a single action directly
   */
  async executeAction(action: AgentAction): Promise<string> {
    // Verify if enabled
    if (this.config.autoVerify) {
      const verification = await this.verifier.verify(action);

      if (!verification.valid) {
        throw new Error(`Verification failed: ${verification.errors.join(', ')}`);
      }

      if (verification.warnings.length > 0) {
        this.addMessage({
          role: 'system',
          content: `Warnings: ${verification.warnings.join(', ')}`
        });
      }
    }

    // Execute with recovery if enabled
    if (this.config.autoRecover) {
      const result = await this.recoveryHandler.executeWithRecovery(
        action,
        (a) => this.runAction(a),
        this.contextManager.getState()
      );

      if (!result.success) {
        this.stats.rollbacks++;
        throw new Error(result.error);
      }

      this.stats.actionsExecuted++;
      return result.output || 'Success';
    }

    // Direct execution
    const result = await this.runAction(action);
    this.stats.actionsExecuted++;
    return result;
  }

  /**
   * Run an action (internal implementation)
   */
  private async runAction(action: AgentAction): Promise<string> {
    switch (action.action) {
      case 'read':
        return await invoke<string>('read_file', { path: action.path });

      case 'write':
        await invoke<void>('write_file', {
          path: action.path,
          content: action.content
        });
        return `Created/updated ${action.path}`;

      case 'edit':
        const content = await invoke<string>('read_file', { path: action.path });
        if (!content.includes(action.oldContent || '')) {
          throw new Error(`Could not find text to replace in ${action.path}`);
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
        return files.join('\n') || 'No matches found';

      case 'think':
        await this.contextManager.addMessage({
          role: 'assistant',
          content: action.thought || '',
          timestamp: Date.now()
        });
        return action.thought || '';

      case 'done':
        return action.content || 'Done';

      case 'ask':
        if (this.onUserInput) {
          return await this.onUserInput(action.question || '');
        }
        throw new Error('No user input handler configured');

      default:
        throw new Error(`Unknown action: ${action.action}`);
    }
  }

  /**
   * Use a cached pattern
   */
  private async usePattern(match: PatternMatch, input: string): Promise<string | null> {
    try {
      // Fill template
      const code = this.patternCache.fillTemplate(match.pattern, match.extractedVars);

      // Check if there are unfilled variables
      if (code.includes('/* TODO:')) {
        // Need LLM help to fill remaining
        return null;
      }

      this.addMessage({
        role: 'assistant',
        content: `Using pattern: ${match.pattern.name}\n\n\`\`\`${match.pattern.language}\n${code}\n\`\`\``,
        patternUsed: match.pattern.id
      });

      this.patternCache.recordUsage(match.pattern.id, true, {
        input: match.extractedVars,
        output: code,
        wasAccepted: true
      });

      this.stats.patternsUsed++;
      return code;

    } catch (e) {
      return null;
    }
  }

  /**
   * Handle task state changes
   */
  private handleTaskStateChange(task: Task): void {
    this.currentTask.value = task;
    this.onStateChange?.(task.state);

    if (task.state === 'completed') {
      this.stats.tasksCompleted++;
    } else if (task.state === 'failed') {
      this.stats.tasksFailed++;
    }
  }

  /**
   * Handle step completion
   */
  private handleStepComplete(step: any, task: Task): void {
    if (step.action) {
      this.addMessage({
        role: 'action',
        content: `${step.action.action}: ${step.output?.slice(0, 200) || 'Success'}`,
        action: step.action
      });
    }
  }

  /**
   * Handle user input request
   */
  private async handleUserInputRequest(question: string): Promise<string> {
    if (this.onUserInput) {
      return await this.onUserInput(question);
    }

    this.addMessage({
      role: 'system',
      content: `Agent is asking: ${question}`
    });

    return '';
  }

  /**
   * Add a message to history
   */
  private addMessage(msg: Omit<AgentMessage, 'id' | 'timestamp'>): void {
    const message: AgentMessage = {
      id: `msg_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      timestamp: Date.now(),
      ...msg
    };

    this.messages.value.push(message);
    this.onMessage?.(message);
  }

  /**
   * Update statistics
   */
  private updateStats(startTime: number, success: boolean): void {
    const responseTime = Date.now() - startTime;
    const totalResponses = this.stats.tasksCompleted + this.stats.tasksFailed + 1;

    this.stats.avgResponseTime =
      (this.stats.avgResponseTime * (totalResponses - 1) + responseTime) / totalResponses;

    if (success) {
      this.stats.tasksCompleted++;
    } else {
      this.stats.tasksFailed++;
    }
  }

  // Public API

  /**
   * Set event callbacks
   */
  setCallbacks(callbacks: {
    onMessage?: (message: AgentMessage) => void;
    onStateChange?: (state: TaskState) => void;
    onUserInput?: (question: string) => Promise<string>;
  }): void {
    this.onMessage = callbacks.onMessage;
    this.onStateChange = callbacks.onStateChange;
    this.onUserInput = callbacks.onUserInput;
  }

  /**
   * Get message history
   */
  getMessages(): AgentMessage[] {
    return this.messages.value;
  }

  /**
   * Clear message history
   */
  clearMessages(): void {
    this.messages.value = [];
    this.contextManager.clear();
  }

  /**
   * Get current state
   */
  getState(): {
    isProcessing: boolean;
    currentModel: string;
    currentTask: Task | null;
    stats: AgentStats;
  } {
    return {
      isProcessing: this.isProcessing.value,
      currentModel: this.currentModel.value,
      currentTask: this.currentTask.value,
      stats: { ...this.stats }
    };
  }

  /**
   * Pause execution
   */
  pause(): void {
    this.orchestrator.pause();
  }

  /**
   * Resume execution
   */
  async resume(): Promise<void> {
    await this.orchestrator.resume();
  }

  /**
   * Stop execution
   */
  stop(): void {
    this.orchestrator.stop();
  }

  /**
   * Undo last action
   */
  async undo(): Promise<{ success: boolean; message: string }> {
    const result = await this.recoveryHandler.undoLast();

    if (result.success) {
      this.addMessage({
        role: 'system',
        content: `Undid: ${result.action?.action}`
      });
      return { success: true, message: `Undid ${result.action?.action}` };
    }

    return { success: false, message: result.error || 'Nothing to undo' };
  }

  /**
   * Get recovery history
   */
  getHistory(): ActionRecord[] {
    return this.recoveryHandler.getHistory();
  }

  /**
   * Get available models
   */
  async getAvailableModels(): Promise<string[]> {
    return await this.modelRouter.getAvailableModels();
  }

  /**
   * Set current model
   */
  setModel(model: string): void {
    this.currentModel.value = model;
    this.config.defaultModel = model;
  }

  /**
   * Learn a new pattern from code
   */
  learnPattern(
    code: string,
    description: string,
    language: string,
    tags: string[]
  ): CodePattern | null {
    return this.patternCache.learnPattern(code, description, language, tags);
  }

  /**
   * Get pattern cache stats
   */
  getPatternStats() {
    return this.patternCache.getStats();
  }

  /**
   * Save state (patterns, etc.)
   */
  async save(): Promise<void> {
    await this.patternCache.save();
  }
}

// Vue composable wrapper
export function useScaffoldedAgent(config?: Partial<AgentConfig>) {
  const agent = new ScaffoldedAgent(config);

  const messages = ref<AgentMessage[]>([]);
  const isProcessing = ref(false);
  const currentTask = ref<Task | null>(null);
  const error = ref<string | null>(null);

  agent.setCallbacks({
    onMessage: (msg) => {
      messages.value = [...agent.getMessages()];
    },
    onStateChange: (state) => {
      currentTask.value = agent.getState().currentTask;
    }
  });

  async function send(input: string): Promise<string> {
    isProcessing.value = true;
    error.value = null;

    try {
      const result = await agent.process(input);
      return result;
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Unknown error';
      throw e;
    } finally {
      isProcessing.value = false;
      messages.value = [...agent.getMessages()];
    }
  }

  return {
    agent,
    messages: computed(() => messages.value),
    isProcessing: computed(() => isProcessing.value),
    currentTask: computed(() => currentTask.value),
    error: computed(() => error.value),
    send,
    pause: () => agent.pause(),
    resume: () => agent.resume(),
    stop: () => agent.stop(),
    undo: () => agent.undo(),
    clear: () => {
      agent.clearMessages();
      messages.value = [];
    },
    setModel: (model: string) => agent.setModel(model),
    getStats: () => agent.getState().stats
  };
}

export default ScaffoldedAgent;
