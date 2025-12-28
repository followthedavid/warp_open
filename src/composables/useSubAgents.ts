/**
 * Sub-agents System
 * Spawn specialized agents for task delegation, similar to Claude Code's Task() function.
 * Each sub-agent runs in its own context and returns results to the parent.
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

export type SubAgentType =
  | 'explore'      // Explore codebase, find files
  | 'review'       // Code review
  | 'test'         // Generate/run tests
  | 'document'     // Generate documentation
  | 'refactor'     // Refactor code
  | 'debug'        // Debug issues
  | 'research'     // Research/web search
  | 'plan'         // Create plans
  | 'custom';      // Custom agent

export interface SubAgentConfig {
  type: SubAgentType;
  name: string;
  description: string;
  systemPrompt: string;
  tools: string[];           // Allowed tools for this agent
  maxIterations: number;
  timeout: number;           // ms
  model?: string;            // Override default model
}

export interface SubAgentTask {
  id: string;
  agentType: SubAgentType;
  prompt: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  result?: string;
  error?: string;
  startedAt?: number;
  completedAt?: number;
  iterations: number;
  toolCalls: Array<{
    tool: string;
    args: Record<string, unknown>;
    result: string;
  }>;
  parentTaskId?: string;     // For nested sub-agents
}

export interface SubAgentResult {
  success: boolean;
  result: string;
  toolCalls: SubAgentTask['toolCalls'];
  iterations: number;
  duration: number;
}

// Built-in agent configurations
const BUILTIN_AGENTS: Record<SubAgentType, SubAgentConfig> = {
  explore: {
    type: 'explore',
    name: 'Explorer',
    description: 'Explores codebase to find relevant files and understand structure',
    systemPrompt: `You are a codebase explorer. Your job is to find relevant files and understand code structure.

Available tools: glob_files, grep_files, read_file

When exploring:
1. Start with glob_files to find files matching patterns
2. Use grep_files to search for specific code patterns
3. Use read_file to examine important files

Return a summary of what you found, including:
- Relevant files discovered
- Code patterns identified
- Suggested areas to focus on`,
    tools: ['glob_files', 'grep_files', 'read_file'],
    maxIterations: 10,
    timeout: 60000,
  },
  review: {
    type: 'review',
    name: 'Code Reviewer',
    description: 'Reviews code for bugs, security issues, and best practices',
    systemPrompt: `You are a code reviewer. Analyze code for:
- Bugs and logic errors
- Security vulnerabilities
- Performance issues
- Code style and best practices
- Missing error handling

Available tools: read_file, grep_files

Provide specific, actionable feedback with line numbers when possible.`,
    tools: ['read_file', 'grep_files'],
    maxIterations: 5,
    timeout: 45000,
  },
  test: {
    type: 'test',
    name: 'Test Generator',
    description: 'Generates and runs tests for code',
    systemPrompt: `You are a test engineer. Your job is to:
1. Understand the code being tested
2. Generate comprehensive test cases
3. Include edge cases and error scenarios

Available tools: read_file, write_file, execute_shell

Generate tests appropriate for the language/framework being used.`,
    tools: ['read_file', 'write_file', 'execute_shell'],
    maxIterations: 8,
    timeout: 90000,
  },
  document: {
    type: 'document',
    name: 'Documentation Writer',
    description: 'Generates documentation for code',
    systemPrompt: `You are a documentation writer. Generate:
- Function/method documentation
- Module/file documentation
- README content
- API documentation

Available tools: read_file, write_file, edit_file

Write clear, concise documentation that helps developers understand the code.`,
    tools: ['read_file', 'write_file', 'edit_file'],
    maxIterations: 6,
    timeout: 60000,
  },
  refactor: {
    type: 'refactor',
    name: 'Refactoring Agent',
    description: 'Refactors code for better quality',
    systemPrompt: `You are a refactoring specialist. Improve code by:
- Extracting functions/methods
- Simplifying complex logic
- Removing duplication
- Improving naming
- Applying design patterns

Available tools: read_file, edit_file, grep_files

Make incremental, safe changes. Preserve functionality.`,
    tools: ['read_file', 'edit_file', 'grep_files'],
    maxIterations: 10,
    timeout: 120000,
  },
  debug: {
    type: 'debug',
    name: 'Debugger',
    description: 'Debugs issues and finds root causes',
    systemPrompt: `You are a debugging expert. To debug:
1. Understand the error/symptom
2. Form hypotheses about the cause
3. Gather evidence through code inspection
4. Narrow down to root cause
5. Suggest fixes

Available tools: read_file, grep_files, execute_shell

Be systematic and thorough in your investigation.`,
    tools: ['read_file', 'grep_files', 'execute_shell'],
    maxIterations: 12,
    timeout: 90000,
  },
  research: {
    type: 'research',
    name: 'Researcher',
    description: 'Researches topics and gathers information',
    systemPrompt: `You are a research assistant. Gather information by:
1. Searching the web for relevant documentation
2. Finding examples and best practices
3. Comparing approaches

Available tools: web_fetch, execute_shell

Summarize findings clearly with sources.`,
    tools: ['web_fetch', 'execute_shell'],
    maxIterations: 8,
    timeout: 120000,
  },
  plan: {
    type: 'plan',
    name: 'Planner',
    description: 'Creates implementation plans',
    systemPrompt: `You are a planning agent. Create detailed plans that include:
1. Clear, actionable steps
2. Dependencies between steps
3. Potential challenges
4. Success criteria

Available tools: glob_files, grep_files, read_file

Understand the codebase before planning.`,
    tools: ['glob_files', 'grep_files', 'read_file'],
    maxIterations: 6,
    timeout: 60000,
  },
  custom: {
    type: 'custom',
    name: 'Custom Agent',
    description: 'Custom agent with user-defined configuration',
    systemPrompt: '',
    tools: [],
    maxIterations: 10,
    timeout: 60000,
  },
};

// State
const activeTasks = ref<Map<string, SubAgentTask>>(new Map());
const completedTasks = ref<SubAgentTask[]>([]);
const customAgents = ref<Map<string, SubAgentConfig>>(new Map());

function generateTaskId(): string {
  return `task_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function useSubAgents() {
  const runningTasks = computed(() =>
    Array.from(activeTasks.value.values()).filter(t => t.status === 'running')
  );

  const pendingTasks = computed(() =>
    Array.from(activeTasks.value.values()).filter(t => t.status === 'pending')
  );

  /**
   * Get agent configuration
   */
  function getAgentConfig(type: SubAgentType): SubAgentConfig {
    return customAgents.value.get(type) || BUILTIN_AGENTS[type];
  }

  /**
   * Register a custom agent
   */
  function registerCustomAgent(config: SubAgentConfig): void {
    customAgents.value.set(config.type, config);
  }

  /**
   * Spawn a sub-agent task
   */
  async function spawnSubAgent(
    type: SubAgentType,
    prompt: string,
    options?: {
      parentTaskId?: string;
      customConfig?: Partial<SubAgentConfig>;
      context?: string;
    }
  ): Promise<SubAgentResult> {
    const config = {
      ...getAgentConfig(type),
      ...options?.customConfig,
    };

    const task: SubAgentTask = {
      id: generateTaskId(),
      agentType: type,
      prompt,
      status: 'pending',
      iterations: 0,
      toolCalls: [],
      parentTaskId: options?.parentTaskId,
    };

    activeTasks.value.set(task.id, task);

    try {
      task.status = 'running';
      task.startedAt = Date.now();

      const result = await executeSubAgent(task, config, options?.context);

      task.status = 'completed';
      task.result = result.result;
      task.completedAt = Date.now();
      task.iterations = result.iterations;
      task.toolCalls = result.toolCalls;

      // Move to completed
      activeTasks.value.delete(task.id);
      completedTasks.value.push(task);

      // Limit completed tasks history
      if (completedTasks.value.length > 100) {
        completedTasks.value = completedTasks.value.slice(-100);
      }

      return result;
    } catch (error) {
      task.status = 'failed';
      task.error = error instanceof Error ? error.message : String(error);
      task.completedAt = Date.now();

      activeTasks.value.delete(task.id);
      completedTasks.value.push(task);

      return {
        success: false,
        result: task.error,
        toolCalls: task.toolCalls,
        iterations: task.iterations,
        duration: (task.completedAt || Date.now()) - (task.startedAt || Date.now()),
      };
    }
  }

  /**
   * Execute sub-agent loop
   */
  async function executeSubAgent(
    task: SubAgentTask,
    config: SubAgentConfig,
    context?: string
  ): Promise<SubAgentResult> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const startTime = Date.now();
    let currentResponse = '';
    const toolCalls: SubAgentTask['toolCalls'] = [];

    // Build system prompt
    const systemPrompt = `${config.systemPrompt}

${context ? `Context:\n${context}\n` : ''}

IMPORTANT:
- You have ${config.maxIterations} iterations maximum
- Available tools: ${config.tools.join(', ')}
- Respond with JSON tool calls when you need to use tools
- When done, provide your final answer without tool calls`;

    // Build initial messages
    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: task.prompt },
    ];

    for (let i = 0; i < config.maxIterations; i++) {
      // Check timeout
      if (Date.now() - startTime > config.timeout) {
        break;
      }

      task.iterations = i + 1;

      try {
        // Query Ollama
        const response = await invoke<string>('query_ollama', {
          model: config.model || 'qwen2.5-coder:1.5b',
          prompt: messages.map(m => `${m.role}: ${m.content}`).join('\n\n'),
        });

        currentResponse = response;

        // Check for tool call
        const toolMatch = response.match(/\{[\s\S]*?"tool"[\s\S]*?\}/);
        if (toolMatch) {
          try {
            const toolCall = JSON.parse(toolMatch[0]);
            const toolName = toolCall.tool;
            const toolArgs = toolCall.args || {};

            // Verify tool is allowed
            if (!config.tools.includes(toolName)) {
              messages.push({
                role: 'assistant',
                content: response,
              });
              messages.push({
                role: 'user',
                content: `Tool "${toolName}" is not available. Available tools: ${config.tools.join(', ')}`,
              });
              continue;
            }

            // Execute tool
            const toolResult = await executeToolForSubAgent(toolName, toolArgs);

            toolCalls.push({
              tool: toolName,
              args: toolArgs,
              result: toolResult,
            });

            messages.push({
              role: 'assistant',
              content: response,
            });
            messages.push({
              role: 'user',
              content: `[Tool Result]\n${toolResult}`,
            });
          } catch (parseError) {
            // Couldn't parse tool call, treat as final response
            break;
          }
        } else {
          // No tool call - this is the final response
          break;
        }
      } catch (error) {
        console.error('[SubAgents] Query error:', error);
        break;
      }
    }

    return {
      success: true,
      result: currentResponse,
      toolCalls,
      iterations: task.iterations,
      duration: Date.now() - startTime,
    };
  }

  /**
   * Execute a tool for sub-agent
   */
  async function executeToolForSubAgent(
    tool: string,
    args: Record<string, unknown>
  ): Promise<string> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    try {
      switch (tool) {
        case 'glob_files':
          const globResult = await invoke<Array<{ path: string }>>('glob_files', args);
          return globResult.map(f => f.path).join('\n');

        case 'grep_files':
          const grepResult = await invoke<Array<{ path: string; line: number; content: string }>>('grep_files', args);
          return grepResult.map(r => `${r.path}:${r.line}: ${r.content}`).join('\n');

        case 'read_file':
          return await invoke<string>('read_file', args);

        case 'write_file':
          return await invoke<string>('write_file', args);

        case 'edit_file':
          const editResult = await invoke<{ success: boolean; message: string }>('edit_file', args);
          return editResult.message;

        case 'execute_shell':
          return await invoke<string>('execute_shell', args);

        case 'web_fetch':
          return await invoke<string>('web_fetch', args);

        default:
          return `Unknown tool: ${tool}`;
      }
    } catch (error) {
      return `Tool error: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  /**
   * Cancel a running task
   */
  function cancelTask(taskId: string): boolean {
    const task = activeTasks.value.get(taskId);
    if (task && task.status === 'running') {
      task.status = 'cancelled';
      task.completedAt = Date.now();
      activeTasks.value.delete(taskId);
      completedTasks.value.push(task);
      return true;
    }
    return false;
  }

  /**
   * Get task by ID
   */
  function getTask(taskId: string): SubAgentTask | undefined {
    return activeTasks.value.get(taskId) ||
           completedTasks.value.find(t => t.id === taskId);
  }

  /**
   * Get all tasks (active and completed)
   */
  function getAllTasks(): SubAgentTask[] {
    return [
      ...Array.from(activeTasks.value.values()),
      ...completedTasks.value,
    ];
  }

  /**
   * Clear completed tasks
   */
  function clearCompletedTasks(): void {
    completedTasks.value = [];
  }

  /**
   * Quick spawn helpers
   */
  async function explore(prompt: string, context?: string): Promise<SubAgentResult> {
    return spawnSubAgent('explore', prompt, { context });
  }

  async function review(filePath: string): Promise<SubAgentResult> {
    return spawnSubAgent('review', `Review the code in ${filePath} for issues, bugs, and improvements.`);
  }

  async function generateTests(filePath: string): Promise<SubAgentResult> {
    return spawnSubAgent('test', `Generate comprehensive tests for ${filePath}`);
  }

  async function document(filePath: string): Promise<SubAgentResult> {
    return spawnSubAgent('document', `Generate documentation for ${filePath}`);
  }

  async function debug(issue: string, context?: string): Promise<SubAgentResult> {
    return spawnSubAgent('debug', `Debug this issue: ${issue}`, { context });
  }

  async function research(topic: string): Promise<SubAgentResult> {
    return spawnSubAgent('research', `Research: ${topic}`);
  }

  return {
    // State
    activeTasks: computed(() => Array.from(activeTasks.value.values())),
    completedTasks: computed(() => completedTasks.value),
    runningTasks,
    pendingTasks,

    // Agent management
    getAgentConfig,
    registerCustomAgent,
    builtinAgents: BUILTIN_AGENTS,

    // Task management
    spawnSubAgent,
    cancelTask,
    getTask,
    getAllTasks,
    clearCompletedTasks,

    // Quick helpers
    explore,
    review,
    generateTests,
    document,
    debug,
    research,
  };
}
