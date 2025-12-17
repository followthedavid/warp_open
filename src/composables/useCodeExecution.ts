/**
 * Code Execution Composable
 * Enables conversational AI to execute code and tasks
 * Similar to Claude Code or Warp Terminal
 */

import { ref } from 'vue';
import { v4 as uuidv4 } from 'uuid';

export interface ExecutionStep {
  id: string;
  type: 'thinking' | 'file_read' | 'file_write' | 'command' | 'result';
  title: string;
  content: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  timestamp: Date;
  error?: string;
}

export interface ExecutionTask {
  id: string;
  messageId: string;
  description: string;
  steps: ExecutionStep[];
  status: 'pending' | 'running' | 'completed' | 'failed';
  createdAt: Date;
  completedAt?: Date;
}

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;
type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

const activeTasks = ref<Map<string, ExecutionTask>>(new Map());

export function useCodeExecution() {
  /**
   * Parse user message to identify actionable tasks
   */
  async function parseTaskFromMessage(message: string): Promise<string | null> {
    // Use Ollama to determine if this is an actionable request
    const analysisPrompt = `Analyze this user message and determine if it's requesting code changes, file operations, or terminal commands:

User message: "${message}"

Response format (JSON only):
{
  "isActionable": true/false,
  "taskDescription": "brief description of what to do",
  "taskType": "code_change" | "file_operation" | "terminal_command" | "conversation"
}

Rules:
- "isActionable" is true if the user wants you to DO something (create, modify, delete, run, etc.)
- "isActionable" is false if they're just asking a question or having a conversation
- Be conservative - only mark as actionable if it's clear they want action

JSON only:`;

    try {
      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'deepseek-coder:6.7b',
          prompt: analysisPrompt,
          stream: false,
        }),
      });

      if (!response.ok) return null;

      const data = await response.json();
      const parsed = JSON.parse(data.response);

      if (parsed.isActionable && parsed.taskType !== 'conversation') {
        return parsed.taskDescription;
      }
      return null;
    } catch (error) {
      console.error('[CodeExecution] Failed to parse task:', error);
      return null;
    }
  }

  /**
   * Generate execution plan for a task
   */
  async function generateExecutionPlan(taskDescription: string): Promise<ExecutionStep[]> {
    const planPrompt = `You are a coding assistant. Generate a step-by-step execution plan for this task:

Task: ${taskDescription}

Generate an array of steps. Each step should have:
- type: "thinking" | "file_read" | "file_write" | "command"
- title: Brief description (e.g., "Read main.ts", "Update function", "Run tests")
- content: Detailed content (file path, code, or command)

Output JSON array only:
[
  { "type": "file_read", "title": "Read existing file", "content": "src/App.vue" },
  { "type": "thinking", "title": "Analyze current code", "content": "Identifying where to add the feature..." },
  { "type": "file_write", "title": "Update component", "content": "src/Component.vue\\n\\n<code here>" },
  { "type": "command", "title": "Run tests", "content": "npm test" }
]

JSON only:`;

    try {
      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'deepseek-coder:6.7b',
          prompt: planPrompt,
          stream: false,
        }),
      });

      if (!response.ok) throw new Error('Ollama request failed');

      const data = await response.json();
      const stepData = JSON.parse(data.response);

      interface StepData {
        type: ExecutionStep['type'];
        title: string;
        content: string;
      }
      return (stepData as StepData[]).map((s) => ({
        id: uuidv4(),
        type: s.type,
        title: s.title,
        content: s.content,
        status: 'pending' as const,
        timestamp: new Date(),
      }));
    } catch (error) {
      console.error('[CodeExecution] Failed to generate plan:', error);
      return [];
    }
  }

  /**
   * Execute a single step
   */
  async function executeStep(step: ExecutionStep): Promise<void> {
    step.status = 'running';

    try {
      switch (step.type) {
        case 'thinking':
          // Simulate thinking delay
          await new Promise(resolve => setTimeout(resolve, 1000));
          step.status = 'completed';
          break;

        case 'file_read':
          if (isTauri && invoke) {
            const content = await invoke('read_file', { path: step.content });
            step.content = `File: ${step.content}\n\n${content}`;
          } else {
            // Browser mode - can't read files
            step.content = `[Browser mode] Cannot read file: ${step.content}`;
          }
          step.status = 'completed';
          break;

        case 'file_write':
          if (isTauri && invoke) {
            const [path, ...contentParts] = step.content.split('\n\n');
            const fileContent = contentParts.join('\n\n');
            await invoke('write_file', { path, content: fileContent });
            step.content = `✓ Wrote to ${path}`;
          } else {
            step.content = `[Browser mode] Cannot write file: ${step.content.split('\n')[0]}`;
          }
          step.status = 'completed';
          break;

        case 'command':
          if (isTauri && invoke) {
            const output = await invoke('execute_command', { command: step.content });
            step.content = `$ ${step.content}\n\n${output}`;
          } else {
            step.content = `[Browser mode] Cannot execute: ${step.content}`;
          }
          step.status = 'completed';
          break;

        default:
          step.status = 'completed';
      }
    } catch (error) {
      step.status = 'failed';
      step.error = String(error);
    }
  }

  /**
   * Execute a task with all its steps
   */
  async function executeTask(
    messageId: string,
    taskDescription: string,
    onStepUpdate?: (steps: ExecutionStep[]) => void
  ): Promise<ExecutionTask> {
    const task: ExecutionTask = {
      id: uuidv4(),
      messageId,
      description: taskDescription,
      steps: [],
      status: 'running',
      createdAt: new Date(),
    };

    activeTasks.value.set(task.id, task);

    // Generate plan
    const steps = await generateExecutionPlan(taskDescription);
    task.steps = steps;

    if (onStepUpdate) onStepUpdate(steps);

    // Execute each step
    for (const step of steps) {
      await executeStep(step);
      if (onStepUpdate) onStepUpdate([...steps]); // Trigger update
    }

    // Mark task as completed
    task.status = 'completed';
    task.completedAt = new Date();

    return task;
  }

  /**
   * Get summary of execution results
   */
  function getTaskSummary(task: ExecutionTask): string {
    const completed = task.steps.filter(s => s.status === 'completed').length;
    const failed = task.steps.filter(s => s.status === 'failed').length;

    let summary = `Task: ${task.description}\n\n`;
    summary += `Status: ${task.status}\n`;
    summary += `Steps: ${completed}/${task.steps.length} completed`;

    if (failed > 0) {
      summary += `, ${failed} failed`;
    }

    summary += '\n\nSteps:\n';
    task.steps.forEach((step, idx) => {
      const icon = step.status === 'completed' ? '✓' :
                   step.status === 'failed' ? '✗' :
                   step.status === 'running' ? '⟳' : '○';
      summary += `${idx + 1}. ${icon} ${step.title}\n`;
    });

    return summary;
  }

  return {
    parseTaskFromMessage,
    generateExecutionPlan,
    executeTask,
    getTaskSummary,
    activeTasks,
  };
}
