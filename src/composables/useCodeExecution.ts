/**
 * Code Execution Composable
 * Enables conversational AI to execute code and tasks
 * Similar to Claude Code or Warp Terminal
 *
 * Enhanced with:
 * - Rule-based fast paths (bypass LLM for common commands)
 * - Confidence scoring for auto-execution
 * - Pattern learning from successful executions
 * - Output validation and safety checks
 */

import { ref } from 'vue';
import { v4 as uuidv4 } from 'uuid';
import { useSmartCommands } from './useSmartCommands';
import { useErrorRecovery } from './useErrorRecovery';
import {
  TASK_ANALYSIS_PROMPT,
  COMMAND_GEN_PROMPT,
  MULTI_STEP_PROMPT,
  applyTemplate,
  extractJSON as extractJSONFromPrompts,
  validateCommandOutput,
  detectIntent,
  getPromptForIntent
} from './usePromptTemplates';

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
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;
type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;
let invokeReady: Promise<void> | null = null;

if (isTauri) {
  console.log('[CodeExecution] Tauri detected, importing invoke...');
  invokeReady = import('@tauri-apps/api/tauri').then(async module => {
    invoke = module.invoke as InvokeFn;
    console.log('[CodeExecution] ✅ Tauri invoke loaded successfully');

    // AUTO-TEST: Run self-test on startup and write results to file
    try {
      const testResult = await invoke<string>('execute_shell', {
        command: 'echo "=== CODE EXECUTION SELF-TEST ===" && echo "Timestamp: $(date)" && echo "Status: SUCCESS - execute_shell works!" && pwd'
      });
      console.log('[CodeExecution] ✅ SELF-TEST PASSED:', testResult);
      // Write test results to a file we can check
      await invoke<string>('execute_shell', {
        command: `echo '${JSON.stringify({ success: true, timestamp: new Date().toISOString(), output: testResult.substring(0, 200) })}' > /tmp/warp_code_execution_test.json`
      });
    } catch (e) {
      console.error('[CodeExecution] ❌ SELF-TEST FAILED:', e);
      await invoke<string>('execute_shell', {
        command: `echo '${JSON.stringify({ success: false, error: String(e) })}' > /tmp/warp_code_execution_test.json`
      }).catch(() => {});
    }
  }).catch(err => {
    console.error('[CodeExecution] ❌ Failed to load Tauri invoke:', err);
  });
} else {
  console.log('[CodeExecution] Not running in Tauri environment');
}

// Helper to ensure invoke is ready
async function getInvoke(): Promise<InvokeFn | null> {
  if (invokeReady) await invokeReady;
  return invoke;
}

const activeTasks = ref<Map<string, ExecutionTask>>(new Map());

/**
 * Extract JSON from LLM response (handles markdown code blocks)
 */
function extractJSON(response: string): string {
  // Try to find JSON in code blocks first
  const codeBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (codeBlockMatch) {
    return codeBlockMatch[1].trim();
  }

  // Try to find raw JSON array or object
  const jsonMatch = response.match(/(\[[\s\S]*\]|\{[\s\S]*\})/);
  if (jsonMatch) {
    return jsonMatch[1].trim();
  }

  // Return as-is and let JSON.parse fail with a clear error
  return response.trim();
}

/**
 * Validate and auto-correct LLM output for command execution
 * Fixes common LLM mistakes to make small models more reliable
 */
function validateAndCorrectCommand(stepData: any[]): any[] {
  const VALID_COMMANDS = new Set([
    'ls', 'pwd', 'cd', 'cat', 'echo', 'mkdir', 'rm', 'cp', 'mv', 'grep', 'find',
    'date', 'df', 'du', 'ps', 'top', 'npm', 'node', 'python', 'python3', 'git',
    'curl', 'wget', 'touch', 'chmod', 'head', 'tail', 'wc', 'sort', 'uniq',
    'tar', 'zip', 'unzip', 'ssh', 'scp', 'rsync', 'docker', 'kubectl', 'brew',
    'pip', 'pip3', 'cargo', 'rustc', 'go', 'make', 'cmake', 'which', 'whereis',
    'whoami', 'hostname', 'uname', 'uptime', 'free', 'ifconfig', 'ip', 'ping',
    'netstat', 'lsof', 'kill', 'pkill', 'pgrep', 'tree', 'less', 'more', 'vim',
    'nano', 'sed', 'awk', 'xargs', 'tee', 'env', 'export', 'source', 'bash', 'sh', 'zsh'
  ]);

  const COMMAND_CORRECTIONS: Record<string, string> = {
    'list': 'ls -la',
    'list files': 'ls -la',
    'show files': 'ls -la',
    'directory': 'pwd',
    'current directory': 'pwd',
    'where am i': 'pwd',
    'disk': 'df -h',
    'disk space': 'df -h',
    'memory': 'free -h 2>/dev/null || vm_stat',
    'processes': 'ps aux | head -20',
    'running': 'ps aux | head -20',
    'create': 'touch',
    'make': 'mkdir -p',
    'delete': 'rm',
    'remove': 'rm',
    'copy': 'cp',
    'move': 'mv',
    'read': 'cat',
    'show': 'cat',
    'view': 'cat',
    'search': 'grep -r',
    'find file': 'find . -name',
  };

  return stepData.map(step => {
    if (step.type !== 'command' || !step.content) return step;

    let cmd = step.content.trim();
    const firstWord = cmd.split(/\s+/)[0].toLowerCase();

    // Check if it's already a valid command
    if (VALID_COMMANDS.has(firstWord) || firstWord.startsWith('./') || firstWord.startsWith('/')) {
      return step;
    }

    // Try to correct common LLM mistakes
    const lowerCmd = cmd.toLowerCase();

    // Direct corrections
    if (COMMAND_CORRECTIONS[lowerCmd]) {
      console.log(`[Validator] Corrected "${cmd}" -> "${COMMAND_CORRECTIONS[lowerCmd]}"`);
      return { ...step, content: COMMAND_CORRECTIONS[lowerCmd] };
    }

    // Pattern-based corrections
    for (const [pattern, replacement] of Object.entries(COMMAND_CORRECTIONS)) {
      if (lowerCmd.startsWith(pattern + ' ') || lowerCmd === pattern) {
        const args = cmd.substring(pattern.length).trim();
        const corrected = args ? `${replacement} ${args}` : replacement;
        console.log(`[Validator] Pattern corrected "${cmd}" -> "${corrected}"`);
        return { ...step, content: corrected };
      }
    }

    // If command starts with natural language, try to extract intent
    if (lowerCmd.startsWith('create ')) {
      const target = cmd.substring(7).trim();
      if (target.includes('/') || target.includes('.')) {
        return { ...step, content: `touch "${target}"` };
      }
      return { ...step, content: `mkdir -p "${target}"` };
    }

    if (lowerCmd.startsWith('show ') || lowerCmd.startsWith('display ')) {
      const target = cmd.replace(/^(show|display)\s+/i, '').trim();
      return { ...step, content: `cat "${target}"` };
    }

    // Log unknown command for debugging
    console.warn(`[Validator] Unknown command: "${cmd}" - passing through`);
    return step;
  });
}

export function useCodeExecution() {
  /**
   * Parse user message to identify actionable tasks
   * Uses fast intent detection first, falls back to LLM only when needed
   */
  async function parseTaskFromMessage(message: string): Promise<string | null> {
    // FAST PATH: Use keyword-based intent detection first
    const intent = detectIntent(message);

    // If it's clearly a question or chat, skip LLM entirely
    if (intent === 'QUESTION' || intent === 'CHAT') {
      console.log('[CodeExecution] Fast path: non-actionable intent:', intent);
      return null;
    }

    // If it's clearly an actionable intent with simple command, return it directly
    if (intent === 'FILE' || intent === 'GIT' || intent === 'NPM' || intent === 'DOCKER' || intent === 'COMMAND') {
      console.log('[CodeExecution] Fast path: actionable intent:', intent);
      return message; // Return the message as the task description
    }

    // SLOW PATH: Use LLM for ambiguous cases
    const analysisPrompt = applyTemplate(TASK_ANALYSIS_PROMPT, message);

    try {
      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'qwen2.5-coder:1.5b',
          prompt: analysisPrompt,
          stream: false,
        }),
      });

      if (!response.ok) return null;

      const data = await response.json();
      const jsonStr = extractJSON(data.response);
      console.log('[CodeExecution] Task analysis response:', jsonStr);
      const parsed = JSON.parse(jsonStr);

      if (parsed.isActionable && parsed.taskType !== 'conversation') {
        console.log('[CodeExecution] Actionable task detected:', parsed.taskDescription);
        // await logToFile(`Actionable task: ${parsed.taskDescription}`);
        return parsed.taskDescription;
      }
      // await logToFile('Not actionable, returning null');
      return null;
    } catch (error) {
      console.error('[CodeExecution] Failed to parse task:', error);
      return null;
    }
  }

  // Initialize smart commands and error recovery
  const smartCommands = useSmartCommands();
  const errorRecovery = useErrorRecovery();

  /**
   * Generate execution plan for a task
   * Uses rule-based fast paths first, falls back to LLM
   */
  async function generateExecutionPlan(taskDescription: string): Promise<ExecutionStep[]> {
    // STEP 1: Try smart command matching (rule-based, no LLM needed)
    const smartMatch = smartCommands.findCommand(taskDescription);

    if (smartMatch && smartMatch.confidence >= 0.7) {
      console.log(`[CodeExecution] Smart match found: ${smartMatch.command} (confidence: ${smartMatch.confidence})`);
      return [{
        id: uuidv4(),
        type: 'command',
        title: smartMatch.description,
        content: smartMatch.command,
        status: 'pending',
        timestamp: new Date(),
        // Store metadata for learning
        // @ts-ignore - extended property
        _meta: {
          source: smartMatch.source,
          confidence: smartMatch.confidence,
          safe: smartMatch.safe,
          autoExecute: smartCommands.shouldAutoExecute(smartMatch)
        }
      }];
    }

    console.log('[CodeExecution] No smart match, falling back to LLM...');

    // STEP 2: Determine if this is a multi-step task
    const isMultiStep = /\band\b|\bthen\b|,/.test(taskDescription);

    // STEP 3: Use appropriate prompt template
    const promptTemplate = isMultiStep ? MULTI_STEP_PROMPT : COMMAND_GEN_PROMPT;
    const planPrompt = applyTemplate(promptTemplate, taskDescription);

    try {
      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'qwen2.5-coder:1.5b',
          prompt: planPrompt,
          stream: false,
        }),
      });

      if (!response.ok) throw new Error('Ollama request failed');

      const data = await response.json();
      console.log('[CodeExecution] Raw LLM response:', data.response);

      // Use improved JSON extraction from prompt templates
      const parsed = extractJSONFromPrompts(data.response);
      console.log('[CodeExecution] Parsed JSON:', parsed);

      // Validate and normalize the output
      const validation = validateCommandOutput(parsed);
      if (!validation.valid) {
        console.warn('[CodeExecution] Invalid LLM output:', validation.error);
        // Fallback: create a simple command step
        return [{
          id: uuidv4(),
          type: 'command',
          title: 'Execute',
          content: taskDescription.includes('list') ? 'ls -la' : taskDescription,
          status: 'pending' as const,
          timestamp: new Date(),
        }];
      }

      let stepData = validation.steps;

      // VALIDATE AND AUTO-CORRECT LLM output
      stepData = validateAndCorrectCommand(stepData);
      console.log('[CodeExecution] Validated steps:', stepData);

      interface StepData {
        type: ExecutionStep['type'];
        title: string;
        content: string;
      }
      return (stepData as StepData[]).map((s) => ({
        id: uuidv4(),
        type: s.type || 'command',
        title: s.title || 'Execute step',
        content: s.content || '',
        status: 'pending' as const,
        timestamp: new Date(),
      }));
    } catch (error) {
      console.error('[CodeExecution] Failed to generate plan:', error);
      // Fallback: try to execute the task description as a command
      return [{
        id: uuidv4(),
        type: 'command',
        title: 'Execute command',
        content: taskDescription.includes('list') ? 'ls -la' : taskDescription,
        status: 'pending' as const,
        timestamp: new Date(),
      }];
    }
  }

  /**
   * Execute a single step
   */
  async function executeStep(step: ExecutionStep): Promise<void> {
    // await logToFile(`executeStep: type=${step.type}, title=${step.title}, content=${step.content}`);
    console.log('[CodeExecution] executeStep called:', step.type, step.title, step.content);
    step.status = 'running';
    const inv = await getInvoke();
    // await logToFile(`invoke ready: ${!!inv}, isTauri: ${isTauri}`);
    console.log('[CodeExecution] isTauri:', isTauri, 'invoke available:', !!inv);

    try {
      console.log('[CodeExecution] Step type is:', step.type, 'typeof:', typeof step.type);

      // Handle command type explicitly
      if (step.type === 'command') {
        // await logToFile('Command type matched, attempting execution');
        if (isTauri && inv) {
          let cmd = step.content.trim();
          // await logToFile(`EXECUTING: ${cmd}`);
          console.log('[CodeExecution] EXECUTING COMMAND:', cmd);
          const output = await inv<string>('execute_shell', { command: cmd });
          // await logToFile(`SUCCESS: ${output.substring(0, 100)}`);
          step.content = `$ ${cmd}\n\n${output}`;
          step.status = 'completed';
        } else {
          // await logToFile(`Cannot execute - isTauri: ${isTauri}, inv: ${!!inv}`);
          console.log('[CodeExecution] Cannot execute - isTauri:', isTauri, 'inv:', !!inv);
          step.content = `[Browser mode] Cannot execute: ${step.content}`;
          step.status = 'completed';
        }
        return; // Exit early after handling command
      }

      switch (step.type) {
        case 'thinking':
          // Simulate thinking delay
          await new Promise(resolve => setTimeout(resolve, 500));
          step.status = 'completed';
          break;

        case 'file_read':
          if (isTauri && inv) {
            console.log('[CodeExecution] Reading file:', step.content);
            const content = await inv<string>('read_file', { path: step.content });
            step.content = `File: ${step.content}\n\n${content}`;
          } else {
            step.content = `[Browser mode] Cannot read file: ${step.content}`;
          }
          step.status = 'completed';
          break;

        case 'file_write':
          if (isTauri && inv) {
            const [path, ...contentParts] = step.content.split('\n\n');
            const fileContent = contentParts.join('\n\n');
            console.log('[CodeExecution] Writing file:', path);
            await inv('write_file', { path, content: fileContent });
            step.content = `✓ Wrote to ${path}`;
          } else {
            step.content = `[Browser mode] Cannot write file: ${step.content.split('\n')[0]}`;
          }
          step.status = 'completed';
          break;

        // 'command' type is handled above before the switch
        default:
          step.status = 'completed';
      }
    } catch (error) {
      console.error('[CodeExecution] Step failed:', error);

      // Try auto-recovery for command failures
      if (step.type === 'command' && isTauri && inv) {
        console.log('[CodeExecution] Attempting auto-recovery...');

        const execute = async (cmd: string) => inv<string>('execute_shell', { command: cmd });
        const recovery = await errorRecovery.autoRecoverAndRetry(
          step.content,
          String(error),
          execute
        );

        if (recovery.recovered) {
          console.log('[CodeExecution] Recovery successful!');
          step.content = `$ ${step.content}\n\n[Auto-recovered]\n${recovery.output || ''}`;
          step.status = 'completed';
          return;
        }

        // Store suggestion for user review
        if (recovery.suggestion) {
          step.error = `${String(error)}\n\n💡 Suggestion: ${recovery.suggestion.description}\n   Command: ${recovery.suggestion.command}`;
        } else {
          step.error = String(error);
        }
      } else {
        step.error = String(error);
      }

      step.status = 'failed';
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
    console.log('[CodeExecution] Generating plan for:', taskDescription);
    const steps = await generateExecutionPlan(taskDescription);
    console.log('[CodeExecution] Generated steps:', steps.length, steps);
    task.steps = steps;

    if (onStepUpdate) onStepUpdate(steps);

    // Execute each step
    console.log('[CodeExecution] Starting execution loop...');
    let allSucceeded = true;
    for (const step of steps) {
      console.log('[CodeExecution] About to execute step:', step.title);
      const originalContent = step.content; // Save for learning

      await executeStep(step);
      console.log('[CodeExecution] Step completed:', step.title, step.status);

      // Track success/failure for learning
      if (step.status === 'failed') {
        allSucceeded = false;
        smartCommands.recordFailure(taskDescription, originalContent);
      }

      if (onStepUpdate) onStepUpdate([...steps]); // Trigger update
    }
    console.log('[CodeExecution] All steps completed');

    // Learn from successful execution
    if (allSucceeded && steps.length > 0) {
      const cmd = steps[0].content.split('\n')[0].replace(/^\$ /, '');
      smartCommands.recordSuccess(taskDescription, cmd);
      console.log('[CodeExecution] 🧠 Learned pattern:', taskDescription, '->', cmd);
    }

    // Mark task as completed
    task.status = allSucceeded ? 'completed' : 'failed';
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

  // Debug function for console testing
  async function debugTest(): Promise<void> {
    console.log('=== CODE EXECUTION DEBUG TEST ===');
    console.log('isTauri:', isTauri);
    const inv = await getInvoke();
    console.log('invoke available:', !!inv);

    if (inv) {
      try {
        console.log('Executing test command: echo "test" && pwd');
        const result = await inv<string>('execute_shell', { command: 'echo "test" && pwd' });
        console.log('✅ SUCCESS:', result);
      } catch (e) {
        console.error('❌ FAILED:', e);
      }
    } else {
      console.log('❌ No invoke function available');
    }
    console.log('=== END DEBUG ===');
  }

  // Expose debug function globally for console testing
  if (typeof window !== 'undefined') {
    (window as any).__codeExecutionDebug = debugTest;
    console.log('[CodeExecution] Debug function available: window.__codeExecutionDebug()');
  }

  return {
    parseTaskFromMessage,
    generateExecutionPlan,
    executeTask,
    getTaskSummary,
    activeTasks,
    debugTest,
  };
}
