/**
 * Background Tasks System
 * Run long-running processes without blocking the AI agent.
 * Similar to Claude Code's background shell support.
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

export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type TaskType = 'shell' | 'build' | 'test' | 'lint' | 'watch' | 'custom';

export interface BackgroundTask {
  id: string;
  type: TaskType;
  name: string;
  command: string;
  status: TaskStatus;
  output: string[];
  exitCode?: number;
  startedAt?: number;
  completedAt?: number;
  pid?: number;
  cwd?: string;
  env?: Record<string, string>;
  onComplete?: (task: BackgroundTask) => void;
}

export interface TaskProgress {
  taskId: string;
  percent: number;
  message: string;
}

// State
const tasks = ref<Map<string, BackgroundTask>>(new Map());
const activePollers = ref<Map<string, number>>(new Map()); // taskId -> intervalId

const MAX_OUTPUT_LINES = 1000;
const POLL_INTERVAL = 500; // ms

function generateTaskId(): string {
  return `bg_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function useBackgroundTasks() {
  const activeTasks = computed(() =>
    Array.from(tasks.value.values()).filter(t => t.status === 'running')
  );

  const completedTasks = computed(() =>
    Array.from(tasks.value.values()).filter(t =>
      t.status === 'completed' || t.status === 'failed' || t.status === 'cancelled'
    )
  );

  const pendingTasks = computed(() =>
    Array.from(tasks.value.values()).filter(t => t.status === 'pending')
  );

  /**
   * Start a background task
   */
  async function startTask(options: {
    name: string;
    command: string;
    type?: TaskType;
    cwd?: string;
    env?: Record<string, string>;
    onComplete?: (task: BackgroundTask) => void;
  }): Promise<BackgroundTask> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const task: BackgroundTask = {
      id: generateTaskId(),
      type: options.type || 'shell',
      name: options.name,
      command: options.command,
      status: 'pending',
      output: [],
      cwd: options.cwd,
      env: options.env,
      onComplete: options.onComplete,
    };

    tasks.value.set(task.id, task);

    try {
      task.status = 'running';
      task.startedAt = Date.now();

      // Start the background process
      const result = await invoke<{ pid: number; task_id: string }>('start_background_task', {
        command: task.command,
        cwd: task.cwd,
        env: task.env,
      });

      task.pid = result.pid;

      // Start polling for output
      startPolling(task.id);

      console.log(`[BackgroundTasks] Started task ${task.id}: ${task.name}`);
      return task;
    } catch (error) {
      task.status = 'failed';
      task.output.push(`Error: ${error instanceof Error ? error.message : String(error)}`);
      task.completedAt = Date.now();
      return task;
    }
  }

  /**
   * Start polling for task output
   */
  function startPolling(taskId: string): void {
    if (activePollers.value.has(taskId)) return;

    const pollerId = window.setInterval(async () => {
      await pollTaskOutput(taskId);
    }, POLL_INTERVAL);

    activePollers.value.set(taskId, pollerId);
  }

  /**
   * Stop polling for task output
   */
  function stopPolling(taskId: string): void {
    const pollerId = activePollers.value.get(taskId);
    if (pollerId) {
      clearInterval(pollerId);
      activePollers.value.delete(taskId);
    }
  }

  /**
   * Poll for task output
   */
  async function pollTaskOutput(taskId: string): Promise<void> {
    if (!invoke) return;

    const task = tasks.value.get(taskId);
    if (!task || task.status !== 'running') {
      stopPolling(taskId);
      return;
    }

    try {
      const result = await invoke<{
        output: string;
        is_complete: boolean;
        exit_code?: number;
      }>('poll_background_task', { taskId });

      // Append new output
      if (result.output) {
        const newLines = result.output.split('\n');
        task.output.push(...newLines);

        // Trim output if too long
        if (task.output.length > MAX_OUTPUT_LINES) {
          task.output = task.output.slice(-MAX_OUTPUT_LINES);
        }
      }

      // Check if completed
      if (result.is_complete) {
        task.status = result.exit_code === 0 ? 'completed' : 'failed';
        task.exitCode = result.exit_code;
        task.completedAt = Date.now();
        stopPolling(taskId);

        // Call completion handler
        if (task.onComplete) {
          task.onComplete(task);
        }

        console.log(`[BackgroundTasks] Task ${taskId} completed with exit code ${result.exit_code}`);
      }
    } catch (error) {
      console.error(`[BackgroundTasks] Poll error for ${taskId}:`, error);
    }
  }

  /**
   * Cancel a running task
   */
  async function cancelTask(taskId: string): Promise<boolean> {
    if (!invoke) return false;

    const task = tasks.value.get(taskId);
    if (!task || task.status !== 'running') return false;

    try {
      await invoke('cancel_background_task', { taskId, pid: task.pid });
      task.status = 'cancelled';
      task.completedAt = Date.now();
      stopPolling(taskId);

      console.log(`[BackgroundTasks] Cancelled task ${taskId}`);
      return true;
    } catch (error) {
      console.error(`[BackgroundTasks] Cancel error for ${taskId}:`, error);
      return false;
    }
  }

  /**
   * Get task by ID
   */
  function getTask(taskId: string): BackgroundTask | undefined {
    return tasks.value.get(taskId);
  }

  /**
   * Get task output
   */
  function getTaskOutput(taskId: string, lastN?: number): string[] {
    const task = tasks.value.get(taskId);
    if (!task) return [];

    if (lastN) {
      return task.output.slice(-lastN);
    }
    return [...task.output];
  }

  /**
   * Wait for a task to complete
   */
  async function waitForTask(taskId: string, timeout?: number): Promise<BackgroundTask> {
    const task = tasks.value.get(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    if (task.status !== 'running' && task.status !== 'pending') {
      return task;
    }

    return new Promise((resolve, reject) => {
      const startTime = Date.now();

      const checkInterval = setInterval(() => {
        const currentTask = tasks.value.get(taskId);
        if (!currentTask) {
          clearInterval(checkInterval);
          reject(new Error(`Task ${taskId} disappeared`));
          return;
        }

        if (currentTask.status !== 'running' && currentTask.status !== 'pending') {
          clearInterval(checkInterval);
          resolve(currentTask);
          return;
        }

        if (timeout && Date.now() - startTime > timeout) {
          clearInterval(checkInterval);
          reject(new Error(`Task ${taskId} timed out`));
        }
      }, 100);
    });
  }

  /**
   * Run common background tasks
   */
  async function runBuild(command: string = 'npm run build', cwd?: string): Promise<BackgroundTask> {
    return startTask({
      name: 'Build',
      command,
      type: 'build',
      cwd,
    });
  }

  async function runTests(command: string = 'npm test', cwd?: string): Promise<BackgroundTask> {
    return startTask({
      name: 'Tests',
      command,
      type: 'test',
      cwd,
    });
  }

  async function runLint(command: string = 'npm run lint', cwd?: string): Promise<BackgroundTask> {
    return startTask({
      name: 'Lint',
      command,
      type: 'lint',
      cwd,
    });
  }

  async function runWatch(command: string, cwd?: string): Promise<BackgroundTask> {
    return startTask({
      name: 'Watch',
      command,
      type: 'watch',
      cwd,
    });
  }

  /**
   * Remove completed tasks from list
   */
  function clearCompleted(): void {
    for (const [id, task] of tasks.value) {
      if (task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled') {
        tasks.value.delete(id);
      }
    }
  }

  /**
   * Remove a specific task
   */
  function removeTask(taskId: string): void {
    const task = tasks.value.get(taskId);
    if (task && task.status === 'running') {
      cancelTask(taskId);
    }
    stopPolling(taskId);
    tasks.value.delete(taskId);
  }

  /**
   * Get summary of all tasks for AI context
   */
  function getTasksSummary(): string {
    const taskList = Array.from(tasks.value.values());
    if (taskList.length === 0) {
      return 'No background tasks.';
    }

    const lines: string[] = ['Background Tasks:'];

    for (const task of taskList) {
      const duration = task.completedAt && task.startedAt
        ? `${((task.completedAt - task.startedAt) / 1000).toFixed(1)}s`
        : task.startedAt
        ? 'running...'
        : 'pending';

      lines.push(`- [${task.status}] ${task.name}: ${task.command} (${duration})`);

      if (task.status === 'failed' && task.output.length > 0) {
        // Include last few lines of error output
        const errorLines = task.output.slice(-3);
        for (const line of errorLines) {
          lines.push(`    ${line}`);
        }
      }
    }

    return lines.join('\n');
  }

  /**
   * Check if any critical tasks are running
   */
  function hasCriticalRunning(): boolean {
    return activeTasks.value.some(t =>
      t.type === 'build' || t.type === 'test'
    );
  }

  /**
   * Get statistics
   */
  function getStats() {
    const allTasks = Array.from(tasks.value.values());
    return {
      total: allTasks.length,
      running: allTasks.filter(t => t.status === 'running').length,
      completed: allTasks.filter(t => t.status === 'completed').length,
      failed: allTasks.filter(t => t.status === 'failed').length,
      cancelled: allTasks.filter(t => t.status === 'cancelled').length,
      pending: allTasks.filter(t => t.status === 'pending').length,
    };
  }

  return {
    // State
    tasks: computed(() => Array.from(tasks.value.values())),
    activeTasks,
    completedTasks,
    pendingTasks,

    // Core methods
    startTask,
    cancelTask,
    getTask,
    getTaskOutput,
    waitForTask,

    // Convenience methods
    runBuild,
    runTests,
    runLint,
    runWatch,

    // Management
    clearCompleted,
    removeTask,
    getTasksSummary,
    hasCriticalRunning,
    getStats,
  };
}
