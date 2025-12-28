/**
 * Hooks System
 * PreToolUse and PostToolUse validation hooks, similar to Claude Code.
 * Allows custom validation, logging, and blocking of tool executions.
 */

import { ref, computed } from 'vue';

export type HookTiming = 'PreToolUse' | 'PostToolUse';
export type HookAction = 'allow' | 'block' | 'warn' | 'log' | 'transform';

export interface Hook {
  id: string;
  name: string;
  description: string;
  timing: HookTiming;
  tool: string | '*';  // Tool name or '*' for all tools
  pattern?: string;    // Regex pattern to match against args
  action: HookAction;
  message?: string;    // Message to show when hook triggers
  transform?: (args: Record<string, unknown>) => Record<string, unknown>;
  enabled: boolean;
  priority: number;    // Lower = runs first
}

export interface HookResult {
  allowed: boolean;
  modified: boolean;
  args: Record<string, unknown>;
  messages: string[];
  triggeredHooks: string[];
}

export interface HookLog {
  id: string;
  timestamp: number;
  hookId: string;
  hookName: string;
  tool: string;
  args: Record<string, unknown>;
  action: HookAction;
  result: 'allowed' | 'blocked' | 'warned' | 'transformed';
  message?: string;
}

// Built-in security hooks
const BUILTIN_HOOKS: Hook[] = [
  // Block dangerous file operations
  {
    id: 'builtin_block_env_write',
    name: 'Block .env writes',
    description: 'Prevents writing to .env files which may contain secrets',
    timing: 'PreToolUse',
    tool: 'write_file',
    pattern: '\\.env$',
    action: 'block',
    message: 'Cannot write to .env files - they may contain secrets',
    enabled: true,
    priority: 1,
  },
  {
    id: 'builtin_block_credentials',
    name: 'Block credentials files',
    description: 'Prevents writing to common credential files',
    timing: 'PreToolUse',
    tool: 'write_file',
    pattern: '(credentials|secrets|\.pem|\.key|id_rsa)$',
    action: 'block',
    message: 'Cannot write to credential/key files',
    enabled: true,
    priority: 1,
  },
  // Warn on destructive operations
  {
    id: 'builtin_warn_delete',
    name: 'Warn on file deletion',
    description: 'Shows warning before deleting files',
    timing: 'PreToolUse',
    tool: 'execute_shell',
    pattern: '\\brm\\b.*-r',
    action: 'warn',
    message: 'Warning: This command will recursively delete files',
    enabled: true,
    priority: 10,
  },
  {
    id: 'builtin_warn_git_force',
    name: 'Warn on git force operations',
    description: 'Shows warning before force push/reset',
    timing: 'PreToolUse',
    tool: 'execute_shell',
    pattern: 'git.*(--force|push.*-f|reset.*--hard)',
    action: 'warn',
    message: 'Warning: This git command may cause data loss',
    enabled: true,
    priority: 10,
  },
  // Log all file writes
  {
    id: 'builtin_log_writes',
    name: 'Log file writes',
    description: 'Logs all file write operations',
    timing: 'PostToolUse',
    tool: 'write_file',
    action: 'log',
    enabled: true,
    priority: 100,
  },
  {
    id: 'builtin_log_edits',
    name: 'Log file edits',
    description: 'Logs all file edit operations',
    timing: 'PostToolUse',
    tool: 'edit_file',
    action: 'log',
    enabled: true,
    priority: 100,
  },
  // Log shell commands
  {
    id: 'builtin_log_shell',
    name: 'Log shell commands',
    description: 'Logs all shell command executions',
    timing: 'PostToolUse',
    tool: 'execute_shell',
    action: 'log',
    enabled: true,
    priority: 100,
  },
];

const STORAGE_KEY = 'warp_open_hooks';
const LOG_STORAGE_KEY = 'warp_open_hook_logs';
const MAX_LOGS = 500;

// State
const customHooks = ref<Hook[]>([]);
const hookLogs = ref<HookLog[]>([]);

// Load from storage
function loadHooks(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      customHooks.value = JSON.parse(stored);
    }
  } catch (e) {
    console.error('[Hooks] Error loading hooks:', e);
  }
}

function saveHooks(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(customHooks.value));
  } catch (e) {
    console.error('[Hooks] Error saving hooks:', e);
  }
}

function loadLogs(): void {
  try {
    const stored = localStorage.getItem(LOG_STORAGE_KEY);
    if (stored) {
      hookLogs.value = JSON.parse(stored);
    }
  } catch (e) {
    console.error('[Hooks] Error loading logs:', e);
  }
}

function saveLogs(): void {
  try {
    // Keep only last MAX_LOGS entries
    const toSave = hookLogs.value.slice(-MAX_LOGS);
    localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(toSave));
  } catch (e) {
    console.error('[Hooks] Error saving logs:', e);
  }
}

// Initialize
loadHooks();
loadLogs();

export function useHooks() {
  const allHooks = computed(() => [...BUILTIN_HOOKS, ...customHooks.value]);

  const enabledHooks = computed(() =>
    allHooks.value.filter(h => h.enabled).sort((a, b) => a.priority - b.priority)
  );

  /**
   * Run PreToolUse hooks before tool execution
   */
  function runPreToolUseHooks(
    tool: string,
    args: Record<string, unknown>
  ): HookResult {
    const result: HookResult = {
      allowed: true,
      modified: false,
      args: { ...args },
      messages: [],
      triggeredHooks: [],
    };

    const hooks = enabledHooks.value.filter(
      h => h.timing === 'PreToolUse' && (h.tool === '*' || h.tool === tool)
    );

    for (const hook of hooks) {
      // Check pattern match if specified
      if (hook.pattern) {
        const regex = new RegExp(hook.pattern, 'i');
        const argsStr = JSON.stringify(args);
        if (!regex.test(argsStr)) {
          continue; // Pattern didn't match, skip this hook
        }
      }

      result.triggeredHooks.push(hook.id);

      switch (hook.action) {
        case 'block':
          result.allowed = false;
          result.messages.push(hook.message || `Blocked by hook: ${hook.name}`);
          logHookExecution(hook, tool, args, 'blocked');
          return result; // Stop processing on block

        case 'warn':
          result.messages.push(hook.message || `Warning from hook: ${hook.name}`);
          logHookExecution(hook, tool, args, 'warned');
          break;

        case 'transform':
          if (hook.transform) {
            result.args = hook.transform(result.args);
            result.modified = true;
            logHookExecution(hook, tool, args, 'transformed');
          }
          break;

        case 'log':
          logHookExecution(hook, tool, args, 'allowed');
          break;

        case 'allow':
        default:
          logHookExecution(hook, tool, args, 'allowed');
          break;
      }
    }

    return result;
  }

  /**
   * Run PostToolUse hooks after tool execution
   */
  function runPostToolUseHooks(
    tool: string,
    args: Record<string, unknown>,
    result: unknown
  ): void {
    const hooks = enabledHooks.value.filter(
      h => h.timing === 'PostToolUse' && (h.tool === '*' || h.tool === tool)
    );

    for (const hook of hooks) {
      if (hook.pattern) {
        const regex = new RegExp(hook.pattern, 'i');
        const argsStr = JSON.stringify(args);
        if (!regex.test(argsStr)) {
          continue;
        }
      }

      logHookExecution(hook, tool, { ...args, _result: result }, 'allowed');
    }
  }

  /**
   * Log hook execution
   */
  function logHookExecution(
    hook: Hook,
    tool: string,
    args: Record<string, unknown>,
    result: HookLog['result']
  ): void {
    const log: HookLog = {
      id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
      timestamp: Date.now(),
      hookId: hook.id,
      hookName: hook.name,
      tool,
      args,
      action: hook.action,
      result,
      message: hook.message,
    };

    hookLogs.value.push(log);

    // Trim logs if too many
    if (hookLogs.value.length > MAX_LOGS * 1.2) {
      hookLogs.value = hookLogs.value.slice(-MAX_LOGS);
    }

    saveLogs();

    console.log(`[Hooks] ${hook.timing} ${hook.name}: ${result} for ${tool}`);
  }

  /**
   * Add a custom hook
   */
  function addHook(hook: Omit<Hook, 'id'>): Hook {
    const newHook: Hook = {
      ...hook,
      id: `custom_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
    };

    customHooks.value.push(newHook);
    saveHooks();

    return newHook;
  }

  /**
   * Update a custom hook
   */
  function updateHook(hookId: string, updates: Partial<Hook>): void {
    const index = customHooks.value.findIndex(h => h.id === hookId);
    if (index >= 0) {
      customHooks.value[index] = { ...customHooks.value[index], ...updates };
      saveHooks();
    }
  }

  /**
   * Remove a custom hook
   */
  function removeHook(hookId: string): void {
    const index = customHooks.value.findIndex(h => h.id === hookId);
    if (index >= 0) {
      customHooks.value.splice(index, 1);
      saveHooks();
    }
  }

  /**
   * Toggle a hook on/off
   */
  function toggleHook(hookId: string): void {
    // Check custom hooks first
    const customIndex = customHooks.value.findIndex(h => h.id === hookId);
    if (customIndex >= 0) {
      customHooks.value[customIndex].enabled = !customHooks.value[customIndex].enabled;
      saveHooks();
      return;
    }

    // For built-in hooks, we can't modify them directly but we can override
    // by creating a custom hook with same ID
    const builtinHook = BUILTIN_HOOKS.find(h => h.id === hookId);
    if (builtinHook) {
      // Create an override in custom hooks
      const override: Hook = {
        ...builtinHook,
        enabled: !builtinHook.enabled,
      };
      customHooks.value.push(override);
      saveHooks();
    }
  }

  /**
   * Get hook by ID
   */
  function getHook(hookId: string): Hook | undefined {
    return allHooks.value.find(h => h.id === hookId);
  }

  /**
   * Get hooks for a specific tool
   */
  function getHooksForTool(tool: string): Hook[] {
    return enabledHooks.value.filter(h => h.tool === '*' || h.tool === tool);
  }

  /**
   * Get recent logs
   */
  function getRecentLogs(count: number = 50): HookLog[] {
    return hookLogs.value.slice(-count).reverse();
  }

  /**
   * Get logs for a specific tool
   */
  function getLogsForTool(tool: string): HookLog[] {
    return hookLogs.value.filter(l => l.tool === tool).reverse();
  }

  /**
   * Clear all logs
   */
  function clearLogs(): void {
    hookLogs.value = [];
    saveLogs();
  }

  /**
   * Export hooks configuration
   */
  function exportHooks(): string {
    return JSON.stringify(customHooks.value, null, 2);
  }

  /**
   * Import hooks configuration
   */
  function importHooks(json: string): number {
    try {
      const imported = JSON.parse(json) as Hook[];
      let count = 0;

      for (const hook of imported) {
        // Skip if already exists
        if (!customHooks.value.find(h => h.id === hook.id)) {
          customHooks.value.push(hook);
          count++;
        }
      }

      saveHooks();
      return count;
    } catch (e) {
      console.error('[Hooks] Import error:', e);
      return 0;
    }
  }

  /**
   * Get hook statistics
   */
  function getStats() {
    const byAction: Record<string, number> = {};
    const byTool: Record<string, number> = {};

    for (const log of hookLogs.value) {
      byAction[log.action] = (byAction[log.action] || 0) + 1;
      byTool[log.tool] = (byTool[log.tool] || 0) + 1;
    }

    return {
      totalHooks: allHooks.value.length,
      enabledHooks: enabledHooks.value.length,
      customHooks: customHooks.value.length,
      totalLogs: hookLogs.value.length,
      blocked: hookLogs.value.filter(l => l.result === 'blocked').length,
      warned: hookLogs.value.filter(l => l.result === 'warned').length,
      byAction,
      byTool,
    };
  }

  return {
    // State
    allHooks,
    enabledHooks,
    customHooks: computed(() => customHooks.value),
    builtinHooks: BUILTIN_HOOKS,
    logs: computed(() => hookLogs.value),

    // Hook execution
    runPreToolUseHooks,
    runPostToolUseHooks,

    // Hook management
    addHook,
    updateHook,
    removeHook,
    toggleHook,
    getHook,
    getHooksForTool,

    // Logs
    getRecentLogs,
    getLogsForTool,
    clearLogs,

    // Import/Export
    exportHooks,
    importHooks,

    // Stats
    getStats,
  };
}
