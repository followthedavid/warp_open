/**
 * Permission Modes System
 * Control AI autonomy levels: plan, ask, trust.
 * Similar to Claude Code's permission modes.
 */

import { ref, computed, watch } from 'vue';

export type PermissionMode = 'plan' | 'ask' | 'trust';
export type ToolCategory = 'read' | 'write' | 'execute' | 'network' | 'dangerous';

export interface ToolPermission {
  tool: string;
  allowed: boolean;
  requiresApproval: boolean;
  category: ToolCategory;
}

export interface PermissionRule {
  id: string;
  pattern: string; // Glob pattern or regex
  mode: PermissionMode;
  tools?: string[];
  enabled: boolean;
  description?: string;
}

export interface PermissionPrompt {
  id: string;
  tool: string;
  args: Record<string, unknown>;
  description: string;
  risk: 'low' | 'medium' | 'high';
  timestamp: number;
  resolved: boolean;
  decision?: 'allow' | 'deny' | 'allow_always' | 'deny_always';
}

// Tool categorization
const TOOL_CATEGORIES: Record<string, ToolCategory> = {
  glob_files: 'read',
  grep_files: 'read',
  read_file: 'read',
  write_file: 'write',
  edit_file: 'write',
  execute_shell: 'execute',
  web_fetch: 'network',
  // Dangerous operations
  'rm -rf': 'dangerous',
  'git push --force': 'dangerous',
  'git reset --hard': 'dangerous',
  'sudo': 'dangerous',
};

// Default permissions by mode
const MODE_DEFAULTS: Record<PermissionMode, Record<ToolCategory, boolean>> = {
  plan: {
    read: true,
    write: false,
    execute: false,
    network: false,
    dangerous: false,
  },
  ask: {
    read: true,
    write: true, // But still asks
    execute: true, // But still asks
    network: true, // But still asks
    dangerous: false,
  },
  trust: {
    read: true,
    write: true,
    execute: true,
    network: true,
    dangerous: false, // Never auto-allow dangerous
  },
};

const STORAGE_KEY = 'warp_open_permission_settings';

// State
const currentMode = ref<PermissionMode>('ask');
const customRules = ref<PermissionRule[]>([]);
const allowedTools = ref<Set<string>>(new Set());
const deniedTools = ref<Set<string>>(new Set());
const pendingPrompts = ref<Map<string, PermissionPrompt>>(new Map());
const promptHistory = ref<PermissionPrompt[]>([]);

// Load settings
function loadSettings(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const data = JSON.parse(stored);
      currentMode.value = data.mode || 'ask';
      customRules.value = data.rules || [];
      allowedTools.value = new Set(data.allowedTools || []);
      deniedTools.value = new Set(data.deniedTools || []);
    }
  } catch (e) {
    console.error('[Permissions] Error loading settings:', e);
  }
}

// Save settings
function saveSettings(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      mode: currentMode.value,
      rules: customRules.value,
      allowedTools: Array.from(allowedTools.value),
      deniedTools: Array.from(deniedTools.value),
    }));
  } catch (e) {
    console.error('[Permissions] Error saving settings:', e);
  }
}

// Initialize
loadSettings();

// Auto-save on changes
watch([currentMode, customRules, allowedTools, deniedTools], () => {
  saveSettings();
}, { deep: true });

function generatePromptId(): string {
  return `perm_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function usePermissionModes() {
  const mode = computed(() => currentMode.value);

  const pendingCount = computed(() => pendingPrompts.value.size);

  /**
   * Set the permission mode
   */
  function setMode(newMode: PermissionMode): void {
    currentMode.value = newMode;
    console.log(`[Permissions] Mode set to: ${newMode}`);
  }

  /**
   * Get tool category
   */
  function getToolCategory(tool: string): ToolCategory {
    return TOOL_CATEGORIES[tool] || 'execute';
  }

  /**
   * Check if tool is allowed in current mode
   */
  function isToolAllowed(tool: string, args?: Record<string, unknown>): {
    allowed: boolean;
    requiresApproval: boolean;
    reason?: string;
  } {
    const category = getToolCategory(tool);

    // Check if permanently denied
    if (deniedTools.value.has(tool)) {
      return { allowed: false, requiresApproval: false, reason: 'Tool permanently denied' };
    }

    // Check if permanently allowed
    if (allowedTools.value.has(tool)) {
      return { allowed: true, requiresApproval: false };
    }

    // Check custom rules
    for (const rule of customRules.value) {
      if (!rule.enabled) continue;

      const regex = new RegExp(rule.pattern);
      if (regex.test(tool) || (rule.tools && rule.tools.includes(tool))) {
        const modeDefaults = MODE_DEFAULTS[rule.mode];
        return {
          allowed: modeDefaults[category],
          requiresApproval: rule.mode !== 'trust' && category !== 'read',
          reason: rule.description,
        };
      }
    }

    // Use mode defaults
    const modeDefaults = MODE_DEFAULTS[currentMode.value];

    // Special handling for dangerous operations
    if (category === 'dangerous') {
      return { allowed: false, requiresApproval: true, reason: 'Dangerous operation requires approval' };
    }

    // Check if command contains dangerous patterns
    if (args && typeof args.command === 'string') {
      const cmd = args.command as string;
      if (/rm\s+-rf/.test(cmd) || /--force/.test(cmd) || /sudo/.test(cmd)) {
        return { allowed: false, requiresApproval: true, reason: 'Command contains dangerous pattern' };
      }
    }

    const allowed = modeDefaults[category];
    const requiresApproval = currentMode.value !== 'trust' && category !== 'read';

    return { allowed, requiresApproval };
  }

  /**
   * Request permission for a tool execution
   */
  async function requestPermission(
    tool: string,
    args: Record<string, unknown>,
    description: string
  ): Promise<'allow' | 'deny'> {
    const check = isToolAllowed(tool, args);

    if (!check.requiresApproval && check.allowed) {
      return 'allow';
    }

    if (!check.allowed && !check.requiresApproval) {
      return 'deny';
    }

    // Create permission prompt
    const prompt: PermissionPrompt = {
      id: generatePromptId(),
      tool,
      args,
      description,
      risk: categorizeRisk(tool, args),
      timestamp: Date.now(),
      resolved: false,
    };

    pendingPrompts.value.set(prompt.id, prompt);

    // Wait for resolution
    return new Promise((resolve) => {
      const checkResolved = setInterval(() => {
        const updated = pendingPrompts.value.get(prompt.id);
        if (updated?.resolved) {
          clearInterval(checkResolved);
          pendingPrompts.value.delete(prompt.id);
          promptHistory.value.push(updated);

          // Handle "always" decisions
          if (updated.decision === 'allow_always') {
            allowedTools.value.add(tool);
          } else if (updated.decision === 'deny_always') {
            deniedTools.value.add(tool);
          }

          resolve(updated.decision === 'allow' || updated.decision === 'allow_always' ? 'allow' : 'deny');
        }
      }, 100);
    });
  }

  /**
   * Resolve a pending permission prompt
   */
  function resolvePrompt(promptId: string, decision: PermissionPrompt['decision']): void {
    const prompt = pendingPrompts.value.get(promptId);
    if (prompt) {
      prompt.resolved = true;
      prompt.decision = decision;
      console.log(`[Permissions] Resolved prompt ${promptId}: ${decision}`);
    }
  }

  /**
   * Categorize risk level
   */
  function categorizeRisk(tool: string, args: Record<string, unknown>): 'low' | 'medium' | 'high' {
    const category = getToolCategory(tool);

    if (category === 'dangerous') return 'high';
    if (category === 'read') return 'low';

    // Check for dangerous patterns
    if (args.command && typeof args.command === 'string') {
      const cmd = args.command as string;
      if (/rm|delete|drop|truncate/i.test(cmd)) return 'high';
      if (/git\s+(push|reset|rebase)/i.test(cmd)) return 'medium';
    }

    if (category === 'write' || category === 'execute') return 'medium';

    return 'low';
  }

  /**
   * Add a custom permission rule
   */
  function addRule(rule: Omit<PermissionRule, 'id'>): PermissionRule {
    const newRule: PermissionRule = {
      ...rule,
      id: `rule_${Date.now()}`,
    };
    customRules.value.push(newRule);
    return newRule;
  }

  /**
   * Remove a custom rule
   */
  function removeRule(ruleId: string): void {
    const index = customRules.value.findIndex(r => r.id === ruleId);
    if (index >= 0) {
      customRules.value.splice(index, 1);
    }
  }

  /**
   * Toggle a rule
   */
  function toggleRule(ruleId: string): void {
    const rule = customRules.value.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = !rule.enabled;
    }
  }

  /**
   * Add tool to always allow list
   */
  function alwaysAllow(tool: string): void {
    allowedTools.value.add(tool);
    deniedTools.value.delete(tool);
  }

  /**
   * Add tool to always deny list
   */
  function alwaysDeny(tool: string): void {
    deniedTools.value.add(tool);
    allowedTools.value.delete(tool);
  }

  /**
   * Reset tool to default behavior
   */
  function resetTool(tool: string): void {
    allowedTools.value.delete(tool);
    deniedTools.value.delete(tool);
  }

  /**
   * Get all pending prompts
   */
  function getPendingPrompts(): PermissionPrompt[] {
    return Array.from(pendingPrompts.value.values());
  }

  /**
   * Get permission history
   */
  function getHistory(limit?: number): PermissionPrompt[] {
    const history = [...promptHistory.value].reverse();
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Clear history
   */
  function clearHistory(): void {
    promptHistory.value = [];
  }

  /**
   * Reset all permissions to defaults
   */
  function resetToDefaults(): void {
    currentMode.value = 'ask';
    customRules.value = [];
    allowedTools.value.clear();
    deniedTools.value.clear();
    pendingPrompts.value.clear();
    saveSettings();
  }

  /**
   * Get permission summary for AI context
   */
  function getPermissionSummary(): string {
    let summary = `Current permission mode: ${currentMode.value}\n`;

    if (allowedTools.value.size > 0) {
      summary += `Always allowed: ${Array.from(allowedTools.value).join(', ')}\n`;
    }

    if (deniedTools.value.size > 0) {
      summary += `Always denied: ${Array.from(deniedTools.value).join(', ')}\n`;
    }

    if (customRules.value.length > 0) {
      summary += `Custom rules: ${customRules.value.filter(r => r.enabled).length} active\n`;
    }

    return summary;
  }

  /**
   * Export settings
   */
  function exportSettings(): string {
    return JSON.stringify({
      mode: currentMode.value,
      rules: customRules.value,
      allowedTools: Array.from(allowedTools.value),
      deniedTools: Array.from(deniedTools.value),
    }, null, 2);
  }

  /**
   * Import settings
   */
  function importSettings(json: string): boolean {
    try {
      const data = JSON.parse(json);
      if (data.mode) currentMode.value = data.mode;
      if (data.rules) customRules.value = data.rules;
      if (data.allowedTools) allowedTools.value = new Set(data.allowedTools);
      if (data.deniedTools) deniedTools.value = new Set(data.deniedTools);
      return true;
    } catch (error) {
      console.error('[Permissions] Import error:', error);
      return false;
    }
  }

  return {
    // State
    mode,
    pendingCount,
    customRules: computed(() => customRules.value),
    allowedTools: computed(() => Array.from(allowedTools.value)),
    deniedTools: computed(() => Array.from(deniedTools.value)),

    // Mode management
    setMode,

    // Permission checking
    isToolAllowed,
    requestPermission,
    resolvePrompt,
    getPendingPrompts,

    // Tool management
    alwaysAllow,
    alwaysDeny,
    resetTool,

    // Rule management
    addRule,
    removeRule,
    toggleRule,

    // History
    getHistory,
    clearHistory,

    // Utilities
    getPermissionSummary,
    resetToDefaults,
    exportSettings,
    importSettings,
  };
}
