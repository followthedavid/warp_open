/**
 * Error Recovery System
 * Intelligent error handling with auto-retry and AI-powered fixes
 *
 * Features:
 * - Automatic retry with exponential backoff
 * - Error pattern recognition
 * - AI-powered fix suggestions
 * - Error history tracking
 * - Common error auto-fixes
 */

import { ref, computed } from 'vue';
import { ERROR_RECOVERY_PROMPT, applyTemplate, extractJSON } from './usePromptTemplates';

// ============================================================================
// TYPES
// ============================================================================

export interface ErrorContext {
  id: string;
  command: string;
  error: string;
  errorType: ErrorType;
  timestamp: Date;
  retryCount: number;
  resolved: boolean;
  resolution?: string;
}

export type ErrorType =
  | 'command_not_found'
  | 'permission_denied'
  | 'file_not_found'
  | 'network_error'
  | 'syntax_error'
  | 'dependency_missing'
  | 'git_error'
  | 'npm_error'
  | 'timeout'
  | 'unknown';

export interface RecoverySuggestion {
  description: string;
  command: string;
  confidence: number;
  autoApply: boolean;
}

// ============================================================================
// ERROR PATTERNS - Rule-based error recognition
// ============================================================================

const ERROR_PATTERNS: Array<{
  pattern: RegExp;
  type: ErrorType;
  suggestion: (match: RegExpMatchArray, cmd: string) => RecoverySuggestion;
}> = [
  // Command not found
  {
    pattern: /command not found[:\s]+(\w+)/i,
    type: 'command_not_found',
    suggestion: (match) => ({
      description: `Install ${match[1]}`,
      command: `brew install ${match[1]} 2>/dev/null || apt-get install -y ${match[1]} 2>/dev/null || echo "Please install ${match[1]} manually"`,
      confidence: 0.7,
      autoApply: false
    })
  },
  {
    pattern: /(\w+): not found/i,
    type: 'command_not_found',
    suggestion: (match) => ({
      description: `Install ${match[1]}`,
      command: `which ${match[1]} || brew install ${match[1]} 2>/dev/null || echo "Install ${match[1]} manually"`,
      confidence: 0.7,
      autoApply: false
    })
  },

  // Permission denied
  {
    pattern: /permission denied[:\s]*(.+)?/i,
    type: 'permission_denied',
    suggestion: (match, cmd) => ({
      description: 'Add execute permission',
      command: `chmod +x ${match[1] || cmd.split(' ').pop()}`,
      confidence: 0.8,
      autoApply: true
    })
  },
  {
    pattern: /EACCES|access denied/i,
    type: 'permission_denied',
    suggestion: (_, cmd) => ({
      description: 'Run with sudo (requires user approval)',
      command: `sudo ${cmd}`,
      confidence: 0.6,
      autoApply: false
    })
  },

  // File not found
  {
    pattern: /no such file or directory[:\s]*(.+)?/i,
    type: 'file_not_found',
    suggestion: (match) => ({
      description: 'Create the missing file/directory',
      command: `mkdir -p "$(dirname "${match[1] || '.'}")" && touch "${match[1] || 'file'}"`,
      confidence: 0.7,
      autoApply: false
    })
  },
  {
    pattern: /ENOENT[:\s]*(.+)?/i,
    type: 'file_not_found',
    suggestion: (match) => ({
      description: 'File not found - check path',
      command: `ls -la "$(dirname "${match[1] || '.'}")" 2>/dev/null || echo "Parent directory doesn't exist"`,
      confidence: 0.6,
      autoApply: true
    })
  },

  // Network errors
  {
    pattern: /ECONNREFUSED|connection refused/i,
    type: 'network_error',
    suggestion: () => ({
      description: 'Check if service is running',
      command: 'lsof -i -P -n | grep LISTEN | head -10',
      confidence: 0.8,
      autoApply: true
    })
  },
  {
    pattern: /ETIMEDOUT|timed? ?out/i,
    type: 'timeout',
    suggestion: (_, cmd) => ({
      description: 'Retry with longer timeout',
      command: `timeout 60 ${cmd}`,
      confidence: 0.6,
      autoApply: false
    })
  },

  // NPM errors
  {
    pattern: /npm ERR! missing script[:\s]*(\w+)/i,
    type: 'npm_error',
    suggestion: (match) => ({
      description: `Script "${match[1]}" not found`,
      command: 'npm run',
      confidence: 0.9,
      autoApply: true
    })
  },
  {
    pattern: /npm ERR! (peer dep|ERESOLVE)/i,
    type: 'npm_error',
    suggestion: () => ({
      description: 'Force install with legacy peer deps',
      command: 'npm install --legacy-peer-deps',
      confidence: 0.8,
      autoApply: false
    })
  },
  {
    pattern: /npm ERR! code ENOENT/i,
    type: 'npm_error',
    suggestion: () => ({
      description: 'Check package.json exists',
      command: 'ls -la package.json 2>/dev/null || npm init -y',
      confidence: 0.8,
      autoApply: false
    })
  },

  // Git errors
  {
    pattern: /not a git repository/i,
    type: 'git_error',
    suggestion: () => ({
      description: 'Initialize git repository',
      command: 'git init',
      confidence: 0.9,
      autoApply: false
    })
  },
  {
    pattern: /nothing to commit/i,
    type: 'git_error',
    suggestion: () => ({
      description: 'No changes to commit',
      command: 'git status',
      confidence: 1.0,
      autoApply: true
    })
  },
  {
    pattern: /merge conflict/i,
    type: 'git_error',
    suggestion: () => ({
      description: 'Show conflicted files',
      command: 'git diff --name-only --diff-filter=U',
      confidence: 0.9,
      autoApply: true
    })
  },

  // Syntax errors
  {
    pattern: /syntax error|unexpected token/i,
    type: 'syntax_error',
    suggestion: (_, cmd) => ({
      description: 'Check command syntax',
      command: `echo "${cmd}" | shellcheck - 2>/dev/null || echo "Review command syntax"`,
      confidence: 0.5,
      autoApply: true
    })
  },

  // Dependency errors
  {
    pattern: /module not found|cannot find module/i,
    type: 'dependency_missing',
    suggestion: () => ({
      description: 'Install dependencies',
      command: 'npm install',
      confidence: 0.85,
      autoApply: false
    })
  }
];

// ============================================================================
// STATE
// ============================================================================

const errorHistory = ref<ErrorContext[]>([]);
const isRecovering = ref(false);

// Load from localStorage
function loadErrorHistory() {
  try {
    const saved = localStorage.getItem('warp_error_history');
    if (saved) {
      const data = JSON.parse(saved) as ErrorContext[];
      errorHistory.value = data.slice(-50).map(e => ({
        ...e,
        timestamp: new Date(e.timestamp)
      }));
    }
  } catch {}
}

function saveErrorHistory() {
  try {
    localStorage.setItem('warp_error_history', JSON.stringify(errorHistory.value.slice(-50)));
  } catch {}
}

// Initialize
loadErrorHistory();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

function classifyError(error: string): ErrorType {
  for (const { pattern, type } of ERROR_PATTERNS) {
    if (pattern.test(error)) {
      return type;
    }
  }
  return 'unknown';
}

function findPatternMatch(error: string, command: string): RecoverySuggestion | null {
  for (const { pattern, suggestion } of ERROR_PATTERNS) {
    const match = error.match(pattern);
    if (match) {
      return suggestion(match, command);
    }
  }
  return null;
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useErrorRecovery() {
  /**
   * Record an error and get recovery suggestion
   */
  async function handleError(command: string, error: string): Promise<{
    context: ErrorContext;
    suggestion: RecoverySuggestion | null;
  }> {
    const errorType = classifyError(error);

    const context: ErrorContext = {
      id: generateId(),
      command,
      error: error.substring(0, 500),
      errorType,
      timestamp: new Date(),
      retryCount: 0,
      resolved: false
    };

    errorHistory.value.push(context);
    saveErrorHistory();

    // Try rule-based recovery first
    let suggestion = findPatternMatch(error, command);

    // If no rule match, try AI recovery
    if (!suggestion && errorType === 'unknown') {
      suggestion = await getAISuggestion(error);
    }

    console.log(`[ErrorRecovery] Error: ${errorType}, Suggestion: ${suggestion?.command || 'none'}`);

    return { context, suggestion };
  }

  /**
   * Get AI-powered recovery suggestion
   */
  async function getAISuggestion(error: string): Promise<RecoverySuggestion | null> {
    const prompt = applyTemplate(ERROR_RECOVERY_PROMPT, error.substring(0, 200));

    try {
      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'qwen2.5-coder:1.5b',
          prompt,
          stream: false,
        }),
      });

      if (!response.ok) throw new Error('Ollama request failed');

      const data = await response.json();
      const parsed = extractJSON(data.response);

      if (parsed && parsed.suggestion && parsed.command) {
        return {
          description: parsed.suggestion,
          command: parsed.command,
          confidence: 0.6,
          autoApply: false
        };
      }
    } catch (err) {
      console.error('[ErrorRecovery] AI suggestion failed:', err);
    }

    return null;
  }

  /**
   * Apply a recovery suggestion
   */
  async function applyRecovery(
    contextId: string,
    suggestion: RecoverySuggestion,
    execute: (cmd: string) => Promise<string>
  ): Promise<{ success: boolean; output?: string; error?: string }> {
    isRecovering.value = true;

    const context = errorHistory.value.find(e => e.id === contextId);
    if (context) {
      context.retryCount++;
    }

    try {
      const output = await execute(suggestion.command);

      if (context) {
        context.resolved = true;
        context.resolution = suggestion.command;
        saveErrorHistory();
      }

      return { success: true, output };
    } catch (error) {
      return { success: false, error: String(error) };
    } finally {
      isRecovering.value = false;
    }
  }

  /**
   * Retry a failed command with exponential backoff
   */
  async function retryWithBackoff(
    command: string,
    execute: (cmd: string) => Promise<string>,
    options?: {
      maxRetries?: number;
      baseDelay?: number;
      maxDelay?: number;
    }
  ): Promise<{ success: boolean; output?: string; attempts: number }> {
    const maxRetries = options?.maxRetries || 3;
    const baseDelay = options?.baseDelay || 1000;
    const maxDelay = options?.maxDelay || 10000;

    let attempts = 0;
    let lastError = '';

    while (attempts < maxRetries) {
      attempts++;

      try {
        const output = await execute(command);
        return { success: true, output, attempts };
      } catch (error) {
        lastError = String(error);
        console.log(`[ErrorRecovery] Attempt ${attempts}/${maxRetries} failed: ${lastError}`);

        if (attempts < maxRetries) {
          const delay = Math.min(baseDelay * Math.pow(2, attempts - 1), maxDelay);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    return { success: false, attempts };
  }

  /**
   * Auto-fix and retry
   */
  async function autoRecoverAndRetry(
    command: string,
    error: string,
    execute: (cmd: string) => Promise<string>
  ): Promise<{
    recovered: boolean;
    suggestion?: RecoverySuggestion;
    output?: string;
    attempts: number;
  }> {
    const { context, suggestion } = await handleError(command, error);

    // If we have an auto-apply suggestion, try it
    if (suggestion && suggestion.autoApply) {
      console.log(`[ErrorRecovery] Auto-applying fix: ${suggestion.command}`);

      const fixResult = await applyRecovery(context.id, suggestion, execute);

      if (fixResult.success) {
        // Now retry the original command
        const retryResult = await retryWithBackoff(command, execute, { maxRetries: 2 });
        return {
          recovered: retryResult.success,
          suggestion,
          output: retryResult.output,
          attempts: retryResult.attempts
        };
      }
    }

    // If no auto-apply or fix failed, return the suggestion for manual review
    return {
      recovered: false,
      suggestion: suggestion || undefined,
      attempts: 1
    };
  }

  /**
   * Get common errors for learning
   */
  function getCommonErrors(): Array<{ type: ErrorType; count: number }> {
    const counts = new Map<ErrorType, number>();

    for (const error of errorHistory.value) {
      counts.set(error.errorType, (counts.get(error.errorType) || 0) + 1);
    }

    return Array.from(counts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Get error recovery success rate
   */
  function getRecoveryStats(): {
    total: number;
    resolved: number;
    rate: number;
  } {
    const total = errorHistory.value.length;
    const resolved = errorHistory.value.filter(e => e.resolved).length;
    return {
      total,
      resolved,
      rate: total > 0 ? resolved / total : 0
    };
  }

  /**
   * Clear error history
   */
  function clearHistory(): void {
    errorHistory.value = [];
    saveErrorHistory();
  }

  /**
   * Get recent errors
   */
  function getRecentErrors(limit: number = 10): ErrorContext[] {
    return errorHistory.value.slice(-limit).reverse();
  }

  return {
    // State
    errorHistory: computed(() => errorHistory.value),
    isRecovering: computed(() => isRecovering.value),

    // Core recovery
    handleError,
    applyRecovery,
    retryWithBackoff,
    autoRecoverAndRetry,

    // AI
    getAISuggestion,

    // Stats
    getCommonErrors,
    getRecoveryStats,
    getRecentErrors,

    // Management
    clearHistory
  };
}

export default useErrorRecovery;
