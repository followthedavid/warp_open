/**
 * Context Compression System
 * Compress conversation context while preserving key information.
 * Implements /compact functionality like Claude Code.
 *
 * Enhanced with:
 * - Incremental compression (compress as you go)
 * - Key fact extraction
 * - File context tracking
 * - Command history
 * - Prompt formatting for small LLMs
 */

import { ref, computed } from 'vue';
import { CONTEXT_SUMMARY_PROMPT, applyTemplate } from './usePromptTemplates';

// Check if we're running in Tauri
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp?: number;
  toolCalls?: Array<{
    tool: string;
    args: Record<string, unknown>;
    result: string;
  }>;
}

export interface CompressionResult {
  originalMessages: number;
  compressedMessages: number;
  originalTokens: number;
  compressedTokens: number;
  compressionRatio: number;
  summary: string;
  preservedContext: string[];
}

export interface CompressionOptions {
  preservePatterns?: string[]; // Regex patterns to preserve
  preserveLastN?: number; // Keep last N messages verbatim
  maxSummaryTokens?: number;
  includeToolCalls?: boolean;
  preserveErrors?: boolean;
  preserveDecisions?: boolean;
}

const DEFAULT_OPTIONS: CompressionOptions = {
  preservePatterns: [],
  preserveLastN: 4,
  maxSummaryTokens: 2000,
  includeToolCalls: true,
  preserveErrors: true,
  preserveDecisions: true,
};

// Patterns that indicate important context
const IMPORTANT_PATTERNS = [
  /error|exception|failed|bug/i,
  /decided|chosen|selected|using/i,
  /important|critical|must|required/i,
  /todo|task|step \d+/i,
  /file created|file modified|file deleted/i,
  /\bapi\b|\bkey\b|\btoken\b|\bsecret\b/i,
];

// State
const isCompressing = ref(false);
const lastCompression = ref<CompressionResult | null>(null);

// Incremental compression state
const incrementalSummary = ref<string>('');
const keyFacts = ref<string[]>([]);
const fileContext = ref<Map<string, string>>(new Map());
const commandHistory = ref<string[]>([]);

// Configuration for incremental compression
const INCREMENTAL_CONFIG = {
  MAX_RECENT_MESSAGES: 6,
  MAX_KEY_FACTS: 10,
  MAX_COMMAND_HISTORY: 10,
  MAX_SUMMARY_LENGTH: 500,
  COMPRESS_THRESHOLD: 10
};

export function useContextCompression() {
  /**
   * Estimate token count (rough approximation)
   */
  function estimateTokens(text: string): number {
    // Rough estimate: ~4 chars per token
    return Math.ceil(text.length / 4);
  }

  /**
   * Check if message contains important content
   */
  function isImportantMessage(message: Message, options: CompressionOptions): boolean {
    const content = message.content;

    // Check for errors
    if (options.preserveErrors && /error|exception|failed/i.test(content)) {
      return true;
    }

    // Check for decisions
    if (options.preserveDecisions && /decided|chosen|selected|confirmed/i.test(content)) {
      return true;
    }

    // Check user-specified patterns
    if (options.preservePatterns) {
      for (const pattern of options.preservePatterns) {
        if (new RegExp(pattern, 'i').test(content)) {
          return true;
        }
      }
    }

    // Check built-in important patterns
    for (const pattern of IMPORTANT_PATTERNS) {
      if (pattern.test(content)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Extract key points from a message
   */
  function extractKeyPoints(message: Message): string[] {
    const points: string[] = [];
    const content = message.content;

    // Extract file operations
    const fileMatches = content.match(/(?:created|modified|deleted|read|wrote to)\s+[`'"]([\w./\-]+)[`'"]/gi);
    if (fileMatches) {
      points.push(...fileMatches);
    }

    // Extract commands executed
    const cmdMatches = content.match(/(?:ran|executed|running):\s*`([^`]+)`/gi);
    if (cmdMatches) {
      points.push(...cmdMatches);
    }

    // Extract decisions
    const decisionMatches = content.match(/(?:decided to|chose to|will|going to)\s+[^.!?]+[.!?]/gi);
    if (decisionMatches) {
      points.push(...decisionMatches);
    }

    // Extract errors
    const errorMatches = content.match(/(?:error|failed|exception):[^.!?\n]+/gi);
    if (errorMatches) {
      points.push(...errorMatches);
    }

    return points;
  }

  /**
   * Summarize tool calls
   */
  function summarizeToolCalls(toolCalls: Message['toolCalls']): string {
    if (!toolCalls || toolCalls.length === 0) return '';

    const summary: string[] = [];

    for (const call of toolCalls) {
      switch (call.tool) {
        case 'read_file':
          summary.push(`Read: ${call.args.path}`);
          break;
        case 'write_file':
          summary.push(`Created: ${call.args.path}`);
          break;
        case 'edit_file':
          summary.push(`Edited: ${call.args.path}`);
          break;
        case 'execute_shell':
          summary.push(`Ran: ${(call.args.command as string).slice(0, 50)}`);
          break;
        case 'glob_files':
          summary.push(`Found files: ${call.args.pattern}`);
          break;
        case 'grep_files':
          summary.push(`Searched: ${call.args.pattern}`);
          break;
        default:
          summary.push(`${call.tool}: ${JSON.stringify(call.args).slice(0, 30)}`);
      }
    }

    return summary.join('\n');
  }

  /**
   * Compress messages using AI summarization
   */
  async function compressWithAI(
    messages: Message[],
    options: CompressionOptions = {}
  ): Promise<{ summary: string; keyPoints: string[] }> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const opts = { ...DEFAULT_OPTIONS, ...options };

    // Build context for summarization
    let context = 'Summarize this conversation, preserving:\n';
    context += '- Key decisions made\n';
    context += '- Files created/modified\n';
    context += '- Commands executed and their outcomes\n';
    context += '- Any errors encountered\n';
    context += '- Current state of the task\n\n';

    context += 'Conversation:\n\n';

    for (const msg of messages) {
      context += `[${msg.role.toUpperCase()}]: ${msg.content.slice(0, 500)}\n`;
      if (msg.toolCalls && opts.includeToolCalls) {
        context += `Tool calls: ${summarizeToolCalls(msg.toolCalls)}\n`;
      }
      context += '\n';
    }

    // Query AI for summary
    const summary = await invoke<string>('query_ollama', {
      model: 'qwen2.5-coder:1.5b', // Fast model for summarization
      prompt: context,
      maxTokens: opts.maxSummaryTokens,
    });

    // Extract key points from all messages
    const keyPoints: string[] = [];
    for (const msg of messages) {
      keyPoints.push(...extractKeyPoints(msg));
    }

    return { summary, keyPoints: [...new Set(keyPoints)] };
  }

  /**
   * Compress conversation context
   */
  async function compress(
    messages: Message[],
    options: CompressionOptions = {}
  ): Promise<{ messages: Message[]; result: CompressionResult }> {
    isCompressing.value = true;

    const opts = { ...DEFAULT_OPTIONS, ...options };

    try {
      const originalTokens = estimateTokens(messages.map(m => m.content).join(''));

      // Keep last N messages verbatim
      const preserveCount = opts.preserveLastN || 4;
      const toPreserve = messages.slice(-preserveCount);
      const toCompress = messages.slice(0, -preserveCount);

      if (toCompress.length === 0) {
        // Nothing to compress
        const result: CompressionResult = {
          originalMessages: messages.length,
          compressedMessages: messages.length,
          originalTokens,
          compressedTokens: originalTokens,
          compressionRatio: 1,
          summary: '',
          preservedContext: [],
        };
        lastCompression.value = result;
        return { messages, result };
      }

      // Find important messages to preserve
      const importantMessages = toCompress.filter(m => isImportantMessage(m, opts));

      // Summarize the rest
      const { summary, keyPoints } = await compressWithAI(toCompress, opts);

      // Build compressed message list
      const compressedMessages: Message[] = [];

      // Add system message with summary
      compressedMessages.push({
        role: 'system',
        content: `[Context Summary]\n${summary}\n\n[Key Points]\n${keyPoints.join('\n')}`,
        timestamp: Date.now(),
      });

      // Add important messages
      for (const msg of importantMessages) {
        compressedMessages.push({
          ...msg,
          content: `[Preserved] ${msg.content}`,
        });
      }

      // Add preserved recent messages
      compressedMessages.push(...toPreserve);

      const compressedTokens = estimateTokens(compressedMessages.map(m => m.content).join(''));

      const result: CompressionResult = {
        originalMessages: messages.length,
        compressedMessages: compressedMessages.length,
        originalTokens,
        compressedTokens,
        compressionRatio: compressedTokens / originalTokens,
        summary,
        preservedContext: keyPoints,
      };

      lastCompression.value = result;

      console.log(`[Context] Compressed ${messages.length} messages to ${compressedMessages.length} (${(result.compressionRatio * 100).toFixed(1)}% of original)`);

      return { messages: compressedMessages, result };
    } finally {
      isCompressing.value = false;
    }
  }

  /**
   * Quick compression without AI (just truncation + key points)
   */
  function quickCompress(
    messages: Message[],
    maxMessages: number = 20
  ): Message[] {
    if (messages.length <= maxMessages) {
      return messages;
    }

    const toKeep = Math.floor(maxMessages / 2);
    const important: Message[] = [];
    const recent = messages.slice(-toKeep);

    // Find important messages from the beginning
    for (const msg of messages.slice(0, -toKeep)) {
      if (isImportantMessage(msg, DEFAULT_OPTIONS)) {
        important.push(msg);
        if (important.length >= toKeep) break;
      }
    }

    // Build summary of truncated messages
    const truncatedCount = messages.length - recent.length - important.length;
    const summaryMsg: Message = {
      role: 'system',
      content: `[${truncatedCount} earlier messages compressed. Key points preserved below.]`,
      timestamp: Date.now(),
    };

    return [summaryMsg, ...important, ...recent];
  }

  /**
   * Get compression statistics
   */
  function getCompressionStats(): CompressionResult | null {
    return lastCompression.value;
  }

  /**
   * Estimate savings from compression
   */
  function estimateCompression(messages: Message[]): {
    currentTokens: number;
    estimatedAfter: number;
    potentialSavings: number;
  } {
    const currentTokens = estimateTokens(messages.map(m => m.content).join(''));
    const importantCount = messages.filter(m => isImportantMessage(m, DEFAULT_OPTIONS)).length;
    const estimatedAfter = Math.ceil(currentTokens * 0.3) + (importantCount * 100);

    return {
      currentTokens,
      estimatedAfter,
      potentialSavings: currentTokens - estimatedAfter,
    };
  }

  /**
   * Check if compression is recommended
   */
  function shouldCompress(messages: Message[], tokenLimit: number = 50000): boolean {
    const tokens = estimateTokens(messages.map(m => m.content).join(''));
    return tokens > tokenLimit * 0.7; // Compress at 70% capacity
  }

  // ============================================================================
  // INCREMENTAL COMPRESSION - Compress as conversation grows
  // ============================================================================

  /**
   * Extract key facts from a message for incremental tracking
   */
  function extractFactsFromMessage(message: Message): string[] {
    const facts: string[] = [];
    const content = message.content.toLowerCase();

    // File operations
    const fileMatch = content.match(/(?:created?|wrote?|modified?|deleted?|read)\s+['"]?([^\s'"]+)['"]?/i);
    if (fileMatch) {
      facts.push(`File ${fileMatch[1]} was ${fileMatch[0].split(' ')[0]}`);
    }

    // Command execution
    const cmdMatch = content.match(/\$\s*(.+)/);
    if (cmdMatch) {
      facts.push(`Ran: ${cmdMatch[1].substring(0, 50)}`);
      // Add to command history
      if (!commandHistory.value.includes(cmdMatch[1])) {
        commandHistory.value.push(cmdMatch[1]);
        if (commandHistory.value.length > INCREMENTAL_CONFIG.MAX_COMMAND_HISTORY) {
          commandHistory.value.shift();
        }
      }
    }

    // Error mentions
    if (content.includes('error') || content.includes('failed')) {
      const errorLine = content.split('\n').find(line =>
        line.toLowerCase().includes('error') || line.toLowerCase().includes('failed')
      );
      if (errorLine) {
        facts.push(`Error: ${errorLine.substring(0, 80)}`);
      }
    }

    return facts;
  }

  /**
   * Update file context from message
   */
  function updateFileContext(message: Message): void {
    const content = message.content;

    // Look for file content patterns
    const fileMatch = content.match(/File:\s*([^\n]+)\n([\s\S]*?)(?=\n\n|$)/);
    if (fileMatch) {
      fileContext.value.set(fileMatch[1], fileMatch[2].substring(0, 150) + '...');
    }

    // Look for "wrote to" patterns
    const writeMatch = content.match(/(?:wrote to|created)\s+([^\s]+)/i);
    if (writeMatch) {
      fileContext.value.set(writeMatch[1], '[modified]');
    }
  }

  /**
   * Add message and incrementally update context
   */
  async function addMessageIncremental(message: Message): Promise<void> {
    // Extract facts
    const newFacts = extractFactsFromMessage(message);
    for (const fact of newFacts) {
      if (!keyFacts.value.includes(fact)) {
        keyFacts.value.push(fact);
      }
    }

    // Trim facts if too many
    while (keyFacts.value.length > INCREMENTAL_CONFIG.MAX_KEY_FACTS) {
      keyFacts.value.shift();
    }

    // Update file context
    updateFileContext(message);
  }

  /**
   * Generate summary for incremental compression using local LLM
   */
  async function updateIncrementalSummary(messages: Message[]): Promise<void> {
    if (messages.length === 0) return;

    const content = messages.map(m =>
      `${m.role}: ${m.content.substring(0, 150)}`
    ).join('\n');

    const prompt = applyTemplate(CONTEXT_SUMMARY_PROMPT, content);

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

      if (response.ok) {
        const data = await response.json();
        const newSummary = data.response.trim();

        // Append to existing summary
        if (incrementalSummary.value) {
          incrementalSummary.value = incrementalSummary.value + '\n' + newSummary;
        } else {
          incrementalSummary.value = newSummary;
        }

        // Trim if too long
        if (incrementalSummary.value.length > INCREMENTAL_CONFIG.MAX_SUMMARY_LENGTH) {
          incrementalSummary.value = incrementalSummary.value.substring(
            incrementalSummary.value.length - INCREMENTAL_CONFIG.MAX_SUMMARY_LENGTH
          );
        }
      }
    } catch (error) {
      console.error('[ContextCompression] Incremental summary failed:', error);
    }
  }

  /**
   * Format context as a prompt prefix for small LLMs
   */
  function formatContextPrompt(): string {
    const parts: string[] = [];

    // Add summary if exists
    if (incrementalSummary.value) {
      parts.push(`Previous:\n${incrementalSummary.value}`);
    }

    // Add key facts
    if (keyFacts.value.length > 0) {
      parts.push(`Facts:\n${keyFacts.value.slice(-5).map(f => `• ${f}`).join('\n')}`);
    }

    // Add recent commands
    if (commandHistory.value.length > 0) {
      parts.push(`Commands:\n${commandHistory.value.slice(-3).map(c => `$ ${c}`).join('\n')}`);
    }

    return parts.length > 0 ? parts.join('\n\n') + '\n\n' : '';
  }

  /**
   * Get incremental compression stats
   */
  function getIncrementalStats() {
    return {
      summaryLength: incrementalSummary.value.length,
      keyFactCount: keyFacts.value.length,
      fileContextCount: fileContext.value.size,
      commandHistoryCount: commandHistory.value.length,
      estimatedTokens: estimateTokens(formatContextPrompt())
    };
  }

  /**
   * Clear incremental state
   */
  function clearIncrementalState(): void {
    incrementalSummary.value = '';
    keyFacts.value = [];
    fileContext.value = new Map();
    commandHistory.value = [];
  }

  return {
    // State
    isCompressing: computed(() => isCompressing.value),
    lastCompression: computed(() => lastCompression.value),

    // Compression methods
    compress,
    quickCompress,

    // Analysis
    estimateTokens,
    estimateCompression,
    shouldCompress,
    getCompressionStats,
    isImportantMessage,
    extractKeyPoints,

    // Incremental compression (for small LLMs)
    addMessageIncremental,
    updateIncrementalSummary,
    formatContextPrompt,
    getIncrementalStats,
    clearIncrementalState,

    // Expose incremental state
    incrementalSummary,
    keyFacts,
    fileContext,
    commandHistory
  };
}
