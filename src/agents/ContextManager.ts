/**
 * ContextManager - Sliding window context with summarization
 *
 * Manages context for small LLMs by:
 * - Keeping only recent exchanges in full
 * - Summarizing older history
 * - Retrieving relevant code snippets via simple matching
 * - Staying within token limits
 */

import { invoke } from '@tauri-apps/api/tauri';

export interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
}

export interface FileSnippet {
  path: string;
  content: string;
  relevance: number;
}

export interface ContextState {
  shortTerm: Message[];
  summary: string;
  relevantFiles: FileSnippet[];
  currentTask: string;
  completedSteps: string[];
  errors: string[];
}

export class ContextManager {
  private state: ContextState;
  private maxShortTermMessages: number;
  private maxTokensPerFile: number;
  private maxRelevantFiles: number;
  private summarizeModel: string;

  constructor(options: {
    maxShortTermMessages?: number;
    maxTokensPerFile?: number;
    maxRelevantFiles?: number;
    summarizeModel?: string;
  } = {}) {
    this.maxShortTermMessages = options.maxShortTermMessages ?? 6;
    this.maxTokensPerFile = options.maxTokensPerFile ?? 500;
    this.maxRelevantFiles = options.maxRelevantFiles ?? 3;
    this.summarizeModel = options.summarizeModel ?? 'tinydolphin:1.1b';

    this.state = {
      shortTerm: [],
      summary: '',
      relevantFiles: [],
      currentTask: '',
      completedSteps: [],
      errors: []
    };
  }

  /**
   * Add a message to context, auto-summarizing if needed
   */
  async addMessage(message: Message): Promise<void> {
    this.state.shortTerm.push(message);

    // If we exceed limit, summarize oldest messages
    if (this.state.shortTerm.length > this.maxShortTermMessages) {
      await this.compressOldMessages();
    }
  }

  /**
   * Compress old messages into summary
   */
  private async compressOldMessages(): Promise<void> {
    const toCompress = this.state.shortTerm.splice(0, 2);

    const compressPrompt = `Summarize this conversation in 1-2 sentences, focusing on what was done:

Previous summary: ${this.state.summary || 'None'}

New messages:
${toCompress.map(m => `${m.role}: ${m.content.slice(0, 200)}`).join('\n')}

Summary:`;

    try {
      const newSummary = await invoke<string>('query_ollama', {
        prompt: compressPrompt,
        model: this.summarizeModel
      });
      this.state.summary = newSummary.trim();
    } catch (e) {
      // Fallback: just concatenate
      this.state.summary += ` ${toCompress.map(m => m.content.slice(0, 50)).join('. ')}`;
    }
  }

  /**
   * Set the current task being worked on
   */
  setTask(task: string): void {
    this.state.currentTask = task;
    this.state.completedSteps = [];
    this.state.errors = [];
  }

  /**
   * Mark a step as completed
   */
  completeStep(step: string): void {
    this.state.completedSteps.push(step);
  }

  /**
   * Add an error for context
   */
  addError(error: string): void {
    this.state.errors.push(error);
    // Keep only last 3 errors
    if (this.state.errors.length > 3) {
      this.state.errors.shift();
    }
  }

  /**
   * Find relevant files based on keywords
   */
  async findRelevantFiles(keywords: string[]): Promise<void> {
    const relevantFiles: FileSnippet[] = [];

    for (const keyword of keywords) {
      try {
        // Use grep to find files containing keyword
        const files = await invoke<string[]>('grep_files', {
          pattern: keyword,
          path: '.',
          maxResults: 5
        });

        for (const file of files.slice(0, 2)) {
          try {
            const content = await invoke<string>('read_file', { path: file });
            relevantFiles.push({
              path: file,
              content: this.truncateContent(content),
              relevance: this.calculateRelevance(content, keywords)
            });
          } catch (e) {
            // Skip unreadable files
          }
        }
      } catch (e) {
        // Grep failed, continue
      }
    }

    // Sort by relevance and keep top N
    this.state.relevantFiles = relevantFiles
      .sort((a, b) => b.relevance - a.relevance)
      .slice(0, this.maxRelevantFiles);
  }

  /**
   * Truncate file content to stay within limits
   */
  private truncateContent(content: string): string {
    const lines = content.split('\n');
    let result = '';
    let tokens = 0;

    for (const line of lines) {
      const lineTokens = Math.ceil(line.length / 4); // Rough estimate
      if (tokens + lineTokens > this.maxTokensPerFile) break;
      result += line + '\n';
      tokens += lineTokens;
    }

    return result;
  }

  /**
   * Calculate relevance score for a file
   */
  private calculateRelevance(content: string, keywords: string[]): number {
    const lowerContent = content.toLowerCase();
    return keywords.reduce((score, kw) => {
      const matches = (lowerContent.match(new RegExp(kw.toLowerCase(), 'g')) || []).length;
      return score + matches;
    }, 0);
  }

  /**
   * Build the final prompt with managed context
   */
  buildPrompt(instruction: string): string {
    const parts: string[] = [];

    // System context
    parts.push(`You are a coding assistant. Respond with ONE action only in JSON format.`);

    // Summary of past work
    if (this.state.summary) {
      parts.push(`\n## Work so far:\n${this.state.summary}`);
    }

    // Current task
    if (this.state.currentTask) {
      parts.push(`\n## Current task:\n${this.state.currentTask}`);
    }

    // Completed steps
    if (this.state.completedSteps.length > 0) {
      parts.push(`\n## Completed steps:\n${this.state.completedSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`);
    }

    // Relevant files
    if (this.state.relevantFiles.length > 0) {
      parts.push(`\n## Relevant code:`);
      for (const file of this.state.relevantFiles) {
        parts.push(`\n### ${file.path}\n\`\`\`\n${file.content}\n\`\`\``);
      }
    }

    // Recent errors
    if (this.state.errors.length > 0) {
      parts.push(`\n## Recent errors (avoid these):\n${this.state.errors.join('\n')}`);
    }

    // Recent conversation
    if (this.state.shortTerm.length > 0) {
      parts.push(`\n## Recent conversation:`);
      for (const msg of this.state.shortTerm.slice(-4)) {
        parts.push(`${msg.role}: ${msg.content.slice(0, 300)}`);
      }
    }

    // Current instruction
    parts.push(`\n## Your task now:\n${instruction}`);

    // Output format reminder
    parts.push(`\nRespond with valid JSON: {"action": "read|write|edit|bash|done", "path": "...", "content": "..."}`);

    return parts.join('\n');
  }

  /**
   * Get current state for checkpointing
   */
  getState(): ContextState {
    return JSON.parse(JSON.stringify(this.state));
  }

  /**
   * Restore from checkpoint
   */
  restoreState(state: ContextState): void {
    this.state = JSON.parse(JSON.stringify(state));
  }

  /**
   * Clear all context
   */
  clear(): void {
    this.state = {
      shortTerm: [],
      summary: '',
      relevantFiles: [],
      currentTask: '',
      completedSteps: [],
      errors: []
    };
  }

  /**
   * Estimate current token usage
   */
  estimateTokens(): number {
    const prompt = this.buildPrompt('');
    return Math.ceil(prompt.length / 4);
  }
}

export default ContextManager;
