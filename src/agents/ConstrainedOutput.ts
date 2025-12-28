/**
 * ConstrainedOutput - JSON schema enforcement for LLM outputs
 *
 * Forces small models to produce valid, structured output by:
 * - Defining strict schemas for tool calls
 * - Parsing and validating responses
 * - Extracting JSON from mixed output
 * - Retrying with corrective prompts on failure
 */

import { invoke } from '@tauri-apps/api/tauri';

// Valid actions the agent can take
export type ActionType = 'read' | 'write' | 'edit' | 'bash' | 'search' | 'think' | 'done' | 'ask';

// Schema for agent actions
export interface AgentAction {
  action: ActionType;
  path?: string;
  content?: string;
  command?: string;
  pattern?: string;
  thought?: string;
  question?: string;
  oldContent?: string;
  newContent?: string;
}

// Validation result
export interface ValidationResult {
  valid: boolean;
  action?: AgentAction;
  error?: string;
  rawOutput?: string;
}

// Schema definitions for each action type
const ACTION_SCHEMAS: Record<ActionType, { required: string[]; optional: string[] }> = {
  read: { required: ['path'], optional: [] },
  write: { required: ['path', 'content'], optional: [] },
  edit: { required: ['path', 'oldContent', 'newContent'], optional: [] },
  bash: { required: ['command'], optional: [] },
  search: { required: ['pattern'], optional: ['path'] },
  think: { required: ['thought'], optional: [] },
  done: { required: [], optional: ['content'] },
  ask: { required: ['question'], optional: [] }
};

export class ConstrainedOutput {
  private maxRetries: number;
  private model: string;

  constructor(options: { maxRetries?: number; model?: string } = {}) {
    this.maxRetries = options.maxRetries ?? 3;
    this.model = options.model ?? 'qwen2.5-coder:1.5b';
  }

  /**
   * Extract JSON from potentially messy LLM output
   */
  extractJSON(output: string): string | null {
    // Try to find JSON object in the output
    const patterns = [
      /\{[\s\S]*\}/,  // Basic JSON object
      /```json\s*([\s\S]*?)\s*```/,  // Markdown code block
      /```\s*([\s\S]*?)\s*```/,  // Generic code block
    ];

    for (const pattern of patterns) {
      const match = output.match(pattern);
      if (match) {
        const jsonStr = match[1] || match[0];
        try {
          JSON.parse(jsonStr);
          return jsonStr;
        } catch {
          continue;
        }
      }
    }

    // Try the whole output as JSON
    try {
      JSON.parse(output);
      return output;
    } catch {
      return null;
    }
  }

  /**
   * Validate an action against its schema
   */
  validateAction(action: unknown): ValidationResult {
    if (!action || typeof action !== 'object') {
      return { valid: false, error: 'Output is not an object' };
    }

    const obj = action as Record<string, unknown>;

    // Check action type exists and is valid
    if (!obj.action || typeof obj.action !== 'string') {
      return { valid: false, error: 'Missing or invalid "action" field' };
    }

    const actionType = obj.action as ActionType;
    if (!ACTION_SCHEMAS[actionType]) {
      return {
        valid: false,
        error: `Invalid action type "${actionType}". Must be one of: ${Object.keys(ACTION_SCHEMAS).join(', ')}`
      };
    }

    // Check required fields
    const schema = ACTION_SCHEMAS[actionType];
    for (const field of schema.required) {
      if (!(field in obj) || obj[field] === undefined || obj[field] === null) {
        return {
          valid: false,
          error: `Missing required field "${field}" for action "${actionType}"`
        };
      }
    }

    // Validate field types
    for (const [key, value] of Object.entries(obj)) {
      if (key !== 'action' && typeof value !== 'string') {
        return {
          valid: false,
          error: `Field "${key}" must be a string, got ${typeof value}`
        };
      }
    }

    return { valid: true, action: obj as AgentAction };
  }

  /**
   * Parse and validate LLM output
   */
  parse(output: string): ValidationResult {
    const rawOutput = output;

    // Extract JSON
    const jsonStr = this.extractJSON(output);
    if (!jsonStr) {
      return {
        valid: false,
        error: 'Could not find valid JSON in output',
        rawOutput
      };
    }

    // Parse JSON
    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonStr);
    } catch (e) {
      return {
        valid: false,
        error: `JSON parse error: ${e instanceof Error ? e.message : 'Unknown error'}`,
        rawOutput
      };
    }

    // Validate against schema
    const result = this.validateAction(parsed);
    result.rawOutput = rawOutput;
    return result;
  }

  /**
   * Generate a corrective prompt for retry
   */
  generateCorrectivePrompt(error: string, originalPrompt: string): string {
    return `${originalPrompt}

IMPORTANT: Your previous response was invalid. Error: ${error}

You MUST respond with ONLY a valid JSON object in this exact format:
{
  "action": "read" | "write" | "edit" | "bash" | "search" | "think" | "done" | "ask",
  "path": "file path (for read/write/edit)",
  "content": "content (for write)",
  "oldContent": "text to replace (for edit)",
  "newContent": "replacement text (for edit)",
  "command": "shell command (for bash)",
  "pattern": "search pattern (for search)",
  "thought": "your reasoning (for think)",
  "question": "question for user (for ask)"
}

Respond with ONLY the JSON, no other text.`;
  }

  /**
   * Query model with constrained output, retrying on failure
   */
  async queryConstrained(prompt: string): Promise<ValidationResult> {
    let currentPrompt = prompt + `

Respond with ONLY a valid JSON object:
{"action": "read|write|edit|bash|search|think|done|ask", ...required fields}`;

    let lastError = '';

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const response = await invoke<string>('query_ollama', {
          prompt: currentPrompt,
          model: this.model
        });

        const result = this.parse(response);

        if (result.valid) {
          return result;
        }

        // Generate corrective prompt for retry
        lastError = result.error || 'Unknown validation error';
        currentPrompt = this.generateCorrectivePrompt(lastError, prompt);

      } catch (e) {
        lastError = e instanceof Error ? e.message : 'Query failed';
      }
    }

    return {
      valid: false,
      error: `Failed after ${this.maxRetries} attempts. Last error: ${lastError}`
    };
  }

  /**
   * Format an action back to JSON string
   */
  formatAction(action: AgentAction): string {
    return JSON.stringify(action, null, 2);
  }

  /**
   * Get the schema help text for prompts
   */
  getSchemaHelp(): string {
    return `Available actions:
- read: Read a file. Required: path
- write: Write/create a file. Required: path, content
- edit: Edit part of a file. Required: path, oldContent, newContent
- bash: Run a shell command. Required: command
- search: Search for files/content. Required: pattern. Optional: path
- think: Express reasoning. Required: thought
- done: Task complete. Optional: content (summary)
- ask: Ask user a question. Required: question`;
  }
}

export default ConstrainedOutput;
