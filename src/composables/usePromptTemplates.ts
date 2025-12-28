/**
 * Prompt Templates for Small LLMs
 * Optimized for qwen2.5-coder:1.5b and similar small models
 *
 * Design principles:
 * 1. SHORT prompts (reduce token overhead)
 * 2. EXPLICIT format requirements
 * 3. FEW-SHOT examples (3-5 showing exact format)
 * 4. STRUCTURED output (JSON only)
 * 5. NO verbose explanations
 * 6. FALLBACK parsing for common errors
 */

// ============================================================================
// TASK ANALYSIS - Determine if message is actionable
// ============================================================================

export const TASK_ANALYSIS_PROMPT = `Analyze if this is actionable. JSON only.

EXAMPLES:
User: "list files" → {"isActionable":true,"taskType":"command","taskDescription":"list files"}
User: "what is node?" → {"isActionable":false,"taskType":"conversation","taskDescription":"question about node"}
User: "create test.txt" → {"isActionable":true,"taskType":"file_operation","taskDescription":"create file test.txt"}
User: "run npm install" → {"isActionable":true,"taskType":"command","taskDescription":"run npm install"}
User: "how are you?" → {"isActionable":false,"taskType":"conversation","taskDescription":"greeting"}

User: "$INPUT"
JSON:`;

// ============================================================================
// COMMAND GENERATION - Convert task to shell command
// ============================================================================

export const COMMAND_GEN_PROMPT = `Convert to shell command. JSON array only.

EXAMPLES:
Task: "list files" → [{"type":"command","title":"List files","content":"ls -la"}]
Task: "show date" → [{"type":"command","title":"Show date","content":"date"}]
Task: "disk space" → [{"type":"command","title":"Disk usage","content":"df -h"}]
Task: "create hello.py with print hello" → [{"type":"command","title":"Create script","content":"echo 'print(\"Hello\")' > hello.py"}]
Task: "run tests" → [{"type":"command","title":"Run tests","content":"npm test"}]
Task: "find py files" → [{"type":"command","title":"Find Python files","content":"find . -name '*.py' 2>/dev/null | head -20"}]

Task: "$INPUT"
JSON:`;

// ============================================================================
// MULTI-STEP PLAN - Complex tasks requiring multiple commands
// ============================================================================

export const MULTI_STEP_PROMPT = `Break into shell commands. JSON array only.

EXAMPLES:
Task: "create and run hello.py" → [{"type":"command","title":"Create script","content":"echo 'print(\"Hello\")' > hello.py"},{"type":"command","title":"Run script","content":"python3 hello.py"}]
Task: "install deps and run dev" → [{"type":"command","title":"Install","content":"npm install"},{"type":"command","title":"Run dev","content":"npm run dev"}]
Task: "git add and commit" → [{"type":"command","title":"Stage changes","content":"git add ."},{"type":"command","title":"Commit","content":"git commit -m 'Update'"}]

Task: "$INPUT"
JSON:`;

// ============================================================================
// FILE OPERATIONS - Read, write, edit files
// ============================================================================

export const FILE_READ_PROMPT = `Extract file path. JSON only.

EXAMPLES:
"show package.json" → {"action":"read","path":"package.json"}
"cat src/main.ts" → {"action":"read","path":"src/main.ts"}
"read the readme" → {"action":"read","path":"README.md"}
"what's in .env" → {"action":"read","path":".env"}

"$INPUT"
JSON:`;

export const FILE_WRITE_PROMPT = `Extract file path and content. JSON only.

EXAMPLES:
"create test.txt with hello" → {"action":"write","path":"test.txt","content":"hello"}
"write console.log to app.js" → {"action":"write","path":"app.js","content":"console.log()"}
"make config.json with {}" → {"action":"write","path":"config.json","content":"{}"}

"$INPUT"
JSON:`;

// ============================================================================
// GIT OPERATIONS
// ============================================================================

export const GIT_COMMIT_PROMPT = `Generate commit message for these changes. One line, present tense.

EXAMPLES:
Changes: "added login form" → "Add login form component"
Changes: "fixed null check" → "Fix null pointer check in auth"
Changes: "updated deps" → "Update dependencies"

Changes: "$INPUT"
Message:`;

export const GIT_BRANCH_PROMPT = `Suggest branch name. Lowercase with hyphens.

EXAMPLES:
Task: "add login page" → "feature/add-login-page"
Task: "fix auth bug" → "fix/auth-bug"
Task: "update readme" → "docs/update-readme"

Task: "$INPUT"
Branch:`;

// ============================================================================
// ERROR RECOVERY - Suggest fixes for failed commands
// ============================================================================

export const ERROR_RECOVERY_PROMPT = `Suggest fix for this error. JSON only.

EXAMPLES:
Error: "command not found: node" → {"suggestion":"Install Node.js","command":"brew install node"}
Error: "ENOENT: no such file" → {"suggestion":"File doesn't exist","command":"touch $FILE"}
Error: "permission denied" → {"suggestion":"Add execute permission","command":"chmod +x $FILE"}
Error: "npm ERR! missing script" → {"suggestion":"Check package.json scripts","command":"npm run"}

Error: "$INPUT"
JSON:`;

// ============================================================================
// CONTEXT COMPRESSION - Summarize conversation history
// ============================================================================

export const CONTEXT_SUMMARY_PROMPT = `Summarize key facts from this conversation. Bullet points only.

EXAMPLES:
Input: "User asked to list files. AI showed ls -la output with 10 files." → "• Listed 10 files in current directory"
Input: "User created hello.py. AI wrote print statement. User ran it. Output was Hello." → "• Created hello.py with print('Hello')\\n• Ran successfully, output: Hello"

Input: "$INPUT"
Summary:`;

// ============================================================================
// CODE EXPLANATION - Explain code to user
// ============================================================================

export const CODE_EXPLAIN_PROMPT = `Explain this code briefly. 1-2 sentences.

EXAMPLES:
Code: "const x = arr.filter(n => n > 0)" → "Filters array to keep only positive numbers."
Code: "async function fetch() { await api.get() }" → "Async function that calls API and waits for response."
Code: "import { ref } from 'vue'" → "Imports Vue's reactive ref for state management."

Code: "$INPUT"
Explanation:`;

// ============================================================================
// INTENT CLASSIFICATION - Quick intent detection
// ============================================================================

export const INTENT_PROMPT = `Classify intent. One word only.

EXAMPLES:
"list files" → FILE
"run npm start" → COMMAND
"what is react" → QUESTION
"create app.js" → FILE
"git status" → GIT
"hello there" → CHAT
"docker ps" → DOCKER
"install lodash" → NPM

"$INPUT"
Intent:`;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Apply input to a template
 */
export function applyTemplate(template: string, input: string): string {
  return template.replace('$INPUT', input.trim());
}

/**
 * Apply multiple inputs to a template
 */
export function applyTemplateMulti(template: string, inputs: Record<string, string>): string {
  let result = template;
  for (const [key, value] of Object.entries(inputs)) {
    result = result.replace(`$${key}`, value.trim());
  }
  return result;
}

/**
 * Extract JSON from LLM response (handles common errors)
 */
export function extractJSON(response: string): any {
  const text = response.trim();

  // Try direct parse first
  try {
    return JSON.parse(text);
  } catch {}

  // Try to extract from code block
  const codeBlockMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (codeBlockMatch) {
    try {
      return JSON.parse(codeBlockMatch[1].trim());
    } catch {}
  }

  // Try to find JSON object or array
  const jsonMatch = text.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
  if (jsonMatch) {
    try {
      return JSON.parse(jsonMatch[1]);
    } catch {}
  }

  // Try to fix common LLM mistakes
  let fixed = text
    .replace(/'/g, '"')  // Single to double quotes
    .replace(/(\w+):/g, '"$1":')  // Unquoted keys
    .replace(/,\s*}/g, '}')  // Trailing commas
    .replace(/,\s*]/g, ']');

  try {
    return JSON.parse(fixed);
  } catch {}

  // Return null if all parsing fails
  return null;
}

/**
 * Validate command output from LLM
 */
export function validateCommandOutput(output: any): { valid: boolean; steps: any[]; error?: string } {
  if (!output) {
    return { valid: false, steps: [], error: 'Failed to parse LLM output' };
  }

  // Ensure it's an array
  const steps = Array.isArray(output) ? output : [output];

  // Validate each step
  const validSteps = steps.filter(step => {
    if (!step || typeof step !== 'object') return false;
    if (!step.content && !step.command) return false;
    return true;
  }).map(step => ({
    type: step.type || 'command',
    title: step.title || 'Execute',
    content: step.content || step.command || ''
  }));

  if (validSteps.length === 0) {
    return { valid: false, steps: [], error: 'No valid steps in output' };
  }

  return { valid: true, steps: validSteps };
}

/**
 * Quick intent detection using keyword matching (bypass LLM)
 */
export function detectIntent(input: string): string {
  const lower = input.toLowerCase().trim();

  // File operations
  if (/^(ls|list|dir|cat|read|show|view|create|touch|mkdir|rm|delete|find|search|tree)/.test(lower)) {
    return 'FILE';
  }

  // Git operations
  if (/^git|^(status|commit|push|pull|branch|log|diff|stash|merge|rebase)/.test(lower)) {
    return 'GIT';
  }

  // NPM operations
  if (/^npm|^(install|test|run|build|start|dev)/.test(lower)) {
    return 'NPM';
  }

  // Docker operations
  if (/^docker|^(container|image|compose)/.test(lower)) {
    return 'DOCKER';
  }

  // Questions
  if (/^(what|how|why|when|where|who|which|can|does|is|are|explain|describe)/.test(lower)) {
    return 'QUESTION';
  }

  // Greetings
  if (/^(hi|hello|hey|thanks|thank|bye|goodbye)/.test(lower)) {
    return 'CHAT';
  }

  // Default to command
  return 'COMMAND';
}

/**
 * Get appropriate prompt template based on intent
 */
export function getPromptForIntent(intent: string): string {
  switch (intent) {
    case 'FILE':
      return COMMAND_GEN_PROMPT;
    case 'GIT':
      return COMMAND_GEN_PROMPT;
    case 'NPM':
      return COMMAND_GEN_PROMPT;
    case 'DOCKER':
      return COMMAND_GEN_PROMPT;
    case 'QUESTION':
      return ''; // Don't use LLM for commands on questions
    case 'CHAT':
      return ''; // Don't use LLM for commands on chat
    default:
      return COMMAND_GEN_PROMPT;
  }
}

export default {
  TASK_ANALYSIS_PROMPT,
  COMMAND_GEN_PROMPT,
  MULTI_STEP_PROMPT,
  FILE_READ_PROMPT,
  FILE_WRITE_PROMPT,
  GIT_COMMIT_PROMPT,
  GIT_BRANCH_PROMPT,
  ERROR_RECOVERY_PROMPT,
  CONTEXT_SUMMARY_PROMPT,
  CODE_EXPLAIN_PROMPT,
  INTENT_PROMPT,
  applyTemplate,
  applyTemplateMulti,
  extractJSON,
  validateCommandOutput,
  detectIntent,
  getPromptForIntent
};
