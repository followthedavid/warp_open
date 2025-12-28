/**
 * Next Command Prediction System
 * Predicts likely next commands based on context, history, and patterns.
 * Similar to Warp Terminal's "Warp AI" suggestions.
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

export interface CommandPrediction {
  command: string;
  description: string;
  confidence: number;
  source: 'pattern' | 'history' | 'ai' | 'context';
  category?: string;
}

export interface CommandContext {
  currentDirectory: string;
  lastCommands: string[];
  lastOutput?: string;
  gitStatus?: {
    branch: string;
    hasChanges: boolean;
    untrackedFiles: number;
  };
  projectType?: string; // 'node', 'python', 'rust', etc.
  errorContext?: string;
}

export interface PredictionConfig {
  maxPredictions: number;
  useAI: boolean;
  usePatterns: boolean;
  useHistory: boolean;
  minConfidence: number;
  contextWindow: number; // number of last commands to consider
}

// Common command patterns by context
const COMMAND_PATTERNS: Record<string, Array<{ pattern: RegExp; next: CommandPrediction[] }>> = {
  git: [
    {
      pattern: /^git add/,
      next: [
        { command: 'git commit -m ""', description: 'Commit staged changes', confidence: 0.9, source: 'pattern', category: 'git' },
        { command: 'git status', description: 'Check current status', confidence: 0.7, source: 'pattern', category: 'git' },
        { command: 'git diff --staged', description: 'View staged changes', confidence: 0.6, source: 'pattern', category: 'git' },
      ],
    },
    {
      pattern: /^git commit/,
      next: [
        { command: 'git push', description: 'Push to remote', confidence: 0.85, source: 'pattern', category: 'git' },
        { command: 'git log --oneline -5', description: 'View recent commits', confidence: 0.5, source: 'pattern', category: 'git' },
      ],
    },
    {
      pattern: /^git pull/,
      next: [
        { command: 'git log --oneline -5', description: 'See what was pulled', confidence: 0.7, source: 'pattern', category: 'git' },
        { command: 'git status', description: 'Check status', confidence: 0.6, source: 'pattern', category: 'git' },
      ],
    },
    {
      pattern: /^git checkout -b/,
      next: [
        { command: 'git push -u origin HEAD', description: 'Push new branch to remote', confidence: 0.8, source: 'pattern', category: 'git' },
      ],
    },
    {
      pattern: /^git stash$/,
      next: [
        { command: 'git stash pop', description: 'Apply stashed changes', confidence: 0.7, source: 'pattern', category: 'git' },
        { command: 'git stash list', description: 'List stashes', confidence: 0.6, source: 'pattern', category: 'git' },
      ],
    },
  ],
  npm: [
    {
      pattern: /^npm install/,
      next: [
        { command: 'npm run dev', description: 'Start development server', confidence: 0.7, source: 'pattern', category: 'npm' },
        { command: 'npm run build', description: 'Build project', confidence: 0.6, source: 'pattern', category: 'npm' },
        { command: 'npm test', description: 'Run tests', confidence: 0.5, source: 'pattern', category: 'npm' },
      ],
    },
    {
      pattern: /^npm run build/,
      next: [
        { command: 'npm run start', description: 'Start production server', confidence: 0.7, source: 'pattern', category: 'npm' },
        { command: 'npm run preview', description: 'Preview build', confidence: 0.6, source: 'pattern', category: 'npm' },
      ],
    },
    {
      pattern: /^npm test/,
      next: [
        { command: 'npm test -- --watch', description: 'Run tests in watch mode', confidence: 0.6, source: 'pattern', category: 'npm' },
        { command: 'npm test -- --coverage', description: 'Run with coverage', confidence: 0.5, source: 'pattern', category: 'npm' },
      ],
    },
  ],
  docker: [
    {
      pattern: /^docker build/,
      next: [
        { command: 'docker run -it', description: 'Run the built image', confidence: 0.8, source: 'pattern', category: 'docker' },
        { command: 'docker images', description: 'List images', confidence: 0.5, source: 'pattern', category: 'docker' },
      ],
    },
    {
      pattern: /^docker-compose up/,
      next: [
        { command: 'docker-compose logs -f', description: 'Follow logs', confidence: 0.7, source: 'pattern', category: 'docker' },
        { command: 'docker-compose down', description: 'Stop services', confidence: 0.5, source: 'pattern', category: 'docker' },
      ],
    },
  ],
  python: [
    {
      pattern: /^pip install/,
      next: [
        { command: 'pip freeze > requirements.txt', description: 'Save dependencies', confidence: 0.6, source: 'pattern', category: 'python' },
        { command: 'python main.py', description: 'Run main script', confidence: 0.5, source: 'pattern', category: 'python' },
      ],
    },
    {
      pattern: /^python -m venv/,
      next: [
        { command: 'source venv/bin/activate', description: 'Activate virtualenv', confidence: 0.9, source: 'pattern', category: 'python' },
      ],
    },
  ],
  cargo: [
    {
      pattern: /^cargo build/,
      next: [
        { command: 'cargo run', description: 'Run the project', confidence: 0.8, source: 'pattern', category: 'rust' },
        { command: 'cargo test', description: 'Run tests', confidence: 0.6, source: 'pattern', category: 'rust' },
      ],
    },
    {
      pattern: /^cargo test/,
      next: [
        { command: 'cargo test -- --nocapture', description: 'Run with output', confidence: 0.6, source: 'pattern', category: 'rust' },
      ],
    },
  ],
  general: [
    {
      pattern: /^mkdir/,
      next: [
        { command: 'cd', description: 'Change to new directory', confidence: 0.8, source: 'pattern', category: 'filesystem' },
      ],
    },
    {
      pattern: /^cd\s+\S+/,
      next: [
        { command: 'ls -la', description: 'List directory contents', confidence: 0.7, source: 'pattern', category: 'filesystem' },
        { command: 'pwd', description: 'Print working directory', confidence: 0.4, source: 'pattern', category: 'filesystem' },
      ],
    },
  ],
};

// Error recovery patterns
const ERROR_PATTERNS: Array<{ pattern: RegExp; suggestions: CommandPrediction[] }> = [
  {
    pattern: /permission denied/i,
    suggestions: [
      { command: 'sudo !!', description: 'Retry with sudo', confidence: 0.9, source: 'context', category: 'error-recovery' },
    ],
  },
  {
    pattern: /command not found/i,
    suggestions: [
      { command: 'which $COMMAND', description: 'Check if command exists', confidence: 0.6, source: 'context', category: 'error-recovery' },
      { command: 'brew install $COMMAND', description: 'Install via Homebrew', confidence: 0.5, source: 'context', category: 'error-recovery' },
    ],
  },
  {
    pattern: /ENOENT|no such file or directory/i,
    suggestions: [
      { command: 'ls -la', description: 'List directory to check files', confidence: 0.7, source: 'context', category: 'error-recovery' },
      { command: 'find . -name "$FILENAME"', description: 'Find the file', confidence: 0.6, source: 'context', category: 'error-recovery' },
    ],
  },
  {
    pattern: /EADDRINUSE|address already in use/i,
    suggestions: [
      { command: 'lsof -i :$PORT', description: 'Find process using port', confidence: 0.9, source: 'context', category: 'error-recovery' },
      { command: 'kill -9 $(lsof -t -i :$PORT)', description: 'Kill process on port', confidence: 0.7, source: 'context', category: 'error-recovery' },
    ],
  },
  {
    pattern: /merge conflict/i,
    suggestions: [
      { command: 'git status', description: 'See conflicted files', confidence: 0.9, source: 'context', category: 'git' },
      { command: 'git diff', description: 'View conflicts', confidence: 0.8, source: 'context', category: 'git' },
      { command: 'git merge --abort', description: 'Abort merge', confidence: 0.5, source: 'context', category: 'git' },
    ],
  },
];

// Default config
const DEFAULT_CONFIG: PredictionConfig = {
  maxPredictions: 5,
  useAI: true,
  usePatterns: true,
  useHistory: true,
  minConfidence: 0.4,
  contextWindow: 10,
};

// State
const config = ref<PredictionConfig>({ ...DEFAULT_CONFIG });
const predictions = ref<CommandPrediction[]>([]);
const isGenerating = ref(false);
const commandHistory = ref<string[]>([]);

const MAX_HISTORY = 100;

export function useNextCommandPrediction() {
  /**
   * Generate predictions based on context
   */
  async function generatePredictions(context: CommandContext): Promise<CommandPrediction[]> {
    isGenerating.value = true;
    const allPredictions: CommandPrediction[] = [];

    try {
      // 1. Pattern-based predictions
      if (config.value.usePatterns && context.lastCommands.length > 0) {
        const lastCommand = context.lastCommands[context.lastCommands.length - 1];
        const patternPredictions = getPatternPredictions(lastCommand);
        allPredictions.push(...patternPredictions);
      }

      // 2. Error-based suggestions
      if (context.errorContext) {
        const errorPredictions = getErrorRecoveryPredictions(context.errorContext);
        allPredictions.push(...errorPredictions);
      }

      // 3. Context-based predictions
      const contextPredictions = getContextPredictions(context);
      allPredictions.push(...contextPredictions);

      // 4. AI-based predictions (if enabled and available)
      if (config.value.useAI && invoke) {
        const aiPredictions = await getAIPredictions(context);
        allPredictions.push(...aiPredictions);
      }

      // Deduplicate and sort by confidence
      const uniquePredictions = deduplicatePredictions(allPredictions);
      const filtered = uniquePredictions.filter(p => p.confidence >= config.value.minConfidence);
      filtered.sort((a, b) => b.confidence - a.confidence);

      predictions.value = filtered.slice(0, config.value.maxPredictions);
      return predictions.value;
    } finally {
      isGenerating.value = false;
    }
  }

  /**
   * Get pattern-based predictions
   */
  function getPatternPredictions(lastCommand: string): CommandPrediction[] {
    const results: CommandPrediction[] = [];

    for (const category of Object.values(COMMAND_PATTERNS)) {
      for (const pattern of category) {
        if (pattern.pattern.test(lastCommand)) {
          results.push(...pattern.next);
        }
      }
    }

    return results;
  }

  /**
   * Get error recovery predictions
   */
  function getErrorRecoveryPredictions(errorOutput: string): CommandPrediction[] {
    const results: CommandPrediction[] = [];

    for (const errorPattern of ERROR_PATTERNS) {
      if (errorPattern.pattern.test(errorOutput)) {
        results.push(...errorPattern.suggestions);
      }
    }

    return results;
  }

  /**
   * Get context-based predictions
   */
  function getContextPredictions(context: CommandContext): CommandPrediction[] {
    const results: CommandPrediction[] = [];

    // Git context
    if (context.gitStatus) {
      if (context.gitStatus.hasChanges) {
        results.push({
          command: 'git add -A',
          description: 'Stage all changes',
          confidence: 0.6,
          source: 'context',
          category: 'git',
        });
      }
      if (context.gitStatus.untrackedFiles > 0) {
        results.push({
          command: 'git status',
          description: `${context.gitStatus.untrackedFiles} untracked files`,
          confidence: 0.5,
          source: 'context',
          category: 'git',
        });
      }
    }

    // Project type context
    if (context.projectType === 'node') {
      results.push({
        command: 'npm run dev',
        description: 'Start dev server',
        confidence: 0.5,
        source: 'context',
        category: 'npm',
      });
    } else if (context.projectType === 'rust') {
      results.push({
        command: 'cargo run',
        description: 'Run Rust project',
        confidence: 0.5,
        source: 'context',
        category: 'rust',
      });
    } else if (context.projectType === 'python') {
      results.push({
        command: 'python main.py',
        description: 'Run Python script',
        confidence: 0.5,
        source: 'context',
        category: 'python',
      });
    }

    return results;
  }

  /**
   * Get AI-powered predictions
   */
  async function getAIPredictions(context: CommandContext): Promise<CommandPrediction[]> {
    if (!invoke) return [];

    try {
      const prompt = buildAIPrompt(context);

      const response = await invoke<string>('query_ollama', {
        model: 'qwen2.5-coder:1.5b', // Fast model for predictions
        prompt,
        maxTokens: 200,
        temperature: 0.3,
      });

      return parseAIPredictions(response);
    } catch (error) {
      console.error('[NextCommand] AI prediction error:', error);
      return [];
    }
  }

  /**
   * Build prompt for AI predictions
   */
  function buildAIPrompt(context: CommandContext): string {
    return `Based on the command history and context, suggest the next likely commands.

Current directory: ${context.currentDirectory}
${context.projectType ? `Project type: ${context.projectType}` : ''}
${context.gitStatus ? `Git branch: ${context.gitStatus.branch}${context.gitStatus.hasChanges ? ' (has changes)' : ''}` : ''}

Recent commands:
${context.lastCommands.slice(-5).map((c, i) => `${i + 1}. ${c}`).join('\n')}

${context.lastOutput ? `Last output:\n${context.lastOutput.slice(0, 500)}` : ''}
${context.errorContext ? `Error:\n${context.errorContext.slice(0, 300)}` : ''}

Suggest 3 likely next commands. Format each as:
COMMAND: <command>
DESC: <brief description>

Only suggest commands, no explanations.`;
  }

  /**
   * Parse AI response into predictions
   */
  function parseAIPredictions(response: string): CommandPrediction[] {
    const predictions: CommandPrediction[] = [];
    const lines = response.split('\n');

    let currentCommand = '';
    let currentDesc = '';

    for (const line of lines) {
      if (line.startsWith('COMMAND:')) {
        if (currentCommand) {
          predictions.push({
            command: currentCommand.trim(),
            description: currentDesc.trim() || 'AI suggestion',
            confidence: 0.65,
            source: 'ai',
          });
        }
        currentCommand = line.replace('COMMAND:', '').trim();
        currentDesc = '';
      } else if (line.startsWith('DESC:')) {
        currentDesc = line.replace('DESC:', '').trim();
      }
    }

    // Don't forget the last one
    if (currentCommand) {
      predictions.push({
        command: currentCommand.trim(),
        description: currentDesc.trim() || 'AI suggestion',
        confidence: 0.65,
        source: 'ai',
      });
    }

    return predictions;
  }

  /**
   * Deduplicate predictions
   */
  function deduplicatePredictions(predictions: CommandPrediction[]): CommandPrediction[] {
    const seen = new Set<string>();
    return predictions.filter(p => {
      const key = p.command.toLowerCase().trim();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Record a command to history
   */
  function recordCommand(command: string): void {
    commandHistory.value.push(command);
    if (commandHistory.value.length > MAX_HISTORY) {
      commandHistory.value = commandHistory.value.slice(-MAX_HISTORY);
    }
  }

  /**
   * Accept a prediction
   */
  function acceptPrediction(prediction: CommandPrediction): string {
    recordCommand(prediction.command);
    return prediction.command;
  }

  /**
   * Dismiss predictions
   */
  function dismissPredictions(): void {
    predictions.value = [];
  }

  /**
   * Set configuration
   */
  function setConfig(newConfig: Partial<PredictionConfig>): void {
    config.value = { ...config.value, ...newConfig };
  }

  /**
   * Get command history
   */
  function getHistory(limit?: number): string[] {
    if (limit) {
      return commandHistory.value.slice(-limit);
    }
    return [...commandHistory.value];
  }

  /**
   * Clear history
   */
  function clearHistory(): void {
    commandHistory.value = [];
  }

  /**
   * Detect project type from current directory
   */
  async function detectProjectType(cwd: string): Promise<string | undefined> {
    if (!invoke) return undefined;

    try {
      const files = await invoke<Array<{ path: string }>>('glob_files', {
        pattern: '*',
        path: cwd,
      });

      const fileNames = files.map(f => f.path.split('/').pop() || '');

      if (fileNames.includes('package.json')) return 'node';
      if (fileNames.includes('Cargo.toml')) return 'rust';
      if (fileNames.includes('requirements.txt') || fileNames.includes('setup.py')) return 'python';
      if (fileNames.includes('go.mod')) return 'go';
      if (fileNames.includes('pom.xml') || fileNames.includes('build.gradle')) return 'java';

      return undefined;
    } catch {
      return undefined;
    }
  }

  return {
    // State
    predictions: computed(() => predictions.value),
    isGenerating: computed(() => isGenerating.value),
    config: computed(() => config.value),
    history: computed(() => commandHistory.value),

    // Core methods
    generatePredictions,
    acceptPrediction,
    dismissPredictions,
    recordCommand,

    // Configuration
    setConfig,
    getHistory,
    clearHistory,
    detectProjectType,
  };
}
