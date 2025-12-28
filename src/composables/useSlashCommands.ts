/**
 * Slash Commands System
 * Custom shortcuts for frequently-used prompts, similar to Claude Code's /commands
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

export interface SlashCommand {
  name: string;
  description: string;
  prompt: string;
  args?: SlashCommandArg[];
  category?: string;
  shortcut?: string;
  isBuiltIn?: boolean;
}

export interface SlashCommandArg {
  name: string;
  description: string;
  required?: boolean;
  type?: 'string' | 'file' | 'selection';
}

export interface ParsedCommand {
  command: SlashCommand;
  args: Record<string, string>;
  rawInput: string;
}

// Built-in commands
const BUILTIN_COMMANDS: SlashCommand[] = [
  {
    name: 'explain',
    description: 'Explain how the selected code works',
    prompt: 'Explain this code in detail, including what it does, how it works, and any potential issues:\n\n```\n{{selection}}\n```',
    args: [{ name: 'selection', description: 'Code to explain', type: 'selection' }],
    category: 'Code Understanding',
    isBuiltIn: true,
  },
  {
    name: 'fix',
    description: 'Fix bugs or issues in code',
    prompt: 'Analyze this code and fix any bugs, errors, or issues. Explain what was wrong and show the corrected code:\n\n```\n{{selection}}\n```',
    args: [{ name: 'selection', description: 'Code to fix', type: 'selection' }],
    category: 'Code Modification',
    isBuiltIn: true,
  },
  {
    name: 'refactor',
    description: 'Refactor code for better quality',
    prompt: 'Refactor this code to improve readability, maintainability, and performance while preserving functionality:\n\n```\n{{selection}}\n```',
    args: [{ name: 'selection', description: 'Code to refactor', type: 'selection' }],
    category: 'Code Modification',
    isBuiltIn: true,
  },
  {
    name: 'test',
    description: 'Generate tests for code',
    prompt: 'Generate comprehensive unit tests for this code. Include edge cases and use appropriate testing patterns:\n\n```\n{{selection}}\n```',
    args: [{ name: 'selection', description: 'Code to test', type: 'selection' }],
    category: 'Testing',
    isBuiltIn: true,
  },
  {
    name: 'docs',
    description: 'Generate documentation',
    prompt: 'Generate comprehensive documentation for this code including JSDoc/docstrings, usage examples, and parameter descriptions:\n\n```\n{{selection}}\n```',
    args: [{ name: 'selection', description: 'Code to document', type: 'selection' }],
    category: 'Documentation',
    isBuiltIn: true,
  },
  {
    name: 'review',
    description: 'Review code for issues',
    prompt: 'Review this code for potential bugs, security vulnerabilities, performance issues, and code style problems. Provide specific suggestions:\n\n```\n{{selection}}\n```',
    args: [{ name: 'selection', description: 'Code to review', type: 'selection' }],
    category: 'Code Quality',
    isBuiltIn: true,
  },
  {
    name: 'optimize',
    description: 'Optimize code for performance',
    prompt: 'Optimize this code for better performance. Explain the optimizations made and their impact:\n\n```\n{{selection}}\n```',
    args: [{ name: 'selection', description: 'Code to optimize', type: 'selection' }],
    category: 'Code Modification',
    isBuiltIn: true,
  },
  {
    name: 'commit',
    description: 'Generate a commit message',
    prompt: 'Generate a conventional commit message for the current staged changes. Use format: type(scope): subject',
    category: 'Git',
    isBuiltIn: true,
  },
  {
    name: 'pr',
    description: 'Generate a PR description',
    prompt: 'Generate a pull request description for the changes in this branch. Include summary, changes list, and test plan.',
    category: 'Git',
    isBuiltIn: true,
  },
  {
    name: 'plan',
    description: 'Create an implementation plan',
    prompt: 'Create a detailed implementation plan for: {{task}}\n\nInclude:\n1. Steps to implement\n2. Files to modify\n3. Potential challenges\n4. Testing strategy',
    args: [{ name: 'task', description: 'Task to plan', required: true }],
    category: 'Planning',
    isBuiltIn: true,
  },
  {
    name: 'debug',
    description: 'Help debug an issue',
    prompt: 'Help me debug this issue: {{issue}}\n\nAnalyze potential causes and suggest solutions.',
    args: [{ name: 'issue', description: 'Issue description', required: true }],
    category: 'Debugging',
    isBuiltIn: true,
  },
  {
    name: 'search',
    description: 'Search codebase for pattern',
    prompt: 'Use grep_files to search the codebase for: {{pattern}}',
    args: [{ name: 'pattern', description: 'Search pattern', required: true }],
    category: 'Navigation',
    isBuiltIn: true,
  },
  {
    name: 'find',
    description: 'Find files matching pattern',
    prompt: 'Use glob_files to find files matching: {{pattern}}',
    args: [{ name: 'pattern', description: 'File pattern (e.g., **/*.ts)', required: true }],
    category: 'Navigation',
    isBuiltIn: true,
  },
  {
    name: 'clear',
    description: 'Clear conversation history',
    prompt: '__CLEAR_CONVERSATION__',
    category: 'System',
    isBuiltIn: true,
  },
  {
    name: 'help',
    description: 'Show available commands',
    prompt: '__SHOW_HELP__',
    category: 'System',
    isBuiltIn: true,
  },
  // Claude Code parity commands
  {
    name: 'compact',
    description: 'Compress conversation context (summarize history)',
    prompt: '__COMPACT_CONTEXT__',
    category: 'System',
    isBuiltIn: true,
  },
  {
    name: 'context',
    description: 'Show current context token usage',
    prompt: '__SHOW_CONTEXT__',
    category: 'System',
    isBuiltIn: true,
  },
  {
    name: 'catchup',
    description: 'Summarize recent git changes',
    prompt: 'Use execute_shell to run "git log --oneline -10" and "git diff --stat HEAD~5", then summarize the recent changes in this repository.',
    category: 'Git',
    isBuiltIn: true,
  },
  {
    name: 'model',
    description: 'Switch AI model',
    prompt: '__SWITCH_MODEL__',
    args: [{ name: 'model', description: 'Model name (e.g., qwen2.5-coder:1.5b)', required: false }],
    category: 'System',
    isBuiltIn: true,
  },
  {
    name: 'init',
    description: 'Initialize project context (create CLAUDE.md)',
    prompt: '__INIT_PROJECT__',
    category: 'System',
    isBuiltIn: true,
  },
  {
    name: 'diff',
    description: 'Show git diff and review changes',
    prompt: 'Use execute_shell to run "git diff --staged" if there are staged changes, otherwise "git diff". Show the diff and provide a code review summary.',
    category: 'Git',
    isBuiltIn: true,
  },
  {
    name: 'status',
    description: 'Show git status',
    prompt: 'Use execute_shell to run "git status" and summarize the current state of the repository.',
    category: 'Git',
    isBuiltIn: true,
  },
  {
    name: 'reset',
    description: 'Reset agent state and start fresh',
    prompt: '__RESET_AGENT__',
    category: 'System',
    isBuiltIn: true,
  },
  {
    name: 'resume',
    description: 'Resume previous session',
    prompt: '__RESUME_SESSION__',
    args: [{ name: 'session_id', description: 'Session ID to resume', required: false }],
    category: 'System',
    isBuiltIn: true,
  },
  {
    name: 'sessions',
    description: 'List available sessions to resume',
    prompt: '__LIST_SESSIONS__',
    category: 'System',
    isBuiltIn: true,
  },
];

// User-defined commands storage
const STORAGE_KEY = 'warp_open_slash_commands';

const customCommands = ref<SlashCommand[]>([]);
const allCommands = computed(() => [...BUILTIN_COMMANDS, ...customCommands.value]);

export function useSlashCommands() {
  /**
   * Load custom commands from storage
   */
  function loadCustomCommands() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        customCommands.value = JSON.parse(stored);
      }
    } catch (e) {
      console.error('[SlashCommands] Error loading custom commands:', e);
    }
  }

  /**
   * Save custom commands to storage
   */
  function saveCustomCommands() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(customCommands.value));
    } catch (e) {
      console.error('[SlashCommands] Error saving custom commands:', e);
    }
  }

  /**
   * Load custom commands from .warp/commands directory
   */
  async function loadFromDirectory(directory: string) {
    if (!isTauri || !invoke) return;

    try {
      const commandsDir = `${directory}/.warp/commands`;
      const files = await invoke<Array<{ path: string }>>('glob_files', {
        pattern: '*.md',
        path: commandsDir,
      });

      for (const file of files) {
        const content = await invoke<string>('read_file', { path: file.path });
        const command = parseCommandFile(file.path, content);
        if (command) {
          // Add if not already exists
          if (!customCommands.value.find(c => c.name === command.name)) {
            customCommands.value.push(command);
          }
        }
      }

      saveCustomCommands();
    } catch (e) {
      // Directory doesn't exist, that's OK
      console.log('[SlashCommands] No custom commands directory found');
    }
  }

  /**
   * Parse a command file (markdown format)
   */
  function parseCommandFile(path: string, content: string): SlashCommand | null {
    const name = path.split('/').pop()?.replace('.md', '') || '';

    // Extract frontmatter if present
    const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);

    let description = `Custom command: ${name}`;
    let prompt = content;
    let category = 'Custom';
    let args: SlashCommandArg[] = [];

    if (frontmatterMatch) {
      const frontmatter = frontmatterMatch[1];
      prompt = frontmatterMatch[2].trim();

      // Parse simple YAML-like frontmatter
      const descMatch = frontmatter.match(/description:\s*(.+)/);
      if (descMatch) description = descMatch[1].trim();

      const catMatch = frontmatter.match(/category:\s*(.+)/);
      if (catMatch) category = catMatch[1].trim();

      // Parse args
      const argsMatch = frontmatter.match(/args:\s*\n((?:\s+-\s+.+\n?)+)/);
      if (argsMatch) {
        const argLines = argsMatch[1].split('\n').filter(l => l.trim().startsWith('-'));
        args = argLines.map(line => {
          const argName = line.replace(/^\s*-\s*/, '').trim();
          return { name: argName, description: argName };
        });
      }
    }

    return { name, description, prompt, category, args };
  }

  /**
   * Add a custom command
   */
  function addCommand(command: SlashCommand) {
    if (BUILTIN_COMMANDS.find(c => c.name === command.name)) {
      throw new Error(`Cannot override built-in command: ${command.name}`);
    }

    const existing = customCommands.value.findIndex(c => c.name === command.name);
    if (existing >= 0) {
      customCommands.value[existing] = command;
    } else {
      customCommands.value.push(command);
    }

    saveCustomCommands();
  }

  /**
   * Remove a custom command
   */
  function removeCommand(name: string) {
    const index = customCommands.value.findIndex(c => c.name === name);
    if (index >= 0) {
      customCommands.value.splice(index, 1);
      saveCustomCommands();
    }
  }

  /**
   * Get a command by name
   */
  function getCommand(name: string): SlashCommand | undefined {
    return allCommands.value.find(c => c.name === name);
  }

  /**
   * Parse input text for slash command
   */
  function parseInput(input: string): ParsedCommand | null {
    const trimmed = input.trim();
    if (!trimmed.startsWith('/')) return null;

    // Match /command or /command arg1 arg2
    const match = trimmed.match(/^\/(\w+)(?:\s+(.*))?$/);
    if (!match) return null;

    const commandName = match[1];
    const argsString = match[2] || '';

    const command = getCommand(commandName);
    if (!command) return null;

    // Parse arguments
    const args: Record<string, string> = {};

    if (command.args && command.args.length > 0) {
      // Simple: treat everything after command as first arg
      if (command.args.length === 1) {
        args[command.args[0].name] = argsString;
      } else {
        // Multiple args: split by spaces (simple approach)
        const parts = argsString.split(/\s+/);
        command.args.forEach((arg, i) => {
          if (parts[i]) {
            args[arg.name] = parts[i];
          }
        });
      }
    }

    return { command, args, rawInput: input };
  }

  /**
   * Execute a parsed command - returns the expanded prompt
   */
  function expandCommand(parsed: ParsedCommand, context?: { selection?: string }): string {
    let prompt = parsed.command.prompt;

    // Replace argument placeholders
    for (const [key, value] of Object.entries(parsed.args)) {
      prompt = prompt.replace(new RegExp(`{{${key}}}`, 'g'), value);
    }

    // Replace selection placeholder
    if (context?.selection) {
      prompt = prompt.replace(/{{selection}}/g, context.selection);
    }

    return prompt;
  }

  /**
   * Get commands matching a prefix (for autocomplete)
   */
  function getMatchingCommands(prefix: string): SlashCommand[] {
    const search = prefix.toLowerCase().replace(/^\//, '');
    return allCommands.value.filter(c =>
      c.name.toLowerCase().startsWith(search) ||
      c.description.toLowerCase().includes(search)
    );
  }

  /**
   * Get commands grouped by category
   */
  function getCommandsByCategory(): Record<string, SlashCommand[]> {
    const grouped: Record<string, SlashCommand[]> = {};

    for (const cmd of allCommands.value) {
      const category = cmd.category || 'Other';
      if (!grouped[category]) {
        grouped[category] = [];
      }
      grouped[category].push(cmd);
    }

    return grouped;
  }

  /**
   * Generate help text
   */
  function getHelpText(): string {
    const grouped = getCommandsByCategory();
    let help = '# Available Slash Commands\n\n';

    for (const [category, commands] of Object.entries(grouped)) {
      help += `## ${category}\n`;
      for (const cmd of commands) {
        help += `- **/${cmd.name}** - ${cmd.description}\n`;
        if (cmd.args && cmd.args.length > 0) {
          help += `  Args: ${cmd.args.map(a => `${a.name}${a.required ? '*' : ''}`).join(', ')}\n`;
        }
      }
      help += '\n';
    }

    return help;
  }

  // Initialize
  loadCustomCommands();

  return {
    allCommands,
    customCommands: computed(() => customCommands.value),
    builtInCommands: BUILTIN_COMMANDS,
    loadCustomCommands,
    loadFromDirectory,
    addCommand,
    removeCommand,
    getCommand,
    parseInput,
    expandCommand,
    getMatchingCommands,
    getCommandsByCategory,
    getHelpText,
  };
}
