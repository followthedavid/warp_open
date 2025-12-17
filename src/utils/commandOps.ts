/**
 * Command execution utilities for autonomous execution
 * Uses Tauri Command API for secure command execution
 */

const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

/**
 * Dangerous commands that require explicit approval
 */
const DANGEROUS_COMMANDS = [
  'rm',
  'rmdir',
  'del',
  'format',
  'dd',
  'shutdown',
  'reboot',
  'kill',
  'killall',
  'sudo',
];

/**
 * Command execution result
 */
export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  command: string;
}

/**
 * Check if command is dangerous
 */
function isDangerousCommand(command: string): boolean {
  const lowerCommand = command.toLowerCase().trim();
  return DANGEROUS_COMMANDS.some(dangerous =>
    lowerCommand.startsWith(dangerous + ' ') || lowerCommand === dangerous
  );
}

/**
 * Execute a shell command safely
 */
export async function executeCommand(
  command: string,
  workingDir?: string
): Promise<CommandResult> {
  if (isDangerousCommand(command)) {
    throw new Error(`Dangerous command blocked: ${command}`);
  }

  console.log(`[CommandOps] Executing: ${command}`);

  if (isTauri) {
    const { Command } = await import('@tauri-apps/api/shell');

    // Parse command into program and args
    const parts = command.split(' ');
    const program = parts[0];
    const args = parts.slice(1);

    const cmd = new Command(program, args, { cwd: workingDir });

    const result = await cmd.execute();

    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.code,
      command,
    };
  } else {
    // Fallback for browser mode (development only)
    const response = await fetch('/api/command/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command, workingDir }),
    });

    if (!response.ok) {
      throw new Error(`Command execution failed: ${response.statusText}`);
    }

    return await response.json();
  }
}

/**
 * Execute multiple commands sequentially
 */
export async function executeCommandSequence(
  commands: string[],
  workingDir?: string
): Promise<CommandResult[]> {
  const results: CommandResult[] = [];

  for (const command of commands) {
    try {
      const result = await executeCommand(command, workingDir);
      results.push(result);

      // Stop on first error
      if (result.exitCode !== 0) {
        break;
      }
    } catch (error) {
      results.push({
        stdout: '',
        stderr: String(error),
        exitCode: 1,
        command,
      });
      break;
    }
  }

  return results;
}

/**
 * Command history for rollback
 */
interface CommandHistoryEntry {
  command: string;
  result: CommandResult;
  timestamp: Date;
  rollbackCommand?: string;
}

const commandHistory: CommandHistoryEntry[] = [];

/**
 * Execute command with rollback support
 */
export async function executeWithRollback(
  command: string,
  rollbackCommand?: string,
  workingDir?: string
): Promise<CommandResult> {
  const result = await executeCommand(command, workingDir);

  commandHistory.push({
    command,
    result,
    timestamp: new Date(),
    rollbackCommand,
  });

  return result;
}

/**
 * Rollback last N commands
 */
export async function rollbackCommands(count: number = 1): Promise<void> {
  const toRollback = commandHistory.slice(-count).reverse();

  for (const entry of toRollback) {
    if (entry.rollbackCommand) {
      console.log(`[CommandOps] Rolling back: ${entry.command}`);
      await executeCommand(entry.rollbackCommand);
    }
  }

  // Remove rolled back commands from history
  commandHistory.splice(-count);
}

/**
 * Get command history
 */
export function getCommandHistory(): CommandHistoryEntry[] {
  return [...commandHistory];
}

/**
 * Clear command history
 */
export function clearCommandHistory(): void {
  commandHistory.length = 0;
}
