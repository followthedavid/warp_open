/**
 * Git operation utilities for autonomous execution
 * Provides safe git operations with rollback support
 */

import { executeCommand, type CommandResult } from './commandOps';

/**
 * Git operation result
 */
export interface GitResult {
  success: boolean;
  output: string;
  error?: string;
}

/**
 * Get current git status
 */
export async function gitStatus(repoPath?: string): Promise<GitResult> {
  try {
    const result = await executeCommand('git status --porcelain', repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Get current branch name
 */
export async function getCurrentBranch(repoPath?: string): Promise<string> {
  const result = await executeCommand('git branch --show-current', repoPath);
  return result.stdout.trim();
}

/**
 * Create a new branch
 */
export async function createBranch(
  branchName: string,
  repoPath?: string
): Promise<GitResult> {
  try {
    const result = await executeCommand(`git checkout -b ${branchName}`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Switch to a branch
 */
export async function switchBranch(
  branchName: string,
  repoPath?: string
): Promise<GitResult> {
  try {
    const result = await executeCommand(`git checkout ${branchName}`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Stage files for commit
 */
export async function gitAdd(
  files: string[] | string = '.',
  repoPath?: string
): Promise<GitResult> {
  try {
    const filesArg = Array.isArray(files) ? files.join(' ') : files;
    const result = await executeCommand(`git add ${filesArg}`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Create a commit
 */
export async function gitCommit(
  message: string,
  repoPath?: string
): Promise<GitResult> {
  try {
    // Escape quotes in message
    const escapedMessage = message.replace(/"/g, '\\"');
    const result = await executeCommand(`git commit -m "${escapedMessage}"`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Push to remote
 */
export async function gitPush(
  remote: string = 'origin',
  branch?: string,
  repoPath?: string
): Promise<GitResult> {
  try {
    const branchArg = branch ? ` ${branch}` : '';
    const result = await executeCommand(`git push ${remote}${branchArg}`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Pull from remote
 */
export async function gitPull(
  remote: string = 'origin',
  branch?: string,
  repoPath?: string
): Promise<GitResult> {
  try {
    const branchArg = branch ? ` ${branch}` : '';
    const result = await executeCommand(`git pull ${remote}${branchArg}`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Get git diff
 */
export async function gitDiff(
  files?: string[],
  repoPath?: string
): Promise<string> {
  const filesArg = files ? files.join(' ') : '';
  const result = await executeCommand(`git diff ${filesArg}`, repoPath);
  return result.stdout;
}

/**
 * Get commit hash
 */
export async function getCurrentCommit(repoPath?: string): Promise<string> {
  const result = await executeCommand('git rev-parse HEAD', repoPath);
  return result.stdout.trim();
}

/**
 * Reset to a specific commit (DANGEROUS - use with caution)
 */
export async function gitReset(
  commitHash: string,
  mode: 'soft' | 'mixed' | 'hard' = 'mixed',
  repoPath?: string
): Promise<GitResult> {
  try {
    const result = await executeCommand(`git reset --${mode} ${commitHash}`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Create a git stash
 */
export async function gitStash(
  message?: string,
  repoPath?: string
): Promise<GitResult> {
  try {
    const messageArg = message ? ` -m "${message.replace(/"/g, '\\"')}"` : '';
    const result = await executeCommand(`git stash push${messageArg}`, repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Apply git stash
 */
export async function gitStashPop(repoPath?: string): Promise<GitResult> {
  try {
    const result = await executeCommand('git stash pop', repoPath);
    return {
      success: result.exitCode === 0,
      output: result.stdout,
      error: result.stderr || undefined,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: String(error),
    };
  }
}

/**
 * Full commit workflow with rollback support
 */
export async function commitWorkflow(
  message: string,
  files: string[] | string = '.',
  repoPath?: string
): Promise<{
  success: boolean;
  commitHash?: string;
  error?: string;
  rollback: () => Promise<void>;
}> {
  // Store original state
  const originalCommit = await getCurrentCommit(repoPath);
  const originalBranch = await getCurrentBranch(repoPath);

  try {
    // Add files
    const addResult = await gitAdd(files, repoPath);
    if (!addResult.success) {
      throw new Error(`Git add failed: ${addResult.error}`);
    }

    // Commit
    const commitResult = await gitCommit(message, repoPath);
    if (!commitResult.success) {
      throw new Error(`Git commit failed: ${commitResult.error}`);
    }

    // Get new commit hash
    const newCommit = await getCurrentCommit(repoPath);

    return {
      success: true,
      commitHash: newCommit,
      rollback: async () => {
        // Rollback to original commit
        await gitReset(originalCommit, 'hard', repoPath);
        await switchBranch(originalBranch, repoPath);
      },
    };
  } catch (error) {
    return {
      success: false,
      error: String(error),
      rollback: async () => {
        // Try to restore original state
        await gitReset(originalCommit, 'hard', repoPath);
        await switchBranch(originalBranch, repoPath);
      },
    };
  }
}
