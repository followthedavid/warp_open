/**
 * Git Integration for Warp Open
 * Provides git status, diff, and AI-powered commit suggestions
 *
 * Features:
 * - Git status tracking
 * - Diff viewing
 * - AI-generated commit messages
 * - Branch management
 * - Stash operations
 */

import { ref, computed } from 'vue';
import { GIT_COMMIT_PROMPT, GIT_BRANCH_PROMPT, applyTemplate } from './usePromptTemplates';

// Check if we're running in Tauri
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

// ============================================================================
// TYPES
// ============================================================================

export interface GitStatus {
  isRepo: boolean;
  branch: string;
  ahead: number;
  behind: number;
  staged: FileChange[];
  unstaged: FileChange[];
  untracked: string[];
  hasChanges: boolean;
}

export interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed' | 'copied';
  oldPath?: string;  // For renames
}

export interface GitDiff {
  file: string;
  additions: number;
  deletions: number;
  hunks: DiffHunk[];
}

export interface DiffHunk {
  header: string;
  lines: DiffLine[];
}

export interface DiffLine {
  type: 'context' | 'addition' | 'deletion';
  content: string;
  lineNumber: { old?: number; new?: number };
}

export interface CommitInfo {
  hash: string;
  shortHash: string;
  author: string;
  date: Date;
  message: string;
}

// ============================================================================
// STATE
// ============================================================================

const status = ref<GitStatus | null>(null);
const currentBranch = ref<string>('');
const isLoading = ref(false);
const lastRefresh = ref<Date | null>(null);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function executeShell(command: string): Promise<string> {
  if (!invoke) {
    throw new Error('Tauri not available');
  }
  return invoke<string>('execute_shell', { command });
}

function parseFileStatus(line: string): { status: FileChange['status']; path: string; oldPath?: string } | null {
  if (!line.trim()) return null;

  const statusCode = line.substring(0, 2);
  const path = line.substring(3).trim();

  // Handle renames: R100 old -> new
  if (statusCode.startsWith('R')) {
    const parts = path.split(' -> ');
    return { status: 'renamed', path: parts[1], oldPath: parts[0] };
  }

  const statusMap: Record<string, FileChange['status']> = {
    'A': 'added',
    'M': 'modified',
    'D': 'deleted',
    'C': 'copied',
    '??': 'added'
  };

  const mapped = statusMap[statusCode.trim()] || statusMap[statusCode[0]];
  if (!mapped) return null;

  return { status: mapped, path };
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useGitIntegration() {
  /**
   * Check if current directory is a git repo
   */
  async function isGitRepo(): Promise<boolean> {
    try {
      await executeShell('git rev-parse --git-dir 2>/dev/null');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get current git status
   */
  async function getStatus(): Promise<GitStatus> {
    isLoading.value = true;

    try {
      const isRepo = await isGitRepo();
      if (!isRepo) {
        const emptyStatus: GitStatus = {
          isRepo: false,
          branch: '',
          ahead: 0,
          behind: 0,
          staged: [],
          unstaged: [],
          untracked: [],
          hasChanges: false
        };
        status.value = emptyStatus;
        return emptyStatus;
      }

      // Get branch info
      const branchOutput = await executeShell('git branch --show-current 2>/dev/null');
      const branch = branchOutput.trim() || 'detached';
      currentBranch.value = branch;

      // Get ahead/behind count
      let ahead = 0;
      let behind = 0;
      try {
        const aheadBehind = await executeShell('git rev-list --left-right --count @{upstream}...HEAD 2>/dev/null');
        const [b, a] = aheadBehind.trim().split('\t').map(Number);
        ahead = a || 0;
        behind = b || 0;
      } catch {}

      // Get staged changes
      const stagedOutput = await executeShell('git diff --cached --name-status 2>/dev/null');
      const staged: FileChange[] = [];
      for (const line of stagedOutput.trim().split('\n').filter(Boolean)) {
        const parsed = parseFileStatus(line);
        if (parsed) {
          staged.push({ path: parsed.path, status: parsed.status, oldPath: parsed.oldPath });
        }
      }

      // Get unstaged changes
      const unstagedOutput = await executeShell('git diff --name-status 2>/dev/null');
      const unstaged: FileChange[] = [];
      for (const line of unstagedOutput.trim().split('\n').filter(Boolean)) {
        const parsed = parseFileStatus(line);
        if (parsed) {
          unstaged.push({ path: parsed.path, status: parsed.status, oldPath: parsed.oldPath });
        }
      }

      // Get untracked files
      const untrackedOutput = await executeShell('git ls-files --others --exclude-standard 2>/dev/null');
      const untracked = untrackedOutput.trim().split('\n').filter(Boolean);

      const gitStatus: GitStatus = {
        isRepo: true,
        branch,
        ahead,
        behind,
        staged,
        unstaged,
        untracked,
        hasChanges: staged.length > 0 || unstaged.length > 0 || untracked.length > 0
      };

      status.value = gitStatus;
      lastRefresh.value = new Date();

      return gitStatus;
    } finally {
      isLoading.value = false;
    }
  }

  /**
   * Get diff for a specific file
   */
  async function getDiff(file?: string, staged: boolean = false): Promise<string> {
    const stagedFlag = staged ? '--cached' : '';
    const fileArg = file ? `-- "${file}"` : '';
    const result = await executeShell(`git diff ${stagedFlag} ${fileArg} 2>/dev/null`);
    return result;
  }

  /**
   * Get full diff summary
   */
  async function getDiffStats(): Promise<{ files: number; additions: number; deletions: number }> {
    try {
      const result = await executeShell('git diff --stat 2>/dev/null | tail -1');
      const match = result.match(/(\d+) files? changed(?:, (\d+) insertions?)?(?:, (\d+) deletions?)?/);
      if (match) {
        return {
          files: parseInt(match[1]) || 0,
          additions: parseInt(match[2]) || 0,
          deletions: parseInt(match[3]) || 0
        };
      }
    } catch {}

    return { files: 0, additions: 0, deletions: 0 };
  }

  /**
   * Generate commit message using AI
   */
  async function generateCommitMessage(): Promise<string> {
    const diff = await getDiff(undefined, true);
    if (!diff.trim()) {
      // No staged changes, get unstaged diff
      const unstagedDiff = await getDiff();
      if (!unstagedDiff.trim()) {
        return 'No changes to commit';
      }
    }

    // Summarize changes for the prompt
    const statusInfo = await getStatus();
    let changesSummary = '';

    if (statusInfo.staged.length > 0) {
      changesSummary += 'Staged: ' + statusInfo.staged.map(f => `${f.status} ${f.path}`).join(', ');
    }
    if (statusInfo.unstaged.length > 0) {
      if (changesSummary) changesSummary += '; ';
      changesSummary += 'Modified: ' + statusInfo.unstaged.map(f => f.path).join(', ');
    }

    const prompt = applyTemplate(GIT_COMMIT_PROMPT, changesSummary);

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
      return data.response.trim().replace(/^["']|["']$/g, '');
    } catch (error) {
      console.error('[GitIntegration] Commit message generation failed:', error);
      // Fallback to simple message
      return `Update ${statusInfo.staged.length + statusInfo.unstaged.length} file(s)`;
    }
  }

  /**
   * Stage files
   */
  async function stageFiles(files: string[]): Promise<void> {
    const fileArgs = files.map(f => `"${f}"`).join(' ');
    await executeShell(`git add ${fileArgs}`);
    await getStatus(); // Refresh status
  }

  /**
   * Stage all changes
   */
  async function stageAll(): Promise<void> {
    await executeShell('git add -A');
    await getStatus();
  }

  /**
   * Unstage files
   */
  async function unstageFiles(files: string[]): Promise<void> {
    const fileArgs = files.map(f => `"${f}"`).join(' ');
    await executeShell(`git reset HEAD ${fileArgs}`);
    await getStatus();
  }

  /**
   * Commit with message
   */
  async function commit(message: string): Promise<{ success: boolean; hash?: string; error?: string }> {
    try {
      const result = await executeShell(`git commit -m "${message.replace(/"/g, '\\"')}"`);
      const hashMatch = result.match(/\[.+ ([a-f0-9]+)\]/);
      await getStatus();
      return { success: true, hash: hashMatch?.[1] };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * Quick commit - stage all and commit with AI message
   */
  async function quickCommit(): Promise<{ success: boolean; message?: string; hash?: string; error?: string }> {
    await stageAll();
    const message = await generateCommitMessage();
    const result = await commit(message);
    return { ...result, message };
  }

  /**
   * Get recent commits
   */
  async function getLog(limit: number = 10): Promise<CommitInfo[]> {
    try {
      const result = await executeShell(
        `git log -${limit} --pretty=format:"%H|%h|%an|%aI|%s" 2>/dev/null`
      );

      return result.trim().split('\n').filter(Boolean).map(line => {
        const [hash, shortHash, author, date, ...messageParts] = line.split('|');
        return {
          hash,
          shortHash,
          author,
          date: new Date(date),
          message: messageParts.join('|')
        };
      });
    } catch {
      return [];
    }
  }

  /**
   * Get list of branches
   */
  async function getBranches(): Promise<{ local: string[]; remote: string[]; current: string }> {
    try {
      const localOutput = await executeShell('git branch 2>/dev/null');
      const local = localOutput.trim().split('\n').map(b => b.replace(/^\*?\s+/, '').trim()).filter(Boolean);

      const remoteOutput = await executeShell('git branch -r 2>/dev/null');
      const remote = remoteOutput.trim().split('\n').map(b => b.trim()).filter(Boolean);

      return { local, remote, current: currentBranch.value };
    } catch {
      return { local: [], remote: [], current: '' };
    }
  }

  /**
   * Suggest branch name using AI
   */
  async function suggestBranchName(taskDescription: string): Promise<string> {
    const prompt = applyTemplate(GIT_BRANCH_PROMPT, taskDescription);

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
      return data.response.trim().replace(/^["']|["']$/g, '').toLowerCase().replace(/\s+/g, '-');
    } catch (error) {
      console.error('[GitIntegration] Branch name suggestion failed:', error);
      return 'feature/new-feature';
    }
  }

  /**
   * Create and checkout new branch
   */
  async function createBranch(name: string, checkout: boolean = true): Promise<{ success: boolean; error?: string }> {
    try {
      if (checkout) {
        await executeShell(`git checkout -b "${name}"`);
      } else {
        await executeShell(`git branch "${name}"`);
      }
      currentBranch.value = name;
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * Switch to branch
   */
  async function checkout(branch: string): Promise<{ success: boolean; error?: string }> {
    try {
      await executeShell(`git checkout "${branch}"`);
      currentBranch.value = branch;
      await getStatus();
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * Stash current changes
   */
  async function stash(message?: string): Promise<{ success: boolean; error?: string }> {
    try {
      const msgArg = message ? `-m "${message}"` : '';
      await executeShell(`git stash ${msgArg}`);
      await getStatus();
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * List stashes
   */
  async function listStashes(): Promise<string[]> {
    try {
      const result = await executeShell('git stash list 2>/dev/null');
      return result.trim().split('\n').filter(Boolean);
    } catch {
      return [];
    }
  }

  /**
   * Pop stash
   */
  async function stashPop(): Promise<{ success: boolean; error?: string }> {
    try {
      await executeShell('git stash pop');
      await getStatus();
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * Discard changes in a file
   */
  async function discardChanges(file: string): Promise<{ success: boolean; error?: string }> {
    try {
      await executeShell(`git checkout -- "${file}"`);
      await getStatus();
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  return {
    // State
    status: computed(() => status.value),
    currentBranch: computed(() => currentBranch.value),
    isLoading: computed(() => isLoading.value),
    lastRefresh: computed(() => lastRefresh.value),

    // Status
    isGitRepo,
    getStatus,
    getDiff,
    getDiffStats,

    // AI features
    generateCommitMessage,
    suggestBranchName,

    // Staging
    stageFiles,
    stageAll,
    unstageFiles,

    // Commits
    commit,
    quickCommit,
    getLog,

    // Branches
    getBranches,
    createBranch,
    checkout,

    // Stash
    stash,
    listStashes,
    stashPop,

    // Utilities
    discardChanges
  };
}

export default useGitIntegration;
