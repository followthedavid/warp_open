/**
 * Multi-File Operations Support
 * Handle complex operations spanning multiple files
 *
 * Features:
 * - Batch file reads
 * - Multi-file edits with rollback
 * - Pattern-based file discovery
 * - Transaction-like operations
 */

import { ref } from 'vue';

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

export interface FileOperation {
  id: string;
  type: 'read' | 'write' | 'edit' | 'delete' | 'create';
  path: string;
  content?: string;
  oldContent?: string;  // For rollback
  status: 'pending' | 'running' | 'completed' | 'failed' | 'rolledback';
  error?: string;
}

export interface FileTransaction {
  id: string;
  operations: FileOperation[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'rolledback';
  createdAt: Date;
  completedAt?: Date;
}

export interface FileMatch {
  path: string;
  content: string;
  matches?: Array<{ line: number; text: string }>;
}

// ============================================================================
// STATE
// ============================================================================

const activeTransaction = ref<FileTransaction | null>(null);
const fileCache = ref<Map<string, string>>(new Map());

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

async function executeShell(command: string): Promise<string> {
  if (!invoke) {
    throw new Error('Tauri not available');
  }
  return invoke<string>('execute_shell', { command });
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useMultiFileOps() {
  /**
   * Find files matching a glob pattern
   */
  async function findFiles(pattern: string, options?: {
    maxDepth?: number;
    exclude?: string[];
    maxResults?: number;
  }): Promise<string[]> {
    const maxResults = options?.maxResults || 50;
    const exclude = options?.exclude || ['node_modules', '.git', 'dist', 'build'];
    const excludePattern = exclude.map(e => `-not -path "*/${e}/*"`).join(' ');

    try {
      const result = await executeShell(
        `find . -name "${pattern}" ${excludePattern} 2>/dev/null | head -${maxResults}`
      );
      return result.trim().split('\n').filter(Boolean);
    } catch (error) {
      console.error('[MultiFileOps] Find failed:', error);
      return [];
    }
  }

  /**
   * Search for text across multiple files
   */
  async function searchInFiles(pattern: string, options?: {
    glob?: string;
    caseSensitive?: boolean;
    maxResults?: number;
  }): Promise<FileMatch[]> {
    const glob = options?.glob || '*';
    const caseFlag = options?.caseSensitive ? '' : '-i';
    const maxResults = options?.maxResults || 20;

    try {
      const result = await executeShell(
        `grep -rn ${caseFlag} "${pattern}" --include="${glob}" . 2>/dev/null | head -${maxResults}`
      );

      const matches: FileMatch[] = [];
      const fileMatches = new Map<string, Array<{ line: number; text: string }>>();

      for (const line of result.trim().split('\n').filter(Boolean)) {
        const match = line.match(/^([^:]+):(\d+):(.*)$/);
        if (match) {
          const [, path, lineNum, text] = match;
          if (!fileMatches.has(path)) {
            fileMatches.set(path, []);
          }
          fileMatches.get(path)!.push({
            line: parseInt(lineNum),
            text: text.trim()
          });
        }
      }

      for (const [path, matchList] of fileMatches) {
        matches.push({
          path,
          content: '', // Don't include full content in search results
          matches: matchList
        });
      }

      return matches;
    } catch (error) {
      console.error('[MultiFileOps] Search failed:', error);
      return [];
    }
  }

  /**
   * Read multiple files in parallel
   */
  async function readFiles(paths: string[]): Promise<Map<string, string>> {
    const results = new Map<string, string>();

    const promises = paths.map(async (path) => {
      try {
        // Check cache first
        if (fileCache.value.has(path)) {
          return { path, content: fileCache.value.get(path)! };
        }

        const content = await executeShell(`cat "${path}" 2>/dev/null`);
        fileCache.value.set(path, content);
        return { path, content };
      } catch {
        return { path, content: '' };
      }
    });

    const resolved = await Promise.all(promises);
    for (const { path, content } of resolved) {
      results.set(path, content);
    }

    return results;
  }

  /**
   * Start a file transaction for atomic multi-file operations
   */
  function beginTransaction(): string {
    const transaction: FileTransaction = {
      id: generateId(),
      operations: [],
      status: 'pending',
      createdAt: new Date()
    };
    activeTransaction.value = transaction;
    return transaction.id;
  }

  /**
   * Add a file operation to the current transaction
   */
  function addOperation(op: Omit<FileOperation, 'id' | 'status'>): void {
    if (!activeTransaction.value) {
      throw new Error('No active transaction');
    }

    activeTransaction.value.operations.push({
      ...op,
      id: generateId(),
      status: 'pending'
    });
  }

  /**
   * Execute all operations in the transaction
   */
  async function commitTransaction(): Promise<{
    success: boolean;
    completed: number;
    failed: number;
    errors: string[];
  }> {
    if (!activeTransaction.value) {
      throw new Error('No active transaction');
    }

    const transaction = activeTransaction.value;
    transaction.status = 'running';

    let completed = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const op of transaction.operations) {
      op.status = 'running';

      try {
        switch (op.type) {
          case 'read':
            op.content = await executeShell(`cat "${op.path}"`);
            break;

          case 'write':
          case 'create':
            // Save old content for rollback
            try {
              op.oldContent = await executeShell(`cat "${op.path}" 2>/dev/null`);
            } catch {
              op.oldContent = '';
            }
            // Write new content
            await executeShell(`cat > "${op.path}" << 'WARP_EOF'\n${op.content}\nWARP_EOF`);
            break;

          case 'edit':
            // Read current content
            op.oldContent = await executeShell(`cat "${op.path}"`);
            // Apply edit (assuming content is the new full content)
            await executeShell(`cat > "${op.path}" << 'WARP_EOF'\n${op.content}\nWARP_EOF`);
            break;

          case 'delete':
            // Save for rollback
            try {
              op.oldContent = await executeShell(`cat "${op.path}" 2>/dev/null`);
            } catch {
              op.oldContent = '';
            }
            await executeShell(`rm "${op.path}"`);
            break;
        }

        op.status = 'completed';
        completed++;

        // Update cache
        if (op.type === 'write' || op.type === 'edit' || op.type === 'create') {
          fileCache.value.set(op.path, op.content || '');
        } else if (op.type === 'delete') {
          fileCache.value.delete(op.path);
        }

      } catch (error) {
        op.status = 'failed';
        op.error = String(error);
        errors.push(`${op.path}: ${error}`);
        failed++;
      }
    }

    transaction.status = failed > 0 ? 'failed' : 'completed';
    transaction.completedAt = new Date();

    const success = failed === 0;

    // Clear transaction if successful
    if (success) {
      activeTransaction.value = null;
    }

    return { success, completed, failed, errors };
  }

  /**
   * Rollback a failed transaction
   */
  async function rollbackTransaction(): Promise<{
    success: boolean;
    restored: number;
    errors: string[];
  }> {
    if (!activeTransaction.value) {
      throw new Error('No active transaction');
    }

    const transaction = activeTransaction.value;
    let restored = 0;
    const errors: string[] = [];

    // Rollback in reverse order
    for (const op of [...transaction.operations].reverse()) {
      if (op.status !== 'completed') continue;
      if (!op.oldContent && op.type !== 'create') continue;

      try {
        switch (op.type) {
          case 'write':
          case 'edit':
            if (op.oldContent) {
              await executeShell(`cat > "${op.path}" << 'WARP_EOF'\n${op.oldContent}\nWARP_EOF`);
              fileCache.value.set(op.path, op.oldContent);
            }
            break;

          case 'create':
            await executeShell(`rm "${op.path}" 2>/dev/null || true`);
            fileCache.value.delete(op.path);
            break;

          case 'delete':
            if (op.oldContent) {
              await executeShell(`cat > "${op.path}" << 'WARP_EOF'\n${op.oldContent}\nWARP_EOF`);
              fileCache.value.set(op.path, op.oldContent);
            }
            break;
        }

        op.status = 'rolledback';
        restored++;
      } catch (error) {
        errors.push(`Rollback ${op.path}: ${error}`);
      }
    }

    transaction.status = 'rolledback';
    activeTransaction.value = null;

    return { success: errors.length === 0, restored, errors };
  }

  /**
   * Abort transaction without rollback (discard pending ops)
   */
  function abortTransaction(): void {
    activeTransaction.value = null;
  }

  /**
   * Quick file operations (without transaction)
   */
  async function quickRead(path: string): Promise<string> {
    if (fileCache.value.has(path)) {
      return fileCache.value.get(path)!;
    }
    const content = await executeShell(`cat "${path}"`);
    fileCache.value.set(path, content);
    return content;
  }

  async function quickWrite(path: string, content: string): Promise<void> {
    await executeShell(`cat > "${path}" << 'WARP_EOF'\n${content}\nWARP_EOF`);
    fileCache.value.set(path, content);
  }

  async function quickAppend(path: string, content: string): Promise<void> {
    await executeShell(`cat >> "${path}" << 'WARP_EOF'\n${content}\nWARP_EOF`);
    // Invalidate cache
    fileCache.value.delete(path);
  }

  /**
   * Get files changed in git
   */
  async function getChangedFiles(): Promise<string[]> {
    try {
      const result = await executeShell('git diff --name-only 2>/dev/null');
      return result.trim().split('\n').filter(Boolean);
    } catch {
      return [];
    }
  }

  /**
   * Clear file cache
   */
  function clearCache(): void {
    fileCache.value.clear();
  }

  /**
   * Get cache stats
   */
  function getCacheStats() {
    return {
      size: fileCache.value.size,
      totalBytes: Array.from(fileCache.value.values()).reduce((sum, c) => sum + c.length, 0)
    };
  }

  return {
    // File discovery
    findFiles,
    searchInFiles,

    // Multi-file read
    readFiles,

    // Transactions
    beginTransaction,
    addOperation,
    commitTransaction,
    rollbackTransaction,
    abortTransaction,
    activeTransaction,

    // Quick operations
    quickRead,
    quickWrite,
    quickAppend,

    // Git integration
    getChangedFiles,

    // Cache management
    clearCache,
    getCacheStats,
    fileCache
  };
}

export default useMultiFileOps;
