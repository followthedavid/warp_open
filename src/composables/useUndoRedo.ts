/**
 * Undo/Redo System
 * Track and reverse file operations
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

export type OperationType = 'write' | 'edit' | 'delete' | 'create' | 'rename' | 'shell';

export interface Operation {
  id: string;
  type: OperationType;
  path: string;
  timestamp: Date;
  description: string;

  // For file operations
  oldContent?: string;
  newContent?: string;

  // For edit operations
  oldString?: string;
  newString?: string;

  // For rename operations
  newPath?: string;

  // For shell operations
  command?: string;
  output?: string;

  // State
  undone: boolean;
}

const operations = ref<Operation[]>([]);
const currentIndex = ref(-1); // Points to the last applied operation
const MAX_HISTORY = 100;

// Storage key
const STORAGE_KEY = 'warp_open_undo_history';

export function useUndoRedo() {
  /**
   * Load history from storage
   */
  function loadHistory() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const data = JSON.parse(stored);
        operations.value = data.operations.map((op: Operation) => ({
          ...op,
          timestamp: new Date(op.timestamp),
        }));
        currentIndex.value = data.currentIndex;
      }
    } catch (e) {
      console.error('[UndoRedo] Error loading history:', e);
    }
  }

  /**
   * Save history to storage
   */
  function saveHistory() {
    try {
      // Only save last 20 operations to storage (don't store full content)
      const toStore = operations.value.slice(-20).map(op => ({
        ...op,
        // Don't persist full file contents - just metadata
        oldContent: op.oldContent ? '[content]' : undefined,
        newContent: op.newContent ? '[content]' : undefined,
      }));

      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        operations: toStore,
        currentIndex: Math.min(currentIndex.value, 19),
      }));
    } catch (e) {
      console.error('[UndoRedo] Error saving history:', e);
    }
  }

  /**
   * Record a file write operation
   */
  async function recordWrite(path: string, newContent: string, description?: string) {
    let oldContent = '';

    try {
      if (isTauri && invoke) {
        oldContent = await invoke<string>('read_file', { path });
      }
    } catch {
      // File doesn't exist yet
    }

    const operation: Operation = {
      id: generateId(),
      type: 'write',
      path,
      timestamp: new Date(),
      description: description || `Write to ${path}`,
      oldContent,
      newContent,
      undone: false,
    };

    addOperation(operation);
  }

  /**
   * Record an edit operation
   */
  async function recordEdit(
    path: string,
    oldString: string,
    newString: string,
    description?: string
  ) {
    const operation: Operation = {
      id: generateId(),
      type: 'edit',
      path,
      timestamp: new Date(),
      description: description || `Edit ${path}`,
      oldString,
      newString,
      undone: false,
    };

    addOperation(operation);
  }

  /**
   * Record a file creation
   */
  function recordCreate(path: string, content: string, description?: string) {
    const operation: Operation = {
      id: generateId(),
      type: 'create',
      path,
      timestamp: new Date(),
      description: description || `Create ${path}`,
      newContent: content,
      undone: false,
    };

    addOperation(operation);
  }

  /**
   * Record a file deletion
   */
  async function recordDelete(path: string, description?: string) {
    let oldContent = '';

    try {
      if (isTauri && invoke) {
        oldContent = await invoke<string>('read_file', { path });
      }
    } catch {
      // File might not exist
    }

    const operation: Operation = {
      id: generateId(),
      type: 'delete',
      path,
      timestamp: new Date(),
      description: description || `Delete ${path}`,
      oldContent,
      undone: false,
    };

    addOperation(operation);
  }

  /**
   * Record a shell command (not undoable, but tracked)
   */
  function recordShell(command: string, output?: string) {
    const operation: Operation = {
      id: generateId(),
      type: 'shell',
      path: '',
      timestamp: new Date(),
      description: `Run: ${command.substring(0, 50)}...`,
      command,
      output,
      undone: false,
    };

    addOperation(operation);
  }

  /**
   * Add operation to history
   */
  function addOperation(operation: Operation) {
    // Remove any operations after current index (branch)
    if (currentIndex.value < operations.value.length - 1) {
      operations.value = operations.value.slice(0, currentIndex.value + 1);
    }

    operations.value.push(operation);
    currentIndex.value = operations.value.length - 1;

    // Trim history if too long
    if (operations.value.length > MAX_HISTORY) {
      operations.value.shift();
      currentIndex.value--;
    }

    saveHistory();
  }

  /**
   * Undo the last operation
   */
  async function undo(): Promise<{ success: boolean; operation?: Operation; error?: string }> {
    if (!canUndo.value) {
      return { success: false, error: 'Nothing to undo' };
    }

    const operation = operations.value[currentIndex.value];

    if (!operation || operation.type === 'shell') {
      // Skip non-undoable operations
      currentIndex.value--;
      return undo();
    }

    try {
      if (isTauri && invoke) {
        switch (operation.type) {
          case 'write':
            if (operation.oldContent !== undefined) {
              await invoke('write_file', {
                path: operation.path,
                content: operation.oldContent,
              });
            }
            break;

          case 'edit':
            if (operation.oldString && operation.newString) {
              await invoke('edit_file', {
                path: operation.path,
                oldString: operation.newString,
                newString: operation.oldString,
              });
            }
            break;

          case 'create':
            // Delete the created file
            await invoke('execute_shell', {
              command: `rm "${operation.path}"`,
            });
            break;

          case 'delete':
            // Restore the deleted file
            if (operation.oldContent) {
              await invoke('write_file', {
                path: operation.path,
                content: operation.oldContent,
              });
            }
            break;
        }
      }

      operation.undone = true;
      currentIndex.value--;
      saveHistory();

      return { success: true, operation };
    } catch (e) {
      return { success: false, error: String(e) };
    }
  }

  /**
   * Redo the last undone operation
   */
  async function redo(): Promise<{ success: boolean; operation?: Operation; error?: string }> {
    if (!canRedo.value) {
      return { success: false, error: 'Nothing to redo' };
    }

    currentIndex.value++;
    const operation = operations.value[currentIndex.value];

    if (!operation || operation.type === 'shell') {
      // Skip non-redoable operations
      return redo();
    }

    try {
      if (isTauri && invoke) {
        switch (operation.type) {
          case 'write':
            if (operation.newContent !== undefined) {
              await invoke('write_file', {
                path: operation.path,
                content: operation.newContent,
              });
            }
            break;

          case 'edit':
            if (operation.oldString && operation.newString) {
              await invoke('edit_file', {
                path: operation.path,
                oldString: operation.oldString,
                newString: operation.newString,
              });
            }
            break;

          case 'create':
            if (operation.newContent) {
              await invoke('write_file', {
                path: operation.path,
                content: operation.newContent,
              });
            }
            break;

          case 'delete':
            await invoke('execute_shell', {
              command: `rm "${operation.path}"`,
            });
            break;
        }
      }

      operation.undone = false;
      saveHistory();

      return { success: true, operation };
    } catch (e) {
      currentIndex.value--;
      return { success: false, error: String(e) };
    }
  }

  /**
   * Clear all history
   */
  function clearHistory() {
    operations.value = [];
    currentIndex.value = -1;
    localStorage.removeItem(STORAGE_KEY);
  }

  /**
   * Get recent operations
   */
  function getRecentOperations(count: number = 10): Operation[] {
    return operations.value.slice(-count).reverse();
  }

  /**
   * Generate unique ID
   */
  function generateId(): string {
    return `op-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Computed
  const canUndo = computed(() => currentIndex.value >= 0);
  const canRedo = computed(() => currentIndex.value < operations.value.length - 1);
  const undoDescription = computed(() => {
    if (!canUndo.value) return '';
    return operations.value[currentIndex.value]?.description || '';
  });
  const redoDescription = computed(() => {
    if (!canRedo.value) return '';
    return operations.value[currentIndex.value + 1]?.description || '';
  });

  // Initialize
  loadHistory();

  return {
    operations: computed(() => operations.value),
    currentIndex: computed(() => currentIndex.value),
    canUndo,
    canRedo,
    undoDescription,
    redoDescription,
    recordWrite,
    recordEdit,
    recordCreate,
    recordDelete,
    recordShell,
    undo,
    redo,
    clearHistory,
    getRecentOperations,
  };
}
