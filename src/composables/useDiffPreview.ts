/**
 * Diff Preview System
 * Show visual diff before applying file edits
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

export interface DiffLine {
  type: 'context' | 'added' | 'removed' | 'header';
  content: string;
  oldLineNumber?: number;
  newLineNumber?: number;
}

export interface FileDiff {
  path: string;
  oldContent: string;
  newContent: string;
  lines: DiffLine[];
  additions: number;
  deletions: number;
}

export interface PendingEdit {
  id: string;
  path: string;
  oldString: string;
  newString: string;
  replaceAll: boolean;
  diff: FileDiff | null;
  status: 'pending' | 'approved' | 'rejected' | 'applied';
  createdAt: Date;
}

const pendingEdits = ref<PendingEdit[]>([]);
const currentPreview = ref<PendingEdit | null>(null);

export function useDiffPreview() {
  /**
   * Generate a unified diff between two strings
   */
  function generateDiff(oldContent: string, newContent: string, path: string): FileDiff {
    const oldLines = oldContent.split('\n');
    const newLines = newContent.split('\n');
    const diffLines: DiffLine[] = [];

    // Simple line-by-line diff (Myers algorithm would be better but complex)
    const maxLen = Math.max(oldLines.length, newLines.length);
    let additions = 0;
    let deletions = 0;
    let oldLineNum = 1;
    let newLineNum = 1;

    // Add header
    diffLines.push({
      type: 'header',
      content: `--- a/${path}`,
    });
    diffLines.push({
      type: 'header',
      content: `+++ b/${path}`,
    });

    // Find differences using LCS-inspired approach
    let i = 0;
    let j = 0;

    while (i < oldLines.length || j < newLines.length) {
      if (i >= oldLines.length) {
        // Remaining new lines are additions
        diffLines.push({
          type: 'added',
          content: `+${newLines[j]}`,
          newLineNumber: newLineNum++,
        });
        additions++;
        j++;
      } else if (j >= newLines.length) {
        // Remaining old lines are deletions
        diffLines.push({
          type: 'removed',
          content: `-${oldLines[i]}`,
          oldLineNumber: oldLineNum++,
        });
        deletions++;
        i++;
      } else if (oldLines[i] === newLines[j]) {
        // Lines match - context
        diffLines.push({
          type: 'context',
          content: ` ${oldLines[i]}`,
          oldLineNumber: oldLineNum++,
          newLineNumber: newLineNum++,
        });
        i++;
        j++;
      } else {
        // Lines differ - look ahead for matches
        let foundMatch = false;

        // Check if old line appears soon in new
        for (let k = j + 1; k < Math.min(j + 5, newLines.length); k++) {
          if (oldLines[i] === newLines[k]) {
            // New lines were added
            while (j < k) {
              diffLines.push({
                type: 'added',
                content: `+${newLines[j]}`,
                newLineNumber: newLineNum++,
              });
              additions++;
              j++;
            }
            foundMatch = true;
            break;
          }
        }

        if (!foundMatch) {
          // Check if new line appears soon in old
          for (let k = i + 1; k < Math.min(i + 5, oldLines.length); k++) {
            if (newLines[j] === oldLines[k]) {
              // Old lines were removed
              while (i < k) {
                diffLines.push({
                  type: 'removed',
                  content: `-${oldLines[i]}`,
                  oldLineNumber: oldLineNum++,
                });
                deletions++;
                i++;
              }
              foundMatch = true;
              break;
            }
          }
        }

        if (!foundMatch) {
          // Simple replacement
          diffLines.push({
            type: 'removed',
            content: `-${oldLines[i]}`,
            oldLineNumber: oldLineNum++,
          });
          deletions++;
          i++;

          diffLines.push({
            type: 'added',
            content: `+${newLines[j]}`,
            newLineNumber: newLineNum++,
          });
          additions++;
          j++;
        }
      }
    }

    return {
      path,
      oldContent,
      newContent,
      lines: diffLines,
      additions,
      deletions,
    };
  }

  /**
   * Create a pending edit with diff preview
   */
  async function createPendingEdit(
    path: string,
    oldString: string,
    newString: string,
    replaceAll: boolean = false
  ): Promise<PendingEdit> {
    // Read current file content
    let currentContent = '';

    try {
      if (isTauri && invoke) {
        currentContent = await invoke<string>('read_file', { path });
      }
    } catch (e) {
      console.error('[DiffPreview] Could not read file:', e);
    }

    // Calculate new content
    let newContent: string;
    if (replaceAll) {
      newContent = currentContent.replace(new RegExp(escapeRegex(oldString), 'g'), newString);
    } else {
      newContent = currentContent.replace(oldString, newString);
    }

    // Generate diff
    const diff = generateDiff(currentContent, newContent, path);

    const edit: PendingEdit = {
      id: `edit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      path,
      oldString,
      newString,
      replaceAll,
      diff,
      status: 'pending',
      createdAt: new Date(),
    };

    pendingEdits.value.push(edit);
    currentPreview.value = edit;

    return edit;
  }

  /**
   * Escape special regex characters
   */
  function escapeRegex(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Apply a pending edit
   */
  async function applyEdit(editId: string): Promise<boolean> {
    const edit = pendingEdits.value.find(e => e.id === editId);
    if (!edit || edit.status !== 'pending') return false;

    try {
      if (isTauri && invoke) {
        await invoke('edit_file', {
          path: edit.path,
          oldString: edit.oldString,
          newString: edit.newString,
          replaceAll: edit.replaceAll,
        });
      }

      edit.status = 'applied';

      // Add to undo history
      addToUndoHistory(edit);

      return true;
    } catch (e) {
      console.error('[DiffPreview] Failed to apply edit:', e);
      return false;
    }
  }

  /**
   * Reject a pending edit
   */
  function rejectEdit(editId: string) {
    const edit = pendingEdits.value.find(e => e.id === editId);
    if (edit) {
      edit.status = 'rejected';
    }
  }

  /**
   * Approve a pending edit (mark for batch apply)
   */
  function approveEdit(editId: string) {
    const edit = pendingEdits.value.find(e => e.id === editId);
    if (edit) {
      edit.status = 'approved';
    }
  }

  /**
   * Apply all approved edits
   */
  async function applyApprovedEdits(): Promise<number> {
    let applied = 0;
    const approved = pendingEdits.value.filter(e => e.status === 'approved');

    for (const edit of approved) {
      if (await applyEdit(edit.id)) {
        applied++;
      }
    }

    return applied;
  }

  /**
   * Clear all pending edits
   */
  function clearPendingEdits() {
    pendingEdits.value = [];
    currentPreview.value = null;
  }

  /**
   * Get diff as formatted string
   */
  function formatDiff(diff: FileDiff): string {
    return diff.lines.map(line => line.content).join('\n');
  }

  /**
   * Get diff statistics
   */
  function getDiffStats(diff: FileDiff): string {
    return `+${diff.additions} -${diff.deletions}`;
  }

  // Undo history for applied edits
  const undoHistory = ref<PendingEdit[]>([]);
  const MAX_UNDO_HISTORY = 50;

  function addToUndoHistory(edit: PendingEdit) {
    undoHistory.value.unshift(edit);
    if (undoHistory.value.length > MAX_UNDO_HISTORY) {
      undoHistory.value.pop();
    }
  }

  /**
   * Undo the last applied edit
   */
  async function undoLastEdit(): Promise<boolean> {
    const lastEdit = undoHistory.value.shift();
    if (!lastEdit) return false;

    try {
      if (isTauri && invoke) {
        // Reverse the edit
        await invoke('edit_file', {
          path: lastEdit.path,
          oldString: lastEdit.newString,
          newString: lastEdit.oldString,
          replaceAll: lastEdit.replaceAll,
        });
      }

      return true;
    } catch (e) {
      console.error('[DiffPreview] Failed to undo edit:', e);
      // Put back on history
      undoHistory.value.unshift(lastEdit);
      return false;
    }
  }

  return {
    pendingEdits: computed(() => pendingEdits.value),
    currentPreview: computed(() => currentPreview.value),
    undoHistory: computed(() => undoHistory.value),
    generateDiff,
    createPendingEdit,
    applyEdit,
    rejectEdit,
    approveEdit,
    applyApprovedEdits,
    clearPendingEdits,
    formatDiff,
    getDiffStats,
    undoLastEdit,
  };
}
