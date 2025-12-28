/**
 * RecoveryHandler - Checkpoint and rollback system
 *
 * Provides safety net for agent actions by:
 * - Creating checkpoints before risky operations
 * - Storing file backups
 * - Rolling back on failure
 * - Tracking action history for undo
 */

import { invoke } from '@tauri-apps/api/tauri';
import type { AgentAction } from './ConstrainedOutput';
import type { ContextState } from './ContextManager';

export interface FileBackup {
  path: string;
  content: string;
  timestamp: number;
}

export interface ActionRecord {
  action: AgentAction;
  timestamp: number;
  result: 'success' | 'failed' | 'rolled_back';
  output?: string;
  error?: string;
  backup?: FileBackup;
}

export interface Checkpoint {
  id: string;
  timestamp: number;
  contextState: ContextState;
  fileBackups: FileBackup[];
  actionHistory: ActionRecord[];
  description: string;
}

export class RecoveryHandler {
  private checkpoints: Map<string, Checkpoint>;
  private actionHistory: ActionRecord[];
  private maxCheckpoints: number;
  private maxHistoryLength: number;
  private backupDir: string;

  constructor(options: {
    maxCheckpoints?: number;
    maxHistoryLength?: number;
    backupDir?: string;
  } = {}) {
    this.checkpoints = new Map();
    this.actionHistory = [];
    this.maxCheckpoints = options.maxCheckpoints ?? 10;
    this.maxHistoryLength = options.maxHistoryLength ?? 50;
    this.backupDir = options.backupDir ?? '/tmp/warp_open_backups';

    // Ensure backup directory exists
    this.initBackupDir();
  }

  private async initBackupDir(): Promise<void> {
    try {
      await invoke<void>('execute_shell', {
        command: `mkdir -p ${this.backupDir}`
      });
    } catch (e) {
      console.error('Failed to create backup directory:', e);
    }
  }

  /**
   * Create a checkpoint before a risky operation
   */
  async createCheckpoint(
    contextState: ContextState,
    description: string
  ): Promise<string> {
    const id = `cp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const checkpoint: Checkpoint = {
      id,
      timestamp: Date.now(),
      contextState: JSON.parse(JSON.stringify(contextState)),
      fileBackups: [],
      actionHistory: [...this.actionHistory],
      description
    };

    this.checkpoints.set(id, checkpoint);

    // Prune old checkpoints
    if (this.checkpoints.size > this.maxCheckpoints) {
      const oldest = Array.from(this.checkpoints.keys())[0];
      await this.deleteCheckpoint(oldest);
    }

    return id;
  }

  /**
   * Backup a file before modifying it
   */
  async backupFile(path: string, checkpointId?: string): Promise<FileBackup | null> {
    try {
      const content = await invoke<string>('read_file', { path });

      const backup: FileBackup = {
        path,
        content,
        timestamp: Date.now()
      };

      // Also write to disk for persistence
      const backupPath = `${this.backupDir}/${path.replace(/\//g, '_')}_${Date.now()}`;
      await invoke<void>('write_file', { path: backupPath, content });

      // Add to checkpoint if specified
      if (checkpointId) {
        const checkpoint = this.checkpoints.get(checkpointId);
        if (checkpoint) {
          checkpoint.fileBackups.push(backup);
        }
      }

      return backup;
    } catch (e) {
      // File doesn't exist yet, no backup needed
      return null;
    }
  }

  /**
   * Record an action execution
   */
  recordAction(
    action: AgentAction,
    result: 'success' | 'failed' | 'rolled_back',
    output?: string,
    error?: string,
    backup?: FileBackup
  ): void {
    const record: ActionRecord = {
      action,
      timestamp: Date.now(),
      result,
      output,
      error,
      backup
    };

    this.actionHistory.push(record);

    // Prune old history
    if (this.actionHistory.length > this.maxHistoryLength) {
      this.actionHistory.shift();
    }
  }

  /**
   * Rollback to a checkpoint
   */
  async rollback(checkpointId: string): Promise<{ success: boolean; errors: string[] }> {
    const checkpoint = this.checkpoints.get(checkpointId);
    if (!checkpoint) {
      return { success: false, errors: [`Checkpoint ${checkpointId} not found`] };
    }

    const errors: string[] = [];

    // Restore file backups
    for (const backup of checkpoint.fileBackups) {
      try {
        await invoke<void>('write_file', {
          path: backup.path,
          content: backup.content
        });
      } catch (e) {
        errors.push(`Failed to restore ${backup.path}: ${e instanceof Error ? e.message : 'Unknown error'}`);
      }
    }

    // Mark rolled back actions
    const rollbackTime = checkpoint.timestamp;
    for (const record of this.actionHistory) {
      if (record.timestamp > rollbackTime && record.result === 'success') {
        record.result = 'rolled_back';
      }
    }

    return { success: errors.length === 0, errors };
  }

  /**
   * Undo the last successful action
   */
  async undoLast(): Promise<{ success: boolean; action?: AgentAction; error?: string }> {
    // Find last successful action with a backup
    for (let i = this.actionHistory.length - 1; i >= 0; i--) {
      const record = this.actionHistory[i];
      if (record.result === 'success' && record.backup) {
        try {
          await invoke<void>('write_file', {
            path: record.backup.path,
            content: record.backup.content
          });
          record.result = 'rolled_back';
          return { success: true, action: record.action };
        } catch (e) {
          return {
            success: false,
            error: e instanceof Error ? e.message : 'Unknown error'
          };
        }
      }
    }

    return { success: false, error: 'No undoable actions found' };
  }

  /**
   * Execute an action with automatic backup and recovery
   */
  async executeWithRecovery(
    action: AgentAction,
    executor: (action: AgentAction) => Promise<string>,
    contextState: ContextState
  ): Promise<{ success: boolean; output?: string; error?: string }> {
    // Create checkpoint for risky actions
    const isRisky = action.action === 'write' || action.action === 'edit' || action.action === 'bash';
    let checkpointId: string | undefined;
    let backup: FileBackup | undefined;

    if (isRisky) {
      checkpointId = await this.createCheckpoint(contextState, `Before ${action.action}`);

      // Backup file if modifying
      if ((action.action === 'write' || action.action === 'edit') && action.path) {
        const fileBackup = await this.backupFile(action.path, checkpointId);
        if (fileBackup) backup = fileBackup;
      }
    }

    try {
      const output = await executor(action);
      this.recordAction(action, 'success', output, undefined, backup);
      return { success: true, output };
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      this.recordAction(action, 'failed', undefined, error, backup);

      // Auto-rollback on failure if we have a backup
      if (backup) {
        try {
          await invoke<void>('write_file', {
            path: backup.path,
            content: backup.content
          });
        } catch (rollbackError) {
          console.error('Rollback failed:', rollbackError);
        }
      }

      return { success: false, error };
    }
  }

  /**
   * Delete a checkpoint and its backups
   */
  private async deleteCheckpoint(id: string): Promise<void> {
    const checkpoint = this.checkpoints.get(id);
    if (!checkpoint) return;

    // Clean up backup files
    for (const backup of checkpoint.fileBackups) {
      try {
        const backupPath = `${this.backupDir}/${backup.path.replace(/\//g, '_')}_${backup.timestamp}`;
        await invoke<void>('execute_shell', {
          command: `rm -f ${backupPath}`
        });
      } catch (e) {
        // Ignore cleanup errors
      }
    }

    this.checkpoints.delete(id);
  }

  /**
   * Get recent action history
   */
  getHistory(count: number = 10): ActionRecord[] {
    return this.actionHistory.slice(-count);
  }

  /**
   * Get all checkpoints
   */
  getCheckpoints(): Checkpoint[] {
    return Array.from(this.checkpoints.values());
  }

  /**
   * Clear all checkpoints and history
   */
  async clear(): Promise<void> {
    for (const id of this.checkpoints.keys()) {
      await this.deleteCheckpoint(id);
    }
    this.actionHistory = [];
  }

  /**
   * Get statistics about recovery state
   */
  getStats(): {
    checkpointCount: number;
    historyLength: number;
    successRate: number;
    rollbackCount: number;
  } {
    const successCount = this.actionHistory.filter(a => a.result === 'success').length;
    const rollbackCount = this.actionHistory.filter(a => a.result === 'rolled_back').length;
    const total = this.actionHistory.length;

    return {
      checkpointCount: this.checkpoints.size,
      historyLength: total,
      successRate: total > 0 ? successCount / total : 1,
      rollbackCount
    };
  }
}

export default RecoveryHandler;
