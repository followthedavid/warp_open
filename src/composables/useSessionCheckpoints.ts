/**
 * Session Checkpoints System
 * Save and restore conversation states at any point.
 * Implements /rewind functionality like Claude Code.
 */

import { ref, computed } from 'vue';

export interface Checkpoint {
  id: string;
  sessionId: string;
  name: string;
  description?: string;
  timestamp: number;
  messageCount: number;
  lastMessage: string;
  state: {
    messages: Array<{
      role: 'user' | 'assistant' | 'system';
      content: string;
      timestamp: number;
    }>;
    context?: Record<string, unknown>;
    todoList?: Array<{ content: string; status: string }>;
  };
}

export interface CheckpointStats {
  totalCheckpoints: number;
  oldestCheckpoint?: number;
  newestCheckpoint?: number;
  bySession: Record<string, number>;
}

const STORAGE_KEY = 'warp_open_checkpoints';
const MAX_CHECKPOINTS_PER_SESSION = 20;
const MAX_TOTAL_CHECKPOINTS = 100;

// State
const checkpoints = ref<Map<string, Checkpoint>>(new Map());
const currentSessionId = ref<string | null>(null);

// Load from storage
function loadCheckpoints(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const data = JSON.parse(stored);
      checkpoints.value = new Map(Object.entries(data));
    }
  } catch (e) {
    console.error('[Checkpoints] Error loading:', e);
  }
}

// Save to storage
function saveCheckpoints(): void {
  try {
    const data = Object.fromEntries(checkpoints.value);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch (e) {
    console.error('[Checkpoints] Error saving:', e);
  }
}

// Initialize
loadCheckpoints();

function generateCheckpointId(): string {
  return `ckpt_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function useSessionCheckpoints() {
  const sessionCheckpoints = computed(() => {
    if (!currentSessionId.value) return [];
    return Array.from(checkpoints.value.values())
      .filter(c => c.sessionId === currentSessionId.value)
      .sort((a, b) => b.timestamp - a.timestamp);
  });

  const allCheckpoints = computed(() =>
    Array.from(checkpoints.value.values())
      .sort((a, b) => b.timestamp - a.timestamp)
  );

  /**
   * Set the current session
   */
  function setSession(sessionId: string): void {
    currentSessionId.value = sessionId;
  }

  /**
   * Create a checkpoint
   */
  function createCheckpoint(
    messages: Checkpoint['state']['messages'],
    options?: {
      name?: string;
      description?: string;
      context?: Record<string, unknown>;
      todoList?: Array<{ content: string; status: string }>;
    }
  ): Checkpoint {
    if (!currentSessionId.value) {
      throw new Error('No session active');
    }

    const checkpoint: Checkpoint = {
      id: generateCheckpointId(),
      sessionId: currentSessionId.value,
      name: options?.name || `Checkpoint ${sessionCheckpoints.value.length + 1}`,
      description: options?.description,
      timestamp: Date.now(),
      messageCount: messages.length,
      lastMessage: messages[messages.length - 1]?.content.slice(0, 100) || '',
      state: {
        messages: [...messages],
        context: options?.context,
        todoList: options?.todoList,
      },
    };

    checkpoints.value.set(checkpoint.id, checkpoint);

    // Prune old checkpoints for this session
    pruneSessionCheckpoints(currentSessionId.value);

    // Prune total checkpoints if needed
    pruneTotalCheckpoints();

    saveCheckpoints();

    console.log(`[Checkpoints] Created checkpoint: ${checkpoint.name}`);
    return checkpoint;
  }

  /**
   * Create an auto-checkpoint (named automatically)
   */
  function autoCheckpoint(
    messages: Checkpoint['state']['messages'],
    context?: Record<string, unknown>
  ): Checkpoint {
    const lastUserMessage = [...messages].reverse().find(m => m.role === 'user');
    const name = lastUserMessage
      ? `After: "${lastUserMessage.content.slice(0, 30)}..."`
      : `Auto checkpoint`;

    return createCheckpoint(messages, { name, context });
  }

  /**
   * Restore a checkpoint
   */
  function restoreCheckpoint(checkpointId: string): Checkpoint['state'] | null {
    const checkpoint = checkpoints.value.get(checkpointId);
    if (!checkpoint) {
      console.error(`[Checkpoints] Checkpoint not found: ${checkpointId}`);
      return null;
    }

    console.log(`[Checkpoints] Restored checkpoint: ${checkpoint.name}`);
    return { ...checkpoint.state };
  }

  /**
   * Rewind to a specific number of messages back
   */
  function rewindToMessage(
    messages: Checkpoint['state']['messages'],
    stepsBack: number
  ): Checkpoint['state']['messages'] {
    if (stepsBack <= 0 || stepsBack >= messages.length) {
      return messages;
    }

    // Create checkpoint before rewinding
    autoCheckpoint(messages);

    // Return truncated messages
    return messages.slice(0, messages.length - stepsBack);
  }

  /**
   * Rewind to before last user message
   */
  function rewindLastTurn(
    messages: Checkpoint['state']['messages']
  ): Checkpoint['state']['messages'] {
    // Find the last user message
    let lastUserIndex = -1;
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].role === 'user') {
        lastUserIndex = i;
        break;
      }
    }

    if (lastUserIndex <= 0) {
      return messages;
    }

    // Create checkpoint before rewinding
    autoCheckpoint(messages);

    // Return messages up to (not including) the last user message
    return messages.slice(0, lastUserIndex);
  }

  /**
   * Fork from a checkpoint (create new branch)
   */
  function forkFromCheckpoint(checkpointId: string, newSessionId: string): Checkpoint['state'] | null {
    const checkpoint = checkpoints.value.get(checkpointId);
    if (!checkpoint) return null;

    // Set the new session as current
    currentSessionId.value = newSessionId;

    // Create a checkpoint in the new session
    createCheckpoint(checkpoint.state.messages, {
      name: `Forked from: ${checkpoint.name}`,
      context: checkpoint.state.context,
    });

    return { ...checkpoint.state };
  }

  /**
   * Delete a checkpoint
   */
  function deleteCheckpoint(checkpointId: string): boolean {
    const deleted = checkpoints.value.delete(checkpointId);
    if (deleted) {
      saveCheckpoints();
    }
    return deleted;
  }

  /**
   * Rename a checkpoint
   */
  function renameCheckpoint(checkpointId: string, newName: string): void {
    const checkpoint = checkpoints.value.get(checkpointId);
    if (checkpoint) {
      checkpoint.name = newName;
      saveCheckpoints();
    }
  }

  /**
   * Get checkpoint by ID
   */
  function getCheckpoint(checkpointId: string): Checkpoint | undefined {
    return checkpoints.value.get(checkpointId);
  }

  /**
   * Get checkpoints for a specific session
   */
  function getSessionCheckpoints(sessionId: string): Checkpoint[] {
    return Array.from(checkpoints.value.values())
      .filter(c => c.sessionId === sessionId)
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Prune old checkpoints for a session
   */
  function pruneSessionCheckpoints(sessionId: string): void {
    const sessionCkpts = getSessionCheckpoints(sessionId);
    if (sessionCkpts.length > MAX_CHECKPOINTS_PER_SESSION) {
      const toDelete = sessionCkpts.slice(MAX_CHECKPOINTS_PER_SESSION);
      for (const ckpt of toDelete) {
        checkpoints.value.delete(ckpt.id);
      }
    }
  }

  /**
   * Prune total checkpoints
   */
  function pruneTotalCheckpoints(): void {
    if (checkpoints.value.size > MAX_TOTAL_CHECKPOINTS) {
      const allCkpts = allCheckpoints.value;
      const toDelete = allCkpts.slice(MAX_TOTAL_CHECKPOINTS);
      for (const ckpt of toDelete) {
        checkpoints.value.delete(ckpt.id);
      }
    }
  }

  /**
   * Clear all checkpoints for current session
   */
  function clearSessionCheckpoints(): void {
    if (!currentSessionId.value) return;

    for (const [id, ckpt] of checkpoints.value) {
      if (ckpt.sessionId === currentSessionId.value) {
        checkpoints.value.delete(id);
      }
    }
    saveCheckpoints();
  }

  /**
   * Clear all checkpoints
   */
  function clearAllCheckpoints(): void {
    checkpoints.value.clear();
    saveCheckpoints();
  }

  /**
   * Get statistics
   */
  function getStats(): CheckpointStats {
    const all = allCheckpoints.value;
    const bySession: Record<string, number> = {};

    for (const ckpt of all) {
      bySession[ckpt.sessionId] = (bySession[ckpt.sessionId] || 0) + 1;
    }

    return {
      totalCheckpoints: all.length,
      oldestCheckpoint: all[all.length - 1]?.timestamp,
      newestCheckpoint: all[0]?.timestamp,
      bySession,
    };
  }

  /**
   * Export checkpoints for backup
   */
  function exportCheckpoints(): string {
    return JSON.stringify(Array.from(checkpoints.value.values()), null, 2);
  }

  /**
   * Import checkpoints from backup
   */
  function importCheckpoints(json: string): number {
    try {
      const imported = JSON.parse(json) as Checkpoint[];
      let count = 0;

      for (const ckpt of imported) {
        if (!checkpoints.value.has(ckpt.id)) {
          checkpoints.value.set(ckpt.id, ckpt);
          count++;
        }
      }

      saveCheckpoints();
      return count;
    } catch (error) {
      console.error('[Checkpoints] Import error:', error);
      return 0;
    }
  }

  return {
    // State
    currentSessionId: computed(() => currentSessionId.value),
    sessionCheckpoints,
    allCheckpoints,

    // Session
    setSession,

    // Checkpoint operations
    createCheckpoint,
    autoCheckpoint,
    restoreCheckpoint,
    deleteCheckpoint,
    renameCheckpoint,
    getCheckpoint,
    getSessionCheckpoints,
    forkFromCheckpoint,

    // Rewind operations
    rewindToMessage,
    rewindLastTurn,

    // Cleanup
    clearSessionCheckpoints,
    clearAllCheckpoints,

    // Stats & export
    getStats,
    exportCheckpoints,
    importCheckpoints,
  };
}
