/**
 * Command History System
 * Advanced command history with search, filtering, and analytics
 */

import { ref, computed } from 'vue';

export interface CommandEntry {
  id: string;
  command: string;
  timestamp: Date;
  cwd: string;
  exitCode?: number;
  duration?: number; // milliseconds
  output?: string;
  tags?: string[];
  favorite?: boolean;
}

export interface CommandStats {
  totalCommands: number;
  uniqueCommands: number;
  mostUsed: Array<{ command: string; count: number }>;
  byHour: number[];
  byDay: number[];
  averageDuration: number;
  successRate: number;
}

const STORAGE_KEY = 'warp_open_command_history';
const MAX_ENTRIES = 10000;
const MAX_OUTPUT_LENGTH = 1000;

const history = ref<CommandEntry[]>([]);
const searchQuery = ref('');
const searchFilters = ref({
  cwd: '',
  exitCode: null as number | null,
  fromDate: null as Date | null,
  toDate: null as Date | null,
  favorites: false,
  tags: [] as string[],
});

export function useCommandHistory() {
  /**
   * Load history from storage
   */
  function loadHistory() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const data = JSON.parse(stored);
        history.value = data.map((entry: CommandEntry) => ({
          ...entry,
          timestamp: new Date(entry.timestamp),
        }));
      }
    } catch (e) {
      console.error('[CommandHistory] Error loading history:', e);
    }
  }

  /**
   * Save history to storage
   */
  function saveHistory() {
    try {
      // Trim output to save space
      const toSave = history.value.map(entry => ({
        ...entry,
        output: entry.output?.substring(0, MAX_OUTPUT_LENGTH),
      }));
      localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
    } catch (e) {
      console.error('[CommandHistory] Error saving history:', e);
    }
  }

  /**
   * Add a command to history
   */
  function add(entry: Omit<CommandEntry, 'id'>): CommandEntry {
    const newEntry: CommandEntry = {
      ...entry,
      id: generateId(),
    };

    history.value.unshift(newEntry);

    // Trim if too many entries
    if (history.value.length > MAX_ENTRIES) {
      // Keep favorites
      const favorites = history.value.filter(e => e.favorite);
      const nonFavorites = history.value.filter(e => !e.favorite);
      history.value = [...favorites, ...nonFavorites.slice(0, MAX_ENTRIES - favorites.length)];
    }

    saveHistory();
    return newEntry;
  }

  /**
   * Update an entry (e.g., add exit code after completion)
   */
  function update(id: string, updates: Partial<CommandEntry>): boolean {
    const entry = history.value.find(e => e.id === id);
    if (!entry) return false;

    Object.assign(entry, updates);
    saveHistory();
    return true;
  }

  /**
   * Delete an entry
   */
  function remove(id: string): boolean {
    const index = history.value.findIndex(e => e.id === id);
    if (index < 0) return false;

    history.value.splice(index, 1);
    saveHistory();
    return true;
  }

  /**
   * Clear history
   */
  function clear(keepFavorites: boolean = true) {
    if (keepFavorites) {
      history.value = history.value.filter(e => e.favorite);
    } else {
      history.value = [];
    }
    saveHistory();
  }

  /**
   * Toggle favorite status
   */
  function toggleFavorite(id: string): boolean {
    const entry = history.value.find(e => e.id === id);
    if (!entry) return false;

    entry.favorite = !entry.favorite;
    saveHistory();
    return entry.favorite;
  }

  /**
   * Add tag to entry
   */
  function addTag(id: string, tag: string): boolean {
    const entry = history.value.find(e => e.id === id);
    if (!entry) return false;

    if (!entry.tags) entry.tags = [];
    if (!entry.tags.includes(tag)) {
      entry.tags.push(tag);
      saveHistory();
    }
    return true;
  }

  /**
   * Remove tag from entry
   */
  function removeTag(id: string, tag: string): boolean {
    const entry = history.value.find(e => e.id === id);
    if (!entry || !entry.tags) return false;

    const index = entry.tags.indexOf(tag);
    if (index >= 0) {
      entry.tags.splice(index, 1);
      saveHistory();
      return true;
    }
    return false;
  }

  /**
   * Search history
   */
  function search(query: string, options: {
    limit?: number;
    cwd?: string;
    exitCode?: number;
    fromDate?: Date;
    toDate?: Date;
    favorites?: boolean;
    tags?: string[];
  } = {}): CommandEntry[] {
    let results = history.value;

    // Text search
    if (query) {
      const q = query.toLowerCase();
      results = results.filter(e => e.command.toLowerCase().includes(q));
    }

    // Filter by cwd
    if (options.cwd) {
      const cwd = options.cwd.toLowerCase();
      results = results.filter(e => e.cwd.toLowerCase().includes(cwd));
    }

    // Filter by exit code
    if (options.exitCode !== undefined && options.exitCode !== null) {
      results = results.filter(e => e.exitCode === options.exitCode);
    }

    // Filter by date range
    if (options.fromDate) {
      results = results.filter(e => e.timestamp >= options.fromDate!);
    }
    if (options.toDate) {
      results = results.filter(e => e.timestamp <= options.toDate!);
    }

    // Filter favorites
    if (options.favorites) {
      results = results.filter(e => e.favorite);
    }

    // Filter by tags
    if (options.tags && options.tags.length > 0) {
      results = results.filter(e =>
        e.tags && options.tags!.every(tag => e.tags!.includes(tag))
      );
    }

    // Apply limit
    if (options.limit) {
      results = results.slice(0, options.limit);
    }

    return results;
  }

  /**
   * Fuzzy search (for autocomplete)
   */
  function fuzzySearch(query: string, limit: number = 10): CommandEntry[] {
    if (!query) return history.value.slice(0, limit);

    const q = query.toLowerCase();

    // Score entries by relevance
    const scored = history.value.map(entry => {
      const cmd = entry.command.toLowerCase();
      let score = 0;

      // Exact match
      if (cmd === q) score += 100;
      // Starts with query
      else if (cmd.startsWith(q)) score += 50;
      // Contains query
      else if (cmd.includes(q)) score += 25;
      // Fuzzy match
      else {
        let queryIndex = 0;
        for (let i = 0; i < cmd.length && queryIndex < q.length; i++) {
          if (cmd[i] === q[queryIndex]) {
            score += 1;
            queryIndex++;
          }
        }
        if (queryIndex < q.length) score = 0; // Didn't match all chars
      }

      // Boost recent entries
      const hoursSince = (Date.now() - entry.timestamp.getTime()) / 3600000;
      if (hoursSince < 1) score *= 1.5;
      else if (hoursSince < 24) score *= 1.2;

      // Boost favorites
      if (entry.favorite) score *= 1.3;

      // Boost successful commands
      if (entry.exitCode === 0) score *= 1.1;

      return { entry, score };
    });

    return scored
      .filter(s => s.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(s => s.entry);
  }

  /**
   * Get unique commands (for autocomplete)
   */
  function getUniqueCommands(limit: number = 100): string[] {
    const seen = new Set<string>();
    const unique: string[] = [];

    for (const entry of history.value) {
      if (!seen.has(entry.command)) {
        seen.add(entry.command);
        unique.push(entry.command);
        if (unique.length >= limit) break;
      }
    }

    return unique;
  }

  /**
   * Get commands by prefix (for tab completion)
   */
  function getByPrefix(prefix: string, limit: number = 10): string[] {
    const seen = new Set<string>();
    const results: string[] = [];
    const p = prefix.toLowerCase();

    for (const entry of history.value) {
      if (entry.command.toLowerCase().startsWith(p) && !seen.has(entry.command)) {
        seen.add(entry.command);
        results.push(entry.command);
        if (results.length >= limit) break;
      }
    }

    return results;
  }

  /**
   * Get all unique tags
   */
  function getAllTags(): string[] {
    const tags = new Set<string>();
    for (const entry of history.value) {
      if (entry.tags) {
        for (const tag of entry.tags) {
          tags.add(tag);
        }
      }
    }
    return Array.from(tags).sort();
  }

  /**
   * Get all unique cwds
   */
  function getAllCwds(): string[] {
    const cwds = new Set<string>();
    for (const entry of history.value) {
      cwds.add(entry.cwd);
    }
    return Array.from(cwds).sort();
  }

  /**
   * Get statistics
   */
  function getStats(): CommandStats {
    const entries = history.value;

    // Basic counts
    const totalCommands = entries.length;
    const uniqueCommands = new Set(entries.map(e => e.command)).size;

    // Most used commands
    const commandCounts = new Map<string, number>();
    for (const entry of entries) {
      const base = entry.command.split(' ')[0]; // Just the command name
      commandCounts.set(base, (commandCounts.get(base) || 0) + 1);
    }
    const mostUsed = Array.from(commandCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([command, count]) => ({ command, count }));

    // By hour of day
    const byHour = new Array(24).fill(0);
    for (const entry of entries) {
      byHour[entry.timestamp.getHours()]++;
    }

    // By day of week
    const byDay = new Array(7).fill(0);
    for (const entry of entries) {
      byDay[entry.timestamp.getDay()]++;
    }

    // Average duration
    const withDuration = entries.filter(e => e.duration !== undefined);
    const averageDuration = withDuration.length > 0
      ? withDuration.reduce((sum, e) => sum + (e.duration || 0), 0) / withDuration.length
      : 0;

    // Success rate
    const withExitCode = entries.filter(e => e.exitCode !== undefined);
    const successCount = withExitCode.filter(e => e.exitCode === 0).length;
    const successRate = withExitCode.length > 0
      ? (successCount / withExitCode.length) * 100
      : 0;

    return {
      totalCommands,
      uniqueCommands,
      mostUsed,
      byHour,
      byDay,
      averageDuration,
      successRate,
    };
  }

  /**
   * Navigate history (up/down arrow)
   */
  const navigationIndex = ref(-1);
  const currentInput = ref('');

  function navigateUp(currentCommand: string): string | null {
    if (navigationIndex.value === -1) {
      currentInput.value = currentCommand;
    }

    if (navigationIndex.value < history.value.length - 1) {
      navigationIndex.value++;
      return history.value[navigationIndex.value].command;
    }

    return null;
  }

  function navigateDown(): string | null {
    if (navigationIndex.value > 0) {
      navigationIndex.value--;
      return history.value[navigationIndex.value].command;
    } else if (navigationIndex.value === 0) {
      navigationIndex.value = -1;
      return currentInput.value;
    }

    return null;
  }

  function resetNavigation() {
    navigationIndex.value = -1;
    currentInput.value = '';
  }

  /**
   * Export history
   */
  function exportHistory(format: 'json' | 'csv' = 'json'): string {
    if (format === 'csv') {
      const header = 'command,timestamp,cwd,exitCode,duration\n';
      const rows = history.value.map(e =>
        `"${e.command.replace(/"/g, '""')}","${e.timestamp.toISOString()}","${e.cwd}",${e.exitCode ?? ''},${e.duration ?? ''}`
      );
      return header + rows.join('\n');
    }

    return JSON.stringify(history.value, null, 2);
  }

  /**
   * Import history
   */
  function importHistory(data: string, format: 'json' | 'csv' = 'json'): number {
    let imported: CommandEntry[] = [];

    if (format === 'json') {
      imported = JSON.parse(data).map((e: CommandEntry) => ({
        ...e,
        id: e.id || generateId(),
        timestamp: new Date(e.timestamp),
      }));
    }

    // Merge with existing, avoiding duplicates
    const existingIds = new Set(history.value.map(e => e.id));
    const newEntries = imported.filter(e => !existingIds.has(e.id));

    history.value = [...newEntries, ...history.value]
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, MAX_ENTRIES);

    saveHistory();
    return newEntries.length;
  }

  /**
   * Generate unique ID
   */
  function generateId(): string {
    return `cmd-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Initialize
  loadHistory();

  // Computed values
  const filteredHistory = computed(() => {
    return search(searchQuery.value, {
      cwd: searchFilters.value.cwd,
      exitCode: searchFilters.value.exitCode ?? undefined,
      fromDate: searchFilters.value.fromDate ?? undefined,
      toDate: searchFilters.value.toDate ?? undefined,
      favorites: searchFilters.value.favorites,
      tags: searchFilters.value.tags,
    });
  });

  return {
    history: computed(() => history.value),
    filteredHistory,
    searchQuery,
    searchFilters,
    navigationIndex: computed(() => navigationIndex.value),
    add,
    update,
    remove,
    clear,
    toggleFavorite,
    addTag,
    removeTag,
    search,
    fuzzySearch,
    getUniqueCommands,
    getByPrefix,
    getAllTags,
    getAllCwds,
    getStats,
    navigateUp,
    navigateDown,
    resetNavigation,
    exportHistory,
    importHistory,
  };
}
