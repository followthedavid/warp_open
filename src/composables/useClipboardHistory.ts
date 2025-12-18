/**
 * Clipboard History System
 * Track and manage clipboard history
 */

import { ref, computed, onMounted, onUnmounted } from 'vue';

export interface ClipboardEntry {
  id: string;
  content: string;
  type: 'text' | 'code' | 'command' | 'path' | 'url';
  timestamp: Date;
  source?: string;
  pinned?: boolean;
  tags?: string[];
}

const STORAGE_KEY = 'warp_open_clipboard_history';
const MAX_ENTRIES = 100;
const MAX_CONTENT_LENGTH = 50000; // 50KB per entry

const history = ref<ClipboardEntry[]>([]);
const lastClipboardContent = ref<string>('');
const isWatching = ref(false);

export function useClipboardHistory() {
  /**
   * Load history from storage
   */
  function loadHistory() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const data = JSON.parse(stored);
        history.value = data.map((entry: ClipboardEntry) => ({
          ...entry,
          timestamp: new Date(entry.timestamp),
        }));
      }
    } catch (e) {
      console.error('[ClipboardHistory] Error loading history:', e);
    }
  }

  /**
   * Save history to storage
   */
  function saveHistory() {
    try {
      // Only save non-pinned entries up to limit
      const toSave = history.value.slice(0, MAX_ENTRIES);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
    } catch (e) {
      console.error('[ClipboardHistory] Error saving history:', e);
    }
  }

  /**
   * Detect content type
   */
  function detectType(content: string): ClipboardEntry['type'] {
    // URL detection
    if (/^https?:\/\/[^\s]+$/.test(content.trim())) {
      return 'url';
    }

    // Path detection
    if (/^[\/~][\w\/\-._]+$/.test(content.trim()) || /^[A-Z]:\\[\w\\.\-_]+$/.test(content.trim())) {
      return 'path';
    }

    // Command detection (starts with common commands)
    const commandPrefixes = [
      'git ', 'npm ', 'yarn ', 'pnpm ', 'cargo ', 'docker ', 'kubectl ',
      'cd ', 'ls ', 'pwd ', 'cat ', 'grep ', 'find ', 'mkdir ', 'rm ',
      'cp ', 'mv ', 'chmod ', 'chown ', 'sudo ', 'brew ', 'apt ', 'pip ',
      'python ', 'node ', 'deno ', 'go ', 'rustc ', 'make ', 'cmake ',
    ];

    const trimmed = content.trim();
    for (const prefix of commandPrefixes) {
      if (trimmed.startsWith(prefix)) {
        return 'command';
      }
    }

    // Code detection (has programming language patterns)
    const codePatterns = [
      /^(function|const|let|var|class|interface|type|import|export|async|await)\s/m,
      /^(def|class|import|from|async|await)\s/m,
      /^(fn|let|mut|struct|impl|use|mod|pub)\s/m,
      /^(func|package|import|type|struct|interface)\s/m,
      /[{}\[\]();]\s*$/m,
      /^\s*(if|for|while|switch|case|try|catch|return)\s*[({]/m,
    ];

    for (const pattern of codePatterns) {
      if (pattern.test(content)) {
        return 'code';
      }
    }

    return 'text';
  }

  /**
   * Add content to history
   */
  function add(content: string, source?: string): ClipboardEntry | null {
    if (!content || content.length > MAX_CONTENT_LENGTH) {
      return null;
    }

    // Skip if same as last entry
    if (history.value.length > 0 && history.value[0].content === content) {
      return null;
    }

    const entry: ClipboardEntry = {
      id: generateId(),
      content,
      type: detectType(content),
      timestamp: new Date(),
      source,
      pinned: false,
    };

    // Add to beginning
    history.value.unshift(entry);

    // Trim history (keep pinned items)
    const pinned = history.value.filter(e => e.pinned);
    const unpinned = history.value.filter(e => !e.pinned);

    if (unpinned.length > MAX_ENTRIES) {
      history.value = [...pinned, ...unpinned.slice(0, MAX_ENTRIES - pinned.length)];
    }

    saveHistory();
    return entry;
  }

  /**
   * Copy content to clipboard and add to history
   */
  async function copy(content: string, source?: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(content);
      lastClipboardContent.value = content;
      add(content, source);
    } catch (e) {
      console.error('[ClipboardHistory] Error copying:', e);
    }
  }

  /**
   * Paste from a history entry
   */
  async function paste(entryId: string): Promise<string | null> {
    const entry = history.value.find(e => e.id === entryId);
    if (!entry) return null;

    try {
      await navigator.clipboard.writeText(entry.content);
      lastClipboardContent.value = entry.content;

      // Move to top (if not pinned)
      if (!entry.pinned) {
        const index = history.value.indexOf(entry);
        if (index > 0) {
          history.value.splice(index, 1);
          history.value.unshift(entry);
          saveHistory();
        }
      }

      return entry.content;
    } catch (e) {
      console.error('[ClipboardHistory] Error pasting:', e);
      return null;
    }
  }

  /**
   * Pin/unpin an entry
   */
  function togglePin(entryId: string): boolean {
    const entry = history.value.find(e => e.id === entryId);
    if (!entry) return false;

    entry.pinned = !entry.pinned;
    saveHistory();
    return entry.pinned;
  }

  /**
   * Delete an entry
   */
  function remove(entryId: string): boolean {
    const index = history.value.findIndex(e => e.id === entryId);
    if (index < 0) return false;

    history.value.splice(index, 1);
    saveHistory();
    return true;
  }

  /**
   * Clear all history (except pinned)
   */
  function clearHistory(includePinned: boolean = false) {
    if (includePinned) {
      history.value = [];
    } else {
      history.value = history.value.filter(e => e.pinned);
    }
    saveHistory();
  }

  /**
   * Search history
   */
  function search(query: string, type?: ClipboardEntry['type']): ClipboardEntry[] {
    let results = history.value;

    if (type) {
      results = results.filter(e => e.type === type);
    }

    if (query) {
      const q = query.toLowerCase();
      results = results.filter(e => e.content.toLowerCase().includes(q));
    }

    return results;
  }

  /**
   * Get recent entries by type
   */
  function getByType(type: ClipboardEntry['type'], limit: number = 10): ClipboardEntry[] {
    return history.value.filter(e => e.type === type).slice(0, limit);
  }

  /**
   * Get recent commands
   */
  function getRecentCommands(limit: number = 10): ClipboardEntry[] {
    return getByType('command', limit);
  }

  /**
   * Get recent code snippets
   */
  function getRecentCode(limit: number = 10): ClipboardEntry[] {
    return getByType('code', limit);
  }

  /**
   * Get recent URLs
   */
  function getRecentUrls(limit: number = 10): ClipboardEntry[] {
    return getByType('url', limit);
  }

  /**
   * Get pinned entries
   */
  function getPinned(): ClipboardEntry[] {
    return history.value.filter(e => e.pinned);
  }

  /**
   * Watch clipboard for changes
   */
  function startWatching() {
    if (isWatching.value) return;
    isWatching.value = true;

    // Check clipboard periodically
    const checkClipboard = async () => {
      if (!isWatching.value) return;

      try {
        const content = await navigator.clipboard.readText();
        if (content && content !== lastClipboardContent.value) {
          lastClipboardContent.value = content;
          add(content, 'clipboard');
        }
      } catch {
        // Permission denied or clipboard empty
      }

      if (isWatching.value) {
        setTimeout(checkClipboard, 1000);
      }
    };

    checkClipboard();
  }

  /**
   * Stop watching clipboard
   */
  function stopWatching() {
    isWatching.value = false;
  }

  /**
   * Add tags to an entry
   */
  function addTag(entryId: string, tag: string): boolean {
    const entry = history.value.find(e => e.id === entryId);
    if (!entry) return false;

    if (!entry.tags) entry.tags = [];
    if (!entry.tags.includes(tag)) {
      entry.tags.push(tag);
      saveHistory();
    }

    return true;
  }

  /**
   * Remove tag from an entry
   */
  function removeTag(entryId: string, tag: string): boolean {
    const entry = history.value.find(e => e.id === entryId);
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
   * Get entries by tag
   */
  function getByTag(tag: string): ClipboardEntry[] {
    return history.value.filter(e => e.tags?.includes(tag));
  }

  /**
   * Get all tags
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
   * Format content preview
   */
  function formatPreview(content: string, maxLength: number = 100): string {
    const singleLine = content.replace(/\n/g, ' ').trim();
    if (singleLine.length <= maxLength) return singleLine;
    return singleLine.substring(0, maxLength) + '...';
  }

  /**
   * Generate unique ID
   */
  function generateId(): string {
    return `clip-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Initialize
  loadHistory();

  // Computed values
  const count = computed(() => history.value.length);
  const pinnedCount = computed(() => history.value.filter(e => e.pinned).length);

  return {
    history: computed(() => history.value),
    count,
    pinnedCount,
    isWatching: computed(() => isWatching.value),
    add,
    copy,
    paste,
    togglePin,
    remove,
    clearHistory,
    search,
    getByType,
    getRecentCommands,
    getRecentCode,
    getRecentUrls,
    getPinned,
    startWatching,
    stopWatching,
    addTag,
    removeTag,
    getByTag,
    getAllTags,
    formatPreview,
  };
}
