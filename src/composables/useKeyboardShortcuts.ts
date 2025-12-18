/**
 * Custom Keyboard Shortcuts System
 * User-configurable keybindings
 */

import { ref, computed, onMounted, onUnmounted } from 'vue';

export interface KeyBinding {
  id: string;
  action: string;
  description: string;
  keys: string[]; // e.g., ['Cmd', 'Shift', 'P']
  category: string;
  isCustom?: boolean;
  enabled?: boolean;
}

export interface ShortcutAction {
  id: string;
  name: string;
  description: string;
  category: string;
  handler: () => void;
}

// Default keybindings
const DEFAULT_BINDINGS: KeyBinding[] = [
  // Terminal
  { id: 'new-tab', action: 'newTab', description: 'New Tab', keys: ['Cmd', 'T'], category: 'Terminal' },
  { id: 'close-tab', action: 'closeTab', description: 'Close Tab', keys: ['Cmd', 'W'], category: 'Terminal' },
  { id: 'next-tab', action: 'nextTab', description: 'Next Tab', keys: ['Cmd', 'Shift', ']'], category: 'Terminal' },
  { id: 'prev-tab', action: 'prevTab', description: 'Previous Tab', keys: ['Cmd', 'Shift', '['], category: 'Terminal' },
  { id: 'clear', action: 'clear', description: 'Clear Terminal', keys: ['Cmd', 'K'], category: 'Terminal' },
  { id: 'split-horizontal', action: 'splitHorizontal', description: 'Split Horizontal', keys: ['Cmd', 'D'], category: 'Terminal' },
  { id: 'split-vertical', action: 'splitVertical', description: 'Split Vertical', keys: ['Cmd', 'Shift', 'D'], category: 'Terminal' },

  // Navigation
  { id: 'command-palette', action: 'commandPalette', description: 'Command Palette', keys: ['Cmd', 'Shift', 'P'], category: 'Navigation' },
  { id: 'global-search', action: 'globalSearch', description: 'Global Search', keys: ['Cmd', 'Shift', 'F'], category: 'Navigation' },
  { id: 'go-to-file', action: 'goToFile', description: 'Go to File', keys: ['Cmd', 'P'], category: 'Navigation' },
  { id: 'toggle-sidebar', action: 'toggleSidebar', description: 'Toggle Sidebar', keys: ['Cmd', 'B'], category: 'Navigation' },

  // AI
  { id: 'ai-panel', action: 'aiPanel', description: 'Toggle AI Panel', keys: ['Cmd', 'Shift', 'A'], category: 'AI' },
  { id: 'explain-selection', action: 'explainSelection', description: 'Explain Selection', keys: ['Cmd', 'Shift', 'E'], category: 'AI' },
  { id: 'fix-selection', action: 'fixSelection', description: 'Fix Selection', keys: ['Cmd', 'Shift', 'X'], category: 'AI' },

  // Edit
  { id: 'undo', action: 'undo', description: 'Undo', keys: ['Cmd', 'Z'], category: 'Edit' },
  { id: 'redo', action: 'redo', description: 'Redo', keys: ['Cmd', 'Shift', 'Z'], category: 'Edit' },
  { id: 'copy', action: 'copy', description: 'Copy', keys: ['Cmd', 'C'], category: 'Edit' },
  { id: 'paste', action: 'paste', description: 'Paste', keys: ['Cmd', 'V'], category: 'Edit' },
  { id: 'select-all', action: 'selectAll', description: 'Select All', keys: ['Cmd', 'A'], category: 'Edit' },

  // View
  { id: 'zoom-in', action: 'zoomIn', description: 'Zoom In', keys: ['Cmd', '='], category: 'View' },
  { id: 'zoom-out', action: 'zoomOut', description: 'Zoom Out', keys: ['Cmd', '-'], category: 'View' },
  { id: 'reset-zoom', action: 'resetZoom', description: 'Reset Zoom', keys: ['Cmd', '0'], category: 'View' },
  { id: 'toggle-fullscreen', action: 'toggleFullscreen', description: 'Toggle Fullscreen', keys: ['Cmd', 'Ctrl', 'F'], category: 'View' },

  // Git
  { id: 'git-commit', action: 'gitCommit', description: 'Smart Commit', keys: ['Cmd', 'Shift', 'G'], category: 'Git' },
  { id: 'git-status', action: 'gitStatus', description: 'Git Status', keys: ['Cmd', 'Shift', 'S'], category: 'Git' },

  // Workflows
  { id: 'notebook-mode', action: 'notebookMode', description: 'Toggle Notebook Mode', keys: ['Cmd', 'Shift', 'N'], category: 'Workflows' },
  { id: 'save-workflow', action: 'saveWorkflow', description: 'Save Workflow', keys: ['Cmd', 'Shift', 'W'], category: 'Workflows' },
];

const STORAGE_KEY = 'warp_open_keybindings';

const bindings = ref<KeyBinding[]>([]);
const actionHandlers = ref<Map<string, () => void>>(new Map());
const isListening = ref(false);
const conflictWarnings = ref<string[]>([]);

export function useKeyboardShortcuts() {
  /**
   * Load keybindings from storage
   */
  function loadBindings() {
    // Start with defaults
    bindings.value = [...DEFAULT_BINDINGS];

    // Load custom overrides
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const customBindings = JSON.parse(stored) as KeyBinding[];

        // Merge custom bindings
        for (const custom of customBindings) {
          const index = bindings.value.findIndex(b => b.id === custom.id);
          if (index >= 0) {
            bindings.value[index] = { ...bindings.value[index], ...custom };
          } else {
            bindings.value.push({ ...custom, isCustom: true });
          }
        }
      }
    } catch (e) {
      console.error('[Shortcuts] Error loading bindings:', e);
    }

    checkConflicts();
  }

  /**
   * Save keybindings to storage
   */
  function saveBindings() {
    try {
      // Only save non-default or modified bindings
      const toSave = bindings.value.filter(b => {
        const defaultBinding = DEFAULT_BINDINGS.find(d => d.id === b.id);
        if (!defaultBinding) return true; // Custom binding
        return JSON.stringify(b.keys) !== JSON.stringify(defaultBinding.keys);
      });

      localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
    } catch (e) {
      console.error('[Shortcuts] Error saving bindings:', e);
    }
  }

  /**
   * Register an action handler
   */
  function registerAction(action: string, handler: () => void) {
    actionHandlers.value.set(action, handler);
  }

  /**
   * Unregister an action handler
   */
  function unregisterAction(action: string) {
    actionHandlers.value.delete(action);
  }

  /**
   * Update a keybinding
   */
  function updateBinding(id: string, newKeys: string[]) {
    const binding = bindings.value.find(b => b.id === id);
    if (binding) {
      binding.keys = newKeys;
      saveBindings();
      checkConflicts();
    }
  }

  /**
   * Reset a binding to default
   */
  function resetBinding(id: string) {
    const defaultBinding = DEFAULT_BINDINGS.find(b => b.id === id);
    const binding = bindings.value.find(b => b.id === id);

    if (defaultBinding && binding) {
      binding.keys = [...defaultBinding.keys];
      saveBindings();
      checkConflicts();
    }
  }

  /**
   * Reset all bindings to defaults
   */
  function resetAllBindings() {
    bindings.value = [...DEFAULT_BINDINGS];
    localStorage.removeItem(STORAGE_KEY);
    checkConflicts();
  }

  /**
   * Add a custom binding
   */
  function addCustomBinding(binding: Omit<KeyBinding, 'id' | 'isCustom'>) {
    const newBinding: KeyBinding = {
      ...binding,
      id: `custom-${Date.now()}`,
      isCustom: true,
    };

    bindings.value.push(newBinding);
    saveBindings();
    checkConflicts();

    return newBinding.id;
  }

  /**
   * Remove a custom binding
   */
  function removeCustomBinding(id: string) {
    const index = bindings.value.findIndex(b => b.id === id && b.isCustom);
    if (index >= 0) {
      bindings.value.splice(index, 1);
      saveBindings();
    }
  }

  /**
   * Check for conflicting keybindings
   */
  function checkConflicts() {
    conflictWarnings.value = [];
    const keyMap = new Map<string, string[]>();

    for (const binding of bindings.value) {
      if (binding.enabled === false) continue;

      const keyStr = normalizeKeys(binding.keys).join('+');
      if (keyMap.has(keyStr)) {
        keyMap.get(keyStr)!.push(binding.description);
      } else {
        keyMap.set(keyStr, [binding.description]);
      }
    }

    for (const [keys, actions] of keyMap) {
      if (actions.length > 1) {
        conflictWarnings.value.push(`${keys}: ${actions.join(', ')}`);
      }
    }
  }

  /**
   * Normalize key names
   */
  function normalizeKeys(keys: string[]): string[] {
    return keys.map(k => {
      const lower = k.toLowerCase();
      if (lower === 'command' || lower === 'meta' || lower === '⌘') return 'Cmd';
      if (lower === 'control' || lower === 'ctrl') return 'Ctrl';
      if (lower === 'option' || lower === 'alt') return 'Alt';
      if (lower === 'shift') return 'Shift';
      return k.toUpperCase();
    });
  }

  /**
   * Convert key event to key string
   */
  function eventToKeys(event: KeyboardEvent): string[] {
    const keys: string[] = [];

    if (event.metaKey) keys.push('Cmd');
    if (event.ctrlKey) keys.push('Ctrl');
    if (event.altKey) keys.push('Alt');
    if (event.shiftKey) keys.push('Shift');

    // Add the actual key
    const key = event.key.length === 1 ? event.key.toUpperCase() : event.key;
    if (!['Meta', 'Control', 'Alt', 'Shift'].includes(key)) {
      keys.push(key);
    }

    return keys;
  }

  /**
   * Find binding matching keys
   */
  function findBinding(keys: string[]): KeyBinding | undefined {
    const normalizedInput = normalizeKeys(keys).sort().join('+');

    return bindings.value.find(b => {
      if (b.enabled === false) return false;
      const normalizedBinding = normalizeKeys(b.keys).sort().join('+');
      return normalizedInput === normalizedBinding;
    });
  }

  /**
   * Handle keyboard event
   */
  function handleKeyDown(event: KeyboardEvent) {
    // Ignore if in input field (unless it's a global shortcut)
    const target = event.target as HTMLElement;
    const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

    const keys = eventToKeys(event);
    const binding = findBinding(keys);

    if (binding) {
      // Check if this should work in input fields
      const globalShortcuts = ['commandPalette', 'globalSearch', 'toggleSidebar'];
      if (isInput && !globalShortcuts.includes(binding.action)) {
        return;
      }

      const handler = actionHandlers.value.get(binding.action);
      if (handler) {
        event.preventDefault();
        event.stopPropagation();
        handler();
      }
    }
  }

  /**
   * Start listening for keyboard events
   */
  function startListening() {
    if (isListening.value) return;
    isListening.value = true;
    window.addEventListener('keydown', handleKeyDown);
  }

  /**
   * Stop listening for keyboard events
   */
  function stopListening() {
    if (!isListening.value) return;
    isListening.value = false;
    window.removeEventListener('keydown', handleKeyDown);
  }

  /**
   * Get bindings grouped by category
   */
  function getBindingsByCategory(): Record<string, KeyBinding[]> {
    const grouped: Record<string, KeyBinding[]> = {};

    for (const binding of bindings.value) {
      const category = binding.category || 'Other';
      if (!grouped[category]) {
        grouped[category] = [];
      }
      grouped[category].push(binding);
    }

    return grouped;
  }

  /**
   * Format keys for display
   */
  function formatKeys(keys: string[]): string {
    const symbols: Record<string, string> = {
      Cmd: '⌘',
      Ctrl: '⌃',
      Alt: '⌥',
      Shift: '⇧',
      Enter: '↵',
      Backspace: '⌫',
      Tab: '⇥',
      Escape: 'Esc',
    };

    return keys.map(k => symbols[k] || k).join('');
  }

  /**
   * Record a new keybinding (for UI)
   */
  function recordKeys(
    callback: (keys: string[]) => void,
    cancel: () => void,
    timeout: number = 5000
  ) {
    let keys: string[] = [];
    let timeoutId: ReturnType<typeof setTimeout>;

    const handler = (event: KeyboardEvent) => {
      event.preventDefault();
      event.stopPropagation();

      if (event.key === 'Escape') {
        cleanup();
        cancel();
        return;
      }

      keys = eventToKeys(event);

      // If no modifier keys, require at least one
      if (!event.metaKey && !event.ctrlKey && !event.altKey) {
        return;
      }

      cleanup();
      callback(keys);
    };

    const cleanup = () => {
      window.removeEventListener('keydown', handler);
      clearTimeout(timeoutId);
    };

    window.addEventListener('keydown', handler);
    timeoutId = setTimeout(() => {
      cleanup();
      cancel();
    }, timeout);
  }

  // Initialize
  loadBindings();

  return {
    bindings: computed(() => bindings.value),
    conflictWarnings: computed(() => conflictWarnings.value),
    isListening: computed(() => isListening.value),
    DEFAULT_BINDINGS,
    loadBindings,
    registerAction,
    unregisterAction,
    updateBinding,
    resetBinding,
    resetAllBindings,
    addCustomBinding,
    removeCustomBinding,
    startListening,
    stopListening,
    getBindingsByCategory,
    formatKeys,
    recordKeys,
  };
}
