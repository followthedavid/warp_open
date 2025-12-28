/**
 * Launch Configurations System
 * Save and restore window/pane layouts and startup commands.
 * Similar to Warp Terminal's launch configurations.
 */

import { ref, computed, watch } from 'vue';

export type PaneLayout = 'single' | 'split-horizontal' | 'split-vertical' | 'quad' | 'custom';

export interface PaneConfig {
  id: string;
  command?: string;
  directory?: string;
  title?: string;
  environment?: Record<string, string>;
  shell?: string;
  width?: number; // Percentage
  height?: number;
}

export interface WindowConfig {
  id: string;
  title?: string;
  width?: number;
  height?: number;
  x?: number;
  y?: number;
  fullscreen?: boolean;
  layout: PaneLayout;
  panes: PaneConfig[];
}

export interface LaunchConfiguration {
  id: string;
  name: string;
  description?: string;
  icon?: string;
  windows: WindowConfig[];
  globalEnv?: Record<string, string>;
  startupHook?: string; // Command to run before launching
  createdAt: number;
  updatedAt: number;
  lastUsedAt?: number;
  useCount: number;
  isDefault?: boolean;
  tags?: string[];
}

const STORAGE_KEY = 'warp_open_launch_configs';
const DEFAULT_CONFIG_KEY = 'warp_open_default_launch';

// State
const configurations = ref<Map<string, LaunchConfiguration>>(new Map());
const defaultConfigId = ref<string | null>(null);
const currentConfig = ref<LaunchConfiguration | null>(null);

// Built-in configurations
const BUILTIN_CONFIGS: LaunchConfiguration[] = [
  {
    id: 'builtin_single',
    name: 'Single Terminal',
    description: 'Simple single terminal window',
    icon: '🖥️',
    windows: [{
      id: 'main',
      layout: 'single',
      panes: [{ id: 'main-pane' }],
    }],
    createdAt: 0,
    updatedAt: 0,
    useCount: 0,
  },
  {
    id: 'builtin_split',
    name: 'Split Terminal',
    description: 'Two panes side by side',
    icon: '📐',
    windows: [{
      id: 'main',
      layout: 'split-horizontal',
      panes: [
        { id: 'left', width: 50 },
        { id: 'right', width: 50 },
      ],
    }],
    createdAt: 0,
    updatedAt: 0,
    useCount: 0,
  },
  {
    id: 'builtin_dev',
    name: 'Development Setup',
    description: 'Editor, terminal, and logs',
    icon: '💻',
    windows: [{
      id: 'main',
      layout: 'custom',
      panes: [
        { id: 'editor', title: 'Editor', width: 60, height: 70 },
        { id: 'terminal', title: 'Terminal', width: 60, height: 30 },
        { id: 'logs', title: 'Logs', width: 40, height: 100, command: 'tail -f /var/log/system.log' },
      ],
    }],
    createdAt: 0,
    updatedAt: 0,
    useCount: 0,
  },
  {
    id: 'builtin_fullstack',
    name: 'Full Stack Dev',
    description: 'Frontend, backend, and database terminals',
    icon: '🚀',
    windows: [{
      id: 'main',
      layout: 'quad',
      panes: [
        { id: 'frontend', title: 'Frontend', command: 'npm run dev' },
        { id: 'backend', title: 'Backend', command: 'npm run server' },
        { id: 'db', title: 'Database', command: 'docker-compose up' },
        { id: 'general', title: 'General' },
      ],
    }],
    createdAt: 0,
    updatedAt: 0,
    useCount: 0,
  },
];

// Load from storage
function loadConfigs(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const data = JSON.parse(stored);
      configurations.value = new Map(Object.entries(data));
    }

    const defaultId = localStorage.getItem(DEFAULT_CONFIG_KEY);
    if (defaultId) {
      defaultConfigId.value = defaultId;
    }
  } catch (e) {
    console.error('[LaunchConfigs] Error loading:', e);
  }
}

// Save to storage
function saveConfigs(): void {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(Object.fromEntries(configurations.value))
    );
    if (defaultConfigId.value) {
      localStorage.setItem(DEFAULT_CONFIG_KEY, defaultConfigId.value);
    }
  } catch (e) {
    console.error('[LaunchConfigs] Error saving:', e);
  }
}

// Initialize
loadConfigs();

// Auto-save on changes
watch([configurations, defaultConfigId], () => {
  saveConfigs();
}, { deep: true });

function generateId(): string {
  return `config_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function useLaunchConfigurations() {
  const allConfigs = computed(() => [
    ...BUILTIN_CONFIGS,
    ...Array.from(configurations.value.values()),
  ]);

  const customConfigs = computed(() =>
    Array.from(configurations.value.values())
  );

  const defaultConfig = computed(() => {
    if (defaultConfigId.value) {
      return allConfigs.value.find(c => c.id === defaultConfigId.value);
    }
    return allConfigs.value[0];
  });

  const recentConfigs = computed(() =>
    allConfigs.value
      .filter(c => c.lastUsedAt)
      .sort((a, b) => (b.lastUsedAt || 0) - (a.lastUsedAt || 0))
      .slice(0, 5)
  );

  /**
   * Create a new configuration
   */
  function createConfig(config: Omit<LaunchConfiguration, 'id' | 'createdAt' | 'updatedAt' | 'useCount'>): LaunchConfiguration {
    const newConfig: LaunchConfiguration = {
      ...config,
      id: generateId(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      useCount: 0,
    };

    configurations.value.set(newConfig.id, newConfig);
    console.log(`[LaunchConfigs] Created: ${newConfig.name}`);

    return newConfig;
  }

  /**
   * Create from current layout
   */
  function createFromCurrent(
    name: string,
    currentLayout: {
      windows: WindowConfig[];
    }
  ): LaunchConfiguration {
    return createConfig({
      name,
      windows: currentLayout.windows,
    });
  }

  /**
   * Update a configuration
   */
  function updateConfig(configId: string, updates: Partial<LaunchConfiguration>): void {
    const config = configurations.value.get(configId);
    if (config) {
      Object.assign(config, {
        ...updates,
        updatedAt: Date.now(),
      });
    }
  }

  /**
   * Delete a configuration
   */
  function deleteConfig(configId: string): boolean {
    // Can't delete built-in configs
    if (configId.startsWith('builtin_')) {
      return false;
    }

    const deleted = configurations.value.delete(configId);
    if (deleted && defaultConfigId.value === configId) {
      defaultConfigId.value = null;
    }
    return deleted;
  }

  /**
   * Get configuration by ID
   */
  function getConfig(configId: string): LaunchConfiguration | undefined {
    return allConfigs.value.find(c => c.id === configId);
  }

  /**
   * Set default configuration
   */
  function setDefault(configId: string): void {
    defaultConfigId.value = configId;

    // Update the config's isDefault flag
    for (const config of allConfigs.value) {
      if (configurations.value.has(config.id)) {
        const stored = configurations.value.get(config.id)!;
        stored.isDefault = config.id === configId;
      }
    }
  }

  /**
   * Launch a configuration
   */
  function launch(configId: string): {
    windows: WindowConfig[];
    env?: Record<string, string>;
    startupHook?: string;
  } | null {
    const config = getConfig(configId);
    if (!config) return null;

    // Update usage stats
    if (configurations.value.has(configId)) {
      const stored = configurations.value.get(configId)!;
      stored.lastUsedAt = Date.now();
      stored.useCount++;
    }

    currentConfig.value = config;

    console.log(`[LaunchConfigs] Launching: ${config.name}`);

    return {
      windows: config.windows,
      env: config.globalEnv,
      startupHook: config.startupHook,
    };
  }

  /**
   * Add a pane to a configuration
   */
  function addPane(
    configId: string,
    windowId: string,
    pane: Omit<PaneConfig, 'id'>
  ): PaneConfig | null {
    const config = configurations.value.get(configId);
    if (!config) return null;

    const window = config.windows.find(w => w.id === windowId);
    if (!window) return null;

    const newPane: PaneConfig = {
      ...pane,
      id: `pane_${Date.now()}`,
    };

    window.panes.push(newPane);
    config.updatedAt = Date.now();

    return newPane;
  }

  /**
   * Remove a pane from a configuration
   */
  function removePane(configId: string, windowId: string, paneId: string): boolean {
    const config = configurations.value.get(configId);
    if (!config) return false;

    const window = config.windows.find(w => w.id === windowId);
    if (!window) return false;

    const index = window.panes.findIndex(p => p.id === paneId);
    if (index >= 0) {
      window.panes.splice(index, 1);
      config.updatedAt = Date.now();
      return true;
    }

    return false;
  }

  /**
   * Add a window to a configuration
   */
  function addWindow(configId: string, window: Omit<WindowConfig, 'id'>): WindowConfig | null {
    const config = configurations.value.get(configId);
    if (!config) return null;

    const newWindow: WindowConfig = {
      ...window,
      id: `window_${Date.now()}`,
    };

    config.windows.push(newWindow);
    config.updatedAt = Date.now();

    return newWindow;
  }

  /**
   * Duplicate a configuration
   */
  function duplicateConfig(configId: string, newName?: string): LaunchConfiguration | null {
    const config = getConfig(configId);
    if (!config) return null;

    const duplicate = createConfig({
      ...config,
      name: newName || `${config.name} (Copy)`,
      isDefault: false,
      lastUsedAt: undefined,
    });

    return duplicate;
  }

  /**
   * Search configurations
   */
  function searchConfigs(query: string): LaunchConfiguration[] {
    const lowerQuery = query.toLowerCase();
    return allConfigs.value.filter(config =>
      config.name.toLowerCase().includes(lowerQuery) ||
      config.description?.toLowerCase().includes(lowerQuery) ||
      config.tags?.some(t => t.toLowerCase().includes(lowerQuery))
    );
  }

  /**
   * Export configurations
   */
  function exportConfigs(): string {
    return JSON.stringify(
      Array.from(configurations.value.values()),
      null,
      2
    );
  }

  /**
   * Import configurations
   */
  function importConfigs(json: string): number {
    try {
      const imported = JSON.parse(json) as LaunchConfiguration[];
      let count = 0;

      for (const config of imported) {
        if (!configurations.value.has(config.id)) {
          configurations.value.set(config.id, {
            ...config,
            id: generateId(), // Generate new ID to avoid conflicts
          });
          count++;
        }
      }

      return count;
    } catch (error) {
      console.error('[LaunchConfigs] Import error:', error);
      return 0;
    }
  }

  /**
   * Get statistics
   */
  function getStats() {
    const all = allConfigs.value;
    return {
      totalConfigs: all.length,
      customConfigs: customConfigs.value.length,
      mostUsed: all.reduce((max, c) =>
        c.useCount > (max?.useCount || 0) ? c : max,
        null as LaunchConfiguration | null
      ),
      totalPanes: all.reduce((sum, c) =>
        sum + c.windows.reduce((ws, w) => ws + w.panes.length, 0),
        0
      ),
    };
  }

  return {
    // State
    allConfigs,
    customConfigs,
    defaultConfig,
    recentConfigs,
    currentConfig: computed(() => currentConfig.value),
    builtinConfigs: BUILTIN_CONFIGS,

    // CRUD
    createConfig,
    createFromCurrent,
    updateConfig,
    deleteConfig,
    getConfig,
    duplicateConfig,

    // Default
    setDefault,

    // Launch
    launch,

    // Panes/Windows
    addPane,
    removePane,
    addWindow,

    // Search
    searchConfigs,

    // Import/Export
    exportConfigs,
    importConfigs,
    getStats,
  };
}
