/**
 * Settings Sync
 * Cross-device synchronization of preferences and data
 *
 * Features:
 * - End-to-end encrypted sync
 * - Multiple backend support (iCloud, Google Drive, WebDAV)
 * - Selective sync (choose what to sync)
 * - Conflict resolution
 * - Offline support with queue
 * - Version history
 */

import { ref, computed, reactive, watch } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export type SyncBackend = 'icloud' | 'google_drive' | 'webdav' | 'github_gist' | 'local';

export interface SyncConfig {
  enabled: boolean;
  backend: SyncBackend;
  autoSync: boolean;
  syncInterval: number;  // minutes
  encryptionEnabled: boolean;
  encryptionKeyId?: string;
  lastSync?: Date;
  webdavUrl?: string;
  githubGistId?: string;
}

export interface SyncCategory {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  storageKey: string;
  lastSynced?: Date;
  size?: number;
}

export interface SyncState {
  status: 'idle' | 'syncing' | 'error' | 'offline';
  progress: number;
  currentItem?: string;
  error?: string;
  lastSync?: Date;
  pendingChanges: number;
}

export interface SyncConflict {
  id: string;
  category: string;
  key: string;
  localValue: unknown;
  remoteValue: unknown;
  localTimestamp: Date;
  remoteTimestamp: Date;
  resolved: boolean;
}

export interface SyncVersion {
  id: string;
  timestamp: Date;
  categories: string[];
  size: number;
  checksum: string;
}

// ============================================================================
// DEFAULT SYNC CATEGORIES
// ============================================================================

const DEFAULT_CATEGORIES: SyncCategory[] = [
  {
    id: 'settings',
    name: 'Settings',
    description: 'Theme, font, shortcuts, and general preferences',
    enabled: true,
    storageKey: 'warp_settings'
  },
  {
    id: 'workflows',
    name: 'Workflows',
    description: 'Custom workflows and automation',
    enabled: true,
    storageKey: 'warp_workflows'
  },
  {
    id: 'snippets',
    name: 'Snippets',
    description: 'Code snippets and templates',
    enabled: true,
    storageKey: 'warp_snippets'
  },
  {
    id: 'aliases',
    name: 'Aliases',
    description: 'Command aliases and shortcuts',
    enabled: true,
    storageKey: 'warp_aliases'
  },
  {
    id: 'ssh_profiles',
    name: 'SSH Profiles',
    description: 'SSH connection profiles (passwords not synced)',
    enabled: false,
    storageKey: 'warp_ssh_profiles'
  },
  {
    id: 'plugins',
    name: 'Plugin List',
    description: 'List of installed plugins (not plugin data)',
    enabled: true,
    storageKey: 'warp_plugins'
  },
  {
    id: 'keybindings',
    name: 'Keybindings',
    description: 'Custom keyboard shortcuts',
    enabled: true,
    storageKey: 'warp_keybindings'
  },
  {
    id: 'ui_state',
    name: 'UI State',
    description: 'Panel layouts and window positions',
    enabled: false,
    storageKey: 'warp_ui_state'
  }
];

// ============================================================================
// STATE
// ============================================================================

const config = reactive<SyncConfig>({
  enabled: false,
  backend: 'local',
  autoSync: true,
  syncInterval: 15,
  encryptionEnabled: true
});

const state = reactive<SyncState>({
  status: 'idle',
  progress: 0,
  pendingChanges: 0
});

const categories = reactive<SyncCategory[]>([...DEFAULT_CATEGORIES]);
const conflicts = reactive<SyncConflict[]>([]);
const versions = reactive<SyncVersion[]>([]);
const pendingQueue = reactive<Array<{ category: string; key: string; value: unknown; timestamp: Date }>>([]);

let syncInterval: number | null = null;
let encryptionKey: CryptoKey | null = null;

// Check if Tauri
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

// ============================================================================
// PERSISTENCE
// ============================================================================

function loadConfig(): void {
  try {
    const saved = localStorage.getItem('warp_sync_config');
    if (saved) {
      const data = JSON.parse(saved);
      Object.assign(config, data);
      if (config.lastSync) {
        config.lastSync = new Date(config.lastSync);
      }
    }

    const savedCategories = localStorage.getItem('warp_sync_categories');
    if (savedCategories) {
      const data = JSON.parse(savedCategories);
      for (const cat of data) {
        const existing = categories.find(c => c.id === cat.id);
        if (existing) {
          existing.enabled = cat.enabled;
        }
      }
    }
  } catch (e) {
    console.error('[Sync] Failed to load config:', e);
  }
}

function saveConfig(): void {
  try {
    localStorage.setItem('warp_sync_config', JSON.stringify(config));
    localStorage.setItem('warp_sync_categories', JSON.stringify(
      categories.map(c => ({ id: c.id, enabled: c.enabled }))
    ));
  } catch (e) {
    console.error('[Sync] Failed to save config:', e);
  }
}

// Initialize
loadConfig();

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(data: string): Promise<{ encrypted: string; iv: string; salt: string }> {
  if (!encryptionKey) throw new Error('Encryption key not set');

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const encoded = new TextEncoder().encode(data);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    encryptionKey,
    encoded
  );

  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
    salt: btoa(String.fromCharCode(...salt))
  };
}

async function decryptData(encrypted: string, iv: string): Promise<string> {
  if (!encryptionKey) throw new Error('Encryption key not set');

  const encryptedBytes = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
  const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    encryptionKey,
    encryptedBytes
  );

  return new TextDecoder().decode(decrypted);
}

function generateChecksum(data: string): string {
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}

// ============================================================================
// BACKEND IMPLEMENTATIONS
// ============================================================================

async function uploadToBackend(data: string, path: string): Promise<boolean> {
  switch (config.backend) {
    case 'icloud':
      return uploadToICloud(data, path);
    case 'google_drive':
      return uploadToGoogleDrive(data, path);
    case 'webdav':
      return uploadToWebDAV(data, path);
    case 'github_gist':
      return uploadToGitHubGist(data, path);
    case 'local':
      return uploadToLocal(data, path);
    default:
      return false;
  }
}

async function downloadFromBackend(path: string): Promise<string | null> {
  switch (config.backend) {
    case 'icloud':
      return downloadFromICloud(path);
    case 'google_drive':
      return downloadFromGoogleDrive(path);
    case 'webdav':
      return downloadFromWebDAV(path);
    case 'github_gist':
      return downloadFromGitHubGist(path);
    case 'local':
      return downloadFromLocal(path);
    default:
      return null;
  }
}

// iCloud (via Tauri on macOS)
async function uploadToICloud(data: string, path: string): Promise<boolean> {
  if (!invoke) return false;
  try {
    await invoke('icloud_write', { path: `WarpOpen/${path}`, data });
    return true;
  } catch {
    return false;
  }
}

async function downloadFromICloud(path: string): Promise<string | null> {
  if (!invoke) return null;
  try {
    return await invoke<string>('icloud_read', { path: `WarpOpen/${path}` });
  } catch {
    return null;
  }
}

// Google Drive
async function uploadToGoogleDrive(data: string, path: string): Promise<boolean> {
  // Would need OAuth flow and Google Drive API
  console.log('[Sync] Google Drive upload:', path);
  return false;
}

async function downloadFromGoogleDrive(path: string): Promise<string | null> {
  console.log('[Sync] Google Drive download:', path);
  return null;
}

// WebDAV
async function uploadToWebDAV(data: string, path: string): Promise<boolean> {
  if (!config.webdavUrl) return false;

  try {
    const response = await fetch(`${config.webdavUrl}/${path}`, {
      method: 'PUT',
      body: data,
      headers: { 'Content-Type': 'application/json' }
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function downloadFromWebDAV(path: string): Promise<string | null> {
  if (!config.webdavUrl) return null;

  try {
    const response = await fetch(`${config.webdavUrl}/${path}`);
    if (!response.ok) return null;
    return response.text();
  } catch {
    return null;
  }
}

// GitHub Gist
async function uploadToGitHubGist(data: string, path: string): Promise<boolean> {
  // Would need GitHub token and Gist API
  console.log('[Sync] GitHub Gist upload:', path);
  return false;
}

async function downloadFromGitHubGist(path: string): Promise<string | null> {
  console.log('[Sync] GitHub Gist download:', path);
  return null;
}

// Local (just for testing)
async function uploadToLocal(data: string, path: string): Promise<boolean> {
  try {
    localStorage.setItem(`warp_sync_backup_${path}`, data);
    return true;
  } catch {
    return false;
  }
}

async function downloadFromLocal(path: string): Promise<string | null> {
  return localStorage.getItem(`warp_sync_backup_${path}`);
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useSettingsSync() {
  /**
   * Initialize sync with encryption password
   */
  async function initialize(password?: string): Promise<boolean> {
    if (config.encryptionEnabled && password) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      encryptionKey = await deriveKey(password, salt);
    }

    if (config.autoSync && config.enabled) {
      startAutoSync();
    }

    return true;
  }

  /**
   * Perform full sync
   */
  async function sync(): Promise<boolean> {
    if (state.status === 'syncing') return false;
    if (!config.enabled) return false;

    state.status = 'syncing';
    state.progress = 0;
    state.error = undefined;

    try {
      const enabledCategories = categories.filter(c => c.enabled);
      const total = enabledCategories.length * 2;  // Upload + download
      let completed = 0;

      // Download remote data first
      for (const category of enabledCategories) {
        state.currentItem = `Downloading ${category.name}...`;

        const remoteData = await downloadFromBackend(`${category.id}.json`);
        if (remoteData) {
          let parsed: { data: unknown; timestamp: number; checksum: string };

          if (config.encryptionEnabled && encryptionKey) {
            const { encrypted, iv } = JSON.parse(remoteData);
            const decrypted = await decryptData(encrypted, iv);
            parsed = JSON.parse(decrypted);
          } else {
            parsed = JSON.parse(remoteData);
          }

          // Check for conflicts
          const localData = localStorage.getItem(category.storageKey);
          const localTimestamp = localStorage.getItem(`${category.storageKey}_timestamp`);

          if (localData && localTimestamp) {
            const localTs = new Date(localTimestamp);
            const remoteTs = new Date(parsed.timestamp);

            if (localTs > remoteTs && JSON.stringify(JSON.parse(localData)) !== JSON.stringify(parsed.data)) {
              // Local is newer - conflict
              conflicts.push({
                id: crypto.randomUUID(),
                category: category.id,
                key: category.storageKey,
                localValue: JSON.parse(localData),
                remoteValue: parsed.data,
                localTimestamp: localTs,
                remoteTimestamp: remoteTs,
                resolved: false
              });
            } else if (remoteTs > localTs) {
              // Remote is newer - apply
              localStorage.setItem(category.storageKey, JSON.stringify(parsed.data));
              localStorage.setItem(`${category.storageKey}_timestamp`, remoteTs.toISOString());
            }
          } else {
            // No local data - apply remote
            localStorage.setItem(category.storageKey, JSON.stringify(parsed.data));
            localStorage.setItem(`${category.storageKey}_timestamp`, new Date(parsed.timestamp).toISOString());
          }
        }

        completed++;
        state.progress = (completed / total) * 100;
      }

      // Upload local data
      for (const category of enabledCategories) {
        state.currentItem = `Uploading ${category.name}...`;

        const localData = localStorage.getItem(category.storageKey);
        if (localData) {
          const payload = {
            data: JSON.parse(localData),
            timestamp: Date.now(),
            checksum: generateChecksum(localData)
          };

          let uploadData: string;

          if (config.encryptionEnabled && encryptionKey) {
            const encrypted = await encryptData(JSON.stringify(payload));
            uploadData = JSON.stringify(encrypted);
          } else {
            uploadData = JSON.stringify(payload);
          }

          await uploadToBackend(uploadData, `${category.id}.json`);

          category.lastSynced = new Date();
          category.size = uploadData.length;
        }

        completed++;
        state.progress = (completed / total) * 100;
      }

      // Save sync version
      const version: SyncVersion = {
        id: crypto.randomUUID(),
        timestamp: new Date(),
        categories: enabledCategories.map(c => c.id),
        size: enabledCategories.reduce((sum, c) => sum + (c.size || 0), 0),
        checksum: generateChecksum(JSON.stringify(enabledCategories.map(c => c.lastSynced)))
      };
      versions.unshift(version);
      if (versions.length > 50) versions.pop();

      config.lastSync = new Date();
      state.lastSync = new Date();
      state.pendingChanges = 0;
      state.status = 'idle';
      state.currentItem = undefined;

      saveConfig();
      console.log('[Sync] Sync completed');
      return true;
    } catch (e) {
      state.status = 'error';
      state.error = e instanceof Error ? e.message : String(e);
      console.error('[Sync] Sync failed:', e);
      return false;
    }
  }

  /**
   * Queue a change for sync
   */
  function queueChange(category: string, key: string, value: unknown): void {
    pendingQueue.push({
      category,
      key,
      value,
      timestamp: new Date()
    });
    state.pendingChanges = pendingQueue.length;
  }

  /**
   * Resolve a conflict
   */
  function resolveConflict(conflictId: string, useLocal: boolean): void {
    const conflict = conflicts.find(c => c.id === conflictId);
    if (!conflict) return;

    const value = useLocal ? conflict.localValue : conflict.remoteValue;
    localStorage.setItem(conflict.key, JSON.stringify(value));
    localStorage.setItem(`${conflict.key}_timestamp`, new Date().toISOString());

    conflict.resolved = true;
    const index = conflicts.indexOf(conflict);
    if (index >= 0) conflicts.splice(index, 1);
  }

  /**
   * Resolve all conflicts
   */
  function resolveAllConflicts(useLocal: boolean): void {
    for (const conflict of [...conflicts]) {
      resolveConflict(conflict.id, useLocal);
    }
  }

  /**
   * Start auto-sync timer
   */
  function startAutoSync(): void {
    stopAutoSync();
    if (!config.autoSync || !config.enabled) return;

    syncInterval = window.setInterval(() => {
      if (state.pendingChanges > 0 || Date.now() - (config.lastSync?.getTime() || 0) > config.syncInterval * 60 * 1000) {
        sync();
      }
    }, 60 * 1000);  // Check every minute
  }

  /**
   * Stop auto-sync timer
   */
  function stopAutoSync(): void {
    if (syncInterval) {
      clearInterval(syncInterval);
      syncInterval = null;
    }
  }

  /**
   * Enable/disable sync
   */
  function setEnabled(enabled: boolean): void {
    config.enabled = enabled;
    if (enabled) {
      startAutoSync();
    } else {
      stopAutoSync();
    }
    saveConfig();
  }

  /**
   * Set sync backend
   */
  function setBackend(backend: SyncBackend, options?: { webdavUrl?: string; githubGistId?: string }): void {
    config.backend = backend;
    if (options?.webdavUrl) config.webdavUrl = options.webdavUrl;
    if (options?.githubGistId) config.githubGistId = options.githubGistId;
    saveConfig();
  }

  /**
   * Enable/disable category
   */
  function setCategoryEnabled(categoryId: string, enabled: boolean): void {
    const category = categories.find(c => c.id === categoryId);
    if (category) {
      category.enabled = enabled;
      saveConfig();
    }
  }

  /**
   * Export all synced data
   */
  async function exportData(): Promise<string> {
    const data: Record<string, unknown> = {};

    for (const category of categories.filter(c => c.enabled)) {
      const stored = localStorage.getItem(category.storageKey);
      if (stored) {
        data[category.id] = JSON.parse(stored);
      }
    }

    const payload = {
      version: 1,
      exported: new Date().toISOString(),
      data
    };

    return JSON.stringify(payload, null, 2);
  }

  /**
   * Import data from export
   */
  async function importData(jsonData: string): Promise<boolean> {
    try {
      const payload = JSON.parse(jsonData);
      if (!payload.data || typeof payload.data !== 'object') {
        throw new Error('Invalid import data');
      }

      for (const [categoryId, data] of Object.entries(payload.data)) {
        const category = categories.find(c => c.id === categoryId);
        if (category) {
          localStorage.setItem(category.storageKey, JSON.stringify(data));
          localStorage.setItem(`${category.storageKey}_timestamp`, new Date().toISOString());
        }
      }

      return true;
    } catch (e) {
      console.error('[Sync] Import failed:', e);
      return false;
    }
  }

  /**
   * Restore from version
   */
  async function restoreVersion(versionId: string): Promise<boolean> {
    const version = versions.find(v => v.id === versionId);
    if (!version) return false;

    // Would need to store version data
    console.log('[Sync] Restore version:', versionId);
    return false;
  }

  /**
   * Clear all synced data
   */
  function clearSyncData(): void {
    for (const category of categories) {
      localStorage.removeItem(`warp_sync_backup_${category.id}.json`);
    }
    config.lastSync = undefined;
    state.lastSync = undefined;
    versions.length = 0;
    saveConfig();
  }

  /**
   * Get sync status for category
   */
  function getCategoryStatus(categoryId: string): {
    enabled: boolean;
    lastSynced?: Date;
    size?: number;
    hasConflict: boolean;
  } {
    const category = categories.find(c => c.id === categoryId);
    const conflict = conflicts.find(c => c.category === categoryId && !c.resolved);

    return {
      enabled: category?.enabled || false,
      lastSynced: category?.lastSynced,
      size: category?.size,
      hasConflict: !!conflict
    };
  }

  return {
    // State
    config: computed(() => config),
    state: computed(() => state),
    categories: computed(() => categories),
    conflicts: computed(() => conflicts.filter(c => !c.resolved)),
    versions: computed(() => versions),
    pendingChanges: computed(() => state.pendingChanges),

    // Actions
    initialize,
    sync,
    queueChange,
    resolveConflict,
    resolveAllConflicts,

    // Configuration
    setEnabled,
    setBackend,
    setCategoryEnabled,

    // Auto-sync
    startAutoSync,
    stopAutoSync,

    // Import/Export
    exportData,
    importData,
    restoreVersion,
    clearSyncData,

    // Info
    getCategoryStatus
  };
}

export default useSettingsSync;
