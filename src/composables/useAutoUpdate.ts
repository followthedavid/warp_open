/**
 * Auto-Update System
 * Seamless application updates using Tauri's built-in updater
 *
 * Features:
 * - Background update checks
 * - Delta updates (smaller downloads)
 * - Rollback support
 * - Release channel selection (stable/beta/nightly)
 * - Update notifications
 * - Download progress
 */

import { ref, computed, reactive } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export type ReleaseChannel = 'stable' | 'beta' | 'nightly';

export interface UpdateInfo {
  version: string;
  releaseDate: string;
  releaseNotes: string;
  downloadUrl: string;
  signature: string;
  size: number;
  mandatory: boolean;
  channel: ReleaseChannel;
}

export interface UpdateProgress {
  downloaded: number;
  total: number;
  percent: number;
  speed: number;  // bytes per second
  eta: number;    // seconds remaining
}

export interface UpdateSettings {
  autoCheck: boolean;
  autoDownload: boolean;
  autoInstall: boolean;
  channel: ReleaseChannel;
  checkInterval: number;  // hours
  lastCheck: Date | null;
  skippedVersions: string[];
}

export interface UpdateState {
  checking: boolean;
  downloading: boolean;
  installing: boolean;
  available: UpdateInfo | null;
  progress: UpdateProgress | null;
  error: string | null;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const DEFAULT_SETTINGS: UpdateSettings = {
  autoCheck: true,
  autoDownload: false,
  autoInstall: false,
  channel: 'stable',
  checkInterval: 24,
  lastCheck: null,
  skippedVersions: []
};

const UPDATE_ENDPOINTS: Record<ReleaseChannel, string> = {
  stable: 'https://releases.warp-open.dev/stable',
  beta: 'https://releases.warp-open.dev/beta',
  nightly: 'https://releases.warp-open.dev/nightly'
};

// Fallback to GitHub releases
const GITHUB_RELEASE_URL = 'https://api.github.com/repos/warp-open/warp-open/releases';

// ============================================================================
// STATE
// ============================================================================

const settings = reactive<UpdateSettings>({ ...DEFAULT_SETTINGS });
const state = reactive<UpdateState>({
  checking: false,
  downloading: false,
  installing: false,
  available: null,
  progress: null,
  error: null
});

const currentVersion = ref<string>('1.0.0');  // Will be set from Tauri

// Check if Tauri
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
    // Get current version
    invoke<string>('get_app_version').then(v => {
      currentVersion.value = v;
    }).catch(() => {});
  });
}

// ============================================================================
// PERSISTENCE
// ============================================================================

function loadSettings(): void {
  try {
    const saved = localStorage.getItem('warp_update_settings');
    if (saved) {
      const data = JSON.parse(saved);
      Object.assign(settings, data);
      if (settings.lastCheck) {
        settings.lastCheck = new Date(settings.lastCheck);
      }
    }
  } catch (e) {
    console.error('[AutoUpdate] Failed to load settings:', e);
  }
}

function saveSettings(): void {
  try {
    localStorage.setItem('warp_update_settings', JSON.stringify(settings));
  } catch (e) {
    console.error('[AutoUpdate] Failed to save settings:', e);
  }
}

// Initialize
loadSettings();

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useAutoUpdate() {
  /**
   * Check for updates
   */
  async function checkForUpdate(options?: {
    force?: boolean;
    silent?: boolean;
  }): Promise<UpdateInfo | null> {
    if (state.checking) return null;

    // Skip if recently checked (unless forced)
    if (!options?.force && settings.lastCheck) {
      const hoursSinceCheck = (Date.now() - settings.lastCheck.getTime()) / (1000 * 60 * 60);
      if (hoursSinceCheck < settings.checkInterval) {
        console.log('[AutoUpdate] Skipping check - recently checked');
        return state.available;
      }
    }

    state.checking = true;
    state.error = null;

    try {
      // Try Tauri's built-in updater first
      if (invoke) {
        try {
          const update = await invoke<UpdateInfo | null>('check_for_update', {
            channel: settings.channel
          });
          if (update) {
            state.available = update;
            settings.lastCheck = new Date();
            saveSettings();
            return update;
          }
        } catch (e) {
          console.log('[AutoUpdate] Tauri updater not available, using fallback');
        }
      }

      // Fallback: Check GitHub releases
      const update = await checkGitHubReleases();
      if (update) {
        state.available = update;
      }

      settings.lastCheck = new Date();
      saveSettings();

      return state.available;
    } catch (error) {
      if (!options?.silent) {
        state.error = error instanceof Error ? error.message : String(error);
      }
      return null;
    } finally {
      state.checking = false;
    }
  }

  /**
   * Check GitHub releases for updates
   */
  async function checkGitHubReleases(): Promise<UpdateInfo | null> {
    try {
      const response = await fetch(GITHUB_RELEASE_URL);
      if (!response.ok) return null;

      const releases = await response.json();

      // Find appropriate release based on channel
      for (const release of releases) {
        const isPrerelease = release.prerelease;
        const version = release.tag_name.replace(/^v/, '');

        // Match channel
        if (settings.channel === 'stable' && isPrerelease) continue;
        if (settings.channel === 'beta' && !isPrerelease) continue;

        // Check if newer than current
        if (!isNewerVersion(version, currentVersion.value)) continue;

        // Check if skipped
        if (settings.skippedVersions.includes(version)) continue;

        // Find appropriate asset
        const platform = getPlatform();
        const asset = release.assets.find((a: { name: string }) =>
          a.name.includes(platform) && (a.name.endsWith('.dmg') || a.name.endsWith('.msi') || a.name.endsWith('.AppImage'))
        );

        if (!asset) continue;

        return {
          version,
          releaseDate: release.published_at,
          releaseNotes: release.body || 'No release notes',
          downloadUrl: asset.browser_download_url,
          signature: '',  // Would need .sig file
          size: asset.size,
          mandatory: false,
          channel: isPrerelease ? 'beta' : 'stable'
        };
      }

      return null;
    } catch (error) {
      console.error('[AutoUpdate] GitHub check failed:', error);
      return null;
    }
  }

  /**
   * Download update
   */
  async function downloadUpdate(): Promise<boolean> {
    if (!state.available || state.downloading) return false;

    state.downloading = true;
    state.error = null;
    state.progress = { downloaded: 0, total: state.available.size, percent: 0, speed: 0, eta: 0 };

    try {
      // Use Tauri's download if available
      if (invoke) {
        const success = await invoke<boolean>('download_update', {
          url: state.available.downloadUrl,
          signature: state.available.signature
        });

        if (success) {
          state.progress = { downloaded: state.available.size, total: state.available.size, percent: 100, speed: 0, eta: 0 };
          return true;
        }
      }

      // Fallback: Manual download not supported in browser
      state.error = 'Please download the update manually from the releases page';
      return false;
    } catch (error) {
      state.error = error instanceof Error ? error.message : String(error);
      return false;
    } finally {
      state.downloading = false;
    }
  }

  /**
   * Install update and restart
   */
  async function installUpdate(): Promise<boolean> {
    if (!state.available || state.installing) return false;

    state.installing = true;
    state.error = null;

    try {
      if (invoke) {
        await invoke('install_update_and_restart');
        return true;  // Won't reach here if restart succeeds
      }

      state.error = 'Manual installation required';
      return false;
    } catch (error) {
      state.error = error instanceof Error ? error.message : String(error);
      return false;
    } finally {
      state.installing = false;
    }
  }

  /**
   * Skip this version
   */
  function skipVersion(version: string): void {
    if (!settings.skippedVersions.includes(version)) {
      settings.skippedVersions.push(version);
      saveSettings();
    }
    if (state.available?.version === version) {
      state.available = null;
    }
  }

  /**
   * Clear skipped versions
   */
  function clearSkippedVersions(): void {
    settings.skippedVersions = [];
    saveSettings();
  }

  /**
   * Update settings
   */
  function updateSettings(newSettings: Partial<UpdateSettings>): void {
    Object.assign(settings, newSettings);
    saveSettings();
  }

  /**
   * Start background update checker
   */
  function startBackgroundChecker(): () => void {
    if (!settings.autoCheck) return () => {};

    // Initial check
    checkForUpdate({ silent: true });

    // Periodic checks
    const interval = setInterval(() => {
      checkForUpdate({ silent: true }).then(update => {
        if (update && settings.autoDownload) {
          downloadUpdate().then(success => {
            if (success && settings.autoInstall) {
              // Show notification before installing
              notifyUpdateReady(update);
            }
          });
        }
      });
    }, settings.checkInterval * 60 * 60 * 1000);

    return () => clearInterval(interval);
  }

  /**
   * Notify user about update
   */
  async function notifyUpdateReady(update: UpdateInfo): Promise<void> {
    if (!('Notification' in window)) return;

    if (Notification.permission === 'granted') {
      new Notification('Warp Open Update Available', {
        body: `Version ${update.version} is ready to install`,
        icon: '/icon.png'
      });
    } else if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission();
      if (permission === 'granted') {
        notifyUpdateReady(update);
      }
    }
  }

  /**
   * Get release notes for current version
   */
  async function getCurrentReleaseNotes(): Promise<string> {
    try {
      const response = await fetch(`${GITHUB_RELEASE_URL}/tags/v${currentVersion.value}`);
      if (!response.ok) return 'Release notes not available';
      const release = await response.json();
      return release.body || 'No release notes';
    } catch {
      return 'Failed to fetch release notes';
    }
  }

  return {
    // State
    state: computed(() => state),
    settings: computed(() => settings),
    currentVersion: computed(() => currentVersion.value),
    isUpdateAvailable: computed(() => !!state.available),
    updateVersion: computed(() => state.available?.version),

    // Actions
    checkForUpdate,
    downloadUpdate,
    installUpdate,
    skipVersion,
    clearSkippedVersions,

    // Settings
    updateSettings,

    // Background
    startBackgroundChecker,

    // Info
    getCurrentReleaseNotes
  };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function isNewerVersion(newVersion: string, currentVersion: string): boolean {
  const newParts = newVersion.split('.').map(Number);
  const currentParts = currentVersion.split('.').map(Number);

  for (let i = 0; i < Math.max(newParts.length, currentParts.length); i++) {
    const newPart = newParts[i] || 0;
    const currentPart = currentParts[i] || 0;

    if (newPart > currentPart) return true;
    if (newPart < currentPart) return false;
  }

  return false;
}

function getPlatform(): string {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('mac')) return 'darwin';
  if (ua.includes('win')) return 'windows';
  if (ua.includes('linux')) return 'linux';
  return 'unknown';
}

export default useAutoUpdate;
