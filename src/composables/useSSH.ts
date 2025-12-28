/**
 * SSH Connection Support
 * Connect to remote servers with full terminal functionality
 *
 * Features:
 * - SSH key management
 * - Connection profiles
 * - Secure credential storage (system keychain)
 * - Remote file operations
 * - Agent mode over SSH
 * - Jump host / bastion support
 * - Connection multiplexing
 */

import { ref, computed, reactive } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export interface SSHProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'key' | 'agent';
  keyPath?: string;
  useJumpHost?: boolean;
  jumpHost?: string;
  jumpPort?: number;
  jumpUsername?: string;
  environment?: Record<string, string>;
  startupCommand?: string;
  lastConnected?: Date;
  color?: string;
  tags?: string[];
}

export interface SSHConnection {
  id: string;
  profileId: string;
  profile: SSHProfile;
  status: 'connecting' | 'connected' | 'disconnected' | 'error';
  connectedAt?: Date;
  error?: string;
  remoteInfo?: {
    hostname: string;
    os: string;
    shell: string;
    cwd: string;
  };
}

export interface SSHKey {
  id: string;
  name: string;
  path: string;
  type: 'rsa' | 'ed25519' | 'ecdsa' | 'dsa';
  fingerprint: string;
  hasPassphrase: boolean;
  createdAt: Date;
}

export interface RemoteFileInfo {
  name: string;
  path: string;
  type: 'file' | 'directory' | 'symlink';
  size: number;
  permissions: string;
  owner: string;
  group: string;
  modifiedAt: Date;
}

// ============================================================================
// STATE
// ============================================================================

const profiles = ref<SSHProfile[]>([]);
const connections = reactive<Map<string, SSHConnection>>(new Map());
const sshKeys = ref<SSHKey[]>([]);
const isConnecting = ref(false);

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

function loadProfiles(): void {
  try {
    const saved = localStorage.getItem('warp_ssh_profiles');
    if (saved) {
      const data = JSON.parse(saved);
      profiles.value = data.map((p: SSHProfile) => ({
        ...p,
        lastConnected: p.lastConnected ? new Date(p.lastConnected) : undefined
      }));
    }
  } catch (e) {
    console.error('[SSH] Failed to load profiles:', e);
  }
}

function saveProfiles(): void {
  try {
    localStorage.setItem('warp_ssh_profiles', JSON.stringify(profiles.value));
  } catch (e) {
    console.error('[SSH] Failed to save profiles:', e);
  }
}

// Initialize
loadProfiles();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

async function executeRemote(connectionId: string, command: string): Promise<string> {
  if (!invoke) {
    throw new Error('SSH not available in browser mode');
  }
  return invoke<string>('ssh_execute', { connectionId, command });
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useSSH() {
  /**
   * Create a new SSH profile
   */
  function createProfile(profile: Omit<SSHProfile, 'id'>): SSHProfile {
    const newProfile: SSHProfile = {
      ...profile,
      id: generateId()
    };
    profiles.value.push(newProfile);
    saveProfiles();
    return newProfile;
  }

  /**
   * Update an existing profile
   */
  function updateProfile(id: string, updates: Partial<SSHProfile>): SSHProfile | null {
    const index = profiles.value.findIndex(p => p.id === id);
    if (index < 0) return null;

    profiles.value[index] = { ...profiles.value[index], ...updates };
    saveProfiles();
    return profiles.value[index];
  }

  /**
   * Delete a profile
   */
  function deleteProfile(id: string): boolean {
    const index = profiles.value.findIndex(p => p.id === id);
    if (index < 0) return false;

    // Disconnect if connected
    const connection = Array.from(connections.values()).find(c => c.profileId === id);
    if (connection) {
      disconnect(connection.id);
    }

    profiles.value.splice(index, 1);
    saveProfiles();
    return true;
  }

  /**
   * Get profile by ID
   */
  function getProfile(id: string): SSHProfile | undefined {
    return profiles.value.find(p => p.id === id);
  }

  /**
   * Connect to a remote server
   */
  async function connect(profileId: string, options?: {
    password?: string;
    keyPassphrase?: string;
  }): Promise<SSHConnection> {
    const profile = getProfile(profileId);
    if (!profile) {
      throw new Error(`Profile not found: ${profileId}`);
    }

    isConnecting.value = true;

    const connection: SSHConnection = {
      id: generateId(),
      profileId,
      profile,
      status: 'connecting'
    };

    connections.set(connection.id, connection);

    try {
      if (!invoke) {
        throw new Error('SSH not available in browser mode. Use the desktop app.');
      }

      // Build connection options
      const connectOptions: Record<string, unknown> = {
        host: profile.host,
        port: profile.port,
        username: profile.username,
        authMethod: profile.authMethod
      };

      if (profile.authMethod === 'password') {
        connectOptions.password = options?.password;
      } else if (profile.authMethod === 'key') {
        connectOptions.keyPath = profile.keyPath;
        connectOptions.passphrase = options?.keyPassphrase;
      }

      // Handle jump host
      if (profile.useJumpHost && profile.jumpHost) {
        connectOptions.jumpHost = profile.jumpHost;
        connectOptions.jumpPort = profile.jumpPort || 22;
        connectOptions.jumpUsername = profile.jumpUsername || profile.username;
      }

      // Connect via Tauri
      await invoke('ssh_connect', {
        connectionId: connection.id,
        options: connectOptions
      });

      // Get remote info
      const hostname = await executeRemote(connection.id, 'hostname');
      const os = await executeRemote(connection.id, 'uname -s');
      const shell = await executeRemote(connection.id, 'echo $SHELL');
      const cwd = await executeRemote(connection.id, 'pwd');

      connection.status = 'connected';
      connection.connectedAt = new Date();
      connection.remoteInfo = {
        hostname: hostname.trim(),
        os: os.trim(),
        shell: shell.trim(),
        cwd: cwd.trim()
      };

      // Update profile last connected
      updateProfile(profileId, { lastConnected: new Date() });

      // Run startup command if configured
      if (profile.startupCommand) {
        await executeRemote(connection.id, profile.startupCommand);
      }

      console.log(`[SSH] Connected to ${profile.host}`);
      return connection;
    } catch (error) {
      connection.status = 'error';
      connection.error = error instanceof Error ? error.message : String(error);
      throw error;
    } finally {
      isConnecting.value = false;
    }
  }

  /**
   * Disconnect from a remote server
   */
  async function disconnect(connectionId: string): Promise<void> {
    const connection = connections.get(connectionId);
    if (!connection) return;

    try {
      if (invoke) {
        await invoke('ssh_disconnect', { connectionId });
      }
    } catch (e) {
      console.error('[SSH] Disconnect error:', e);
    }

    connections.delete(connectionId);
  }

  /**
   * Execute command on remote server
   */
  async function execute(connectionId: string, command: string): Promise<string> {
    const connection = connections.get(connectionId);
    if (!connection || connection.status !== 'connected') {
      throw new Error('Not connected');
    }

    return executeRemote(connectionId, command);
  }

  /**
   * Read file from remote server
   */
  async function readRemoteFile(connectionId: string, path: string): Promise<string> {
    return execute(connectionId, `cat "${path}"`);
  }

  /**
   * Write file to remote server
   */
  async function writeRemoteFile(connectionId: string, path: string, content: string): Promise<void> {
    // Use heredoc for reliable content transfer
    await execute(connectionId, `cat > "${path}" << 'WARP_EOF'\n${content}\nWARP_EOF`);
  }

  /**
   * List directory on remote server
   */
  async function listRemoteDirectory(connectionId: string, path: string): Promise<RemoteFileInfo[]> {
    const output = await execute(connectionId, `ls -la "${path}" | tail -n +2`);
    const files: RemoteFileInfo[] = [];

    for (const line of output.trim().split('\n')) {
      if (!line.trim()) continue;

      const parts = line.split(/\s+/);
      if (parts.length < 9) continue;

      const permissions = parts[0];
      const owner = parts[2];
      const group = parts[3];
      const size = parseInt(parts[4]) || 0;
      const name = parts.slice(8).join(' ');

      if (name === '.' || name === '..') continue;

      let type: RemoteFileInfo['type'] = 'file';
      if (permissions.startsWith('d')) type = 'directory';
      if (permissions.startsWith('l')) type = 'symlink';

      files.push({
        name,
        path: `${path}/${name}`.replace(/\/+/g, '/'),
        type,
        size,
        permissions,
        owner,
        group,
        modifiedAt: new Date()  // Would need to parse from ls output
      });
    }

    return files;
  }

  /**
   * Upload file to remote server
   */
  async function uploadFile(connectionId: string, localPath: string, remotePath: string): Promise<void> {
    if (!invoke) {
      throw new Error('File upload not available in browser mode');
    }
    await invoke('ssh_upload', { connectionId, localPath, remotePath });
  }

  /**
   * Download file from remote server
   */
  async function downloadFile(connectionId: string, remotePath: string, localPath: string): Promise<void> {
    if (!invoke) {
      throw new Error('File download not available in browser mode');
    }
    await invoke('ssh_download', { connectionId, remotePath, localPath });
  }

  /**
   * List SSH keys
   */
  async function listSSHKeys(): Promise<SSHKey[]> {
    if (!invoke) {
      // Return mock data for browser
      return [
        {
          id: '1',
          name: 'Default',
          path: '~/.ssh/id_ed25519',
          type: 'ed25519',
          fingerprint: 'SHA256:xxxx...',
          hasPassphrase: true,
          createdAt: new Date()
        }
      ];
    }

    const keys = await invoke<SSHKey[]>('list_ssh_keys');
    sshKeys.value = keys;
    return keys;
  }

  /**
   * Generate new SSH key
   */
  async function generateSSHKey(options: {
    name: string;
    type: 'rsa' | 'ed25519';
    passphrase?: string;
    comment?: string;
  }): Promise<SSHKey> {
    if (!invoke) {
      throw new Error('Key generation not available in browser mode');
    }

    const key = await invoke<SSHKey>('generate_ssh_key', options);
    sshKeys.value.push(key);
    return key;
  }

  /**
   * Test connection without fully connecting
   */
  async function testConnection(profile: SSHProfile, password?: string): Promise<{
    success: boolean;
    latency?: number;
    error?: string;
  }> {
    const startTime = Date.now();

    try {
      // Quick connection test
      const connection = await connect(profile.id, { password });
      const latency = Date.now() - startTime;

      // Disconnect immediately
      await disconnect(connection.id);

      return { success: true, latency };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Import profile from SSH config
   */
  async function importFromSSHConfig(): Promise<SSHProfile[]> {
    if (!invoke) {
      throw new Error('SSH config import not available in browser mode');
    }

    const imported = await invoke<SSHProfile[]>('import_ssh_config');

    // Add imported profiles (avoiding duplicates)
    for (const profile of imported) {
      const existing = profiles.value.find(p =>
        p.host === profile.host && p.username === profile.username
      );
      if (!existing) {
        profiles.value.push({ ...profile, id: generateId() });
      }
    }

    saveProfiles();
    return imported;
  }

  /**
   * Export profile to SSH config format
   */
  function exportToSSHConfig(profileId: string): string {
    const profile = getProfile(profileId);
    if (!profile) return '';

    let config = `Host ${profile.name.replace(/\s+/g, '-')}\n`;
    config += `  HostName ${profile.host}\n`;
    config += `  User ${profile.username}\n`;
    config += `  Port ${profile.port}\n`;

    if (profile.keyPath) {
      config += `  IdentityFile ${profile.keyPath}\n`;
    }

    if (profile.useJumpHost && profile.jumpHost) {
      config += `  ProxyJump ${profile.jumpUsername || profile.username}@${profile.jumpHost}:${profile.jumpPort || 22}\n`;
    }

    return config;
  }

  /**
   * Get connection by ID
   */
  function getConnection(id: string): SSHConnection | undefined {
    return connections.get(id);
  }

  /**
   * Get active connections
   */
  const activeConnections = computed(() =>
    Array.from(connections.values()).filter(c => c.status === 'connected')
  );

  /**
   * Get recent profiles (sorted by last connected)
   */
  const recentProfiles = computed(() =>
    [...profiles.value]
      .filter(p => p.lastConnected)
      .sort((a, b) => (b.lastConnected?.getTime() || 0) - (a.lastConnected?.getTime() || 0))
      .slice(0, 5)
  );

  return {
    // State
    profiles: computed(() => profiles.value),
    connections: computed(() => Array.from(connections.values())),
    activeConnections,
    recentProfiles,
    sshKeys: computed(() => sshKeys.value),
    isConnecting: computed(() => isConnecting.value),

    // Profile management
    createProfile,
    updateProfile,
    deleteProfile,
    getProfile,

    // Connection management
    connect,
    disconnect,
    getConnection,
    testConnection,

    // Remote execution
    execute,

    // File operations
    readRemoteFile,
    writeRemoteFile,
    listRemoteDirectory,
    uploadFile,
    downloadFile,

    // SSH keys
    listSSHKeys,
    generateSSHKey,

    // Import/Export
    importFromSSHConfig,
    exportToSSHConfig
  };
}

export default useSSH;
