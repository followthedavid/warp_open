/**
 * Container Support
 * Docker and Podman integration for container management
 *
 * Features:
 * - List running/stopped containers
 * - Exec into containers
 * - Container logs
 * - Image management
 * - Docker Compose support
 * - Container-aware file operations
 * - Resource monitoring
 */

import { ref, computed, reactive, shallowRef } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export type ContainerRuntime = 'docker' | 'podman';

export interface Container {
  id: string;
  name: string;
  image: string;
  imageId: string;
  status: ContainerStatus;
  state: string;
  created: Date;
  started?: Date;
  ports: PortMapping[];
  networks: string[];
  volumes: VolumeMount[];
  labels: Record<string, string>;
  env?: string[];
  command?: string;
  health?: HealthStatus;
  stats?: ContainerStats;
}

export type ContainerStatus = 'running' | 'paused' | 'exited' | 'created' | 'restarting' | 'dead';

export interface PortMapping {
  containerPort: number;
  hostPort?: number;
  hostIp?: string;
  protocol: 'tcp' | 'udp';
}

export interface VolumeMount {
  source: string;
  destination: string;
  mode: 'ro' | 'rw';
  type: 'bind' | 'volume' | 'tmpfs';
}

export interface HealthStatus {
  status: 'healthy' | 'unhealthy' | 'starting' | 'none';
  failingStreak: number;
  log?: string[];
}

export interface ContainerStats {
  cpuPercent: number;
  memoryUsage: number;
  memoryLimit: number;
  memoryPercent: number;
  networkRx: number;
  networkTx: number;
  blockRead: number;
  blockWrite: number;
  pids: number;
}

export interface ContainerImage {
  id: string;
  tags: string[];
  size: number;
  created: Date;
  labels: Record<string, string>;
  layers: number;
}

export interface ContainerNetwork {
  id: string;
  name: string;
  driver: string;
  scope: 'local' | 'global' | 'swarm';
  ipam?: {
    driver: string;
    config: Array<{ subnet: string; gateway?: string }>;
  };
  containers: string[];
}

export interface ContainerVolume {
  name: string;
  driver: string;
  mountpoint: string;
  created: Date;
  labels: Record<string, string>;
  scope: 'local' | 'global';
}

export interface ComposeProject {
  name: string;
  path: string;
  status: 'running' | 'partial' | 'stopped';
  services: ComposeService[];
}

export interface ComposeService {
  name: string;
  containerId?: string;
  status: ContainerStatus | 'not_created';
  replicas: number;
  ports: PortMapping[];
}

export interface ExecSession {
  id: string;
  containerId: string;
  command: string;
  status: 'running' | 'exited';
  exitCode?: number;
  started: Date;
  finished?: Date;
}

// ============================================================================
// STATE
// ============================================================================

const runtime = ref<ContainerRuntime>('docker');
const containers = reactive<Map<string, Container>>(new Map());
const images = reactive<Map<string, ContainerImage>>(new Map());
const networks = reactive<Map<string, ContainerNetwork>>(new Map());
const volumes = reactive<Map<string, ContainerVolume>>(new Map());
const composeProjects = reactive<Map<string, ComposeProject>>(new Map());
const execSessions = reactive<Map<string, ExecSession>>(new Map());

const isLoading = ref(false);
const error = ref<string | null>(null);
const isAvailable = ref(false);

// Check if Tauri
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
    detectRuntime();
  });
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function detectRuntime(): Promise<void> {
  if (!invoke) return;

  // Try Docker first
  try {
    await invoke('run_command', { command: 'docker', args: ['version', '--format', '{{.Server.Version}}'] });
    runtime.value = 'docker';
    isAvailable.value = true;
    return;
  } catch {}

  // Try Podman
  try {
    await invoke('run_command', { command: 'podman', args: ['version', '--format', '{{.Server.Version}}'] });
    runtime.value = 'podman';
    isAvailable.value = true;
    return;
  } catch {}

  isAvailable.value = false;
}

async function runContainerCommand(args: string[]): Promise<string> {
  if (!invoke) throw new Error('Containers not available in browser mode');
  return invoke<string>('run_command', { command: runtime.value, args });
}

function parseJsonLines<T>(output: string): T[] {
  return output.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useContainers() {
  /**
   * List all containers
   */
  async function listContainers(showAll = true): Promise<Container[]> {
    if (!isAvailable.value) return [];

    isLoading.value = true;
    error.value = null;

    try {
      const args = ['ps', '--format', '{{json .}}'];
      if (showAll) args.push('-a');

      const output = await runContainerCommand(args);
      const rawContainers = parseJsonLines<Record<string, unknown>>(output);

      containers.clear();

      for (const raw of rawContainers) {
        const container = parseContainer(raw);
        containers.set(container.id, container);
      }

      return Array.from(containers.values());
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return [];
    } finally {
      isLoading.value = false;
    }
  }

  /**
   * Parse container from JSON
   */
  function parseContainer(raw: Record<string, unknown>): Container {
    // Docker format
    const id = (raw.ID || raw.Id || '') as string;
    const name = ((raw.Names || raw.Name || '') as string).replace(/^\//, '');
    const image = (raw.Image || '') as string;

    let status: ContainerStatus = 'created';
    const stateStr = ((raw.State || raw.Status || '') as string).toLowerCase();
    if (stateStr.includes('running') || stateStr.startsWith('up')) status = 'running';
    else if (stateStr.includes('paused')) status = 'paused';
    else if (stateStr.includes('exited') || stateStr.includes('exit')) status = 'exited';
    else if (stateStr.includes('restarting')) status = 'restarting';
    else if (stateStr.includes('dead')) status = 'dead';

    // Parse ports
    const ports: PortMapping[] = [];
    const portsStr = (raw.Ports || '') as string;
    const portMatches = portsStr.matchAll(/(\d+\.\d+\.\d+\.\d+)?:?(\d+)->(\d+)\/(tcp|udp)/g);
    for (const match of portMatches) {
      ports.push({
        hostIp: match[1],
        hostPort: match[2] ? parseInt(match[2]) : undefined,
        containerPort: parseInt(match[3]),
        protocol: match[4] as 'tcp' | 'udp'
      });
    }

    return {
      id: id.substring(0, 12),
      name,
      image,
      imageId: (raw.ImageID || '') as string,
      status,
      state: (raw.State || raw.Status || '') as string,
      created: new Date((raw.CreatedAt || raw.Created || 0) as string | number),
      ports,
      networks: ((raw.Networks || '') as string).split(',').filter(Boolean),
      volumes: [],
      labels: (raw.Labels || {}) as Record<string, string>
    };
  }

  /**
   * Get container details
   */
  async function inspectContainer(containerId: string): Promise<Container | null> {
    try {
      const output = await runContainerCommand(['inspect', containerId]);
      const data = JSON.parse(output)[0];

      const container = containers.get(containerId);
      if (!container) return null;

      // Enrich with inspect data
      container.command = data.Config?.Cmd?.join(' ');
      container.env = data.Config?.Env;
      container.started = data.State?.StartedAt ? new Date(data.State.StartedAt) : undefined;

      // Parse volumes
      container.volumes = (data.Mounts || []).map((m: Record<string, unknown>) => ({
        source: m.Source as string,
        destination: m.Destination as string,
        mode: m.RW ? 'rw' : 'ro',
        type: m.Type as 'bind' | 'volume' | 'tmpfs'
      }));

      // Health status
      if (data.State?.Health) {
        container.health = {
          status: data.State.Health.Status,
          failingStreak: data.State.Health.FailingStreak,
          log: data.State.Health.Log?.slice(-5).map((l: { Output: string }) => l.Output)
        };
      }

      return container;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return null;
    }
  }

  /**
   * Get container stats
   */
  async function getContainerStats(containerId: string): Promise<ContainerStats | null> {
    try {
      const output = await runContainerCommand([
        'stats', containerId, '--no-stream', '--format',
        '{{json .}}'
      ]);
      const raw = JSON.parse(output.trim());

      const stats: ContainerStats = {
        cpuPercent: parseFloat(raw.CPUPerc?.replace('%', '') || '0'),
        memoryUsage: parseBytes(raw.MemUsage?.split('/')[0] || '0'),
        memoryLimit: parseBytes(raw.MemUsage?.split('/')[1] || '0'),
        memoryPercent: parseFloat(raw.MemPerc?.replace('%', '') || '0'),
        networkRx: parseBytes(raw.NetIO?.split('/')[0] || '0'),
        networkTx: parseBytes(raw.NetIO?.split('/')[1] || '0'),
        blockRead: parseBytes(raw.BlockIO?.split('/')[0] || '0'),
        blockWrite: parseBytes(raw.BlockIO?.split('/')[1] || '0'),
        pids: parseInt(raw.PIDs || '0')
      };

      const container = containers.get(containerId);
      if (container) container.stats = stats;

      return stats;
    } catch (e) {
      return null;
    }
  }

  /**
   * Parse byte string (e.g., "1.5GiB")
   */
  function parseBytes(str: string): number {
    const match = str.trim().match(/^([\d.]+)\s*([KMGT]?i?B)?$/i);
    if (!match) return 0;

    const value = parseFloat(match[1]);
    const unit = (match[2] || 'B').toUpperCase();

    const multipliers: Record<string, number> = {
      'B': 1,
      'KB': 1024,
      'KIB': 1024,
      'MB': 1024 * 1024,
      'MIB': 1024 * 1024,
      'GB': 1024 * 1024 * 1024,
      'GIB': 1024 * 1024 * 1024,
      'TB': 1024 * 1024 * 1024 * 1024,
      'TIB': 1024 * 1024 * 1024 * 1024
    };

    return value * (multipliers[unit] || 1);
  }

  /**
   * Start a container
   */
  async function startContainer(containerId: string): Promise<boolean> {
    try {
      await runContainerCommand(['start', containerId]);
      const container = containers.get(containerId);
      if (container) container.status = 'running';
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Stop a container
   */
  async function stopContainer(containerId: string, timeout = 10): Promise<boolean> {
    try {
      await runContainerCommand(['stop', '-t', String(timeout), containerId]);
      const container = containers.get(containerId);
      if (container) container.status = 'exited';
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Restart a container
   */
  async function restartContainer(containerId: string): Promise<boolean> {
    try {
      await runContainerCommand(['restart', containerId]);
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Pause a container
   */
  async function pauseContainer(containerId: string): Promise<boolean> {
    try {
      await runContainerCommand(['pause', containerId]);
      const container = containers.get(containerId);
      if (container) container.status = 'paused';
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Unpause a container
   */
  async function unpauseContainer(containerId: string): Promise<boolean> {
    try {
      await runContainerCommand(['unpause', containerId]);
      const container = containers.get(containerId);
      if (container) container.status = 'running';
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Remove a container
   */
  async function removeContainer(containerId: string, force = false): Promise<boolean> {
    try {
      const args = ['rm'];
      if (force) args.push('-f');
      args.push(containerId);
      await runContainerCommand(args);
      containers.delete(containerId);
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Get container logs
   */
  async function getLogs(
    containerId: string,
    options?: {
      tail?: number;
      since?: string;
      until?: string;
      timestamps?: boolean;
      follow?: boolean;
    }
  ): Promise<string> {
    const args = ['logs'];
    if (options?.tail) args.push('--tail', String(options.tail));
    if (options?.since) args.push('--since', options.since);
    if (options?.until) args.push('--until', options.until);
    if (options?.timestamps) args.push('-t');
    args.push(containerId);

    return runContainerCommand(args);
  }

  /**
   * Execute command in container
   */
  async function exec(
    containerId: string,
    command: string[],
    options?: {
      workdir?: string;
      user?: string;
      env?: Record<string, string>;
      interactive?: boolean;
      tty?: boolean;
    }
  ): Promise<{ output: string; exitCode: number }> {
    const args = ['exec'];

    if (options?.interactive) args.push('-i');
    if (options?.tty) args.push('-t');
    if (options?.workdir) args.push('-w', options.workdir);
    if (options?.user) args.push('-u', options.user);
    if (options?.env) {
      for (const [key, value] of Object.entries(options.env)) {
        args.push('-e', `${key}=${value}`);
      }
    }

    args.push(containerId, ...command);

    try {
      const output = await runContainerCommand(args);
      return { output, exitCode: 0 };
    } catch (e) {
      return { output: e instanceof Error ? e.message : String(e), exitCode: 1 };
    }
  }

  /**
   * Copy file to container
   */
  async function copyToContainer(containerId: string, srcPath: string, destPath: string): Promise<boolean> {
    try {
      await runContainerCommand(['cp', srcPath, `${containerId}:${destPath}`]);
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Copy file from container
   */
  async function copyFromContainer(containerId: string, srcPath: string, destPath: string): Promise<boolean> {
    try {
      await runContainerCommand(['cp', `${containerId}:${srcPath}`, destPath]);
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * List images
   */
  async function listImages(): Promise<ContainerImage[]> {
    try {
      const output = await runContainerCommand(['images', '--format', '{{json .}}']);
      const rawImages = parseJsonLines<Record<string, unknown>>(output);

      images.clear();

      for (const raw of rawImages) {
        const image: ContainerImage = {
          id: (raw.ID || '') as string,
          tags: [(raw.Repository || '') + ':' + (raw.Tag || 'latest')].filter(t => t !== ':latest'),
          size: parseBytes((raw.Size || '0') as string),
          created: new Date((raw.CreatedAt || raw.Created || 0) as string),
          labels: {},
          layers: 0
        };
        images.set(image.id, image);
      }

      return Array.from(images.values());
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return [];
    }
  }

  /**
   * Pull image
   */
  async function pullImage(imageName: string): Promise<boolean> {
    try {
      await runContainerCommand(['pull', imageName]);
      await listImages();
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Remove image
   */
  async function removeImage(imageId: string, force = false): Promise<boolean> {
    try {
      const args = ['rmi'];
      if (force) args.push('-f');
      args.push(imageId);
      await runContainerCommand(args);
      images.delete(imageId);
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Run a new container
   */
  async function runContainer(
    image: string,
    options?: {
      name?: string;
      detach?: boolean;
      rm?: boolean;
      ports?: Array<{ host: number; container: number }>;
      volumes?: Array<{ host: string; container: string; mode?: 'ro' | 'rw' }>;
      env?: Record<string, string>;
      network?: string;
      command?: string[];
    }
  ): Promise<string | null> {
    const args = ['run'];

    if (options?.detach !== false) args.push('-d');
    if (options?.rm) args.push('--rm');
    if (options?.name) args.push('--name', options.name);
    if (options?.network) args.push('--network', options.network);

    if (options?.ports) {
      for (const port of options.ports) {
        args.push('-p', `${port.host}:${port.container}`);
      }
    }

    if (options?.volumes) {
      for (const vol of options.volumes) {
        const mode = vol.mode || 'rw';
        args.push('-v', `${vol.host}:${vol.container}:${mode}`);
      }
    }

    if (options?.env) {
      for (const [key, value] of Object.entries(options.env)) {
        args.push('-e', `${key}=${value}`);
      }
    }

    args.push(image);

    if (options?.command) {
      args.push(...options.command);
    }

    try {
      const containerId = await runContainerCommand(args);
      await listContainers();
      return containerId.trim();
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return null;
    }
  }

  /**
   * List networks
   */
  async function listNetworks(): Promise<ContainerNetwork[]> {
    try {
      const output = await runContainerCommand(['network', 'ls', '--format', '{{json .}}']);
      const rawNetworks = parseJsonLines<Record<string, unknown>>(output);

      networks.clear();

      for (const raw of rawNetworks) {
        const network: ContainerNetwork = {
          id: (raw.ID || '') as string,
          name: (raw.Name || '') as string,
          driver: (raw.Driver || '') as string,
          scope: (raw.Scope || 'local') as 'local' | 'global' | 'swarm',
          containers: []
        };
        networks.set(network.id, network);
      }

      return Array.from(networks.values());
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return [];
    }
  }

  /**
   * List volumes
   */
  async function listVolumes(): Promise<ContainerVolume[]> {
    try {
      const output = await runContainerCommand(['volume', 'ls', '--format', '{{json .}}']);
      const rawVolumes = parseJsonLines<Record<string, unknown>>(output);

      volumes.clear();

      for (const raw of rawVolumes) {
        const volume: ContainerVolume = {
          name: (raw.Name || '') as string,
          driver: (raw.Driver || '') as string,
          mountpoint: (raw.Mountpoint || '') as string,
          created: new Date(),
          labels: {},
          scope: 'local'
        };
        volumes.set(volume.name, volume);
      }

      return Array.from(volumes.values());
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return [];
    }
  }

  /**
   * Docker Compose up
   */
  async function composeUp(projectPath: string, options?: { detach?: boolean; build?: boolean }): Promise<boolean> {
    const args = ['-f', projectPath, 'up'];
    if (options?.detach !== false) args.push('-d');
    if (options?.build) args.push('--build');

    try {
      await runContainerCommand(args.map(a => a === '-f' ? 'compose' : a).filter((_, i) => i !== 0));
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Docker Compose down
   */
  async function composeDown(projectPath: string, options?: { volumes?: boolean; removeOrphans?: boolean }): Promise<boolean> {
    const args = ['compose', '-f', projectPath, 'down'];
    if (options?.volumes) args.push('-v');
    if (options?.removeOrphans) args.push('--remove-orphans');

    try {
      await runContainerCommand(args);
      return true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return false;
    }
  }

  /**
   * Prune unused resources
   */
  async function prune(options?: { all?: boolean; volumes?: boolean }): Promise<{ spaceReclaimed: number }> {
    try {
      const args = ['system', 'prune', '-f'];
      if (options?.all) args.push('-a');
      if (options?.volumes) args.push('--volumes');

      const output = await runContainerCommand(args);
      const match = output.match(/Total reclaimed space:\s*([\d.]+\s*[KMGT]?i?B)/i);
      const spaceReclaimed = match ? parseBytes(match[1]) : 0;

      return { spaceReclaimed };
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
      return { spaceReclaimed: 0 };
    }
  }

  /**
   * Refresh all data
   */
  async function refresh(): Promise<void> {
    await Promise.all([
      listContainers(),
      listImages(),
      listNetworks(),
      listVolumes()
    ]);
  }

  return {
    // State
    runtime: computed(() => runtime.value),
    isAvailable: computed(() => isAvailable.value),
    isLoading: computed(() => isLoading.value),
    error: computed(() => error.value),
    containers: computed(() => Array.from(containers.values())),
    images: computed(() => Array.from(images.values())),
    networks: computed(() => Array.from(networks.values())),
    volumes: computed(() => Array.from(volumes.values())),

    // Computed
    runningContainers: computed(() =>
      Array.from(containers.values()).filter(c => c.status === 'running')
    ),
    stoppedContainers: computed(() =>
      Array.from(containers.values()).filter(c => c.status === 'exited')
    ),

    // Container operations
    listContainers,
    inspectContainer,
    getContainerStats,
    startContainer,
    stopContainer,
    restartContainer,
    pauseContainer,
    unpauseContainer,
    removeContainer,
    getLogs,
    exec,
    copyToContainer,
    copyFromContainer,
    runContainer,

    // Image operations
    listImages,
    pullImage,
    removeImage,

    // Network/Volume
    listNetworks,
    listVolumes,

    // Compose
    composeUp,
    composeDown,

    // Maintenance
    prune,
    refresh
  };
}

export default useContainers;
