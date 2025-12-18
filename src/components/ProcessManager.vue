<template>
  <div class="process-manager" :class="{ 'process-manager--compact': compact }">
    <!-- Header -->
    <div class="process-manager__header">
      <h3 class="process-manager__title">Process Manager</h3>
      <div class="process-manager__controls">
        <input
          v-model="filterText"
          type="text"
          class="process-manager__filter"
          placeholder="Filter processes..."
        />
        <button class="process-manager__refresh" @click="refresh" :disabled="isLoading">
          {{ isLoading ? '...' : '↻' }}
        </button>
        <button class="process-manager__close" @click="emit('close')">×</button>
      </div>
    </div>

    <!-- Stats -->
    <div class="process-manager__stats">
      <div class="process-manager__stat">
        <span class="process-manager__stat-label">Processes:</span>
        <span class="process-manager__stat-value">{{ filteredProcesses.length }}</span>
      </div>
      <div class="process-manager__stat">
        <span class="process-manager__stat-label">CPU:</span>
        <span class="process-manager__stat-value">{{ totalCpu.toFixed(1) }}%</span>
      </div>
      <div class="process-manager__stat">
        <span class="process-manager__stat-label">Memory:</span>
        <span class="process-manager__stat-value">{{ totalMemory.toFixed(1) }}%</span>
      </div>
    </div>

    <!-- Process List -->
    <div class="process-manager__list">
      <table class="process-manager__table">
        <thead>
          <tr>
            <th @click="sortBy('pid')" class="process-manager__th--sortable">
              PID {{ sortField === 'pid' ? (sortAsc ? '↑' : '↓') : '' }}
            </th>
            <th @click="sortBy('name')" class="process-manager__th--sortable">
              Name {{ sortField === 'name' ? (sortAsc ? '↑' : '↓') : '' }}
            </th>
            <th @click="sortBy('cpu')" class="process-manager__th--sortable">
              CPU % {{ sortField === 'cpu' ? (sortAsc ? '↑' : '↓') : '' }}
            </th>
            <th @click="sortBy('memory')" class="process-manager__th--sortable">
              Mem % {{ sortField === 'memory' ? (sortAsc ? '↑' : '↓') : '' }}
            </th>
            <th>User</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="proc in sortedProcesses"
            :key="proc.pid"
            :class="{ 'process-manager__row--selected': selectedPid === proc.pid }"
            @click="selectProcess(proc.pid)"
          >
            <td class="process-manager__pid">{{ proc.pid }}</td>
            <td class="process-manager__name" :title="proc.command">{{ proc.name }}</td>
            <td class="process-manager__cpu" :class="cpuClass(proc.cpu)">{{ proc.cpu.toFixed(1) }}</td>
            <td class="process-manager__memory" :class="memoryClass(proc.memory)">{{ proc.memory.toFixed(1) }}</td>
            <td class="process-manager__user">{{ proc.user }}</td>
            <td class="process-manager__actions">
              <button
                class="process-manager__btn process-manager__btn--term"
                @click.stop="killProcess(proc.pid, 15)"
                title="Terminate (SIGTERM)"
              >
                Term
              </button>
              <button
                class="process-manager__btn process-manager__btn--kill"
                @click.stop="killProcess(proc.pid, 9)"
                title="Kill (SIGKILL)"
              >
                Kill
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="filteredProcesses.length === 0" class="process-manager__empty">
        {{ filterText ? 'No matching processes' : 'No processes found' }}
      </div>
    </div>

    <!-- Process Details -->
    <div v-if="selectedProcess" class="process-manager__details">
      <h4>Process Details</h4>
      <div class="process-manager__detail-row">
        <span class="process-manager__detail-label">PID:</span>
        <span class="process-manager__detail-value">{{ selectedProcess.pid }}</span>
      </div>
      <div class="process-manager__detail-row">
        <span class="process-manager__detail-label">Name:</span>
        <span class="process-manager__detail-value">{{ selectedProcess.name }}</span>
      </div>
      <div class="process-manager__detail-row">
        <span class="process-manager__detail-label">Command:</span>
        <span class="process-manager__detail-value process-manager__detail-value--command">
          {{ selectedProcess.command }}
        </span>
      </div>
      <div class="process-manager__detail-row">
        <span class="process-manager__detail-label">User:</span>
        <span class="process-manager__detail-value">{{ selectedProcess.user }}</span>
      </div>
      <div class="process-manager__detail-row">
        <span class="process-manager__detail-label">Started:</span>
        <span class="process-manager__detail-value">{{ selectedProcess.started }}</span>
      </div>
    </div>

    <!-- Background Jobs -->
    <div v-if="backgroundJobs.length > 0" class="process-manager__jobs">
      <h4>Background Jobs</h4>
      <div
        v-for="job in backgroundJobs"
        :key="job.id"
        class="process-manager__job"
        :class="`process-manager__job--${job.status}`"
      >
        <span class="process-manager__job-status">{{ job.status }}</span>
        <span class="process-manager__job-command">{{ job.command }}</span>
        <button
          v-if="job.status === 'running'"
          class="process-manager__btn process-manager__btn--stop"
          @click="stopJob(job.id)"
        >
          Stop
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

// Props
interface Props {
  compact?: boolean;
  autoRefresh?: boolean;
  refreshInterval?: number;
}

const props = withDefaults(defineProps<Props>(), {
  compact: false,
  autoRefresh: true,
  refreshInterval: 5000,
});

// Emits
const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'process-killed', pid: number): void;
}>();

// Types
interface ProcessInfo {
  pid: number;
  name: string;
  command: string;
  user: string;
  cpu: number;
  memory: number;
  started: string;
}

interface BackgroundJob {
  id: string;
  command: string;
  status: 'running' | 'done' | 'failed';
  pid?: number;
}

// State
const processes = ref<ProcessInfo[]>([]);
const isLoading = ref(false);
const filterText = ref('');
const selectedPid = ref<number | null>(null);
const sortField = ref<'pid' | 'name' | 'cpu' | 'memory'>('cpu');
const sortAsc = ref(false);
const backgroundJobs = ref<BackgroundJob[]>([]);

// Computed
const filteredProcesses = computed(() => {
  if (!filterText.value) return processes.value;

  const filter = filterText.value.toLowerCase();
  return processes.value.filter(
    p =>
      p.name.toLowerCase().includes(filter) ||
      p.command.toLowerCase().includes(filter) ||
      p.user.toLowerCase().includes(filter) ||
      p.pid.toString().includes(filter)
  );
});

const sortedProcesses = computed(() => {
  const sorted = [...filteredProcesses.value];

  sorted.sort((a, b) => {
    let cmp = 0;
    switch (sortField.value) {
      case 'pid':
        cmp = a.pid - b.pid;
        break;
      case 'name':
        cmp = a.name.localeCompare(b.name);
        break;
      case 'cpu':
        cmp = a.cpu - b.cpu;
        break;
      case 'memory':
        cmp = a.memory - b.memory;
        break;
    }
    return sortAsc.value ? cmp : -cmp;
  });

  return sorted;
});

const selectedProcess = computed(() => {
  if (selectedPid.value === null) return null;
  return processes.value.find(p => p.pid === selectedPid.value);
});

const totalCpu = computed(() => processes.value.reduce((sum, p) => sum + p.cpu, 0));

const totalMemory = computed(() => processes.value.reduce((sum, p) => sum + p.memory, 0));

// Methods
function cpuClass(cpu: number): string {
  if (cpu > 50) return 'process-manager__cpu--high';
  if (cpu > 20) return 'process-manager__cpu--medium';
  return '';
}

function memoryClass(memory: number): string {
  if (memory > 20) return 'process-manager__memory--high';
  if (memory > 10) return 'process-manager__memory--medium';
  return '';
}

function sortBy(field: 'pid' | 'name' | 'cpu' | 'memory') {
  if (sortField.value === field) {
    sortAsc.value = !sortAsc.value;
  } else {
    sortField.value = field;
    sortAsc.value = field === 'name' || field === 'pid';
  }
}

function selectProcess(pid: number) {
  selectedPid.value = selectedPid.value === pid ? null : pid;
}

async function refresh() {
  if (!isTauri || !invoke) return;

  isLoading.value = true;

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: 'ps aux',
    });

    const lines = result.stdout.split('\n').slice(1); // Skip header
    const parsed: ProcessInfo[] = [];

    for (const line of lines) {
      if (!line.trim()) continue;

      const parts = line.trim().split(/\s+/);
      if (parts.length < 11) continue;

      parsed.push({
        user: parts[0],
        pid: parseInt(parts[1]),
        cpu: parseFloat(parts[2]),
        memory: parseFloat(parts[3]),
        started: parts[8],
        name: parts[10].split('/').pop() || parts[10],
        command: parts.slice(10).join(' '),
      });
    }

    processes.value = parsed;
  } catch (e) {
    console.error('[ProcessManager] Error refreshing:', e);
  } finally {
    isLoading.value = false;
  }
}

async function killProcess(pid: number, signal: number) {
  if (!isTauri || !invoke) return;

  try {
    await invoke('execute_shell', {
      command: `kill -${signal} ${pid}`,
    });

    emit('process-killed', pid);

    // Refresh after a short delay
    setTimeout(refresh, 500);
  } catch (e) {
    console.error('[ProcessManager] Error killing process:', e);
  }
}

function stopJob(jobId: string) {
  const job = backgroundJobs.value.find(j => j.id === jobId);
  if (job && job.pid) {
    killProcess(job.pid, 15);
  }
}

// Lifecycle
let refreshTimer: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  refresh();

  if (props.autoRefresh) {
    refreshTimer = setInterval(refresh, props.refreshInterval);
  }
});

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
});

// Expose methods
defineExpose({
  refresh,
  addBackgroundJob: (job: BackgroundJob) => {
    backgroundJobs.value.push(job);
  },
  removeBackgroundJob: (id: string) => {
    const index = backgroundJobs.value.findIndex(j => j.id === id);
    if (index >= 0) backgroundJobs.value.splice(index, 1);
  },
  updateJobStatus: (id: string, status: 'running' | 'done' | 'failed') => {
    const job = backgroundJobs.value.find(j => j.id === id);
    if (job) job.status = status;
  },
});
</script>

<style scoped>
.process-manager {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--panel-bg, #1e1e2e);
  color: var(--panel-fg, #cdd6f4);
  font-size: 13px;
}

.process-manager--compact {
  font-size: 12px;
}

.process-manager__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.process-manager__title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}

.process-manager__controls {
  display: flex;
  align-items: center;
  gap: 8px;
}

.process-manager__filter {
  padding: 4px 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--border-color, #45475a);
  border-radius: 4px;
  color: inherit;
  font-size: 12px;
  width: 150px;
}

.process-manager__filter:focus {
  outline: none;
  border-color: var(--accent-color, #89b4fa);
}

.process-manager__refresh,
.process-manager__close {
  padding: 4px 8px;
  background: var(--button-bg, #45475a);
  border: none;
  border-radius: 4px;
  color: inherit;
  cursor: pointer;
  font-size: 14px;
}

.process-manager__refresh:hover,
.process-manager__close:hover {
  background: var(--button-hover, #585b70);
}

.process-manager__refresh:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.process-manager__stats {
  display: flex;
  gap: 24px;
  padding: 8px 16px;
  background: var(--stats-bg, #181825);
  border-bottom: 1px solid var(--border-color, #313244);
}

.process-manager__stat {
  display: flex;
  gap: 4px;
}

.process-manager__stat-label {
  color: var(--label-color, #9399b2);
}

.process-manager__stat-value {
  font-weight: 500;
}

.process-manager__list {
  flex: 1;
  overflow: auto;
}

.process-manager__table {
  width: 100%;
  border-collapse: collapse;
}

.process-manager__table th {
  position: sticky;
  top: 0;
  padding: 8px 12px;
  background: var(--table-header-bg, #313244);
  text-align: left;
  font-weight: 500;
  font-size: 11px;
  text-transform: uppercase;
  color: var(--label-color, #9399b2);
}

.process-manager__th--sortable {
  cursor: pointer;
}

.process-manager__th--sortable:hover {
  color: var(--accent-color, #89b4fa);
}

.process-manager__table td {
  padding: 6px 12px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.process-manager__table tbody tr:hover {
  background: var(--row-hover, #313244);
}

.process-manager__row--selected {
  background: var(--row-selected, #45475a) !important;
}

.process-manager__pid {
  font-family: monospace;
  color: var(--pid-color, #89b4fa);
}

.process-manager__name {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.process-manager__cpu,
.process-manager__memory {
  font-family: monospace;
  text-align: right;
}

.process-manager__cpu--high,
.process-manager__memory--high {
  color: var(--danger-color, #f38ba8);
  font-weight: 600;
}

.process-manager__cpu--medium,
.process-manager__memory--medium {
  color: var(--warning-color, #f9e2af);
}

.process-manager__user {
  color: var(--user-color, #a6e3a1);
}

.process-manager__actions {
  display: flex;
  gap: 4px;
}

.process-manager__btn {
  padding: 2px 6px;
  font-size: 11px;
  border: none;
  border-radius: 3px;
  cursor: pointer;
}

.process-manager__btn--term {
  background: var(--warning-bg, #f9e2af33);
  color: var(--warning-color, #f9e2af);
}

.process-manager__btn--kill {
  background: var(--danger-bg, #f38ba833);
  color: var(--danger-color, #f38ba8);
}

.process-manager__btn--stop {
  background: var(--danger-bg, #f38ba833);
  color: var(--danger-color, #f38ba8);
}

.process-manager__btn:hover {
  opacity: 0.8;
}

.process-manager__empty {
  padding: 24px;
  text-align: center;
  color: var(--muted-color, #6c7086);
}

.process-manager__details {
  padding: 12px 16px;
  background: var(--details-bg, #181825);
  border-top: 1px solid var(--border-color, #313244);
}

.process-manager__details h4 {
  margin: 0 0 8px 0;
  font-size: 12px;
  text-transform: uppercase;
  color: var(--label-color, #9399b2);
}

.process-manager__detail-row {
  display: flex;
  gap: 8px;
  padding: 2px 0;
}

.process-manager__detail-label {
  width: 80px;
  color: var(--label-color, #9399b2);
}

.process-manager__detail-value {
  flex: 1;
}

.process-manager__detail-value--command {
  font-family: monospace;
  font-size: 11px;
  word-break: break-all;
}

.process-manager__jobs {
  padding: 12px 16px;
  border-top: 1px solid var(--border-color, #313244);
}

.process-manager__jobs h4 {
  margin: 0 0 8px 0;
  font-size: 12px;
  text-transform: uppercase;
  color: var(--label-color, #9399b2);
}

.process-manager__job {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  background: var(--job-bg, #313244);
  border-radius: 4px;
  margin-bottom: 4px;
}

.process-manager__job--running .process-manager__job-status {
  color: var(--running-color, #89b4fa);
}

.process-manager__job--done .process-manager__job-status {
  color: var(--success-color, #a6e3a1);
}

.process-manager__job--failed .process-manager__job-status {
  color: var(--danger-color, #f38ba8);
}

.process-manager__job-status {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  width: 60px;
}

.process-manager__job-command {
  flex: 1;
  font-family: monospace;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
