<template>
  <div class="status-bar" :class="{ 'status-bar--compact': compact }">
    <!-- Left section -->
    <div class="status-bar__left">
      <!-- Current working directory -->
      <div class="status-bar__item status-bar__cwd" @click="copyCwd" title="Click to copy">
        <span class="status-bar__icon">📁</span>
        <span class="status-bar__text">{{ displayCwd }}</span>
      </div>

      <!-- Git branch -->
      <div v-if="gitInfo.branch" class="status-bar__item status-bar__git" :class="gitStatusClass">
        <span class="status-bar__icon">{{ gitInfo.isDirty ? '●' : '○' }}</span>
        <span class="status-bar__text">{{ gitInfo.branch }}</span>
        <span v-if="gitInfo.ahead > 0" class="status-bar__badge status-bar__badge--ahead">↑{{ gitInfo.ahead }}</span>
        <span v-if="gitInfo.behind > 0" class="status-bar__badge status-bar__badge--behind">↓{{ gitInfo.behind }}</span>
      </div>

      <!-- Shell type -->
      <div class="status-bar__item status-bar__shell">
        <span class="status-bar__icon">$</span>
        <span class="status-bar__text">{{ shellType }}</span>
      </div>
    </div>

    <!-- Center section -->
    <div class="status-bar__center">
      <!-- AI status -->
      <div v-if="aiStatus.isProcessing" class="status-bar__item status-bar__ai">
        <span class="status-bar__spinner"></span>
        <span class="status-bar__text">{{ aiStatus.currentTask || 'AI thinking...' }}</span>
      </div>

      <!-- Background jobs -->
      <div v-if="backgroundJobs.length > 0" class="status-bar__item status-bar__jobs" @click="showJobsPanel">
        <span class="status-bar__icon">⚡</span>
        <span class="status-bar__text">{{ backgroundJobs.length }} job{{ backgroundJobs.length > 1 ? 's' : '' }}</span>
      </div>
    </div>

    <!-- Right section -->
    <div class="status-bar__right">
      <!-- Model -->
      <div v-if="currentModel" class="status-bar__item status-bar__model" @click="changeModel">
        <span class="status-bar__icon">🤖</span>
        <span class="status-bar__text">{{ currentModel }}</span>
      </div>

      <!-- Connection status -->
      <div class="status-bar__item status-bar__connection" :class="connectionClass">
        <span class="status-bar__dot"></span>
        <span class="status-bar__text">{{ connectionStatus }}</span>
      </div>

      <!-- Time -->
      <div v-if="showTime" class="status-bar__item status-bar__time">
        <span class="status-bar__text">{{ currentTime }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';

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
  cwd?: string;
  compact?: boolean;
  showTime?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  cwd: '',
  compact: false,
  showTime: true,
});

// Emits
const emit = defineEmits<{
  (e: 'show-jobs'): void;
  (e: 'change-model'): void;
  (e: 'change-directory', path: string): void;
}>();

// State
const currentCwd = ref(props.cwd || '~');
const currentTime = ref('');
const shellType = ref('zsh');
const currentModel = ref('qwen2.5:3b');

interface GitInfo {
  branch: string;
  isDirty: boolean;
  ahead: number;
  behind: number;
  staged: number;
  unstaged: number;
}

const gitInfo = ref<GitInfo>({
  branch: '',
  isDirty: false,
  ahead: 0,
  behind: 0,
  staged: 0,
  unstaged: 0,
});

interface AIStatus {
  isProcessing: boolean;
  currentTask: string;
}

const aiStatus = ref<AIStatus>({
  isProcessing: false,
  currentTask: '',
});

interface BackgroundJob {
  id: string;
  command: string;
  status: 'running' | 'done' | 'failed';
  pid?: number;
}

const backgroundJobs = ref<BackgroundJob[]>([]);

const connectionStatus = ref<'connected' | 'disconnected' | 'connecting'>('connected');

// Computed
const displayCwd = computed(() => {
  const cwd = currentCwd.value;
  const home = '/Users/' + (typeof process !== 'undefined' ? process.env.USER : 'user');

  if (cwd.startsWith(home)) {
    return '~' + cwd.slice(home.length);
  }

  // Truncate long paths
  if (cwd.length > 40) {
    const parts = cwd.split('/');
    if (parts.length > 4) {
      return parts[0] + '/.../' + parts.slice(-2).join('/');
    }
  }

  return cwd;
});

const gitStatusClass = computed(() => ({
  'status-bar__git--dirty': gitInfo.value.isDirty,
  'status-bar__git--clean': !gitInfo.value.isDirty && gitInfo.value.branch,
}));

const connectionClass = computed(() => ({
  'status-bar__connection--connected': connectionStatus.value === 'connected',
  'status-bar__connection--disconnected': connectionStatus.value === 'disconnected',
  'status-bar__connection--connecting': connectionStatus.value === 'connecting',
}));

// Methods
function copyCwd() {
  navigator.clipboard.writeText(currentCwd.value);
}

function showJobsPanel() {
  emit('show-jobs');
}

function changeModel() {
  emit('change-model');
}

async function updateGitInfo() {
  if (!isTauri || !invoke) return;

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: 'git rev-parse --abbrev-ref HEAD 2>/dev/null',
      workingDir: currentCwd.value,
    });

    if (result.exit_code === 0 && result.stdout.trim()) {
      gitInfo.value.branch = result.stdout.trim();

      // Check for dirty state
      const statusResult = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
        command: 'git status --porcelain 2>/dev/null',
        workingDir: currentCwd.value,
      });
      gitInfo.value.isDirty = statusResult.stdout.trim().length > 0;

      // Check ahead/behind
      const aheadBehindResult = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
        command: 'git rev-list --left-right --count HEAD...@{upstream} 2>/dev/null',
        workingDir: currentCwd.value,
      });
      if (aheadBehindResult.exit_code === 0) {
        const [ahead, behind] = aheadBehindResult.stdout.trim().split(/\s+/).map(Number);
        gitInfo.value.ahead = ahead || 0;
        gitInfo.value.behind = behind || 0;
      }
    } else {
      gitInfo.value.branch = '';
    }
  } catch {
    gitInfo.value.branch = '';
  }
}

function updateTime() {
  const now = new Date();
  currentTime.value = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

async function detectShell() {
  if (!isTauri || !invoke) return;

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: 'echo $SHELL',
    });
    const shell = result.stdout.trim().split('/').pop() || 'sh';
    shellType.value = shell;
  } catch {
    shellType.value = 'sh';
  }
}

// Update CWD from prop
watch(() => props.cwd, (newCwd) => {
  if (newCwd) {
    currentCwd.value = newCwd;
    updateGitInfo();
  }
});

// Lifecycle
let timeInterval: ReturnType<typeof setInterval>;
let gitInterval: ReturnType<typeof setInterval>;

onMounted(() => {
  updateTime();
  timeInterval = setInterval(updateTime, 1000);

  detectShell();
  updateGitInfo();
  gitInterval = setInterval(updateGitInfo, 5000);
});

onUnmounted(() => {
  clearInterval(timeInterval);
  clearInterval(gitInterval);
});

// Expose methods for parent components
defineExpose({
  updateGitInfo,
  setAIStatus: (processing: boolean, task?: string) => {
    aiStatus.value.isProcessing = processing;
    aiStatus.value.currentTask = task || '';
  },
  addBackgroundJob: (job: BackgroundJob) => {
    backgroundJobs.value.push(job);
  },
  removeBackgroundJob: (id: string) => {
    const index = backgroundJobs.value.findIndex(j => j.id === id);
    if (index >= 0) backgroundJobs.value.splice(index, 1);
  },
  setConnectionStatus: (status: 'connected' | 'disconnected' | 'connecting') => {
    connectionStatus.value = status;
  },
  setModel: (model: string) => {
    currentModel.value = model;
  },
  setCwd: (cwd: string) => {
    currentCwd.value = cwd;
    updateGitInfo();
  },
});
</script>

<style scoped>
.status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 24px;
  padding: 0 12px;
  background: var(--status-bar-bg, #1e1e2e);
  border-top: 1px solid var(--border-color, #313244);
  font-size: 12px;
  color: var(--status-bar-fg, #cdd6f4);
  user-select: none;
}

.status-bar--compact {
  height: 20px;
  font-size: 11px;
}

.status-bar__left,
.status-bar__center,
.status-bar__right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.status-bar__left {
  flex: 1;
}

.status-bar__center {
  flex: 0 0 auto;
}

.status-bar__right {
  flex: 1;
  justify-content: flex-end;
}

.status-bar__item {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 2px 6px;
  border-radius: 3px;
  cursor: default;
  transition: background-color 0.15s ease;
}

.status-bar__item:hover {
  background: var(--status-bar-hover, #313244);
}

.status-bar__icon {
  font-size: 10px;
  opacity: 0.8;
}

.status-bar__text {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.status-bar__cwd {
  cursor: pointer;
  max-width: 200px;
}

.status-bar__git--dirty .status-bar__icon {
  color: var(--git-dirty, #fab387);
}

.status-bar__git--clean .status-bar__icon {
  color: var(--git-clean, #a6e3a1);
}

.status-bar__badge {
  font-size: 10px;
  padding: 0 4px;
  border-radius: 2px;
  background: var(--badge-bg, #45475a);
}

.status-bar__badge--ahead {
  color: var(--badge-ahead, #89dceb);
}

.status-bar__badge--behind {
  color: var(--badge-behind, #f38ba8);
}

.status-bar__spinner {
  width: 10px;
  height: 10px;
  border: 2px solid var(--spinner-color, #89b4fa);
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.status-bar__jobs {
  cursor: pointer;
  color: var(--jobs-color, #f9e2af);
}

.status-bar__model {
  cursor: pointer;
}

.status-bar__dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  margin-right: 2px;
}

.status-bar__connection--connected .status-bar__dot {
  background: var(--connected-color, #a6e3a1);
}

.status-bar__connection--disconnected .status-bar__dot {
  background: var(--disconnected-color, #f38ba8);
}

.status-bar__connection--connecting .status-bar__dot {
  background: var(--connecting-color, #f9e2af);
  animation: pulse 1s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.status-bar__time {
  color: var(--time-color, #9399b2);
  font-variant-numeric: tabular-nums;
}
</style>
