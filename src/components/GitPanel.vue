<template>
  <div class="git-panel">
    <!-- Header -->
    <div class="git-panel__header">
      <h3 class="git-panel__title">Git</h3>
      <div class="git-panel__branch" v-if="currentBranch">
        <span class="git-panel__branch-icon">⎇</span>
        <span class="git-panel__branch-name">{{ currentBranch }}</span>
      </div>
      <div class="git-panel__controls">
        <button class="git-panel__btn" @click="refresh" :disabled="isLoading" title="Refresh">
          {{ isLoading ? '...' : '↻' }}
        </button>
        <button class="git-panel__btn" @click="emit('close')" title="Close">×</button>
      </div>
    </div>

    <!-- Not a repo message -->
    <div v-if="!isRepo" class="git-panel__not-repo">
      <p>Not a Git repository</p>
      <button class="git-panel__btn git-panel__btn--primary" @click="initRepo">
        Initialize Repository
      </button>
    </div>

    <!-- Main content -->
    <div v-else class="git-panel__content">
      <!-- Branch selector -->
      <div class="git-panel__section">
        <div class="git-panel__section-header" @click="toggleSection('branches')">
          <span class="git-panel__section-icon">{{ expandedSections.branches ? '▼' : '▶' }}</span>
          <span class="git-panel__section-title">Branches</span>
          <span class="git-panel__section-count">{{ branches.length }}</span>
        </div>
        <div v-if="expandedSections.branches" class="git-panel__section-content">
          <div
            v-for="branch in branches"
            :key="branch.name"
            class="git-panel__branch-item"
            :class="{ 'git-panel__branch-item--current': branch.current }"
            @click="checkoutBranch(branch.name)"
          >
            <span class="git-panel__branch-indicator">{{ branch.current ? '●' : '○' }}</span>
            <span class="git-panel__branch-name">{{ branch.name }}</span>
            <span v-if="branch.upstream" class="git-panel__branch-upstream">
              {{ branch.ahead > 0 ? `↑${branch.ahead}` : '' }}
              {{ branch.behind > 0 ? `↓${branch.behind}` : '' }}
            </span>
          </div>
          <button class="git-panel__btn git-panel__btn--small" @click="showNewBranchModal = true">
            + New Branch
          </button>
        </div>
      </div>

      <!-- Staged changes -->
      <div class="git-panel__section">
        <div class="git-panel__section-header" @click="toggleSection('staged')">
          <span class="git-panel__section-icon">{{ expandedSections.staged ? '▼' : '▶' }}</span>
          <span class="git-panel__section-title">Staged Changes</span>
          <span class="git-panel__section-count">{{ stagedFiles.length }}</span>
        </div>
        <div v-if="expandedSections.staged" class="git-panel__section-content">
          <div v-if="stagedFiles.length === 0" class="git-panel__empty">
            No staged changes
          </div>
          <div
            v-for="file in stagedFiles"
            :key="file.path"
            class="git-panel__file"
            @click="showDiff(file, true)"
          >
            <span class="git-panel__file-status" :class="`git-panel__file-status--${file.status}`">
              {{ file.statusChar }}
            </span>
            <span class="git-panel__file-path">{{ file.path }}</span>
            <button
              class="git-panel__file-action"
              @click.stop="unstageFile(file.path)"
              title="Unstage"
            >
              −
            </button>
          </div>
        </div>
      </div>

      <!-- Unstaged changes -->
      <div class="git-panel__section">
        <div class="git-panel__section-header" @click="toggleSection('unstaged')">
          <span class="git-panel__section-icon">{{ expandedSections.unstaged ? '▼' : '▶' }}</span>
          <span class="git-panel__section-title">Changes</span>
          <span class="git-panel__section-count">{{ unstagedFiles.length }}</span>
        </div>
        <div v-if="expandedSections.unstaged" class="git-panel__section-content">
          <div v-if="unstagedFiles.length === 0" class="git-panel__empty">
            No changes
          </div>
          <div
            v-for="file in unstagedFiles"
            :key="file.path"
            class="git-panel__file"
            @click="showDiff(file, false)"
          >
            <span class="git-panel__file-status" :class="`git-panel__file-status--${file.status}`">
              {{ file.statusChar }}
            </span>
            <span class="git-panel__file-path">{{ file.path }}</span>
            <div class="git-panel__file-actions">
              <button
                class="git-panel__file-action"
                @click.stop="stageFile(file.path)"
                title="Stage"
              >
                +
              </button>
              <button
                class="git-panel__file-action git-panel__file-action--danger"
                @click.stop="discardFile(file.path)"
                title="Discard"
              >
                ✕
              </button>
            </div>
          </div>
          <div v-if="unstagedFiles.length > 0" class="git-panel__actions">
            <button class="git-panel__btn git-panel__btn--small" @click="stageAll">
              Stage All
            </button>
          </div>
        </div>
      </div>

      <!-- Commit section -->
      <div class="git-panel__commit-section">
        <textarea
          v-model="commitMessage"
          class="git-panel__commit-input"
          placeholder="Commit message..."
          rows="3"
        ></textarea>
        <div class="git-panel__commit-actions">
          <button
            class="git-panel__btn git-panel__btn--ai"
            @click="generateCommitMessage"
            :disabled="isGenerating"
            title="Generate commit message with AI"
          >
            {{ isGenerating ? '...' : '🤖 Generate' }}
          </button>
          <button
            class="git-panel__btn git-panel__btn--primary"
            @click="commit"
            :disabled="!canCommit"
          >
            Commit
          </button>
        </div>
      </div>

      <!-- Recent commits -->
      <div class="git-panel__section">
        <div class="git-panel__section-header" @click="toggleSection('commits')">
          <span class="git-panel__section-icon">{{ expandedSections.commits ? '▼' : '▶' }}</span>
          <span class="git-panel__section-title">Recent Commits</span>
        </div>
        <div v-if="expandedSections.commits" class="git-panel__section-content">
          <div
            v-for="c in recentCommits"
            :key="c.hash"
            class="git-panel__commit"
            @click="showCommitDetails(c)"
          >
            <div class="git-panel__commit-hash">{{ c.shortHash }}</div>
            <div class="git-panel__commit-message">{{ c.message }}</div>
            <div class="git-panel__commit-author">{{ c.author }}</div>
            <div class="git-panel__commit-date">{{ formatDate(c.date) }}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- New branch modal -->
    <div v-if="showNewBranchModal" class="git-panel__modal-overlay" @click.self="showNewBranchModal = false">
      <div class="git-panel__modal">
        <h4>Create New Branch</h4>
        <input
          v-model="newBranchName"
          type="text"
          class="git-panel__modal-input"
          placeholder="branch-name"
          @keyup.enter="createBranch"
        />
        <div class="git-panel__modal-actions">
          <button class="git-panel__btn" @click="showNewBranchModal = false">Cancel</button>
          <button
            class="git-panel__btn git-panel__btn--primary"
            @click="createBranch"
            :disabled="!newBranchName"
          >
            Create
          </button>
        </div>
      </div>
    </div>

    <!-- Diff viewer -->
    <div v-if="showDiffViewer" class="git-panel__diff-overlay" @click.self="showDiffViewer = false">
      <div class="git-panel__diff-viewer">
        <div class="git-panel__diff-header">
          <span>{{ diffFile }}</span>
          <button class="git-panel__btn" @click="showDiffViewer = false">×</button>
        </div>
        <pre class="git-panel__diff-content">{{ diffContent }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';

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
  workingDir?: string;
}

const props = withDefaults(defineProps<Props>(), {
  workingDir: '',
});

// Emits
const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'commit', hash: string): void;
  (e: 'branch-changed', branch: string): void;
}>();

// Types
interface GitFile {
  path: string;
  status: 'modified' | 'added' | 'deleted' | 'renamed' | 'untracked';
  statusChar: string;
}

interface Branch {
  name: string;
  current: boolean;
  upstream?: string;
  ahead: number;
  behind: number;
}

interface Commit {
  hash: string;
  shortHash: string;
  message: string;
  author: string;
  date: Date;
}

// State
const isRepo = ref(true);
const isLoading = ref(false);
const isGenerating = ref(false);
const currentBranch = ref('');
const branches = ref<Branch[]>([]);
const stagedFiles = ref<GitFile[]>([]);
const unstagedFiles = ref<GitFile[]>([]);
const recentCommits = ref<Commit[]>([]);
const commitMessage = ref('');
const showNewBranchModal = ref(false);
const newBranchName = ref('');
const showDiffViewer = ref(false);
const diffFile = ref('');
const diffContent = ref('');

const expandedSections = ref({
  branches: true,
  staged: true,
  unstaged: true,
  commits: false,
});

// Computed
const canCommit = computed(() => {
  return stagedFiles.value.length > 0 && commitMessage.value.trim().length > 0;
});

// Methods
function toggleSection(section: keyof typeof expandedSections.value) {
  expandedSections.value[section] = !expandedSections.value[section];
}

async function runGit(args: string): Promise<{ stdout: string; stderr: string; success: boolean }> {
  if (!isTauri || !invoke) {
    return { stdout: '', stderr: 'Not in Tauri', success: false };
  }

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: `git ${args}`,
      workingDir: props.workingDir || undefined,
    });
    return { stdout: result.stdout, stderr: result.stderr, success: result.exit_code === 0 };
  } catch (e) {
    return { stdout: '', stderr: String(e), success: false };
  }
}

async function refresh() {
  isLoading.value = true;

  try {
    // Check if repo
    const checkRepo = await runGit('rev-parse --git-dir');
    isRepo.value = checkRepo.success;

    if (!isRepo.value) return;

    // Get current branch
    const branchResult = await runGit('rev-parse --abbrev-ref HEAD');
    currentBranch.value = branchResult.stdout.trim();

    // Get all branches
    await loadBranches();

    // Get status
    await loadStatus();

    // Get recent commits
    await loadCommits();
  } finally {
    isLoading.value = false;
  }
}

async function loadBranches() {
  const result = await runGit('branch -a --format="%(HEAD)|%(refname:short)|%(upstream:short)|%(upstream:track)"');
  if (!result.success) return;

  const parsed: Branch[] = [];
  for (const line of result.stdout.split('\n')) {
    if (!line.trim()) continue;

    const [head, name, upstream, track] = line.split('|');
    if (name.startsWith('remotes/')) continue; // Skip remote refs

    let ahead = 0, behind = 0;
    if (track) {
      const aheadMatch = track.match(/ahead (\d+)/);
      const behindMatch = track.match(/behind (\d+)/);
      if (aheadMatch) ahead = parseInt(aheadMatch[1]);
      if (behindMatch) behind = parseInt(behindMatch[1]);
    }

    parsed.push({
      name,
      current: head === '*',
      upstream: upstream || undefined,
      ahead,
      behind,
    });
  }

  branches.value = parsed;
}

async function loadStatus() {
  const result = await runGit('status --porcelain=v1');
  if (!result.success) return;

  const staged: GitFile[] = [];
  const unstaged: GitFile[] = [];

  for (const line of result.stdout.split('\n')) {
    if (!line.trim()) continue;

    const indexStatus = line[0];
    const workStatus = line[1];
    const path = line.substring(3);

    // Staged changes
    if (indexStatus !== ' ' && indexStatus !== '?') {
      staged.push({
        path,
        status: statusFromChar(indexStatus),
        statusChar: indexStatus,
      });
    }

    // Unstaged changes
    if (workStatus !== ' ' || indexStatus === '?') {
      unstaged.push({
        path,
        status: workStatus === '?' ? 'untracked' : statusFromChar(workStatus),
        statusChar: workStatus === '?' ? '?' : workStatus,
      });
    }
  }

  stagedFiles.value = staged;
  unstagedFiles.value = unstaged;
}

function statusFromChar(char: string): GitFile['status'] {
  switch (char) {
    case 'M': return 'modified';
    case 'A': return 'added';
    case 'D': return 'deleted';
    case 'R': return 'renamed';
    default: return 'modified';
  }
}

async function loadCommits() {
  const result = await runGit('log --oneline -10 --format="%H|%h|%s|%an|%ai"');
  if (!result.success) return;

  const commits: Commit[] = [];
  for (const line of result.stdout.split('\n')) {
    if (!line.trim()) continue;

    const [hash, shortHash, message, author, dateStr] = line.split('|');
    commits.push({
      hash,
      shortHash,
      message,
      author,
      date: new Date(dateStr),
    });
  }

  recentCommits.value = commits;
}

async function stageFile(path: string) {
  await runGit(`add "${path}"`);
  await loadStatus();
}

async function unstageFile(path: string) {
  await runGit(`reset HEAD "${path}"`);
  await loadStatus();
}

async function discardFile(path: string) {
  await runGit(`checkout -- "${path}"`);
  await loadStatus();
}

async function stageAll() {
  await runGit('add -A');
  await loadStatus();
}

async function commit() {
  if (!canCommit.value) return;

  const message = commitMessage.value.replace(/"/g, '\\"');
  const result = await runGit(`commit -m "${message}"`);

  if (result.success) {
    commitMessage.value = '';
    await refresh();

    // Get new commit hash
    const hashResult = await runGit('rev-parse HEAD');
    if (hashResult.success) {
      emit('commit', hashResult.stdout.trim());
    }
  }
}

async function generateCommitMessage() {
  if (stagedFiles.value.length === 0) return;

  isGenerating.value = true;

  try {
    // Get diff of staged changes
    const diffResult = await runGit('diff --cached');
    const diff = diffResult.stdout.substring(0, 3000); // Limit size

    // Generate message with AI
    if (isTauri && invoke) {
      const prompt = `Generate a concise git commit message for these changes:

${diff}

Rules:
- Start with a type: feat, fix, refactor, docs, test, chore
- Use imperative mood
- Keep under 72 characters
- Be specific about what changed

Output ONLY the commit message, nothing else.`;

      const response = await invoke<string>('query_ollama', {
        prompt,
        model: 'qwen2.5-coder:1.5b',
      });

      commitMessage.value = response.trim().replace(/^["']|["']$/g, '');
    }
  } catch (e) {
    console.error('[GitPanel] Error generating message:', e);
  } finally {
    isGenerating.value = false;
  }
}

async function checkoutBranch(name: string) {
  const result = await runGit(`checkout "${name}"`);
  if (result.success) {
    emit('branch-changed', name);
    await refresh();
  }
}

async function createBranch() {
  if (!newBranchName.value) return;

  const result = await runGit(`checkout -b "${newBranchName.value}"`);
  if (result.success) {
    newBranchName.value = '';
    showNewBranchModal.value = false;
    emit('branch-changed', newBranchName.value);
    await refresh();
  }
}

async function initRepo() {
  const result = await runGit('init');
  if (result.success) {
    await refresh();
  }
}

async function showDiff(file: GitFile, staged: boolean) {
  const args = staged ? `diff --cached "${file.path}"` : `diff "${file.path}"`;
  const result = await runGit(args);

  diffFile.value = file.path;
  diffContent.value = result.stdout || 'No diff available';
  showDiffViewer.value = true;
}

function showCommitDetails(c: Commit) {
  // Could open a detailed view
  console.log('Show commit:', c.hash);
}

function formatDate(date: Date): string {
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return date.toLocaleDateString();
}

// Lifecycle
onMounted(() => {
  refresh();
});

// Expose
defineExpose({
  refresh,
});
</script>

<style scoped>
.git-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--panel-bg, #1e1e2e);
  color: var(--panel-fg, #cdd6f4);
  font-size: 13px;
}

.git-panel__header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.git-panel__title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}

.git-panel__branch {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  background: var(--branch-bg, #45475a);
  border-radius: 4px;
  font-size: 12px;
}

.git-panel__branch-icon {
  color: var(--branch-icon, #89b4fa);
}

.git-panel__controls {
  margin-left: auto;
  display: flex;
  gap: 4px;
}

.git-panel__btn {
  padding: 4px 8px;
  background: var(--button-bg, #45475a);
  border: none;
  border-radius: 4px;
  color: inherit;
  cursor: pointer;
  font-size: 12px;
}

.git-panel__btn:hover {
  background: var(--button-hover, #585b70);
}

.git-panel__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.git-panel__btn--primary {
  background: var(--accent-color, #89b4fa);
  color: var(--panel-bg, #1e1e2e);
}

.git-panel__btn--small {
  padding: 2px 6px;
  font-size: 11px;
}

.git-panel__btn--ai {
  background: var(--ai-color, #cba6f7);
  color: var(--panel-bg, #1e1e2e);
}

.git-panel__not-repo {
  padding: 24px;
  text-align: center;
}

.git-panel__content {
  flex: 1;
  overflow: auto;
}

.git-panel__section {
  border-bottom: 1px solid var(--border-color, #313244);
}

.git-panel__section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  cursor: pointer;
  user-select: none;
}

.git-panel__section-header:hover {
  background: var(--header-hover, #313244);
}

.git-panel__section-icon {
  font-size: 10px;
  color: var(--muted-color, #6c7086);
}

.git-panel__section-title {
  font-weight: 500;
}

.git-panel__section-count {
  margin-left: auto;
  padding: 0 6px;
  background: var(--count-bg, #45475a);
  border-radius: 10px;
  font-size: 11px;
}

.git-panel__section-content {
  padding: 4px 16px 12px;
}

.git-panel__empty {
  padding: 8px 0;
  color: var(--muted-color, #6c7086);
  font-size: 12px;
}

.git-panel__branch-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
}

.git-panel__branch-item:hover {
  background: var(--item-hover, #313244);
}

.git-panel__branch-item--current {
  background: var(--item-current, #45475a);
}

.git-panel__branch-indicator {
  color: var(--accent-color, #89b4fa);
}

.git-panel__branch-upstream {
  margin-left: auto;
  font-size: 11px;
  color: var(--muted-color, #6c7086);
}

.git-panel__file {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
}

.git-panel__file:hover {
  background: var(--item-hover, #313244);
}

.git-panel__file-status {
  width: 16px;
  font-family: monospace;
  font-weight: 600;
}

.git-panel__file-status--modified { color: var(--modified-color, #f9e2af); }
.git-panel__file-status--added { color: var(--added-color, #a6e3a1); }
.git-panel__file-status--deleted { color: var(--deleted-color, #f38ba8); }
.git-panel__file-status--renamed { color: var(--renamed-color, #89b4fa); }
.git-panel__file-status--untracked { color: var(--untracked-color, #6c7086); }

.git-panel__file-path {
  flex: 1;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.git-panel__file-actions {
  display: flex;
  gap: 2px;
  opacity: 0;
}

.git-panel__file:hover .git-panel__file-actions {
  opacity: 1;
}

.git-panel__file-action {
  padding: 2px 6px;
  background: var(--action-bg, #45475a);
  border: none;
  border-radius: 2px;
  color: inherit;
  cursor: pointer;
  font-size: 12px;
}

.git-panel__file-action:hover {
  background: var(--action-hover, #585b70);
}

.git-panel__file-action--danger:hover {
  background: var(--danger-bg, #f38ba833);
  color: var(--danger-color, #f38ba8);
}

.git-panel__actions {
  padding-top: 8px;
}

.git-panel__commit-section {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.git-panel__commit-input {
  width: 100%;
  padding: 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--border-color, #45475a);
  border-radius: 4px;
  color: inherit;
  font-family: inherit;
  font-size: 13px;
  resize: vertical;
  box-sizing: border-box;
}

.git-panel__commit-input:focus {
  outline: none;
  border-color: var(--accent-color, #89b4fa);
}

.git-panel__commit-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 8px;
}

.git-panel__commit {
  padding: 8px;
  border-radius: 4px;
  cursor: pointer;
  margin-bottom: 4px;
}

.git-panel__commit:hover {
  background: var(--item-hover, #313244);
}

.git-panel__commit-hash {
  font-family: monospace;
  font-size: 11px;
  color: var(--accent-color, #89b4fa);
}

.git-panel__commit-message {
  font-size: 12px;
  margin: 2px 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.git-panel__commit-author,
.git-panel__commit-date {
  font-size: 11px;
  color: var(--muted-color, #6c7086);
}

.git-panel__modal-overlay,
.git-panel__diff-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.git-panel__modal {
  background: var(--modal-bg, #1e1e2e);
  border: 1px solid var(--border-color, #313244);
  border-radius: 8px;
  padding: 20px;
  width: 300px;
}

.git-panel__modal h4 {
  margin: 0 0 12px 0;
}

.git-panel__modal-input {
  width: 100%;
  padding: 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--border-color, #45475a);
  border-radius: 4px;
  color: inherit;
  font-size: 13px;
  box-sizing: border-box;
}

.git-panel__modal-input:focus {
  outline: none;
  border-color: var(--accent-color, #89b4fa);
}

.git-panel__modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 12px;
}

.git-panel__diff-viewer {
  background: var(--modal-bg, #1e1e2e);
  border: 1px solid var(--border-color, #313244);
  border-radius: 8px;
  width: 80%;
  max-width: 800px;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
}

.git-panel__diff-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
  font-family: monospace;
}

.git-panel__diff-content {
  flex: 1;
  overflow: auto;
  padding: 16px;
  margin: 0;
  font-family: monospace;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
