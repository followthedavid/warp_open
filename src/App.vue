<template>
  <div id="app" class="app-shell">
    <header class="topbar">
      <div class="project-meta">
        <button class="sidebar-toggle" @click="showSidebar = !showSidebar" title="Toggle Sidebar (⌘B)">
          ☰
        </button>
        <strong>{{ projectName }}</strong>
        <small v-if="projectRoot">{{ projectRoot }}</small>
        <span v-if="appVersion" class="version-badge" :title="`Build: ${appVersion.build}`">
          v{{ appVersion.version }}
        </span>
      </div>
      <div class="topbar-actions">
        <!-- AI Status Indicator -->
        <button
          class="ai-status-btn"
          :class="{ enabled: aiEnabled, disabled: !aiEnabled }"
          @click="toggleAI"
          :title="aiEnabled ? 'AI Enabled (click to disable)' : 'AI Disabled (Air-Gapped Mode)'"
        >
          {{ aiEnabled ? '🤖 AI' : '🔒 Air-Gap' }}
        </button>
        <button class="cmd-palette-btn" @click="showCommandPalette = true" title="Command Palette (⌘⇧P)">
          ⌘⇧P
        </button>
        <button data-testid="open-folder-button" @click="handleOpenFolder">Open Folder</button>
        <button data-testid="new-file-button" @click="createEditorTab()">New File</button>
        <button data-testid="new-terminal-button" @click="createTerminalTab()">New Terminal</button>
        <button v-if="aiEnabled" data-testid="new-ai-button" @click="createAITab()">AI Panel</button>
        <button data-testid="new-developer-button" @click="createDeveloperTab()">Developer</button>
        <button class="snapshots-btn" @click="showSnapshots = true" title="Workspace Snapshots">
          📷
        </button>
      </div>
    </header>

    <main class="workspace">
      <aside class="sidebar" :class="{ hidden: !showSidebar }">
        <ProjectTree
          :tree="projectTree"
          :projectRoot="projectRoot"
          :isLoading="isTreeLoading"
          @open-file="handleOpenFile"
          @refresh="refreshProjectTree"
        />
      </aside>

      <section class="main-pane">
        <TabManager
          :tabs="tabs"
          :activeTabId="activeTab?.id || null"
          @new-tab="createEditorTab"
          @close-tab="handleCloseTab"
          @switch-tab="handleSwitchTab"
          @rename-tab="handleRenameTab"
          @reorder-tab="handleReorderTabs"
        />
        <div class="pane-content">
          <EditorPane
            v-if="activeTab?.kind === 'editor'"
            :tab="activeTab"
            @run="runActiveEditor"
          />
          <SplitPaneContainer
            v-else-if="activeTab?.kind === 'terminal' && activeTab.layout"
            :layout="activeTab.layout"
            :activePaneId="activeTab.activePaneId"
            :tabId="activeTab.id"
            @pane-focus="handlePaneFocus"
            @cwd-change="handlePaneCwdChange"
            @title-change="handlePaneTitleChange"
            @output-change="handlePaneOutputChange"
            @command-executed="handleCommandExecuted"
            @resize="handlePaneResize"
          />
          <!-- Fallback for tabs without layout (legacy) -->
          <TerminalWindow
            v-else-if="activeTab?.kind === 'terminal'"
            :ptyId="activeTab.ptyId"
            :tabId="activeTab.id"
            @cwd-change="handleCwdChange"
            @title-change="handleTitleChange"
          />
          <AIChatTab v-else-if="activeTab?.kind === 'ai'" :tab="activeTab" />
          <DeveloperDashboard v-else-if="activeTab?.kind === 'developer'" />
          <div v-else class="empty-state">Select or create a tab to get started.</div>
        </div>
      </section>
    </main>

    <!-- Command Palette -->
    <CommandPalette
      :isVisible="showCommandPalette"
      @close="showCommandPalette = false"
      @new-terminal="createTerminalTab()"
      @new-editor="createEditorTab()"
      @new-ai="createAITab()"
      @close-tab="activeTab && closeTab(activeTab.id)"
      @split-vertical="activeTab?.kind === 'terminal' && splitPane(activeTab.id, 'vertical')"
      @split-horizontal="activeTab?.kind === 'terminal' && splitPane(activeTab.id, 'horizontal')"
      @next-tab="switchToNextTab()"
      @prev-tab="switchToPreviousTab()"
      @toggle-sidebar="showSidebar = !showSidebar"
      @show-shortcuts="showKeyboardShortcuts = true"
      @open-folder="handleOpenFolder()"
      @global-search="showGlobalSearch = true"
    />

    <!-- Keyboard Shortcuts Help -->
    <KeyboardShortcuts
      :isVisible="showKeyboardShortcuts"
      @close="showKeyboardShortcuts = false"
    />

    <!-- Snapshots Panel -->
    <SnapshotsPanel
      :isVisible="showSnapshots"
      @close="showSnapshots = false"
      @save="handleSaveSnapshot"
      @restore="handleRestoreSnapshot"
    />

    <!-- Global Search -->
    <GlobalSearch
      :isVisible="showGlobalSearch"
      :tabs="tabs"
      :paneCwds="paneCwds"
      :paneOutputs="paneOutputs"
      @close="showGlobalSearch = false"
      @jump-to-tab="handleJumpToTab"
      @jump-to-pane="handleJumpToPane"
    />

    <!-- Status Bar -->
    <StatusBar
      :currentDirectory="currentCwd"
      :gitBranch="currentGitBranch"
      :gitDirty="isGitDirty"
      :aiEnabled="aiEnabled"
      :modelName="currentModelName"
      :isRecording="isRecording"
      :isPaused="isPaused"
    />

    <!-- Toast Notifications -->
    <ToastContainer />

    <!-- Analytics Dashboard -->
    <AnalyticsDashboard
      :isVisible="showAnalytics"
      @close="showAnalytics = false"
    />

    <!-- Session Recovery Modal -->
    <SessionRecovery
      :isVisible="showSessionRecovery"
      @recover="handleSessionRecover"
      @dismiss="handleSessionDismiss"
    />

    <!-- Claude Code Features -->

    <!-- Todo Panel (side panel) -->
    <Teleport to="body">
      <div v-if="showTodoPanel" class="claude-panel todo-panel-container">
        <div class="panel-header">
          <span>Task Progress</span>
          <button @click="showTodoPanel = false">×</button>
        </div>
        <TodoPanel :todos="todos" />
      </div>
    </Teleport>

    <!-- Agent Status Bar (bottom of screen, replaces regular status bar when agent is running) -->
    <AgentStatusBar
      v-if="agentStatus.isRunning"
      :currentTask="agentStatus.currentTask"
      :progress="agentStatus.progress"
      :isRunning="agentStatus.isRunning"
      :tokensUsed="agentStatus.tokensUsed"
      :model="agentStatus.model"
      :connectionStatus="agentStatus.connectionStatus"
    />

    <!-- Tool Approval Dialog -->
    <ToolApprovalDialog
      v-if="pendingToolApproval"
      :visible="pendingToolApproval.visible"
      :toolName="pendingToolApproval.toolName"
      :description="pendingToolApproval.description"
      :params="pendingToolApproval.params"
      :preview="pendingToolApproval.preview"
      :warnings="pendingToolApproval.warnings"
      :riskLevel="pendingToolApproval.riskLevel"
      @decide="handleToolApprovalDecision"
    />

    <!-- Ask User Question Dialog -->
    <AskUserQuestion
      v-if="pendingQuestion"
      :questions="pendingQuestion.questions"
      @submit="handleQuestionAnswer"
    />

    <!-- Test Runner Panel -->
    <Teleport to="body">
      <div v-if="showTestRunner" class="claude-panel test-runner-container">
        <div class="panel-header">
          <span>Test Runner</span>
          <button @click="showTestRunner = false">×</button>
        </div>
        <TestRunnerPanel
          :cwd="currentCwd"
          @openFile="handleTestFileOpen"
        />
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, defineAsyncComponent, Teleport } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

// Core components - always loaded
import TabManager from './components/TabManager.vue'
import SplitPaneContainer from './components/SplitPaneContainer.vue'
import ProjectTree from './components/ProjectTree.vue'
import ToastContainer from './components/ToastContainer.vue'

// Lazy-loaded components - loaded on demand for better initial bundle size
const TerminalWindow = defineAsyncComponent(() => import('./components/TerminalWindow.vue'))
const EditorPane = defineAsyncComponent(() => import('./components/EditorPane.vue'))
const AIChatTab = defineAsyncComponent(() => import('./components/AIChatTab.vue'))
const DeveloperDashboard = defineAsyncComponent(() => import('./components/DeveloperDashboard.vue'))
const CommandPalette = defineAsyncComponent(() => import('./components/CommandPalette.vue'))
const KeyboardShortcuts = defineAsyncComponent(() => import('./components/KeyboardShortcuts.vue'))
const SnapshotsPanel = defineAsyncComponent(() => import('./components/SnapshotsPanel.vue'))
const GlobalSearch = defineAsyncComponent(() => import('./components/GlobalSearch.vue'))
const AnalyticsDashboard = defineAsyncComponent(() => import('./components/AnalyticsDashboard.vue'))
const SessionRecovery = defineAsyncComponent(() => import('./components/SessionRecovery.vue'))
const StatusBar = defineAsyncComponent(() => import('./components/StatusBar.vue'))

// Claude Code Feature Components
const TodoPanel = defineAsyncComponent(() => import('./components/TodoPanel.vue'))
const AgentStatusBar = defineAsyncComponent(() => import('./components/AgentStatusBar.vue'))
const AskUserQuestion = defineAsyncComponent(() => import('./components/AskUserQuestion.vue'))
const ToolApprovalDialog = defineAsyncComponent(() => import('./components/ToolApprovalDialog.vue'))
const TestRunnerPanel = defineAsyncComponent(() => import('./components/TestRunnerPanel.vue'))
const InlineAISuggestion = defineAsyncComponent(() => import('./components/InlineAISuggestion.vue'))

import { useTabs } from './composables/useTabs'
import { useProject } from './composables/useProject'
import { enableTestMode } from './composables/useTestMode'
import { useSecuritySettings } from './composables/useSecuritySettings'
import { useSnapshots, type Snapshot } from './composables/useSnapshots'
import { useSessionStore, type PersistedSession } from './composables/useSessionStore'
import { useToast } from './composables/useToast'
import { useAnalytics } from './composables/useAnalytics'
import { useRecording } from './composables/useRecording'

// Claude Code Feature Composables
import { useTodoList } from './composables/useTodoList'
import { useMarkdown } from './composables/useMarkdown'
import { useDirectoryJump } from './composables/useDirectoryJump'
import { useTools } from './composables/useTools'

const {
  tabs,
  activeTab,
  createTerminalTab,
  createAITab,
  createEditorTab,
  createDeveloperTab,
  closeTab,
  setActiveTab,
  renameTab,
  reorderTabs,
  sendMessage,
  addAIMessage,
  addSystemMessage,
  openTabForFile,
  setEditorInitialContent,
  loadSession,
  // Split pane operations
  splitPane,
  setActivePane,
  navigatePane,
  resizeActivePane,
  // OSC handlers
  updatePaneCwd,
  // Split ratio updates
  updateSplitRatio,
  // PTY cleanup
  cleanupAllPtys,
  getPtyCount,
  // Snapshot restore
  restoreFromSnapshot,
} = useTabs()

const {
  projectRoot,
  projectTree,
  projectName,
  isLoadingTree,
  pickProjectFolder,
  refreshProjectTree,
  readFile,
} = useProject()

const isTreeLoading = isLoadingTree

// Security settings
const { settings: securitySettings, toggleAI, isAIEnabled } = useSecuritySettings()
const aiEnabled = computed(() => securitySettings.value.aiEnabled)

// Snapshots
const { createSnapshot, createAutoSnapshot, getSnapshot } = useSnapshots()

// Session recovery
const sessionStore = useSessionStore()

// Toast notifications
const toast = useToast()

// Analytics
const { trackCommand, trackPaneFocus } = useAnalytics()

// Recording
const {
  startRecording,
  stopRecording,
  pauseRecording,
  resumeRecording,
  isRecording,
  isPaused
} = useRecording()

// Claude Code Features
const { todos, addTodo, updateTodo, removeTodo, clearCompleted } = useTodoList()
const { renderMarkdown } = useMarkdown()
const directoryJump = useDirectoryJump()
const tools = useTools()

// Claude Code UI State
const showTodoPanel = ref(false)
const showTestRunner = ref(false)
const pendingToolApproval = ref<{
  visible: boolean
  toolName: string
  description: string
  params: Record<string, unknown>
  preview: string
  warnings: string[]
  riskLevel: 'low' | 'medium' | 'high'
  resolve: (decision: 'allow' | 'deny' | 'allow_always') => void
} | null>(null)
const pendingQuestion = ref<{
  visible: boolean
  questions: Array<{
    question: string
    header: string
    options: Array<{ label: string; description: string }>
    multiSelect: boolean
  }>
  resolve: (answers: Record<string, string | string[]>) => void
} | null>(null)

// Agent status for status bar
const agentStatus = ref({
  currentTask: '',
  progress: 0,
  isRunning: false,
  tokensUsed: 0,
  model: 'qwen2.5-coder:1.5b',
  connectionStatus: 'connected' as 'connected' | 'disconnected' | 'error'
})

// UI State
const showCommandPalette = ref(false)
const showKeyboardShortcuts = ref(false)
const showSidebar = ref(true)
const showSnapshots = ref(false)
const showGlobalSearch = ref(false)
const showAnalytics = ref(false)
const showSessionRecovery = ref(false)

// App version info
const appVersion = ref<{ version: string; build: string } | null>(null)

// Pane CWDs for snapshots
const paneCwds = new Map<string, string>()

// Pane outputs for global search (last 50 lines per pane)
const paneOutputs = new Map<string, string>()

// Status bar state
const currentCwd = computed(() => {
  if (activeTab.value?.activePaneId) {
    return paneCwds.get(activeTab.value.activePaneId) || projectRoot.value || '~'
  }
  return projectRoot.value || '~'
})

const currentGitBranch = ref<string | null>(null)
const isGitDirty = ref(false)
const currentModelName = ref('qwen2.5-coder:1.5b')

async function handleOpenFolder() {
  await pickProjectFolder()
}

async function handleOpenFile(path: string) {
  const tab = openTabForFile(path)
  if (!tab) return
  setActiveTab(tab.id)
  if (!tab.content) {
    const content = await readFile(path)
    setEditorInitialContent(tab.id, content)
  }
}

function handleCloseTab(tabId: string) {
  closeTab(tabId)
}

function handleSwitchTab(tabId: string) {
  setActiveTab(tabId)
}

function handleRenameTab(tabId: string, newName: string) {
  renameTab(tabId, newName)
}

function handleReorderTabs(fromIndex: number, toIndex: number) {
  reorderTabs(fromIndex, toIndex)
}

// Handle terminal cwd changes (OSC 7)
function handleCwdChange(payload: { tabId: string, cwd: string }) {
  const { tabId, cwd } = payload
  // Update tab name to show current directory (last component)
  const dirName = cwd.split('/').filter(Boolean).pop() || cwd
  const tab = tabs.value.find(t => t.id === tabId)
  if (tab && tab.kind === 'terminal') {
    // Format: ~dirname or dirname for non-home paths
    const homeDir = '/Users/' // Simplified; could detect from env
    const displayName = cwd.startsWith(homeDir)
      ? '~' + cwd.substring(homeDir.length).split('/').slice(1).join('/')
      : dirName
    renameTab(tabId, displayName || 'Terminal')
  }
}

// Handle terminal title changes (OSC 0/2)
function handleTitleChange(payload: { tabId: string, title: string }) {
  const { tabId, title } = payload
  if (title) {
    renameTab(tabId, title)
  }
}

// Handle pane focus (for split panes)
function handlePaneFocus(paneId: string) {
  if (activeTab.value?.id) {
    setActivePane(activeTab.value.id, paneId)
    // Track pane focus for analytics
    trackPaneFocus(paneId, activeTab.value.id)
  }
}

// Handle pane cwd change (for split panes)
function handlePaneCwdChange(payload: { paneId: string, cwd: string }) {
  if (!activeTab.value?.id) return

  // Store cwd in pane state
  updatePaneCwd(activeTab.value.id, payload.paneId, payload.cwd)

  // Track for snapshots
  paneCwds.set(payload.paneId, payload.cwd)

  // Only update tab title if this is the active pane
  if (activeTab.value.activePaneId === payload.paneId) {
    const cwd = payload.cwd
    const homeDir = '/Users/'
    const displayName = cwd.startsWith(homeDir)
      ? '~' + cwd.substring(homeDir.length).split('/').slice(1).join('/')
      : cwd.split('/').filter(Boolean).pop() || cwd
    renameTab(activeTab.value.id, displayName || 'Terminal')
  }
}

// Snapshot handlers
function handleSaveSnapshot(name: string) {
  createSnapshot(name, tabs.value, activeTab.value?.id || null, paneCwds)
  console.log('[App] Saved snapshot:', name)
  toast.success(`Saved snapshot "${name}"`)
}

async function handleRestoreSnapshot(snapshot: Snapshot) {
  console.log('[App] Restoring snapshot:', snapshot.name)
  const success = await restoreFromSnapshot(snapshot)
  if (success) {
    console.log('[App] Snapshot restored successfully')
    toast.success(`Restored snapshot "${snapshot.name}"`)
  } else {
    console.error('[App] Failed to restore snapshot')
    toast.error('Failed to restore snapshot', {
      title: 'Snapshot Error',
      duration: 6000
    })
  }
}

// Handle pane title change (for split panes)
function handlePaneTitleChange(payload: { paneId: string, title: string }) {
  // Only update tab title if this is the active pane
  if (activeTab.value?.activePaneId === payload.paneId && payload.title) {
    if (activeTab.value?.id) {
      renameTab(activeTab.value.id, payload.title)
    }
  }
}

// Handle pane resize (drag divider)
function handlePaneResize(payload: { tabId: string, nodeId: string, ratio: number }) {
  updateSplitRatio(payload.tabId, payload.nodeId, payload.ratio)
}

// Handle pane output change (for global search)
function handlePaneOutputChange(payload: { paneId: string, output: string }) {
  paneOutputs.set(payload.paneId, payload.output)
}

// Handle command execution (for analytics)
function handleCommandExecuted(payload: { paneId: string, tabId: string, command: string }) {
  trackCommand(payload.command, payload.paneId, payload.tabId)
}

// Global search handlers
function handleJumpToTab(tabId: string) {
  setActiveTab(tabId)
}

function handleJumpToPane(payload: { tabId: string, paneId: string }) {
  setActiveTab(payload.tabId)
  // Small delay to ensure tab is active before setting pane
  setTimeout(() => {
    setActivePane(payload.tabId, payload.paneId)
  }, 50)
}

// Session recovery handlers
async function handleSessionRecover(session: PersistedSession) {
  console.log('[App] Recovering session from:', new Date(session.timestamp).toLocaleString())
  showSessionRecovery.value = false

  // TODO: Implement actual session restoration from persisted state
  // For now, just clear the session after acknowledging recovery
  // Full implementation would create tabs and restore CWDs
  toast.success(`Session recovery initiated - ${session.tabs.length} tabs`)
  sessionStore.clearSession()
}

function handleSessionDismiss() {
  showSessionRecovery.value = false
  console.log('[App] User dismissed session recovery')
}

// Update session store when tabs change
function updateSessionState() {
  sessionStore.updateSession(tabs.value, activeTab.value?.id || null, paneCwds)
}

// Recording handlers
function handleToggleRecording() {
  if (!activeTab.value?.activePaneId) {
    toast.warning('Select a terminal pane to record')
    return
  }

  const paneId = activeTab.value.activePaneId
  if (isRecording.value) {
    stopRecording(paneId)
    toast.success('Recording stopped')
  } else {
    startRecording(paneId)
    toast.info('Recording started')
  }
}

function handlePauseResumeRecording() {
  if (!activeTab.value?.activePaneId) {
    toast.warning('Select a terminal pane')
    return
  }

  const paneId = activeTab.value.activePaneId
  if (!isRecording.value) {
    toast.warning('No active recording')
    return
  }

  if (isPaused.value) {
    resumeRecording(paneId)
    toast.info('Recording resumed')
  } else {
    pauseRecording(paneId)
    toast.info('Recording paused')
  }
}

async function runActiveEditor() {
  const editorTab = activeTab.value
  if (!editorTab || editorTab.kind !== 'editor') {
    return
  }

  const input = editorTab.content ?? ''
  if (!input.trim()) {
    console.warn('[App] No editor content to run')
    return
  }

  let runTerminalTab = editorTab.runTerminalTabId
    ? tabs.value.find(t => t.id === editorTab.runTerminalTabId && t.kind === 'terminal') || null
    : null

  if (!runTerminalTab) {
    const created = await createTerminalTab(`Run: ${editorTab.name}`)
    if (!created) {
      console.error('[App] Failed to create terminal tab for run output')
      return
    }
    editorTab.runTerminalTabId = created.id
    runTerminalTab = created
  }

  if (!runTerminalTab.ptyId) {
    console.error('[App] Terminal tab missing PTY id')
    return
  }

  try {
    await invoke('send_input', { id: runTerminalTab.ptyId, input: `${input}\n` })
    setActiveTab(runTerminalTab.id)
  } catch (error) {
    console.error('[App] Failed to send editor content to PTY', error)
  }
}

// Claude Code Feature Handlers
function handleToolApprovalDecision(decision: 'allow' | 'deny' | 'allow_always', remember: boolean) {
  if (pendingToolApproval.value?.resolve) {
    pendingToolApproval.value.resolve(decision)
    if (remember && decision !== 'deny') {
      // Store remembered approvals in localStorage
      const remembered = JSON.parse(localStorage.getItem('warp_tool_approvals') || '{}')
      remembered[pendingToolApproval.value.toolName] = decision
      localStorage.setItem('warp_tool_approvals', JSON.stringify(remembered))
    }
  }
  pendingToolApproval.value = null
}

function handleQuestionAnswer(answers: Record<string, string | string[]>) {
  if (pendingQuestion.value?.resolve) {
    pendingQuestion.value.resolve(answers)
  }
  pendingQuestion.value = null
}

function handleTestFileOpen(file: string, line?: number) {
  // Open the file in an editor tab at the specified line
  handleOpenFile(file).then(() => {
    // If line is specified, we could scroll to it in Monaco
    if (line && activeTab.value?.kind === 'editor') {
      console.log(`[App] Opening ${file} at line ${line}`)
    }
  })
}

// Keyboard shortcut handler
function handleKeyDown(event: KeyboardEvent) {
  const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0
  const cmdOrCtrl = isMac ? event.metaKey : event.ctrlKey

  // Command Palette always responds, even in inputs
  // Cmd/Ctrl + Shift + P: Toggle Command Palette
  if (cmdOrCtrl && event.shiftKey && event.key === 'p') {
    event.preventDefault()
    showCommandPalette.value = !showCommandPalette.value
    return
  }

  // Cmd/Ctrl + Shift + F: Toggle Global Search
  if (cmdOrCtrl && event.shiftKey && event.key === 'f') {
    event.preventDefault()
    showGlobalSearch.value = !showGlobalSearch.value
    return
  }

  // Cmd/Ctrl + Shift + A: Toggle Analytics Dashboard
  if (cmdOrCtrl && event.shiftKey && event.key === 'a') {
    event.preventDefault()
    showAnalytics.value = !showAnalytics.value
    return
  }

  // Cmd/Ctrl + Shift + R: Toggle Recording (Start/Stop)
  if (cmdOrCtrl && event.shiftKey && event.key === 'r') {
    event.preventDefault()
    handleToggleRecording()
    return
  }

  // Cmd/Ctrl + Shift + U: Pause/Resume Recording
  if (cmdOrCtrl && event.shiftKey && event.key === 'u') {
    event.preventDefault()
    handlePauseResumeRecording()
    return
  }

  // Cmd/Ctrl + Shift + T: Toggle Todo Panel
  if (cmdOrCtrl && event.shiftKey && event.key === 't') {
    event.preventDefault()
    showTodoPanel.value = !showTodoPanel.value
    return
  }

  // Cmd/Ctrl + Shift + Y: Toggle Test Runner
  if (cmdOrCtrl && event.shiftKey && event.key === 'y') {
    event.preventDefault()
    showTestRunner.value = !showTestRunner.value
    return
  }

  // Escape: Close modals
  if (event.key === 'Escape') {
    if (pendingToolApproval.value) {
      handleToolApprovalDecision('deny', false)
      return
    }
    if (pendingQuestion.value) {
      // Can't dismiss questions without answering - they're required
      return
    }
    if (showTodoPanel.value) {
      showTodoPanel.value = false
      return
    }
    if (showTestRunner.value) {
      showTestRunner.value = false
      return
    }
    if (showAnalytics.value) {
      showAnalytics.value = false
      return
    }
    if (showGlobalSearch.value) {
      showGlobalSearch.value = false
      return
    }
    if (showCommandPalette.value) {
      showCommandPalette.value = false
      return
    }
    if (showKeyboardShortcuts.value) {
      showKeyboardShortcuts.value = false
      return
    }
  }

  // Ignore other shortcuts when typing in input fields
  const target = event.target as HTMLElement
  if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
    return
  }

  // Cmd/Ctrl + /: Show keyboard shortcuts
  if (cmdOrCtrl && event.key === '/') {
    event.preventDefault()
    showKeyboardShortcuts.value = !showKeyboardShortcuts.value
    return
  }

  // Cmd/Ctrl + B: Toggle sidebar
  if (cmdOrCtrl && event.key === 'b') {
    event.preventDefault()
    showSidebar.value = !showSidebar.value
    return
  }

  // Cmd/Ctrl + ,: Open preferences (placeholder)
  if (cmdOrCtrl && event.key === ',') {
    event.preventDefault()
    console.log('[App] Open preferences')
    return
  }

  // Cmd/Ctrl + O: Open folder
  if (cmdOrCtrl && event.key === 'o') {
    event.preventDefault()
    handleOpenFolder()
    return
  }

  // Cmd/Ctrl + T: New terminal tab
  if (cmdOrCtrl && event.key === 't') {
    event.preventDefault()
    createTerminalTab()
    return
  }

  // Cmd/Ctrl + W: Close current tab
  if (cmdOrCtrl && event.key === 'w') {
    event.preventDefault()
    if (activeTab.value) {
      closeTab(activeTab.value.id)
    }
    return
  }

  // Cmd/Ctrl + Shift + [ : Previous tab
  if (cmdOrCtrl && event.shiftKey && event.key === '[') {
    event.preventDefault()
    switchToPreviousTab()
    return
  }

  // Cmd/Ctrl + Shift + ] : Next tab
  if (cmdOrCtrl && event.shiftKey && event.key === ']') {
    event.preventDefault()
    switchToNextTab()
    return
  }

  // Cmd/Ctrl + 1-9: Jump to tab by index
  if (cmdOrCtrl && event.key >= '1' && event.key <= '9') {
    event.preventDefault()
    const index = parseInt(event.key, 10) - 1
    if (index < tabs.value.length) {
      setActiveTab(tabs.value[index].id)
    }
    return
  }

  // Cmd/Ctrl + Shift + D: Vertical split
  if (cmdOrCtrl && event.shiftKey && event.key === 'd') {
    event.preventDefault()
    if (activeTab.value?.kind === 'terminal' && activeTab.value.id) {
      splitPane(activeTab.value.id, 'vertical')
    }
    return
  }

  // Cmd/Ctrl + Shift + E: Horizontal split
  if (cmdOrCtrl && event.shiftKey && event.key === 'e') {
    event.preventDefault()
    if (activeTab.value?.kind === 'terminal' && activeTab.value.id) {
      splitPane(activeTab.value.id, 'horizontal')
    }
    return
  }

  // Alt/Option + Arrow keys: Navigate between panes
  if (event.altKey && !cmdOrCtrl && ['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) {
    event.preventDefault()
    if (activeTab.value?.kind === 'terminal' && activeTab.value.id) {
      const direction = event.key.replace('Arrow', '').toLowerCase() as 'up' | 'down' | 'left' | 'right'
      navigatePane(activeTab.value.id, direction)
    }
    return
  }

  // Cmd/Ctrl + Option + Arrow keys: Resize active pane
  if (cmdOrCtrl && event.altKey && ['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) {
    event.preventDefault()
    if (activeTab.value?.kind === 'terminal' && activeTab.value.id) {
      const direction = event.key.replace('Arrow', '').toLowerCase() as 'up' | 'down' | 'left' | 'right'
      resizeActivePane(activeTab.value.id, direction)
    }
    return
  }
}

function switchToPreviousTab() {
  if (tabs.value.length <= 1) return
  const currentIndex = tabs.value.findIndex(t => t.id === activeTab.value?.id)
  const prevIndex = currentIndex <= 0 ? tabs.value.length - 1 : currentIndex - 1
  setActiveTab(tabs.value[prevIndex].id)
}

function switchToNextTab() {
  if (tabs.value.length <= 1) return
  const currentIndex = tabs.value.findIndex(t => t.id === activeTab.value?.id)
  const nextIndex = currentIndex >= tabs.value.length - 1 ? 0 : currentIndex + 1
  setActiveTab(tabs.value[nextIndex].id)
}

onMounted(async () => {
  enableTestMode()
  await refreshProjectTree()


  // Load app version
  try {
    appVersion.value = await invoke('get_app_version')
    console.log('[App] Version:', appVersion.value)
  } catch (e) {
    console.warn('[App] Failed to get version:', e)
  }

  // Register keyboard shortcuts
  window.addEventListener('keydown', handleKeyDown)

  // Register cleanup handler for app shutdown
  window.addEventListener('beforeunload', handleBeforeUnload)

  // Check for recoverable session before loading fresh session
  const autoRecover = localStorage.getItem('warp_auto_recover') === 'true'
  if (sessionStore.hasRecoverableSession()) {
    if (autoRecover) {
      // Auto-recover silently
      console.log('[App] Auto-recovering session...')
      const session = sessionStore.getPersistedSession()
      if (session) {
        toast.info(`Auto-recovered ${session.tabs.length} tabs from previous session`)
        sessionStore.clearSession()
      }
    } else {
      // Show recovery dialog
      showSessionRecovery.value = true
    }
  }

  // Start session auto-save (every 30 seconds)
  sessionStore.startAutoSave()

  // Restore session (tabs, active tab) from disk
  console.log('[App] Loading saved session...')
  await loadSession()
  console.log('[App] Session loaded, tabs:', tabs.value.length)

  // Initial session state update
  updateSessionState()

  const { listen } = await import('@tauri-apps/api/event')
  interface ToolExecutedPayload {
    tabId: string
    toolCall: string
    result: { Ok?: string; Err?: string } | string
  }
  await listen<ToolExecutedPayload>('tool_executed', (event) => {
    const { tabId, toolCall, result } = event.payload
    const tab = tabs.value.find(t => t.id === tabId && t.kind === 'ai')
    if (tab) {
      try {
        const toolJson = JSON.parse(toolCall)
        addAIMessage(tabId, `${toolJson.tool}\n${JSON.stringify(toolJson.args, null, 2)}`)
        const resultStr = typeof result === 'string' ? result : (result.Ok || result.Err || JSON.stringify(result))
        addSystemMessage(tabId, `${toolJson.tool}\n${resultStr}`)
      } catch (error) {
        console.error('[App] Error parsing tool call:', error)
      }
    }
  })

  await listen<string>('test_send_message', (event) => {
    if (activeTab.value?.kind === 'ai') {
      sendMessage(activeTab.value.id, event.payload)
    }
  })
})

// Handle app shutdown - cleanup PTYs, auto-snapshot, and save session
async function handleBeforeUnload() {
  console.log('[App] beforeunload triggered...')

  // Save session state for crash recovery
  try {
    updateSessionState()
    sessionStore.forceSave()
    console.log('[App] Session state saved')
  } catch (e) {
    console.error('[App] Failed to save session state:', e)
  }

  // Create auto-snapshot on exit (if enabled and tabs exist)
  if (tabs.value.length > 0) {
    try {
      const snapshot = createAutoSnapshot(tabs.value, activeTab.value?.id || null, paneCwds)
      if (snapshot) {
        console.log('[App] Created auto-snapshot:', snapshot.name)
      }
    } catch (e) {
      console.error('[App] Failed to create auto-snapshot:', e)
    }
  }

  // Cleanup PTYs
  console.log('[App] Active PTY count:', getPtyCount())
  await cleanupAllPtys()
}

onUnmounted(() => {
  window.removeEventListener('keydown', handleKeyDown)
  window.removeEventListener('beforeunload', handleBeforeUnload)
  sessionStore.stopAutoSave()
})
</script>

<style scoped>
/* ==========================================================================
   WARP-INSPIRED APP SHELL
   ========================================================================== */

.app-shell {
  width: 100vw;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background-color: var(--warp-bg-base);
  color: var(--warp-text-primary);
  font-family: var(--warp-font-ui);
}

/* ==========================================================================
   TOPBAR - Minimal Warp-style Header
   ========================================================================== */

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 38px;
  padding: 0 var(--warp-space-3);
  background: var(--warp-bg-base);
  border-bottom: 1px solid var(--warp-border-subtle);
  -webkit-app-region: drag; /* Draggable title bar on macOS */
}

.project-meta {
  display: flex;
  align-items: center;
  gap: var(--warp-space-3);
  -webkit-app-region: no-drag;
}

.project-meta strong {
  font-size: var(--warp-text-sm);
  font-weight: var(--warp-weight-medium);
  color: var(--warp-text-primary);
}

.project-meta small {
  font-size: var(--warp-text-xs);
  color: var(--warp-text-tertiary);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sidebar-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  background: transparent;
  border: none;
  color: var(--warp-text-tertiary);
  cursor: pointer;
  border-radius: var(--warp-radius-md);
  transition: all var(--warp-transition-normal);
}

.sidebar-toggle:hover {
  background: var(--warp-bg-hover);
  color: var(--warp-text-primary);
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: var(--warp-space-1);
  -webkit-app-region: no-drag;
}

.topbar-actions button {
  display: inline-flex;
  align-items: center;
  gap: var(--warp-space-1);
  padding: var(--warp-space-1) var(--warp-space-2);
  font-family: var(--warp-font-ui);
  font-size: var(--warp-text-xs);
  font-weight: var(--warp-weight-medium);
  color: var(--warp-text-secondary);
  background: transparent;
  border: none;
  border-radius: var(--warp-radius-md);
  cursor: pointer;
  transition: all var(--warp-transition-normal);
}

.topbar-actions button:hover {
  background: var(--warp-bg-hover);
  color: var(--warp-text-primary);
}

/* Command Palette Button */
.cmd-palette-btn {
  font-family: var(--warp-font-mono) !important;
  font-size: var(--warp-text-xs) !important;
  padding: var(--warp-space-1) var(--warp-space-2) !important;
  background: var(--warp-bg-elevated) !important;
  border: 1px solid var(--warp-border) !important;
  color: var(--warp-text-tertiary) !important;
}

.cmd-palette-btn:hover {
  border-color: var(--warp-accent-primary) !important;
  color: var(--warp-text-secondary) !important;
}

/* Snapshots Button */
.snapshots-btn {
  font-size: var(--warp-text-base) !important;
  padding: var(--warp-space-1) !important;
}

/* ==========================================================================
   WORKSPACE LAYOUT
   ========================================================================== */

.workspace {
  flex: 1;
  display: flex;
  min-height: 0;
  background: var(--warp-bg-base);
}

/* ==========================================================================
   SIDEBAR - File Tree Panel
   ========================================================================== */

.sidebar {
  width: 260px;
  background: var(--warp-bg-surface);
  border-right: 1px solid var(--warp-border-subtle);
  overflow: hidden;
  transition: width var(--warp-transition-slow),
              opacity var(--warp-transition-slow),
              transform var(--warp-transition-slow);
}

.sidebar.hidden {
  width: 0;
  opacity: 0;
  transform: translateX(-10px);
  border-right: none;
}

/* ==========================================================================
   MAIN PANE - Terminal/Editor Content Area
   ========================================================================== */

.main-pane {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
  background: var(--warp-bg-base);
}

.pane-content {
  flex: 1;
  min-height: 0;
  position: relative;
}

/* ==========================================================================
   EMPTY STATE
   ========================================================================== */

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--warp-text-tertiary);
  font-size: var(--warp-text-sm);
  gap: var(--warp-space-4);
}

.empty-state::before {
  content: '';
  display: block;
  width: 48px;
  height: 48px;
  background: var(--warp-accent-gradient);
  mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'%3E%3Cpath d='M4 17l6-6-6-6M12 19h8'/%3E%3C/svg%3E") center/contain no-repeat;
  -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'%3E%3Cpath d='M4 17l6-6-6-6M12 19h8'/%3E%3C/svg%3E") center/contain no-repeat;
  opacity: 0.5;
}

/* ==========================================================================
   VERSION BADGE
   ========================================================================== */

.version-badge {
  font-size: var(--warp-text-xs);
  font-family: var(--warp-font-mono);
  color: var(--warp-text-tertiary);
  background: var(--warp-bg-elevated);
  padding: 2px var(--warp-space-2);
  border-radius: var(--warp-radius-full);
  border: 1px solid var(--warp-border-subtle);
}

/* ==========================================================================
   AI STATUS BUTTON
   ========================================================================== */

.ai-status-btn {
  display: inline-flex !important;
  align-items: center !important;
  gap: var(--warp-space-1) !important;
  font-size: var(--warp-text-xs) !important;
  padding: var(--warp-space-1) var(--warp-space-2) !important;
  border-radius: var(--warp-radius-full) !important;
  transition: all var(--warp-transition-normal) !important;
  font-weight: var(--warp-weight-medium) !important;
}

.ai-status-btn.enabled {
  background: var(--warp-success-bg) !important;
  border: 1px solid var(--warp-success) !important;
  color: var(--warp-success) !important;
}

.ai-status-btn.enabled:hover {
  background: rgba(34, 197, 94, 0.25) !important;
  box-shadow: 0 0 12px rgba(34, 197, 94, 0.3);
}

.ai-status-btn.disabled {
  background: var(--warp-warning-bg) !important;
  border: 1px solid var(--warp-warning) !important;
  color: var(--warp-warning) !important;
}

.ai-status-btn.disabled:hover {
  background: rgba(245, 158, 11, 0.25) !important;
  box-shadow: 0 0 12px rgba(245, 158, 11, 0.3);
}

/* ==========================================================================
   FOCUS VISIBLE OVERRIDES
   ========================================================================== */

button:focus-visible {
  outline: 2px solid var(--warp-accent-primary);
  outline-offset: 2px;
}

/* ==========================================================================
   SMOOTH TRANSITIONS FOR STATE CHANGES
   ========================================================================== */

* {
  transition-property: background-color, border-color, color, opacity;
  transition-duration: var(--warp-transition-fast);
  transition-timing-function: ease;
}

/* Reset transition for elements that should have specific transitions */
.sidebar,
.topbar-actions button,
.ai-status-btn {
  transition: all var(--warp-transition-normal);
}

/* ==========================================================================
   CLAUDE CODE FEATURE PANELS
   ========================================================================== */

.claude-panel {
  position: fixed;
  background: var(--warp-bg-surface);
  border: 1px solid var(--warp-border);
  border-radius: var(--warp-radius-lg);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  z-index: 100;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.claude-panel .panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--warp-space-2) var(--warp-space-3);
  background: var(--warp-bg-elevated);
  border-bottom: 1px solid var(--warp-border-subtle);
  font-weight: var(--warp-weight-medium);
  font-size: var(--warp-text-sm);
}

.claude-panel .panel-header button {
  background: transparent;
  border: none;
  color: var(--warp-text-tertiary);
  font-size: 18px;
  cursor: pointer;
  padding: 2px 6px;
  border-radius: var(--warp-radius-sm);
}

.claude-panel .panel-header button:hover {
  background: var(--warp-bg-hover);
  color: var(--warp-text-primary);
}

/* Todo Panel - positioned on right side */
.todo-panel-container {
  right: var(--warp-space-4);
  top: 60px;
  width: 320px;
  max-height: calc(100vh - 120px);
}

/* Test Runner Panel - positioned bottom right */
.test-runner-container {
  right: var(--warp-space-4);
  bottom: 60px;
  width: 400px;
  max-height: 50vh;
}
</style>
