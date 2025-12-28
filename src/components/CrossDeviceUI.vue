<script setup lang="ts">
/**
 * Cross-Device UI
 * Apple Human Interface Guidelines compliant
 * Works on iPhone, iPad, Mac, Apple TV
 */

import { ref, computed, onMounted, onUnmounted, watch } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

interface Status {
  isRunning: boolean;
  isPaused: boolean;
  currentTask?: { title: string; description: string };
  cycleProgress: number;
  completedCycles: number;
  failedCycles: number;
}

interface Approval {
  id: string;
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  createdAt: string;
  options: Array<{ id: string; label: string; isDangerous?: boolean }>;
}

interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

// ============================================================================
// STATE
// ============================================================================

const deviceType = ref<'phone' | 'tablet' | 'desktop' | 'tv'>('desktop');
const isConnected = ref(false);
const status = ref<Status>({
  isRunning: false,
  isPaused: true,
  cycleProgress: 0,
  completedCycles: 0,
  failedCycles: 0
});
const approvals = ref<Approval[]>([]);
const messages = ref<Message[]>([]);
const inputText = ref('');
const isLoading = ref(false);
const activeTab = ref<'chat' | 'status' | 'approvals'>('chat');

// WebSocket
let ws: WebSocket | null = null;
const serverUrl = ref(localStorage.getItem('warp_server_url') || 'ws://localhost:3847');
const authToken = ref(localStorage.getItem('warp_auth_token') || '');

// ============================================================================
// DEVICE DETECTION
// ============================================================================

function detectDevice(): void {
  const width = window.innerWidth;
  const ua = navigator.userAgent.toLowerCase();

  if (ua.includes('apple tv') || width > 1920) {
    deviceType.value = 'tv';
  } else if (width >= 1024) {
    deviceType.value = 'desktop';
  } else if (width >= 768) {
    deviceType.value = 'tablet';
  } else {
    deviceType.value = 'phone';
  }
}

// ============================================================================
// WEBSOCKET
// ============================================================================

function connect(): void {
  if (ws?.readyState === WebSocket.OPEN) return;

  ws = new WebSocket(`${serverUrl.value}?device=${deviceType.value}`);

  ws.onopen = () => {
    isConnected.value = true;
    console.log('[UI] Connected to server');
  };

  ws.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      handleServerMessage(message);
    } catch (e) {
      console.error('[UI] Parse error:', e);
    }
  };

  ws.onclose = () => {
    isConnected.value = false;
    // Reconnect after 3 seconds
    setTimeout(connect, 3000);
  };

  ws.onerror = (e) => {
    console.error('[UI] WebSocket error:', e);
  };
}

function send(type: string, payload: unknown): void {
  if (ws?.readyState !== WebSocket.OPEN) return;

  ws.send(JSON.stringify({
    id: Date.now().toString(36),
    type,
    payload,
    deviceId: localStorage.getItem('warp_device_id') || crypto.randomUUID(),
    deviceType: deviceType.value,
    timestamp: Date.now()
  }));
}

function handleServerMessage(message: { type: string; [key: string]: unknown }): void {
  switch (message.type) {
    case 'connected':
      localStorage.setItem('warp_device_id', message.sessionId as string);
      break;

    case 'status_response':
      Object.assign(status.value, message);
      break;

    case 'query_response':
      isLoading.value = false;
      messages.value.push({
        id: crypto.randomUUID(),
        type: 'assistant',
        content: message.response as string,
        timestamp: new Date()
      });
      break;

    case 'approval_required':
      approvals.value.unshift(message.approval as Approval);
      // Haptic feedback on iOS
      if ('vibrate' in navigator) {
        navigator.vibrate([100, 50, 100]);
      }
      break;

    case 'approval_resolved':
      approvals.value = approvals.value.filter(a => a.id !== message.approvalId);
      break;

    case 'cycle_started':
    case 'cycle_completed':
    case 'cycle_failed':
      status.value.cycleProgress = 0;
      send('status', {});
      break;

    case 'loop_paused':
      status.value.isPaused = true;
      status.value.isRunning = false;
      break;

    case 'loop_resumed':
      status.value.isPaused = false;
      status.value.isRunning = true;
      break;
  }
}

// ============================================================================
// ACTIONS
// ============================================================================

function sendMessage(): void {
  if (!inputText.value.trim()) return;

  const text = inputText.value.trim();
  inputText.value = '';

  messages.value.push({
    id: crypto.randomUUID(),
    type: 'user',
    content: text,
    timestamp: new Date()
  });

  isLoading.value = true;
  send('query', text);
}

function toggleLoop(): void {
  if (status.value.isRunning && !status.value.isPaused) {
    send('pause', {});
  } else {
    send('resume', {});
  }
}

function approveAction(approvalId: string, response: string): void {
  send('approve', { approvalId, response });
}

// ============================================================================
// LIFECYCLE
// ============================================================================

onMounted(() => {
  detectDevice();
  window.addEventListener('resize', detectDevice);
  connect();

  // Request status immediately
  setTimeout(() => send('status', {}), 500);
});

onUnmounted(() => {
  window.removeEventListener('resize', detectDevice);
  ws?.close();
});

// ============================================================================
// COMPUTED
// ============================================================================

const statusColor = computed(() => {
  if (status.value.isPaused) return '#FF9500';  // Orange
  if (status.value.isRunning) return '#34C759';  // Green
  return '#8E8E93';  // Gray
});

const pendingCount = computed(() => approvals.value.length);

const hasHighPriority = computed(() =>
  approvals.value.some(a => a.priority === 'high' || a.priority === 'critical')
);
</script>

<template>
  <!-- Apple HIG Compliant Layout -->
  <div
    class="warp-ui"
    :class="[
      `device-${deviceType}`,
      { 'dark-mode': true }
    ]"
  >
    <!-- Navigation Bar (iOS style) -->
    <header class="nav-bar">
      <div class="nav-title">
        <span class="status-indicator" :style="{ backgroundColor: statusColor }"></span>
        <h1>Warp</h1>
      </div>
      <div class="nav-actions">
        <button
          v-if="pendingCount > 0"
          class="nav-button badge"
          :class="{ urgent: hasHighPriority }"
          @click="activeTab = 'approvals'"
        >
          {{ pendingCount }}
        </button>
        <button
          class="nav-button"
          :class="{ active: status.isRunning && !status.isPaused }"
          @click="toggleLoop"
        >
          <span class="sf-symbol">{{ status.isPaused ? '▶' : '⏸' }}</span>
        </button>
      </div>
    </header>

    <!-- Connection Status -->
    <div v-if="!isConnected" class="connection-banner">
      <span class="sf-symbol">⚠️</span>
      Connecting to Warp...
    </div>

    <!-- Tab Bar (Bottom on phone, side on tablet/desktop) -->
    <nav class="tab-bar" v-if="deviceType !== 'tv'">
      <button
        class="tab-item"
        :class="{ active: activeTab === 'chat' }"
        @click="activeTab = 'chat'"
      >
        <span class="tab-icon">💬</span>
        <span class="tab-label">Chat</span>
      </button>
      <button
        class="tab-item"
        :class="{ active: activeTab === 'status' }"
        @click="activeTab = 'status'"
      >
        <span class="tab-icon">📊</span>
        <span class="tab-label">Status</span>
      </button>
      <button
        class="tab-item"
        :class="{ active: activeTab === 'approvals' }"
        @click="activeTab = 'approvals'"
      >
        <span class="tab-icon">✅</span>
        <span class="tab-label">Approvals</span>
        <span v-if="pendingCount > 0" class="tab-badge">{{ pendingCount }}</span>
      </button>
    </nav>

    <!-- Main Content -->
    <main class="content">
      <!-- Chat View -->
      <section v-if="activeTab === 'chat'" class="chat-view">
        <div class="messages">
          <div
            v-for="msg in messages"
            :key="msg.id"
            class="message"
            :class="msg.type"
          >
            <div class="message-bubble">
              {{ msg.content }}
            </div>
            <div class="message-time">
              {{ msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }}
            </div>
          </div>

          <div v-if="isLoading" class="message assistant">
            <div class="message-bubble typing">
              <span class="dot"></span>
              <span class="dot"></span>
              <span class="dot"></span>
            </div>
          </div>
        </div>

        <div class="input-area">
          <input
            v-model="inputText"
            type="text"
            placeholder="Ask anything..."
            class="chat-input"
            @keyup.enter="sendMessage"
          />
          <button class="send-button" @click="sendMessage" :disabled="!inputText.trim()">
            <span class="sf-symbol">↑</span>
          </button>
        </div>
      </section>

      <!-- Status View -->
      <section v-if="activeTab === 'status'" class="status-view">
        <div class="status-card main-status">
          <div class="status-header">
            <h2>AI Status</h2>
            <span class="status-badge" :style="{ backgroundColor: statusColor }">
              {{ status.isPaused ? 'Paused' : status.isRunning ? 'Running' : 'Idle' }}
            </span>
          </div>

          <div v-if="status.currentTask" class="current-task">
            <h3>Current Task</h3>
            <p class="task-title">{{ status.currentTask.title }}</p>
            <p class="task-description">{{ status.currentTask.description }}</p>
            <div class="progress-bar">
              <div class="progress-fill" :style="{ width: `${status.cycleProgress}%` }"></div>
            </div>
          </div>

          <div class="stats-grid">
            <div class="stat-item">
              <span class="stat-value">{{ status.completedCycles }}</span>
              <span class="stat-label">Completed</span>
            </div>
            <div class="stat-item">
              <span class="stat-value">{{ status.failedCycles }}</span>
              <span class="stat-label">Failed</span>
            </div>
            <div class="stat-item">
              <span class="stat-value">{{ Math.round(status.cycleProgress) }}%</span>
              <span class="stat-label">Progress</span>
            </div>
          </div>
        </div>

        <button class="action-button primary" @click="toggleLoop">
          {{ status.isPaused ? 'Resume AI' : 'Pause AI' }}
        </button>
      </section>

      <!-- Approvals View -->
      <section v-if="activeTab === 'approvals'" class="approvals-view">
        <div v-if="approvals.length === 0" class="empty-state">
          <span class="empty-icon">✓</span>
          <h3>All Clear</h3>
          <p>No pending approvals</p>
        </div>

        <div
          v-for="approval in approvals"
          :key="approval.id"
          class="approval-card"
          :class="approval.priority"
        >
          <div class="approval-header">
            <span class="priority-badge">{{ approval.priority }}</span>
            <span class="approval-time">
              {{ new Date(approval.createdAt).toLocaleTimeString() }}
            </span>
          </div>
          <h3 class="approval-title">{{ approval.title }}</h3>
          <p class="approval-description">{{ approval.description }}</p>
          <div class="approval-actions">
            <button
              v-for="option in approval.options"
              :key="option.id"
              class="action-button"
              :class="{
                primary: option.id === 'approve',
                danger: option.isDangerous
              }"
              @click="approveAction(approval.id, option.id)"
            >
              {{ option.label }}
            </button>
          </div>
        </div>
      </section>
    </main>

    <!-- TV Layout (Side panel) -->
    <aside v-if="deviceType === 'tv'" class="tv-sidebar">
      <div class="tv-status">
        <div class="tv-indicator" :style="{ backgroundColor: statusColor }"></div>
        <span>{{ status.isPaused ? 'Paused' : 'Running' }}</span>
      </div>
      <div class="tv-stats">
        <div>{{ status.completedCycles }} cycles</div>
        <div>{{ pendingCount }} approvals</div>
      </div>
    </aside>
  </div>
</template>

<style scoped>
/* ============================================================================
   CSS VARIABLES - Apple System Colors
   ============================================================================ */
:root {
  --apple-blue: #007AFF;
  --apple-green: #34C759;
  --apple-orange: #FF9500;
  --apple-red: #FF3B30;
  --apple-purple: #AF52DE;
  --apple-gray: #8E8E93;
  --apple-gray2: #636366;
  --apple-gray3: #48484A;
  --apple-gray4: #3A3A3C;
  --apple-gray5: #2C2C2E;
  --apple-gray6: #1C1C1E;

  --bg-primary: #000000;
  --bg-secondary: var(--apple-gray6);
  --bg-tertiary: var(--apple-gray5);
  --text-primary: #FFFFFF;
  --text-secondary: var(--apple-gray);

  --spacing-xs: 4px;
  --spacing-sm: 8px;
  --spacing-md: 16px;
  --spacing-lg: 24px;
  --spacing-xl: 32px;

  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-xl: 24px;

  --font-body: -apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif;
  --font-display: -apple-system, BlinkMacSystemFont, 'SF Pro Display', sans-serif;
}

/* ============================================================================
   BASE LAYOUT
   ============================================================================ */
.warp-ui {
  font-family: var(--font-body);
  background: var(--bg-primary);
  color: var(--text-primary);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* ============================================================================
   NAVIGATION BAR
   ============================================================================ */
.nav-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  background: var(--bg-secondary);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  position: sticky;
  top: 0;
  z-index: 100;
  border-bottom: 1px solid var(--apple-gray4);
}

.nav-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.nav-title h1 {
  font-family: var(--font-display);
  font-size: 20px;
  font-weight: 600;
  margin: 0;
}

.status-indicator {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.nav-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.nav-button {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  border: none;
  background: var(--apple-gray4);
  color: var(--text-primary);
  font-size: 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.nav-button:hover {
  background: var(--apple-gray3);
}

.nav-button.active {
  background: var(--apple-green);
}

.nav-button.badge {
  background: var(--apple-orange);
  font-size: 14px;
  font-weight: 600;
}

.nav-button.badge.urgent {
  background: var(--apple-red);
  animation: urgentPulse 1s infinite;
}

@keyframes urgentPulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.1); }
}

/* ============================================================================
   CONNECTION BANNER
   ============================================================================ */
.connection-banner {
  background: var(--apple-orange);
  color: #000;
  padding: var(--spacing-sm) var(--spacing-md);
  text-align: center;
  font-size: 14px;
  font-weight: 500;
}

/* ============================================================================
   TAB BAR
   ============================================================================ */
.tab-bar {
  display: flex;
  justify-content: space-around;
  background: var(--bg-secondary);
  padding: var(--spacing-sm) 0;
  border-top: 1px solid var(--apple-gray4);
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  z-index: 100;
}

.tab-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: var(--spacing-xs) var(--spacing-md);
  background: none;
  border: none;
  color: var(--apple-gray);
  cursor: pointer;
  position: relative;
}

.tab-item.active {
  color: var(--apple-blue);
}

.tab-icon {
  font-size: 24px;
}

.tab-label {
  font-size: 10px;
  font-weight: 500;
}

.tab-badge {
  position: absolute;
  top: 0;
  right: 4px;
  background: var(--apple-red);
  color: white;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 10px;
  min-width: 16px;
  text-align: center;
}

/* ============================================================================
   CONTENT AREA
   ============================================================================ */
.content {
  flex: 1;
  padding: var(--spacing-md);
  padding-bottom: 80px; /* Space for tab bar */
  overflow-y: auto;
}

/* ============================================================================
   CHAT VIEW
   ============================================================================ */
.chat-view {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.messages {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  padding-bottom: var(--spacing-md);
}

.message {
  display: flex;
  flex-direction: column;
  max-width: 80%;
}

.message.user {
  align-self: flex-end;
}

.message.assistant {
  align-self: flex-start;
}

.message-bubble {
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--radius-lg);
  font-size: 16px;
  line-height: 1.4;
}

.message.user .message-bubble {
  background: var(--apple-blue);
  color: white;
  border-bottom-right-radius: var(--spacing-xs);
}

.message.assistant .message-bubble {
  background: var(--apple-gray5);
  color: var(--text-primary);
  border-bottom-left-radius: var(--spacing-xs);
}

.message-time {
  font-size: 11px;
  color: var(--apple-gray);
  margin-top: var(--spacing-xs);
  padding: 0 var(--spacing-sm);
}

.message.user .message-time {
  text-align: right;
}

/* Typing indicator */
.typing {
  display: flex;
  gap: 4px;
  padding: var(--spacing-md);
}

.typing .dot {
  width: 8px;
  height: 8px;
  background: var(--apple-gray);
  border-radius: 50%;
  animation: typing 1.4s infinite;
}

.typing .dot:nth-child(2) { animation-delay: 0.2s; }
.typing .dot:nth-child(3) { animation-delay: 0.4s; }

@keyframes typing {
  0%, 60%, 100% { transform: translateY(0); }
  30% { transform: translateY(-4px); }
}

/* Input area */
.input-area {
  display: flex;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--bg-secondary);
  border-radius: var(--radius-xl);
  margin-top: var(--spacing-md);
}

.chat-input {
  flex: 1;
  background: transparent;
  border: none;
  color: var(--text-primary);
  font-size: 16px;
  padding: var(--spacing-sm) var(--spacing-md);
  outline: none;
}

.chat-input::placeholder {
  color: var(--apple-gray);
}

.send-button {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  border: none;
  background: var(--apple-blue);
  color: white;
  font-size: 18px;
  font-weight: bold;
  cursor: pointer;
  transition: opacity 0.2s;
}

.send-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ============================================================================
   STATUS VIEW
   ============================================================================ */
.status-view {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.status-card {
  background: var(--bg-secondary);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
}

.status-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.status-header h2 {
  font-size: 18px;
  font-weight: 600;
  margin: 0;
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-md);
  border-radius: var(--radius-md);
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}

.current-task {
  margin-bottom: var(--spacing-lg);
}

.current-task h3 {
  font-size: 12px;
  color: var(--apple-gray);
  text-transform: uppercase;
  margin: 0 0 var(--spacing-sm);
}

.task-title {
  font-size: 16px;
  font-weight: 500;
  margin: 0 0 var(--spacing-xs);
}

.task-description {
  font-size: 14px;
  color: var(--text-secondary);
  margin: 0 0 var(--spacing-md);
}

.progress-bar {
  height: 4px;
  background: var(--apple-gray4);
  border-radius: 2px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--apple-blue);
  border-radius: 2px;
  transition: width 0.3s;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--spacing-md);
}

.stat-item {
  text-align: center;
}

.stat-value {
  display: block;
  font-size: 28px;
  font-weight: 600;
  font-family: var(--font-display);
}

.stat-label {
  font-size: 12px;
  color: var(--apple-gray);
  text-transform: uppercase;
}

/* ============================================================================
   APPROVALS VIEW
   ============================================================================ */
.approvals-view {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-xl) 0;
}

.empty-icon {
  font-size: 48px;
  display: block;
  margin-bottom: var(--spacing-md);
}

.empty-state h3 {
  font-size: 20px;
  margin: 0 0 var(--spacing-xs);
}

.empty-state p {
  color: var(--apple-gray);
  margin: 0;
}

.approval-card {
  background: var(--bg-secondary);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
  border-left: 4px solid var(--apple-gray);
}

.approval-card.high,
.approval-card.critical {
  border-left-color: var(--apple-red);
}

.approval-card.medium {
  border-left-color: var(--apple-orange);
}

.approval-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.priority-badge {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--apple-gray);
}

.approval-card.high .priority-badge,
.approval-card.critical .priority-badge {
  color: var(--apple-red);
}

.approval-time {
  font-size: 12px;
  color: var(--apple-gray);
}

.approval-title {
  font-size: 18px;
  font-weight: 600;
  margin: 0 0 var(--spacing-xs);
}

.approval-description {
  font-size: 14px;
  color: var(--text-secondary);
  margin: 0 0 var(--spacing-md);
  line-height: 1.4;
}

.approval-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

/* ============================================================================
   BUTTONS
   ============================================================================ */
.action-button {
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--radius-md);
  border: none;
  font-size: 16px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  background: var(--apple-gray4);
  color: var(--text-primary);
}

.action-button:hover {
  background: var(--apple-gray3);
}

.action-button.primary {
  background: var(--apple-blue);
  color: white;
}

.action-button.primary:hover {
  background: #0056CC;
}

.action-button.danger {
  background: var(--apple-red);
  color: white;
}

/* ============================================================================
   TV LAYOUT
   ============================================================================ */
.device-tv {
  flex-direction: row;
}

.device-tv .content {
  flex: 1;
  padding-bottom: var(--spacing-md);
}

.tv-sidebar {
  width: 300px;
  background: var(--bg-secondary);
  padding: var(--spacing-xl);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.tv-status {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  font-size: 24px;
}

.tv-indicator {
  width: 16px;
  height: 16px;
  border-radius: 50%;
}

.tv-stats {
  font-size: 18px;
  color: var(--apple-gray);
}

/* ============================================================================
   RESPONSIVE ADJUSTMENTS
   ============================================================================ */
.device-tablet .content,
.device-desktop .content {
  max-width: 800px;
  margin: 0 auto;
}

.device-tablet .tab-bar,
.device-desktop .tab-bar {
  position: static;
  border-top: none;
  border-bottom: 1px solid var(--apple-gray4);
  justify-content: center;
  gap: var(--spacing-xl);
}

.device-tablet .content,
.device-desktop .content {
  padding-bottom: var(--spacing-md);
}

.device-tablet .tab-item,
.device-desktop .tab-item {
  flex-direction: row;
  gap: var(--spacing-sm);
}

.device-tablet .tab-icon,
.device-desktop .tab-icon {
  font-size: 18px;
}

.device-tablet .tab-label,
.device-desktop .tab-label {
  font-size: 14px;
}
</style>
