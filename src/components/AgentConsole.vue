<template>
  <div class="agent-console">
    <header class="agent-header">
      <h3>Agent Console</h3>
      <div class="status">
        <span :class="['dot', bridge.connected ? 'online' : 'offline']"></span>
        {{ bridge.connected ? 'Agent Online' : 'Agent Offline' }}
      </div>
    </header>

    <section class="controls">
      <button @click="refresh">Refresh</button>
      <button @click="clearLocalLogs">Clear UI Logs</button>
      <button @click="testConnection">Test Connection</button>
      <button @click="fetchBackends">Show Backends</button>
    </section>

    <section v-if="error" class="error-banner">
      <strong>Error:</strong> {{ error }}
      <button @click="error = ''" class="dismiss">×</button>
    </section>

    <section v-if="backends" class="backends">
      <h4>Discovered Backends</h4>
      <div class="backend-list">
        <div v-if="backends.http?.length" class="backend-group">
          <strong>HTTP:</strong>
          <span v-for="(b, i) in backends.http" :key="i" class="badge">
            Port {{ b.port }}
            <span v-if="b.port === 11434" class="ollama-badge">Ollama</span>
            <span v-if="b.port === 9999" class="chatgpt-badge">ChatGPT</span>
          </span>
        </div>
        <div v-if="backends.cli?.length" class="backend-group">
          <strong>CLI:</strong>
          <span v-for="(b, i) in backends.cli" :key="i" class="badge">{{ b.path.split('/').pop() }}</span>
        </div>
        <div v-if="!backends.http?.length && !backends.cli?.length" class="empty">
          No backends discovered
        </div>
      </div>
    </section>

    <section class="queue">
      <h4>Pending Queue</h4>
      <div v-if="bridge.queue.length === 0" class="empty">No items</div>
      <ul>
        <li v-for="item in bridge.queue" :key="item.id" class="queue-item">
          <div class="meta">
            <strong>{{ item.type }}</strong>
            <small>{{ item.createdAt }}</small>
            <small>approved: {{ String(item.approved) }}</small>
          </div>
          <pre class="payload">{{ pretty(item.payload) }}</pre>
          <div class="actions">
            <button @click="approve(item.id, true)">Approve</button>
            <button @click="approve(item.id, false)">Deny</button>
            <button @click="runNow(item.id)" :disabled="running">Run Now</button>
          </div>
        </li>
      </ul>
    </section>

    <section class="logs">
      <h4>Recent Logs</h4>
      <div v-for="l in recentLogs" :key="l.ts" class="log-line">
        <small>[{{ l.ts }}]</small>
        <span class="level">{{ l.level }}</span> — {{ l.message }}
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { useAgentBridge } from '../composables/useAgentBridge';

const bridge = useAgentBridge(2000);
const running = ref(false);
const error = ref('');
const backends = ref(null);

function pretty(obj) {
  try { return JSON.stringify(obj, null, 2); } catch { return String(obj); }
}

async function refresh() {
  try {
    await bridge.fetchState();
    error.value = '';
  } catch (e) {
    error.value = `Failed to refresh: ${e.message || String(e)}`;
  }
}

async function testConnection() {
  try {
    const response = await fetch('http://localhost:4005/health');
    if (response.ok) {
      const data = await response.json();
      error.value = '';
      alert(`✅ Connection successful!\nServer PID: ${data.pid}\nTime: ${data.now}`);
    } else {
      error.value = `Server returned ${response.status}`;
    }
  } catch (e) {
    error.value = `Connection failed: ${e.message || String(e)}`;
  }
}

async function fetchBackends() {
  try {
    const response = await fetch('http://localhost:4005/backends');
    if (response.ok) {
      const data = await response.json();
      backends.value = data.backends;
      error.value = '';
    } else {
      error.value = `Failed to fetch backends: ${response.status}`;
    }
  } catch (e) {
    error.value = `Backend fetch failed: ${e.message || String(e)}`;
    backends.value = null;
  }
}

async function approve(id, val) {
  try {
    await bridge.approve(id, val, 'user-ui');
    await bridge.fetchState();
    error.value = '';
  } catch (e) {
    error.value = `Approve failed: ${e.message || String(e)}`;
  }
}

async function runNow(id) {
  running.value = true;
  try {
    await bridge.executeNow(id);
    await bridge.fetchState();
    error.value = '';
  } catch (e) {
    error.value = `Execute failed: ${e.message || String(e)}`;
  } finally {
    running.value = false;
  }
}

function clearLocalLogs() {
  // client-side only: don't alter server logs
  bridge.logs.value.splice(0, bridge.logs.value.length);
}

const recentLogs = computed(() => bridge.logs.value.slice(-200).reverse());
</script>

<style scoped>
.agent-console {
  position: fixed;
  top: 60px;
  right: 20px;
  width: 500px;
  max-height: calc(100vh - 100px);
  padding: 12px;
  font-family: Inter, system-ui, sans-serif;
  color: #e6eef8;
  background: #0b1220;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
  z-index: 1000;
  overflow-y: auto;
}
.agent-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
.dot { display:inline-block; width:10px;height:10px;border-radius:12px;margin-right:6px; }
.dot.online { background: #10b981; }
.dot.offline { background: #ef4444; }
.queue { margin-top:12px; }
.queue-item { background:#071022; padding:8px; border-radius:6px; margin-bottom:8px; }
.payload { background:#03101a; padding:8px; color:#bcd; border-radius:4px; overflow:auto; }
.actions button { margin-right:6px; }
.log-line { border-top:1px solid rgba(255,255,255,0.03); padding:6px 0; font-size:12px; }
.level { color:#9aaed0; margin:0 8px; }
.empty { color:#9aa6b8; padding:8px; }
.error-banner { background:#7f1d1d; border:1px solid #dc2626; border-radius:6px; padding:10px; margin:8px 0; display:flex; justify-content:space-between; align-items:center; }
.error-banner .dismiss { background:none; border:none; color:#fff; font-size:20px; cursor:pointer; padding:0 8px; }
.backends { margin-top:12px; padding:10px; background:#071022; border-radius:6px; }
.backend-list { margin-top:8px; }
.backend-group { margin-bottom:8px; }
.badge { display:inline-block; background:#1e293b; padding:4px 8px; border-radius:4px; margin-right:6px; font-size:11px; }
.ollama-badge { background:#10b981; color:#fff; padding:2px 6px; border-radius:3px; margin-left:4px; font-size:9px; font-weight:bold; }
.chatgpt-badge { background:#ef4444; color:#fff; padding:2px 6px; border-radius:3px; margin-left:4px; font-size:9px; font-weight:bold; }
.controls button { margin-right:6px; margin-bottom:6px; }
</style>
