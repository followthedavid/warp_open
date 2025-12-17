// useAgentBridge.ts
// Vue composable to bridge frontend -> local ai_agent_server.cjs
import { ref, onMounted, onUnmounted } from 'vue';

const API_BASE = (import.meta.env.VITE_AGENT_BASE || 'http://localhost:4005');

export function useAgentBridge(pollInterval = 2000) {
  const connected = ref(false);
  const queue = ref([]);
  const logs = ref([]);
  const results = ref({});
  const lastError = ref<string | null>(null);
  let timer: number | null = null;

  async function fetchState() {
    try {
      const res = await fetch(`${API_BASE}/state`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      connected.value = true;
      queue.value = json.queue || [];
      logs.value = json.logs || [];
      results.value = json.results || {};
      lastError.value = null;
    } catch (e) {
      connected.value = false;
      lastError.value = String(e);
    }
  }

  async function enqueue(type: string, payload: any) {
    const res = await fetch(`${API_BASE}/enqueue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, payload }),
    });
    return res.json();
  }

  async function approve(id, approved = true, by = 'user') {
    const res = await fetch(`${API_BASE}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, approved, by }),
    });
    return res.json();
  }

  async function executeNow(id) {
    const res = await fetch(`${API_BASE}/execute-now`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    return res.json();
  }

  async function getLogs() {
    const res = await fetch(`${API_BASE}/logs`);
    if (!res.ok) return [];
    return (await res.json()).logs || [];
  }

  function startPolling() {
    if (timer) return;
    timer = window.setInterval(fetchState, pollInterval);
    fetchState();
  }

  function stopPolling() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  onMounted(() => startPolling());
  onUnmounted(() => stopPolling());

  return {
    connected,
    queue,
    logs,
    results,
    lastError,
    fetchState,
    enqueue,
    approve,
    executeNow,
    getLogs,
    startPolling,
    stopPolling,
  };
}
