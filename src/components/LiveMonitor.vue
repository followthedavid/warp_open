<template>
  <div class="live-monitor p-4">
    <h2 class="text-xl font-bold mb-3">Warp Live Monitor</h2>

    <!-- Alert Banner -->
    <transition name="fade">
      <div v-if="alerts.length" class="fixed top-2 left-1/2 transform -translate-x-1/2 z-50 w-11/12 max-w-xl">
        <div v-for="(alert, i) in alerts" :key="i" 
             class="p-2 mb-2 rounded shadow-lg text-white"
             :class="severityBgClass(alert.phase, alert.severity)"
             :style="alertStyle(alert)">
          <div class="flex justify-between items-center">
            <div class="flex items-center gap-2">
              <span :class="phaseBadgeClass(alert.phase)" class="px-2 py-1 rounded text-white text-xs font-semibold">
                {{ alert.phase?.toUpperCase() || 'UNKNOWN' }}
              </span>
              <span>⚠️ {{ alert.message }}</span>
              <span v-if="alert.countdown !== null" class="countdown font-bold" :style="countdownStyle(alert)">
                ({{ alert.countdown.toFixed(1) }}s)
              </span>
            </div>
            <button @click="removeAlert(i)" class="font-bold px-2 py-0.5 bg-white text-red-600 rounded hover:bg-gray-100">×</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Controls -->
    <div class="flex gap-2 mb-3 flex-wrap">
      <input v-model="search" placeholder="Search messages..." class="input px-2 py-1 border rounded" />

      <select v-model="filterPhase" class="input px-2 py-1 border rounded">
        <option value="">All Phases</option>
        <option v-for="phase in phaseKeys" :key="phase">{{ phase }}</option>
      </select>

      <select v-model="filterAgent" class="input px-2 py-1 border rounded">
        <option value="">All Agents</option>
        <option v-for="agent in agentKeys" :key="agent">{{ agent }}</option>
      </select>

      <select v-model="confidenceFilter" class="input px-2 py-1 border rounded">
        <option value="">All Confidences</option>
        <option value="low">Confidence < 50%</option>
        <option value="mid">Confidence 50-80%</option>
        <option value="high">Confidence > 80%</option>
      </select>

      <label class="flex items-center gap-1">
        <input type="checkbox" v-model="autoScroll" /> Auto-Scroll
      </label>
      <button @click="refresh" class="btn px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600">Refresh</button>
      <button @click="clearAll" class="btn px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600">Clear All</button>
    </div>

    <!-- Events -->
    <div ref="container" class="overflow-y-auto max-h-[600px] border rounded p-2 bg-gray-50">
      <div v-for="(events, phase) in filteredPhases" :key="phase" class="mb-4">
        <h3 class="font-semibold text-lg mb-2 flex items-center gap-2">
          <span :class="phaseBadgeClass(phase)" class="px-2 py-1 rounded text-white text-xs">
            {{ phase.toUpperCase() }}
          </span>
          <span class="text-sm text-gray-600">({{ events.length }} events)</span>
        </h3>
        <div v-for="e in events" :key="e.timestamp" class="p-2 border-b flex justify-between items-center hover:bg-gray-100">
          <div class="flex-1">
            <span class="text-gray-700 text-sm">{{ formatTime(e.timestamp) }}:</span>
            <span class="ml-2">{{ e.message }}</span>

            <!-- Batch Badge -->
            <span v-if="e.batch_id" class="ml-2 px-1 rounded text-sm font-bold bg-blue-100 text-blue-800">
              Batch: {{ e.batch_id.slice(0,8) }}
            </span>

            <!-- Agent Badge -->
            <span v-if="e.agent_id" class="ml-2 px-1 rounded text-sm font-bold bg-green-100 text-green-800">
              Agent: {{ e.agent_id }}
            </span>

            <!-- Policy Suggestion Badge -->
            <span v-if="e.policy_suggestion" class="ml-2 px-1 rounded text-sm font-bold"
              :class="{
                'bg-red-100 text-red-800': e.suggestion_confidence && e.suggestion_confidence < 50,
                'bg-yellow-100 text-yellow-800': e.suggestion_confidence && e.suggestion_confidence >= 50 && e.suggestion_confidence < 80,
                'bg-green-100 text-green-800': e.suggestion_confidence && e.suggestion_confidence >= 80
              }">
              Suggestion: {{ e.policy_suggestion }}
            </span>
          </div>
          <div>
            <span
              :class="{
                'text-green-600': e.status === 'success',
                'text-yellow-500': e.status === 'running',
                'text-red-600 font-bold': e.status === 'failure'
              }"
              class="font-bold text-sm"
            >
              {{ e.status.toUpperCase() }}
            </span>
          </div>
        </div>
      </div>
      <div v-if="Object.keys(filteredPhases).length === 0" class="text-center text-gray-500 py-8">
        No events to display
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { alertStore } from '@/stores/alertStore'

const phases = ref({})
const search = ref('')
const filterPhase = ref('')
const filterAgent = ref('')
const confidenceFilter = ref('')
const autoScroll = ref(true)
const container = ref(null)
const alerts = computed(() => alertStore.alerts)

// Phase colors
const phaseColors = {
  phase1: 'bg-blue-500',
  phase2: 'bg-green-500',
  phase3: 'bg-yellow-600',
  phase4: 'bg-purple-500',
  phase5: 'bg-red-600',
  phase6: 'bg-indigo-600',
}

function phaseBadgeClass(phase) {
  return phaseColors[phase] ?? 'bg-gray-500'
}

function severityBgClass(phase, severity = 'medium') {
  const baseColors = {
    phase1: 'blue',
    phase2: 'green',
    phase3: 'yellow',
    phase4: 'purple',
    phase5: 'red',
    phase6: 'indigo',
  }
  const base = baseColors[phase] ?? 'gray'
  switch (severity) {
    case 'high': return `bg-${base}-700`
    case 'medium': return `bg-${base}-500`
    case 'low': return `bg-${base}-300`
    default: return `bg-${base}-500`
  }
}

function alertStyle(alert) {
  if (!alert.countdown || !alert.initialCountdown) return {}
  
  const intensity = 1 - (alert.countdown / alert.initialCountdown)
  const scale = 1 + intensity * 0.05
  const pulse = Math.abs(Math.sin(Date.now() / 200)) * intensity
  
  return {
    transform: `scale(${scale})`,
    transition: 'transform 0.2s ease',
    boxShadow: `0 0 ${pulse * 15}px rgba(255,0,0,${pulse})`
  }
}

function countdownStyle(alert) {
  if (!alert.countdown || !alert.initialCountdown) return {}
  
  const pct = alert.countdown / alert.initialCountdown
  let color = 'green'
  if (pct < 0.33) color = 'red'
  else if (pct < 0.66) color = 'yellow'
  
  const glow = (1 - pct) * 8
  
  return {
    color,
    textShadow: `0 0 ${glow}px rgba(255,0,0,${1 - pct})`
  }
}

const phaseKeys = computed(() => Object.keys(phases.value))
const agentKeys = computed(() => {
  const agents = new Set()
  Object.values(phases.value).flat().forEach(e => e.agent_id && agents.add(e.agent_id))
  return Array.from(agents)
})

const filteredPhases = computed(() => {
  const filtered = {}
  for (const [phase, events] of Object.entries(phases.value)) {
    if (filterPhase.value && filterPhase.value !== phase) continue

    let evs = events.filter(e => e.message.toLowerCase().includes(search.value.toLowerCase()))
    if (filterAgent.value) evs = evs.filter(e => e.agent_id === filterAgent.value)
    if (confidenceFilter.value) {
      evs = evs.filter(e => {
        const c = e.suggestion_confidence ?? 0
        if (confidenceFilter.value === 'low') return c < 50
        if (confidenceFilter.value === 'mid') return c >= 50 && c < 80
        if (confidenceFilter.value === 'high') return c >= 80
        return true
      })
    }

    if (evs.length) filtered[phase] = evs
  }
  return filtered
})

async function refresh() {
  try {
    const res = await window.__TAURI__.invoke('get_monitoring_events')
    phases.value = res
    scrollToBottom()
    checkAlerts(res)
  } catch(e) {
    console.error("Failed to fetch monitoring events:", e)
  }
}

async function clearAll() {
  try {
    await window.__TAURI__.invoke('clear_monitoring_all')
    phases.value = {}
    alertStore.alerts = []
    alertStore.alertHistory.clear()
  } catch(e) {
    console.error("Failed to clear monitoring:", e)
  }
}

function scrollToBottom() {
  if (!autoScroll.value || !container.value) return
  nextTick(() => { 
    if (container.value) {
      container.value.scrollTop = container.value.scrollHeight 
    }
  })
}

function checkAlerts(eventsByPhase) {
  Object.entries(eventsByPhase).forEach(([phase, events]) => {
    events.forEach(e => {
      const isCritical = e.status === 'failure' || (e.suggestion_confidence && e.suggestion_confidence < 30)
      if (isCritical) {
        const alertKey = `${phase}-${e.timestamp}`
        alertStore.addAlert({
          key: alertKey,
          phase,
          message: e.message,
          severity: e.status === 'failure' ? 'high' : 'medium'
        })
      }
    })
  })
}

function removeAlert(idx) {
  const alert = alerts.value[idx]
  if (alert) alertStore.removeAlert(alert.key)
}

function formatTime(timestamp) {
  try {
    const date = new Date(timestamp)
    return date.toLocaleTimeString()
  } catch {
    return timestamp
  }
}

// Listen for live updates
let unlistenFn = null

onMounted(async () => {
  refresh()
  
  // Listen for monitor updates from Tauri
  try {
    unlistenFn = await window.__TAURI__.event.listen("monitor_update", event => {
      phases.value = event.payload
      scrollToBottom()
      checkAlerts(event.payload)
    })
  } catch(e) {
    console.error("Failed to listen for monitor updates:", e)
  }
  
  // Refresh periodically
  const refreshInterval = setInterval(refresh, 5000)
  
  onUnmounted(() => {
    clearInterval(refreshInterval)
    if (unlistenFn) unlistenFn()
  })
})
</script>

<style scoped>
.fade-enter-active, .fade-leave-active {
  transition: all 0.3s ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}
</style>
