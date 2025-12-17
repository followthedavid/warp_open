<template>
  <div class="policy-reviewer p-6 bg-gray-900 text-gray-100 h-screen overflow-auto">
    <div class="header mb-6">
      <h2 class="text-2xl font-bold mb-2">Policy Reviewer</h2>
      <p class="text-gray-400 text-sm">Phase 4: Telemetry & Phase 5: Policy Learning + Multi-Agent</p>
    </div>

    <!-- Tab Navigation -->
    <div class="tabs flex gap-2 mb-6 border-b border-gray-700">
      <button 
        @click="activeTab = 'telemetry'" 
        :class="['tab', activeTab === 'telemetry' ? 'active' : '']"
      >
        📊 Telemetry
      </button>
      <button 
        @click="activeTab = 'policy'" 
        :class="['tab', activeTab === 'policy' ? 'active' : '']"
      >
        🛡️ Policy Rules
      </button>
      <button 
        @click="activeTab = 'suggestions'" 
        :class="['tab', activeTab === 'suggestions' ? 'active' : '']"
      >
        💡 Suggestions
      </button>
      <button 
        @click="activeTab = 'agents'" 
        :class="['tab', activeTab === 'agents' ? 'active' : '']"
      >
        🤖 Agents
      </button>
    </div>

    <!-- Telemetry Tab -->
    <div v-if="activeTab === 'telemetry'" class="controls flex gap-3 mb-6">
      <button @click="refresh" class="btn btn-primary">
        <span v-if="!loading">🔄 Refresh</span>
        <span v-else>⏳ Loading...</span>
      </button>
      <button @click="exportCsv" class="btn btn-secondary" :disabled="loading">
        📤 Export CSV
      </button>
      <button @click="runTrainer" class="btn btn-success" :disabled="trainerRunning">
        <span v-if="!trainerRunning">🤖 Run Trainer</span>
        <span v-else>⏳ Training...</span>
      </button>
      <div class="flex-1"></div>
      <div class="text-gray-400 text-sm self-center">
        Total events: {{ rows.length }}
      </div>
    </div>

    <div v-if="error" class="alert alert-error mb-4">
      ❌ {{ error }}
    </div>

    <div v-if="success" class="alert alert-success mb-4">
      ✅ {{ success }}
    </div>

    <div class="table-container bg-gray-800 rounded-lg overflow-hidden border border-gray-700">
      <table class="w-full table-auto">
        <thead class="bg-gray-700">
          <tr>
            <th class="px-3 py-2 text-left">Timestamp</th>
            <th class="px-3 py-2 text-left">Event</th>
            <th class="px-3 py-2 text-left">Command</th>
            <th class="px-3 py-2 text-left">Tool</th>
            <th class="px-3 py-2 text-center">Exit</th>
            <th class="px-3 py-2 text-center">Score</th>
            <th class="px-3 py-2 text-left">Label</th>
          </tr>
        </thead>
        <tbody>
          <tr 
            v-for="e in rows" 
            :key="e.id" 
            class="border-t border-gray-700 hover:bg-gray-750"
            :class="getLabelClass(e)"
          >
            <td class="px-3 py-2 text-xs text-gray-400">{{ formatTs(e.ts) }}</td>
            <td class="px-3 py-2 text-xs">{{ e.event_type }}</td>
            <td class="px-3 py-2 font-mono text-sm">
              <code class="bg-gray-900 px-2 py-1 rounded">{{ truncate(e.command, 60) }}</code>
            </td>
            <td class="px-3 py-2 text-xs text-gray-400">{{ e.tool || '—' }}</td>
            <td class="px-3 py-2 text-center text-xs">
              <span v-if="e.exit_code !== null" :class="e.exit_code === 0 ? 'text-green-400' : 'text-red-400'">
                {{ e.exit_code }}
              </span>
              <span v-else class="text-gray-500">—</span>
            </td>
            <td class="px-3 py-2 text-center">
              <span v-if="e.safety_score !== null" class="score-badge" :class="getScoreClass(e.safety_score)">
                {{ e.safety_score }}
              </span>
              <span v-else class="text-gray-500">—</span>
            </td>
            <td class="px-3 py-2">
              <select 
                v-model="e._label" 
                @change="labelChange(e)" 
                class="label-select"
                :class="e._label !== '' ? 'labeled' : ''"
              >
                <option value="">(none)</option>
                <option value="0">✅ safe</option>
                <option value="1">⛔ unsafe</option>
                <option value="2">❓ unknown</option>
              </select>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="rows.length === 0 && !loading" class="text-center py-12 text-gray-500">
      <p class="text-lg mb-2">No telemetry data yet</p>
      <p class="text-sm">Execute some commands to start collecting data</p>
    </div>

    <!-- Policy Rules Tab -->
    <div v-if="activeTab === 'policy'" class="policy-tab">
      <div class="controls flex gap-3 mb-6">
        <button @click="loadPolicyRules" class="btn btn-primary">
          🔄 Refresh Rules
        </button>
        <button @click="showManualPolicyForm = !showManualPolicyForm" class="btn btn-secondary">
          ➕ Add Rule
        </button>
        <div class="flex-1"></div>
        <div class="text-gray-400 text-sm self-center">
          Total rules: {{ policyRules.length }}
        </div>
      </div>

      <!-- Manual Policy Form -->
      <div v-if="showManualPolicyForm" class="bg-gray-800 p-4 rounded-lg mb-4 border border-gray-700">
        <h3 class="text-lg font-bold mb-3">Propose Manual Policy Rule</h3>
        <div class="space-y-3">
          <input 
            v-model="manualPolicy.pattern" 
            placeholder="Pattern (regex, e.g., \\brm\\s+-rf\\b)"
            class="input w-full"
          />
          <select v-model="manualPolicy.effect" class="input w-full">
            <option value="deny">Deny</option>
            <option value="allow">Allow</option>
          </select>
          <input 
            v-model.number="manualPolicy.score" 
            type="number" 
            step="0.01" 
            min="0" 
            max="1"
            placeholder="Confidence (0-1)"
            class="input w-full"
          />
          <div class="flex gap-2">
            <button @click="proposeManualPolicy" class="btn btn-success">Submit</button>
            <button @click="showManualPolicyForm = false" class="btn btn-secondary">Cancel</button>
          </div>
        </div>
      </div>

      <!-- Policy Rules List -->
      <div v-if="policyRules.length > 0" class="space-y-3">
        <div v-for="rule in policyRules" :key="rule.id" class="policy-rule-card">
          <div class="flex items-start justify-between">
            <div class="flex-1">
              <div class="text-red-400 font-bold text-sm mb-1">{{ rule.effect.toUpperCase() }}</div>
              <code class="text-sm bg-gray-900 px-2 py-1 rounded block mb-2">{{ rule.pattern }}</code>
              <div class="text-xs text-gray-500">
                Added by: {{ rule.added_by || 'unknown' }} | 
                Confidence: {{ rule.confidence ? rule.confidence.toFixed(2) : 'N/A' }} |
                {{ formatTs(rule.ts) }}
              </div>
            </div>
          </div>
        </div>
      </div>
      <div v-else class="text-center py-12 text-gray-500">
        <p class="text-lg mb-2">No policy rules yet</p>
        <p class="text-sm">Add rules manually or generate suggestions from trained model</p>
      </div>
    </div>

    <!-- Suggestions Tab -->
    <div v-if="activeTab === 'suggestions'" class="suggestions-tab">
      <div class="controls flex gap-3 mb-6">
        <button @click="loadSuggestions" class="btn btn-primary">
          🔄 Refresh Suggestions
        </button>
        <button @click="generateSuggestions" class="btn btn-success" :disabled="suggestionsRunning">
          <span v-if="!suggestionsRunning">🤖 Generate Suggestions</span>
          <span v-else>⏳ Generating...</span>
        </button>
        <div class="flex-1"></div>
        <div class="text-gray-400 text-sm self-center">
          Total: {{ suggestions.length }}
        </div>
      </div>

      <!-- Suggestions List -->
      <div v-if="suggestions.length > 0" class="space-y-4">
        <div v-for="(sugg, idx) in suggestions" :key="sugg.id" 
             :class="['suggestion-card', `status-${sugg.status}`]">
          <div class="flex items-center justify-between mb-3">
            <div>
              <span class="font-bold">Suggestion {{ idx + 1 }}</span>
              <span :class="['badge ml-2', `badge-${sugg.status}`]">{{ sugg.status.toUpperCase() }}</span>
            </div>
            <div class="text-xs text-gray-500">{{ formatTs(sugg.proposed_at) }}</div>
          </div>
          
          <div class="text-xs text-gray-400 mb-2">
            Proposed by: {{ sugg.proposed_by }}
          </div>

          <div v-if="sugg.diff && sugg.diff.add" class="space-y-2">
            <div class="text-sm text-blue-400 mb-2">
              {{ sugg.diff.add.length }} rules to add, {{ sugg.diff.remove ? sugg.diff.remove.length : 0 }} to remove
            </div>
            <div v-for="(rule, rIdx) in sugg.diff.add" :key="rIdx" 
                 class="bg-gray-900 p-3 rounded border-l-4 border-orange-500">
              <div class="text-red-400 text-xs font-bold mb-1">{{ rule.effect.toUpperCase() }}</div>
              <code class="text-xs">{{ rule.pattern }}</code>
              <div class="text-xs text-gray-500 mt-1">
                Confidence: {{ rule.score ? rule.score.toFixed(2) : 'N/A' }}
              </div>
            </div>
          </div>

          <div v-if="sugg.status === 'pending'" class="mt-4 flex gap-2">
            <button @click="applySuggestion(sugg.id)" class="btn btn-success btn-sm">
              ✅ Approve & Apply
            </button>
            <button @click="rejectSuggestion(sugg.id)" class="btn btn-danger btn-sm">
              ❌ Reject
            </button>
          </div>

          <div v-else class="mt-2 text-xs text-gray-500">
            Reviewed by: {{ sugg.reviewed_by }} at {{ formatTs(sugg.reviewed_at) }}
          </div>
        </div>
      </div>
      <div v-else class="text-center py-12 text-gray-500">
        <p class="text-lg mb-2">No policy suggestions</p>
        <p class="text-sm">Click "Generate Suggestions" to create ML-driven policy recommendations</p>
      </div>
    </div>

    <!-- Agents Tab -->
    <div v-if="activeTab === 'agents'" class="agents-tab">
      <div class="controls flex gap-3 mb-6">
        <input 
          v-model="newAgentName" 
          placeholder="Agent Name (optional)" 
          class="input flex-1"
        />
        <button @click="registerAgent" class="btn btn-success">
          ➕ Register Agent
        </button>
        <button @click="loadAgents" class="btn btn-primary">
          🔄 Refresh
        </button>
      </div>

      <!-- Agents List -->
      <div v-if="agents.length > 0" class="grid grid-cols-2 gap-4">
        <div v-for="agent in agents" :key="agent.id" 
             :class="['agent-card', `status-${agent.status}`]">
          <div class="flex items-center justify-between mb-2">
            <div class="font-bold">{{ agent.name }}</div>
            <div :class="['status-badge', `status-${agent.status}`]">
              {{ agent.status.toUpperCase() }}
            </div>
          </div>
          <div class="text-xs text-gray-500 mb-2">ID: {{ agent.id.substring(0, 12) }}...</div>
          <div v-if="agent.last_action" class="text-xs text-blue-400 mb-2">
            Action: {{ agent.last_action }} (score: {{ agent.last_score }})
          </div>
          <div class="flex gap-2 mt-3">
            <button @click="updateAgent(agent.id)" class="btn btn-secondary btn-sm">Update</button>
            <button @click="unregisterAgent(agent.id)" class="btn btn-danger btn-sm">Remove</button>
          </div>
        </div>
      </div>
      <div v-else class="text-center py-12 text-gray-500">
        <p class="text-lg mb-2">No agents registered</p>
        <p class="text-sm">Register agents to coordinate multi-agent workflows</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

// Phase 4: Telemetry
const rows = ref([])
const loading = ref(false)
const trainerRunning = ref(false)
const error = ref(null)
const success = ref(null)

// Phase 5: Policy & Agents
const activeTab = ref('telemetry')
const policyRules = ref([])
const suggestions = ref([])
const agents = ref([])
const showManualPolicyForm = ref(false)
const manualPolicy = ref({ pattern: '\\brm\\s+-rf\\b', effect: 'deny', score: 0.95 })
const suggestionsRunning = ref(false)
const newAgentName = ref('')

async function refresh() {
  loading.value = true
  error.value = null
  try {
    const res = await window.__TAURI__.invoke('telemetry_query_recent', { limit: 200 })
    rows.value = res.map(r => ({ ...r, _label: r.safety_label?.toString() ?? '' }))
    success.value = `Loaded ${res.length} events`
    setTimeout(() => success.value = null, 3000)
  } catch (e) {
    error.value = `Failed to load telemetry: ${e}`
    console.error(e)
  } finally {
    loading.value = false
  }
}

function formatTs(ts) {
  try { 
    const date = new Date(ts)
    return date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      hour: '2-digit', 
      minute: '2-digit' 
    })
  } catch(e) { 
    return ts 
  }
}

function truncate(str, maxLen) {
  if (!str) return ''
  if (str.length <= maxLen) return str
  return str.substring(0, maxLen) + '...'
}

function getScoreClass(score) {
  if (score >= 80) return 'score-safe'
  if (score < 40) return 'score-unsafe'
  return 'score-unknown'
}

function getLabelClass(event) {
  const label = event._label || event.safety_label?.toString()
  if (label === '0') return 'row-safe'
  if (label === '1') return 'row-unsafe'
  return ''
}

async function exportCsv() {
  loading.value = true
  error.value = null
  try {
    const path = await window.__TAURI__.invoke('telemetry_export_csv', { out_path: null })
    success.value = `Exported to ${path}`
    setTimeout(() => success.value = null, 5000)
  } catch (e) {
    error.value = `Export failed: ${e}`
    console.error(e)
  } finally {
    loading.value = false
  }
}

async function runTrainer() {
  if (!confirm('Run policy trainer? This will train a new model based on current telemetry data. Continue?')) {
    return
  }
  
  trainerRunning.value = true
  error.value = null
  try {
    const result = await window.__TAURI__.invoke('phase4_trigger_trainer', { csv_path: null })
    success.value = 'Trainer completed! Check logs for details.'
    console.log('Trainer result:', result)
    setTimeout(() => success.value = null, 5000)
  } catch (e) {
    error.value = `Trainer failed: ${e}`
    console.error(e)
  } finally {
    trainerRunning.value = false
  }
}

async function labelChange(e) {
  // Create a telemetry event marking the manual label
  const labelEvent = {
    id: `${e.id}-label-${Date.now()}`,
    ts: new Date().toISOString(),
    event_type: "human_label",
    tab_id: e.tab_id,
    batch_id: e.batch_id,
    tool: e.tool,
    command: e.command,
    safety_label: parseInt(e._label),
    metadata: { note: "manual label via UI", original_id: e.id }
  }
  
  try {
    await window.__TAURI__.invoke('telemetry_insert_event', {
      event_json: JSON.stringify(labelEvent)
    })
    console.log('Label saved:', e._label, 'for command:', e.command)
  } catch (err) {
    console.error('Failed to save label:', err)
    error.value = `Failed to save label: ${err}`
  }
}

// Phase 5: Policy Management Functions
async function loadPolicyRules() {
  try {
    policyRules.value = await window.__TAURI__.invoke('policy_list_rules')
    success.value = `Loaded ${policyRules.value.length} policy rules`
    setTimeout(() => success.value = null, 3000)
  } catch (e) {
    error.value = `Failed to load policy rules: ${e}`
    console.error(e)
  }
}

async function proposeManualPolicy() {
  try {
    const diff = {
      add: [{ 
        pattern: manualPolicy.value.pattern, 
        effect: manualPolicy.value.effect, 
        score: manualPolicy.value.score 
      }],
      remove: [],
      meta: { source: 'manual_ui', timestamp: new Date().toISOString() }
    }
    
    const suggestionId = await window.__TAURI__.invoke('policy_propose_diff', {
      proposed_by: 'manual_reviewer',
      diff_json: JSON.stringify(diff)
    })
    
    success.value = `Proposed policy rule: ${suggestionId}`
    showManualPolicyForm.value = false
    setTimeout(() => success.value = null, 3000)
    
    // Refresh suggestions
    await loadSuggestions()
  } catch (e) {
    error.value = `Failed to propose policy: ${e}`
    console.error(e)
  }
}

async function loadSuggestions() {
  try {
    suggestions.value = await window.__TAURI__.invoke('policy_list_suggestions')
    success.value = `Loaded ${suggestions.value.length} suggestions`
    setTimeout(() => success.value = null, 3000)
  } catch (e) {
    error.value = `Failed to load suggestions: ${e}`
    console.error(e)
  }
}

async function generateSuggestions() {
  if (!confirm('Generate ML-driven policy suggestions? This requires a trained model.')) {
    return
  }
  
  suggestionsRunning.value = true
  error.value = null
  
  try {
    const result = await window.__TAURI__.invoke('phase5_generate_suggestions', {
      csv_path: null,
      model_path: null
    })
    success.value = 'Suggestions generated! Review them below.'
    console.log('Suggestion result:', result)
    await loadSuggestions()
  } catch (e) {
    error.value = `Suggestion generation failed: ${e}`
    console.error(e)
  } finally {
    suggestionsRunning.value = false
  }
}

async function applySuggestion(suggestionId) {
  const token = prompt('⚠️  Type APPLY to confirm applying this policy change:')
  if (token !== 'APPLY') {
    error.value = 'Apply cancelled (invalid token)'
    setTimeout(() => error.value = null, 3000)
    return
  }
  
  const author = prompt('Enter your name:') || 'anonymous'
  const comment = prompt('Comment:') || 'Approved via PolicyReviewer UI'
  
  try {
    const version = await window.__TAURI__.invoke('policy_apply_suggestion', {
      suggestion_id: suggestionId,
      author: author,
      comment: comment,
      token: token
    })
    success.value = `✅ Applied suggestion. Version: ${version}`
    await loadSuggestions()
    await loadPolicyRules()
  } catch (e) {
    error.value = `Failed to apply suggestion: ${e}`
    console.error(e)
  }
}

async function rejectSuggestion(suggestionId) {
  if (!confirm('Reject this suggestion?')) return
  
  const author = prompt('Enter your name:') || 'anonymous'
  
  try {
    await window.__TAURI__.invoke('policy_reject_suggestion', {
      suggestion_id: suggestionId,
      author: author
    })
    success.value = '❌ Rejected suggestion'
    await loadSuggestions()
  } catch (e) {
    error.value = `Failed to reject suggestion: ${e}`
    console.error(e)
  }
}

// Phase 5: Agent Coordination Functions
async function loadAgents() {
  try {
    agents.value = await window.__TAURI__.invoke('agent_list')
    success.value = `Loaded ${agents.value.length} agents`
    setTimeout(() => success.value = null, 3000)
  } catch (e) {
    error.value = `Failed to load agents: ${e}`
    console.error(e)
  }
}

async function registerAgent() {
  try {
    const agentId = await window.__TAURI__.invoke('agent_register', { 
      name: newAgentName.value || null 
    })
    success.value = `✅ Registered agent: ${agentId}`
    newAgentName.value = ''
    await loadAgents()
  } catch (e) {
    error.value = `Failed to register agent: ${e}`
    console.error(e)
  }
}

async function updateAgent(agentId) {
  const action = prompt('Action:') || 'idle'
  const score = parseInt(prompt('Score (0-100):') || '50')
  
  try {
    await window.__TAURI__.invoke('agent_update', {
      agent_id: agentId,
      action: action,
      score: score
    })
    success.value = `✅ Updated agent`
    await loadAgents()
  } catch (e) {
    error.value = `Failed to update agent: ${e}`
    console.error(e)
  }
}

async function unregisterAgent(agentId) {
  if (!confirm('Unregister this agent?')) return
  
  try {
    await window.__TAURI__.invoke('agent_unregister', { agent_id: agentId })
    success.value = '✅ Unregistered agent'
    await loadAgents()
  } catch (e) {
    error.value = `Failed to unregister agent: ${e}`
    console.error(e)
  }
}

onMounted(refresh)
</script>

<style scoped>
.btn {
  @apply px-4 py-2 rounded font-medium text-sm transition-colors;
}
.btn-primary {
  @apply bg-blue-600 hover:bg-blue-700 text-white;
}
.btn-secondary {
  @apply bg-gray-700 hover:bg-gray-600 text-white;
}
.btn-success {
  @apply bg-green-600 hover:bg-green-700 text-white;
}
.btn:disabled {
  @apply opacity-50 cursor-not-allowed;
}

.alert {
  @apply px-4 py-3 rounded border;
}
.alert-error {
  @apply bg-red-900/30 border-red-600 text-red-200;
}
.alert-success {
  @apply bg-green-900/30 border-green-600 text-green-200;
}

.table-container {
  @apply max-h-[calc(100vh-300px)] overflow-auto;
}

.score-badge {
  @apply px-2 py-1 rounded text-xs font-bold;
}
.score-safe {
  @apply bg-green-800 text-green-200;
}
.score-unsafe {
  @apply bg-red-800 text-red-200;
}
.score-unknown {
  @apply bg-yellow-800 text-yellow-200;
}

.row-safe {
  @apply bg-green-900/10;
}
.row-unsafe {
  @apply bg-red-900/10;
}

.label-select {
  @apply bg-gray-700 text-gray-100 px-2 py-1 rounded text-xs border border-gray-600;
}
.label-select.labeled {
  @apply border-blue-500;
}

code {
  @apply text-xs;
}

/* Phase 5 Styles */
.tab {
  @apply px-4 py-2 rounded-t text-sm font-medium transition-colors cursor-pointer;
  @apply text-gray-400 hover:text-gray-200 hover:bg-gray-800;
}
.tab.active {
  @apply text-white bg-gray-800 border-b-2 border-blue-500;
}

.input {
  @apply bg-gray-700 text-gray-100 px-3 py-2 rounded border border-gray-600;
  @apply focus:outline-none focus:border-blue-500;
}

.btn-sm {
  @apply px-3 py-1 text-xs;
}

.btn-danger {
  @apply bg-red-600 hover:bg-red-700 text-white;
}

.policy-rule-card {
  @apply bg-gray-800 p-4 rounded-lg border border-gray-700;
  @apply hover:border-gray-600 transition-colors;
}

.suggestion-card {
  @apply bg-gray-800 p-4 rounded-lg border-l-4;
}
.suggestion-card.status-pending {
  @apply border-yellow-500;
}
.suggestion-card.status-applied {
  @apply border-green-500;
}
.suggestion-card.status-rejected {
  @apply border-red-500;
}

.badge {
  @apply px-2 py-1 rounded text-xs font-bold;
}
.badge-pending {
  @apply bg-yellow-600 text-black;
}
.badge-applied {
  @apply bg-green-600 text-black;
}
.badge-rejected {
  @apply bg-red-600 text-white;
}

.agent-card {
  @apply bg-gray-800 p-4 rounded-lg border-l-4;
}
.agent-card.status-idle {
  @apply border-gray-500;
}
.agent-card.status-running {
  @apply border-green-500;
}
.agent-card.status-blocked {
  @apply border-red-500;
}

.status-badge {
  @apply px-2 py-1 rounded text-xs font-bold;
}
.status-badge.status-idle {
  @apply bg-gray-600 text-gray-200;
}
.status-badge.status-running {
  @apply bg-green-600 text-black;
}
.status-badge.status-blocked {
  @apply bg-red-600 text-white;
}
</style>
