<template>
  <div class="batch-panel" v-if="batches && batches.length">
    <div class="panel-header">
      <h3>🔧 Phase 3: Command Batches</h3>
      <button @click="refreshBatches" class="refresh-btn">🔄 Refresh</button>
    </div>

    <div v-for="batch in batches" :key="batch.id" class="batch-card" :class="{ 'auto-approved-batch': batch.auto_approved }">
      <div class="batch-header">
        <div class="batch-info">
          <span class="batch-id">Batch: {{ batch.id.substring(0, 8) }}</span>
          <span v-if="batch.auto_approved" class="auto-badge" title="Auto-approved by Phase 3">🎯 AUTO</span>
          <span v-if="batch.depends_on" class="dependency-badge" :title="'Depends on: ' + batch.depends_on.substring(0, 8)">🔗 DEP</span>
        </div>
        <span :class="['status', statusClass(batch.status)]">{{ batch.status }}</span>
      </div>

      <ul class="entry-list">
        <li v-for="entry in batch.entries" :key="entry.id" :class="entryClass(entry)">
          <span class="tool-icon">{{ toolIcon(entry.tool) }}</span>
          <code class="tool-name">{{ entry.tool }}</code>
          <code class="tool-args">{{ formatArgs(entry.args) }}</code>
          <span :class="['safety-badge', safetyClass(entry.safe_score)]">
            {{ safetyLabel(entry.safe_score) }}
          </span>
          <span v-if="entry.result" class="result-preview" :title="entry.result">
            ✓ {{ entry.result.substring(0, 30) }}...
          </span>
        </li>
      </ul>

      <div class="batch-actions">
        <button 
          v-if="batch.status === 'Pending'"
          @click="approveBatch(batch.id)"
          class="approve-btn"
        >
          ✓ Approve
        </button>
        <button 
          v-if="batch.status === 'Pending' || batch.status === 'Approved'"
          @click="runBatch(batch.id)"
          class="run-btn"
          :disabled="isBlocked(batch)"
          :title="isBlocked(batch) ? 'Blocked by dependency' : 'Execute batch'"
        >
          ▶ Run
        </button>
        <button
          v-if="batch.status === 'Completed' || batch.status === 'Error'"
          @click="rollbackBatch(batch.id)"
          class="rollback-btn"
          title="Rollback changes"
        >
          ↩️ Rollback
        </button>
        <span v-if="batch.status === 'Running'" class="spinner">⌛ Running...</span>
        <span v-if="batch.status === 'Completed'" class="completed">✅ Complete</span>
        <span v-if="batch.status === 'Error'" class="error">❌ Error</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { listen } from '@tauri-apps/api/event'

interface BatchEntry {
  id: string
  tool: string
  args: any
  status: string
  result: string | null
  safe_score: number
  requires_manual: boolean
}

interface Batch {
  id: string
  entries: BatchEntry[]
  status: string
  creator_tab: number
  approved_by: string | null
  auto_approved: boolean
  depends_on: string | null
}

const batches = ref<Batch[]>([])

async function refreshBatches() {
  try {
    batches.value = await invoke('get_batches')
    console.log('[BatchPanel] Loaded', batches.value.length, 'batches')
  } catch (e) {
    console.error('[BatchPanel] Failed to load batches:', e)
  }
}

async function approveBatch(batchId: string) {
  try {
    await invoke('approve_batch', { batchId, autonomyToken: null })
    await refreshBatches()
  } catch (e) {
    console.error('[BatchPanel] Failed to approve batch:', e)
  }
}

async function runBatch(batchId: string) {
  try {
    await invoke('run_batch', { batchId, autonomyToken: null })
    await refreshBatches()
  } catch (e) {
    console.error('[BatchPanel] Failed to run batch:', e)
    alert('Failed to run batch: ' + e)
  }
}

async function rollbackBatch(batchId: string) {
  if (!confirm('Rollback this batch? This will attempt to undo file changes.')) {
    return
  }
  
  try {
    const result = await invoke('rollback_batch', { batchId })
    console.log('[BatchPanel] Rollback result:', result)
    alert('Rollback completed:\n' + result)
    await refreshBatches()
  } catch (e) {
    console.error('[BatchPanel] Failed to rollback batch:', e)
    alert('Failed to rollback: ' + e)
  }
}

function isBlocked(batch: Batch): boolean {
  if (!batch.depends_on) return false
  
  // Find parent batch
  const parent = batches.value.find(b => b.id === batch.depends_on)
  if (!parent) return true // Parent not found = blocked
  
  // Blocked if parent not completed
  return parent.status !== 'Completed'
}

function statusClass(status: string) {
  return status.toLowerCase()
}

function entryClass(entry: BatchEntry) {
  if (entry.safe_score === 0) return 'entry-blocked'
  if (entry.safe_score === 100) return 'entry-safe'
  return 'entry-manual'
}

function safetyClass(score: number) {
  if (score === 0) return 'blocked'
  if (score === 100) return 'safe'
  return 'manual'
}

function safetyLabel(score: number) {
  if (score === 0) return '🔴 BLOCKED'
  if (score === 100) return '🟢 SAFE'
  return '🟡 MANUAL'
}

function toolIcon(tool: string) {
  if (tool === 'execute_shell') return '🔧'
  if (tool === 'read_file') return '📖'
  if (tool === 'write_file') return '✏️'
  return '🔹'
}

function formatArgs(args: any): string {
  if (args.command) return args.command
  if (args.path) return args.path
  return JSON.stringify(args)
}

onMounted(async () => {
  await refreshBatches()
  
  // Listen for batch updates
  await listen('batch_updated', async () => {
    console.log('[BatchPanel] Batch updated, refreshing...')
    await refreshBatches()
  })
  
  // Listen for batch creation (Phase 3)
  await listen('batch_created', async (event: any) => {
    console.log('[BatchPanel] Batch created:', event.payload)
    await refreshBatches()
  })
  
  // Listen for rollback completion
  await listen('batch_rolled_back', async (event: any) => {
    console.log('[BatchPanel] Batch rolled back:', event.payload)
  })
})
</script>

<style scoped>
.batch-panel {
  background: rgba(0,0,0,0.04);
  padding: 10px;
  border-radius: 8px;
  margin-top: 12px;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.panel-header h3 {
  margin: 0;
  font-size: 14px;
  color: #d4d4d4;
}

.refresh-btn {
  padding: 6px 10px;
  background-color: #2d2d2d;
  color: #d4d4d4;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.refresh-btn:hover {
  background-color: #4a9eff;
}

.batch-card {
  background: #1a1a1a;
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  padding: 10px;
  margin-bottom: 10px;
}

.batch-card.auto-approved-batch {
  border: 2px solid rgba(34, 197, 94, 0.3);
  background: rgba(34, 197, 94, 0.05);
}

.batch-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.batch-info {
  display: flex;
  gap: 8px;
  align-items: center;
}

.batch-id {
  font-size: 12px;
  color: #888;
  font-family: monospace;
}

.auto-badge {
  font-size: 10px;
  padding: 2px 6px;
  background: #22c55e;
  color: white;
  border-radius: 3px;
  font-weight: bold;
}

.dependency-badge {
  font-size: 10px;
  padding: 2px 6px;
  background: #f59e0b;
  color: white;
  border-radius: 3px;
  font-weight: bold;
}

.status {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: bold;
  text-transform: uppercase;
}

.status.pending { background: #3b82f6; color: white; }
.status.approved { background: #10b981; color: white; }
.status.running { background: #f59e0b; color: white; }
.status.completed { background: #22c55e; color: white; }
.status.rejected { background: #ef4444; color: white; }
.status.error { background: #dc2626; color: white; }

.entry-list {
  list-style: none;
  padding: 0;
  margin: 8px 0;
}

.entry-list li {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px;
  border-bottom: 1px solid rgba(255,255,255,0.05);
}

.entry-blocked { opacity: 0.5; }
.entry-safe { background: rgba(34, 197, 94, 0.1); }
.entry-manual { background: rgba(245, 158, 11, 0.1); }

.tool-icon {
  font-size: 14px;
}

.tool-name {
  font-family: monospace;
  font-size: 12px;
  color: #4a9eff;
}

.tool-args {
  font-family: monospace;
  font-size: 11px;
  color: #d4d4d4;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.safety-badge {
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: bold;
}

.safety-badge.safe { background: #22c55e; color: white; }
.safety-badge.manual { background: #f59e0b; color: white; }
.safety-badge.blocked { background: #dc2626; color: white; }

.result-preview {
  font-size: 10px;
  color: #888;
  font-family: monospace;
}

.batch-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-top: 8px;
}

.approve-btn, .run-btn, .rollback-btn {
  padding: 6px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.approve-btn:disabled, .run-btn:disabled, .rollback-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.approve-btn {
  background: #10b981;
  color: white;
}

.approve-btn:hover {
  background: #22c55e;
}

.run-btn {
  background: #3b82f6;
  color: white;
}

.run-btn:hover:not(:disabled) {
  background: #4a9eff;
}

.rollback-btn {
  background: #ef4444;
  color: white;
}

.rollback-btn:hover:not(:disabled) {
  background: #dc2626;
}

.spinner, .completed, .error {
  font-size: 12px;
}

.spinner { color: #f59e0b; }
.completed { color: #22c55e; font-weight: bold; }
.error { color: #dc2626; font-weight: bold; }
</style>
