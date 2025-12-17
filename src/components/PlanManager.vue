<template>
  <div class="plan-manager p-4">
    <h2 class="text-lg font-bold mb-3">Long-Term Plan Manager</h2>

    <div class="controls flex gap-2 mb-4">
      <button @click="refreshPlans" class="btn px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600">Refresh</button>
      <button @click="createSamplePlan" class="btn px-3 py-1 bg-green-500 text-white rounded hover:bg-green-600">Create Sample Plan</button>
    </div>

    <div v-if="error" class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
      {{ error }}
    </div>

    <table v-if="plans.length > 0" class="w-full table-auto border-collapse">
      <thead>
        <tr class="bg-gray-100">
          <th class="border px-4 py-2 text-left">Plan ID</th>
          <th class="border px-4 py-2 text-left">Status</th>
          <th class="border px-4 py-2 text-left">Agents</th>
          <th class="border px-4 py-2 text-left">Progress</th>
          <th class="border px-4 py-2 text-left">Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="p in plans" :key="p.plan_id" class="hover:bg-gray-50">
          <td class="border px-4 py-2 font-mono text-sm">{{ p.plan_id.slice(0, 12) }}...</td>
          <td class="border px-4 py-2">
            <span :class="statusClass(p.status)" class="px-2 py-1 rounded text-xs font-semibold">
              {{ p.status }}
            </span>
          </td>
          <td class="border px-4 py-2">{{ p.agent_ids.join(', ') }}</td>
          <td class="border px-4 py-2">
            <div class="flex items-center gap-2">
              <div class="flex-1 bg-gray-200 rounded h-2">
                <div class="bg-blue-500 h-2 rounded" :style="{width: `${progressPercent(p)}%`}"></div>
              </div>
              <span class="text-sm">{{ p.next_task_index }} / {{ p.task_sequence.length }}</span>
            </div>
          </td>
          <td class="border px-4 py-2">
            <button @click="advancePlan(p)" 
                    :disabled="p.status !== 'pending' && p.status !== 'running'"
                    class="btn px-2 py-1 text-sm bg-purple-500 text-white rounded hover:bg-purple-600 disabled:bg-gray-300 disabled:cursor-not-allowed">
              Advance
            </button>
            <button @click="deletePlan(p.plan_id)" 
                    class="btn px-2 py-1 text-sm bg-red-500 text-white rounded hover:bg-red-600 ml-2">
              Delete
            </button>
          </td>
        </tr>
      </tbody>
    </table>

    <div v-else class="text-center text-gray-500 py-8">
      No plans found. Create a sample plan to get started.
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const plans = ref([])
const error = ref('')

function statusClass(status) {
  switch(status) {
    case 'pending': return 'bg-yellow-100 text-yellow-800'
    case 'running': return 'bg-blue-100 text-blue-800'
    case 'completed': return 'bg-green-100 text-green-800'
    case 'failed': return 'bg-red-100 text-red-800'
    default: return 'bg-gray-100 text-gray-800'
  }
}

function progressPercent(plan) {
  if (plan.task_sequence.length === 0) return 0
  return Math.round((plan.next_task_index / plan.task_sequence.length) * 100)
}

async function refreshPlans() {
  try {
    error.value = ''
    plans.value = await window.__TAURI__.invoke('phase6_get_pending_plans', { limit: 50 })
  } catch(e) {
    error.value = `Failed to fetch plans: ${e}`
    console.error("Failed to fetch plans:", e)
  }
}

async function createSamplePlan() {
  try {
    error.value = ''
    const plan = {
      plan_id: `plan_${Date.now()}`,
      created_at: new Date().toISOString(),
      status: 'pending',
      agent_ids: [1, 2],
      task_sequence: ['task1', 'task2', 'task3', 'task4'],
      next_task_index: 0,
      metadata: { description: 'Sample multi-day workflow' }
    }
    
    await window.__TAURI__.invoke('phase6_create_plan', { planJson: JSON.stringify(plan) })
    await refreshPlans()
  } catch(e) {
    error.value = `Failed to create plan: ${e}`
    console.error("Failed to create plan:", e)
  }
}

async function advancePlan(plan) {
  try {
    error.value = ''
    const newIndex = plan.next_task_index + 1
    await window.__TAURI__.invoke('phase6_update_plan_index', { 
      planId: plan.plan_id, 
      index: newIndex 
    })
    
    if (newIndex >= plan.task_sequence.length) {
      await window.__TAURI__.invoke('phase6_update_plan_status', { 
        planId: plan.plan_id, 
        status: 'completed' 
      })
    } else {
      await window.__TAURI__.invoke('phase6_update_plan_status', { 
        planId: plan.plan_id, 
        status: 'running' 
      })
    }
    
    await refreshPlans()
  } catch(e) {
    error.value = `Failed to advance plan: ${e}`
    console.error("Failed to advance plan:", e)
  }
}

async function deletePlan(planId) {
  if (!confirm('Are you sure you want to delete this plan?')) return
  
  try {
    error.value = ''
    await window.__TAURI__.invoke('phase6_delete_plan', { planId })
    await refreshPlans()
  } catch(e) {
    error.value = `Failed to delete plan: ${e}`
    console.error("Failed to delete plan:", e)
  }
}

onMounted(refreshPlans)
</script>

<style scoped>
.btn {
  transition: all 0.2s;
}
</style>
