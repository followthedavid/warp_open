<template>
  <Teleport to="body">
    <div v-if="isVisible && hasSession" class="recovery-overlay">
      <div class="recovery-dialog">
        <div class="dialog-icon">🔄</div>
        <h3>Recover Previous Session?</h3>
        <p class="dialog-info">
          Found a previous session from {{ formatTime(sessionTime) }}
        </p>
        <div class="session-details">
          <div class="detail-item">
            <span class="detail-label">Tabs:</span>
            <span class="detail-value">{{ tabCount }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Working Dirs:</span>
            <span class="detail-value">{{ cwdCount }}</span>
          </div>
        </div>
        <div class="dialog-actions">
          <button class="btn-recover" @click="handleRecover">
            Recover Session
          </button>
          <button class="btn-dismiss" @click="handleDismiss">
            Start Fresh
          </button>
        </div>
        <label class="auto-recover-option">
          <input
            type="checkbox"
            v-model="autoRecoverEnabled"
            @change="updateAutoRecover"
          />
          <span>Auto-recover next time</span>
        </label>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useSessionStore } from '../composables/useSessionStore'

const props = defineProps<{
  isVisible: boolean
}>()

const emit = defineEmits(['recover', 'dismiss'])

const sessionStore = useSessionStore()
const autoRecoverEnabled = ref(false)

// Load auto-recover preference
onMounted(() => {
  const stored = localStorage.getItem('warp_auto_recover')
  autoRecoverEnabled.value = stored === 'true'
})

const hasSession = computed(() => sessionStore.hasRecoverableSession())

const session = computed(() => sessionStore.getPersistedSession())

const sessionTime = computed(() => session.value?.timestamp || 0)
const tabCount = computed(() => session.value?.tabs.length || 0)
const cwdCount = computed(() => Object.keys(session.value?.lastKnownCwds || {}).length)

function formatTime(timestamp: number): string {
  if (!timestamp) return 'unknown time'
  const date = new Date(timestamp)
  const now = new Date()
  const diff = now.getTime() - timestamp

  if (diff < 60000) return 'just now'
  if (diff < 3600000) {
    const mins = Math.floor(diff / 60000)
    return `${mins} minute${mins !== 1 ? 's' : ''} ago`
  }
  if (diff < 86400000) {
    const hours = Math.floor(diff / 3600000)
    return `${hours} hour${hours !== 1 ? 's' : ''} ago`
  }

  return date.toLocaleString()
}

function handleRecover() {
  emit('recover', session.value)
}

function handleDismiss() {
  sessionStore.clearSession()
  emit('dismiss')
}

function updateAutoRecover() {
  localStorage.setItem('warp_auto_recover', String(autoRecoverEnabled.value))
}
</script>

<style scoped>
.recovery-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.8);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2000;
}

.recovery-dialog {
  background: #1a1f2e;
  border-radius: 12px;
  padding: 24px;
  max-width: 400px;
  text-align: center;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
}

.dialog-icon {
  font-size: 48px;
  margin-bottom: 12px;
}

.recovery-dialog h3 {
  margin: 0 0 8px 0;
  font-size: 18px;
  font-weight: 600;
  color: #e2e8f0;
}

.dialog-info {
  color: #94a3b8;
  font-size: 14px;
  margin: 0 0 16px 0;
}

.session-details {
  display: flex;
  justify-content: center;
  gap: 24px;
  margin-bottom: 20px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 12px;
  color: #64748b;
}

.detail-value {
  font-size: 24px;
  font-weight: 600;
  color: #60a5fa;
}

.dialog-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin-bottom: 16px;
}

.btn-recover {
  padding: 10px 24px;
  background: linear-gradient(135deg, #3b82f6, #6366f1);
  border: none;
  border-radius: 6px;
  color: white;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-recover:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
}

.btn-dismiss {
  padding: 10px 24px;
  background: transparent;
  border: 1px solid #334155;
  border-radius: 6px;
  color: #94a3b8;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-dismiss:hover {
  background: #334155;
  color: #e2e8f0;
}

.auto-recover-option {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-size: 12px;
  color: #64748b;
  cursor: pointer;
}

.auto-recover-option input {
  cursor: pointer;
}
</style>
