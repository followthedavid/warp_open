<template>
  <div class="autonomy-settings">
    <div class="settings-header">
      <h3>⚙️ Phase 3: Full Autonomy Settings</h3>
      <button @click="togglePanel" class="close-btn">✕</button>
    </div>

    <div class="setting-group phase3-highlight">
      <label>
        <input type="checkbox" v-model="autoApproveEnabled" @change="saveSettings" />
        🎯 Auto-Approve Safe Batches (Phase 3)
      </label>
      <p class="hint">Automatically approve batches with all safe commands (score=100)</p>
    </div>

    <div class="setting-group phase3-highlight">
      <label>
        <input type="checkbox" v-model="autoExecuteEnabled" @change="saveSettings" :disabled="!autoApproveEnabled" />
        🚀 Auto-Execute Approved Batches (Phase 3)
      </label>
      <p class="hint">Automatically execute auto-approved batches (requires auto-approve)</p>
    </div>

    <div class="setting-group">
      <label>Autonomy Token (optional)</label>
      <input 
        type="text" 
        v-model="autonomyToken" 
        @change="saveSettings"
        placeholder="Leave empty for manual approval"
        class="token-input"
      />
      <p class="hint">Use a token to auto-approve safe batches</p>
    </div>

    <div class="setting-group">
      <label>Max Batch Size</label>
      <input 
        type="number" 
        v-model.number="maxBatchSize" 
        @change="saveSettings"
        min="1"
        max="20"
        class="number-input"
      />
      <p class="hint">Maximum commands per batch (1-20)</p>
    </div>

    <div class="setting-group">
      <label>Allow Patterns (one per line)</label>
      <textarea 
        v-model="allowPatterns" 
        @change="saveSettings"
        class="patterns-textarea"
        placeholder="brew install\napt install\nwhich\nls\ncat"
      ></textarea>
      <p class="hint">Patterns that are always safe</p>
    </div>

    <div class="setting-group">
      <label>Deny Patterns (one per line)</label>
      <textarea 
        v-model="denyPatterns" 
        @change="saveSettings"
        class="patterns-textarea"
        placeholder="rm -rf\ncurl.*\\|.*sh\nsudo\nssh"
      ></textarea>
      <p class="hint">Patterns that are always blocked</p>
    </div>

    <div class="setting-actions">
      <button @click="resetDefaults" class="reset-btn">Reset to Defaults</button>
      <button @click="exportSettings" class="export-btn">Export Settings</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

const emit = defineEmits(['close'])

const autoApproveEnabled = ref(false)
const autoExecuteEnabled = ref(false)
const autonomyToken = ref('')
const maxBatchSize = ref(10)
const allowPatterns = ref('')
const denyPatterns = ref('')

const defaultSettings = {
  autoApproveEnabled: false,
  autoExecuteEnabled: false,
  autonomyToken: '',
  maxBatchSize: 10,
  allowPatterns: `brew install
apt install
which
ls
cat
echo
pwd
whoami
uname
date`,
  denyPatterns: `rm -rf
curl.*\\|.*sh
sudo
ssh
scp
sftp
dd if=
mkfs
fdisk`
}

async function loadSettings() {
  // Try to load from backend first (Phase 3)
  try {
    const backendSettings = await invoke('get_autonomy_settings')
    console.log('[AutonomySettings] Loaded from backend:', backendSettings)
    autoApproveEnabled.value = backendSettings.auto_approve_enabled ?? false
    autoExecuteEnabled.value = backendSettings.auto_execute_enabled ?? false
    autonomyToken.value = backendSettings.autonomy_token ?? ''
  } catch (err) {
    console.warn('[AutonomySettings] Backend not available, using localStorage')
  }

  // Load UI-only settings from localStorage
  const stored = localStorage.getItem('warp_autonomy_settings')
  if (stored) {
    const settings = JSON.parse(stored)
    maxBatchSize.value = settings.maxBatchSize ?? defaultSettings.maxBatchSize
    allowPatterns.value = settings.allowPatterns ?? defaultSettings.allowPatterns
    denyPatterns.value = settings.denyPatterns ?? defaultSettings.denyPatterns
  } else {
    resetDefaults()
  }
}

async function saveSettings() {
  // Save Phase 3 settings to backend
  try {
    await invoke('update_autonomy_settings', {
      settings: {
        autonomy_token: autonomyToken.value || null,
        auto_approve_enabled: autoApproveEnabled.value,
        auto_execute_enabled: autoExecuteEnabled.value
      }
    })
    console.log('[AutonomySettings] Saved to backend')
  } catch (err) {
    console.error('[AutonomySettings] Failed to save to backend:', err)
  }

  // Save UI-only settings to localStorage
  const settings = {
    autoApproveEnabled: autoApproveEnabled.value,
    autoExecuteEnabled: autoExecuteEnabled.value,
    autonomyToken: autonomyToken.value,
    maxBatchSize: maxBatchSize.value,
    allowPatterns: allowPatterns.value,
    denyPatterns: denyPatterns.value
  }
  localStorage.setItem('warp_autonomy_settings', JSON.stringify(settings))
  console.log('[AutonomySettings] Saved settings:', settings)
}

function resetDefaults() {
  autoApproveEnabled.value = defaultSettings.autoApproveEnabled
  autoExecuteEnabled.value = defaultSettings.autoExecuteEnabled
  autonomyToken.value = defaultSettings.autonomyToken
  maxBatchSize.value = defaultSettings.maxBatchSize
  allowPatterns.value = defaultSettings.allowPatterns
  denyPatterns.value = defaultSettings.denyPatterns
  saveSettings()
}

function exportSettings() {
  const settings = {
    autoApproveEnabled: autoApproveEnabled.value,
    autoExecuteEnabled: autoExecuteEnabled.value,
    autonomyToken: autonomyToken.value,
    maxBatchSize: maxBatchSize.value,
    allowPatterns: allowPatterns.value,
    denyPatterns: denyPatterns.value
  }
  const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'warp_autonomy_settings.json'
  a.click()
  URL.revokeObjectURL(url)
}

function togglePanel() {
  emit('close')
}

onMounted(() => {
  loadSettings()
})

// Watch for auto-execute being enabled without auto-approve
watch(autoExecuteEnabled, (newVal) => {
  if (newVal && !autoApproveEnabled.value) {
    autoExecuteEnabled.value = false
    console.warn('[AutonomySettings] Cannot enable auto-execute without auto-approve')
  }
})

// Expose settings for parent components
defineExpose({
  autoApproveEnabled,
  autoExecuteEnabled,
  autonomyToken,
  maxBatchSize,
  allowPatterns,
  denyPatterns
})
</script>

<style scoped>
.autonomy-settings {
  background: #1a1a1a;
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 8px;
  padding: 16px;
  margin-top: 12px;
  max-width: 600px;
}

.settings-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.settings-header h3 {
  margin: 0;
  font-size: 14px;
  color: #d4d4d4;
}

.close-btn {
  background: transparent;
  border: none;
  color: #888;
  font-size: 18px;
  cursor: pointer;
  padding: 4px 8px;
}

.close-btn:hover {
  color: #d4d4d4;
}

.setting-group {
  margin-bottom: 16px;
}

.setting-group label {
  display: block;
  font-size: 13px;
  color: #d4d4d4;
  margin-bottom: 6px;
}

.setting-group input[type="checkbox"] {
  margin-right: 8px;
}

.token-input, .number-input {
  width: 100%;
  padding: 8px;
  background: #0f172a;
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 4px;
  color: #d4d4d4;
  font-family: monospace;
  font-size: 13px;
}

.number-input {
  width: 100px;
}

.patterns-textarea {
  width: 100%;
  min-height: 100px;
  padding: 8px;
  background: #0f172a;
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 4px;
  color: #d4d4d4;
  font-family: monospace;
  font-size: 12px;
  resize: vertical;
}

.hint {
  font-size: 11px;
  color: #888;
  margin: 4px 0 0 0;
}

.setting-actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}

.reset-btn, .export-btn {
  padding: 8px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.reset-btn {
  background: #6b7280;
  color: white;
}

.reset-btn:hover {
  background: #9ca3af;
}

.export-btn {
  background: #3b82f6;
  color: white;
}

.export-btn:hover {
  background: #4a9eff;
}

.phase3-highlight {
  background: rgba(34, 197, 94, 0.05);
  border: 1px solid rgba(34, 197, 94, 0.2);
  border-radius: 6px;
  padding: 12px;
}

.phase3-highlight label {
  font-weight: 600;
  color: #22c55e;
}

.setting-group input[type="checkbox"]:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
