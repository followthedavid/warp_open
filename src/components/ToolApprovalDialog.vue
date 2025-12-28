<template>
  <div class="approval-overlay" v-if="visible" @click.self="handleDeny">
    <div class="approval-dialog" :class="riskLevel">
      <div class="dialog-header">
        <span class="risk-badge" :class="riskLevel">
          {{ riskLevel === 'high' ? '⚠️ High Risk' : riskLevel === 'medium' ? '⚡ Medium Risk' : '✓ Low Risk' }}
        </span>
        <span class="dialog-title">Tool Approval Required</span>
      </div>

      <div class="dialog-content">
        <div class="tool-info">
          <div class="tool-name">{{ toolName }}</div>
          <div class="tool-description">{{ description }}</div>
        </div>

        <div class="params-section" v-if="Object.keys(params).length">
          <div class="section-title">Parameters</div>
          <div class="params-list">
            <div v-for="(value, key) in params" :key="key" class="param-item">
              <span class="param-key">{{ key }}:</span>
              <code class="param-value">{{ formatValue(value) }}</code>
            </div>
          </div>
        </div>

        <div class="preview-section" v-if="preview">
          <div class="section-title">Preview</div>
          <pre class="preview-content">{{ preview }}</pre>
        </div>

        <div class="warning-section" v-if="warnings.length">
          <div class="section-title">⚠️ Warnings</div>
          <ul class="warnings-list">
            <li v-for="(warning, idx) in warnings" :key="idx">{{ warning }}</li>
          </ul>
        </div>
      </div>

      <div class="dialog-footer">
        <label class="remember-choice">
          <input type="checkbox" v-model="rememberChoice" />
          <span>Remember for this tool</span>
        </label>

        <div class="button-group">
          <button class="btn deny" @click="handleDeny">
            Deny
          </button>
          <button class="btn allow" @click="handleAllow">
            Allow
          </button>
          <button class="btn allow-always" @click="handleAllowAlways" v-if="riskLevel !== 'high'">
            Allow Always
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

export type RiskLevel = 'low' | 'medium' | 'high'
export type Decision = 'allow' | 'deny' | 'allow_always' | 'deny_always'

const props = defineProps<{
  visible: boolean
  toolName: string
  description?: string
  params: Record<string, unknown>
  preview?: string
  warnings?: string[]
  riskLevel: RiskLevel
}>()

const emit = defineEmits<{
  (e: 'decide', decision: Decision, remember: boolean): void
}>()

const rememberChoice = ref(false)

function formatValue(value: unknown): string {
  if (typeof value === 'string') {
    // Truncate long strings
    if (value.length > 100) {
      return value.slice(0, 100) + '...'
    }
    return value
  }
  return JSON.stringify(value, null, 2)
}

function handleAllow() {
  emit('decide', 'allow', rememberChoice.value)
}

function handleDeny() {
  emit('decide', 'deny', rememberChoice.value)
}

function handleAllowAlways() {
  emit('decide', 'allow_always', true)
}
</script>

<style scoped>
.approval-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.8);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(4px);
}

.approval-dialog {
  background: var(--bg-primary, #1a1a2e);
  border: 2px solid var(--border-color, #333);
  border-radius: 12px;
  width: 90%;
  max-width: 500px;
  max-height: 80vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.approval-dialog.high {
  border-color: var(--error-color, #f87171);
}

.approval-dialog.medium {
  border-color: var(--warning-color, #fbbf24);
}

.approval-dialog.low {
  border-color: var(--success-color, #4ade80);
}

.dialog-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 20px;
  background: var(--bg-secondary, #252540);
  border-bottom: 1px solid var(--border-color, #333);
}

.risk-badge {
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
}

.risk-badge.high {
  background: rgba(248, 113, 113, 0.2);
  color: var(--error-color, #f87171);
}

.risk-badge.medium {
  background: rgba(251, 191, 36, 0.2);
  color: var(--warning-color, #fbbf24);
}

.risk-badge.low {
  background: rgba(74, 222, 128, 0.2);
  color: var(--success-color, #4ade80);
}

.dialog-title {
  font-weight: 600;
  color: var(--text-primary, #fff);
  font-size: 14px;
}

.dialog-content {
  padding: 20px;
  overflow-y: auto;
  flex: 1;
}

.tool-info {
  margin-bottom: 16px;
}

.tool-name {
  font-size: 18px;
  font-weight: 600;
  color: var(--accent-color, #60a5fa);
  margin-bottom: 4px;
}

.tool-description {
  color: var(--text-muted, #888);
  font-size: 13px;
}

.section-title {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-muted, #666);
  margin-bottom: 8px;
}

.params-section,
.preview-section,
.warning-section {
  margin-bottom: 16px;
}

.params-list {
  background: var(--bg-secondary, #252540);
  border-radius: 6px;
  padding: 8px;
}

.param-item {
  display: flex;
  gap: 8px;
  padding: 4px 0;
  font-size: 12px;
}

.param-key {
  color: var(--text-muted, #888);
  min-width: 80px;
}

.param-value {
  color: var(--text-primary, #ddd);
  font-family: 'SF Mono', 'Fira Code', monospace;
  word-break: break-all;
}

.preview-content {
  background: var(--bg-secondary, #252540);
  border-radius: 6px;
  padding: 12px;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  color: var(--text-primary, #ddd);
  overflow-x: auto;
  max-height: 150px;
  margin: 0;
}

.warnings-list {
  margin: 0;
  padding-left: 20px;
  color: var(--warning-color, #fbbf24);
  font-size: 12px;
}

.warnings-list li {
  margin-bottom: 4px;
}

.dialog-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  background: var(--bg-secondary, #252540);
  border-top: 1px solid var(--border-color, #333);
}

.remember-choice {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--text-muted, #888);
  cursor: pointer;
}

.remember-choice input {
  cursor: pointer;
}

.button-group {
  display: flex;
  gap: 8px;
}

.btn {
  padding: 8px 16px;
  border-radius: 6px;
  font-weight: 500;
  font-size: 13px;
  cursor: pointer;
  border: none;
  transition: all 0.15s;
}

.btn.deny {
  background: transparent;
  color: var(--text-muted, #888);
  border: 1px solid var(--border-color, #333);
}

.btn.deny:hover {
  background: rgba(248, 113, 113, 0.1);
  color: var(--error-color, #f87171);
  border-color: var(--error-color, #f87171);
}

.btn.allow {
  background: var(--accent-color, #60a5fa);
  color: #000;
}

.btn.allow:hover {
  filter: brightness(1.1);
}

.btn.allow-always {
  background: var(--success-color, #4ade80);
  color: #000;
}

.btn.allow-always:hover {
  filter: brightness(1.1);
}
</style>
