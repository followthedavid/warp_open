<template>
  <div class="approval-panel">
    <div class="panel-header">
      <div class="header-left">
        <span class="panel-title">Approval Queue</span>
        <span v-if="approvals.length" class="count-badge">{{ approvals.length }}</span>
      </div>
      <button class="close-btn" @click="$emit('close')">×</button>
    </div>

    <div class="panel-content">
      <div v-if="approvals.length === 0" class="empty-state">
        <div class="empty-icon">✓</div>
        <div class="empty-text">No pending approvals</div>
        <div class="empty-subtext">The daemon is operating within safe parameters</div>
      </div>

      <div v-else class="approvals-list">
        <div
          v-for="approval in approvals"
          :key="approval.id"
          class="approval-item"
          :class="approval.riskLevel"
        >
          <div class="approval-header">
            <span class="approval-type">{{ formatType(approval.type) }}</span>
            <span class="risk-badge" :class="approval.riskLevel">
              {{ approval.riskLevel }}
            </span>
          </div>

          <div class="approval-action">{{ approval.action }}</div>

          <div v-if="approval.target" class="approval-target">
            <span class="target-label">Target:</span>
            <code>{{ approval.target }}</code>
          </div>

          <div class="approval-description">{{ approval.description }}</div>

          <div class="approval-meta">
            <span class="timestamp">{{ formatTime(approval.timestamp) }}</span>
            <span v-if="approval.expiresAt" class="expires">
              Expires: {{ formatRelativeTime(approval.expiresAt) }}
            </span>
          </div>

          <div class="approval-actions">
            <button class="reject-btn" @click="handleReject(approval.id)">
              Reject
            </button>
            <button
              class="approve-btn"
              :class="approval.riskLevel"
              @click="handleApprove(approval.id)"
            >
              {{ getApproveLabel(approval.riskLevel) }}
            </button>
          </div>
        </div>
      </div>

      <!-- Quick Actions -->
      <div v-if="approvals.length > 1" class="quick-actions">
        <button class="quick-btn reject-all" @click="rejectAll">
          Reject All
        </button>
        <button
          v-if="hasOnlyLowRisk"
          class="quick-btn approve-low"
          @click="approveAllLowRisk"
        >
          Approve Low-Risk
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { ApprovalRequest } from '../composables/useDaemonOrchestrator'

const props = defineProps<{
  approvals: ApprovalRequest[]
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'approve', approvalId: string): void
  (e: 'reject', approvalId: string): void
}>()

const hasOnlyLowRisk = computed(() =>
  props.approvals.every(a => a.riskLevel === 'low')
)

function formatType(type: string): string {
  return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function formatTime(date: Date): string {
  const d = new Date(date)
  return d.toLocaleString()
}

function formatRelativeTime(date: Date): string {
  const now = new Date()
  const d = new Date(date)
  const diff = d.getTime() - now.getTime()

  if (diff <= 0) return 'Expired'

  const minutes = Math.round(diff / 60000)
  if (minutes < 60) return `${minutes}m`

  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h`

  return `${Math.round(hours / 24)}d`
}

function getApproveLabel(riskLevel: string): string {
  switch (riskLevel) {
    case 'critical':
      return 'Approve (CRITICAL)'
    case 'high':
      return 'Approve (High Risk)'
    case 'medium':
      return 'Approve'
    default:
      return 'Approve'
  }
}

function handleApprove(id: string) {
  emit('approve', id)
}

function handleReject(id: string) {
  emit('reject', id)
}

function rejectAll() {
  for (const approval of props.approvals) {
    emit('reject', approval.id)
  }
}

function approveAllLowRisk() {
  for (const approval of props.approvals) {
    if (approval.riskLevel === 'low') {
      emit('approve', approval.id)
    }
  }
}
</script>

<style scoped>
.approval-panel {
  position: fixed;
  right: 16px;
  top: 60px;
  width: 420px;
  max-height: calc(100vh - 100px);
  background: var(--warp-bg-surface);
  border: 1px solid var(--warp-border);
  border-radius: var(--warp-radius-lg);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  z-index: 100;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: var(--warp-bg-elevated);
  border-bottom: 1px solid var(--warp-border-subtle);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.panel-title {
  font-weight: 600;
  font-size: 14px;
}

.count-badge {
  background: var(--warp-warning);
  color: white;
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
}

.close-btn {
  background: transparent;
  border: none;
  color: var(--warp-text-tertiary);
  font-size: 20px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 4px;
}

.close-btn:hover {
  background: var(--warp-bg-hover);
  color: var(--warp-text-primary);
}

.panel-content {
  padding: 16px;
  overflow-y: auto;
}

/* Empty State */
.empty-state {
  text-align: center;
  padding: 40px 20px;
}

.empty-icon {
  font-size: 48px;
  color: #22c55e;
  margin-bottom: 16px;
}

.empty-text {
  font-weight: 600;
  font-size: 16px;
  margin-bottom: 8px;
}

.empty-subtext {
  color: var(--warp-text-tertiary);
  font-size: 13px;
}

/* Approvals List */
.approvals-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.approval-item {
  background: var(--warp-bg-elevated);
  border-radius: 10px;
  padding: 14px;
  border-left: 3px solid;
}

.approval-item.low {
  border-left-color: #22c55e;
}

.approval-item.medium {
  border-left-color: #3b82f6;
}

.approval-item.high {
  border-left-color: #f59e0b;
}

.approval-item.critical {
  border-left-color: #ef4444;
  background: rgba(239, 68, 68, 0.05);
}

.approval-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.approval-type {
  font-size: 11px;
  text-transform: uppercase;
  color: var(--warp-text-tertiary);
  letter-spacing: 0.5px;
}

.risk-badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
  text-transform: uppercase;
}

.risk-badge.low {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}

.risk-badge.medium {
  background: rgba(59, 130, 246, 0.15);
  color: #3b82f6;
}

.risk-badge.high {
  background: rgba(245, 158, 11, 0.15);
  color: #f59e0b;
}

.risk-badge.critical {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.approval-action {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 8px;
}

.approval-target {
  font-size: 12px;
  margin-bottom: 6px;
  display: flex;
  gap: 6px;
  align-items: center;
}

.target-label {
  color: var(--warp-text-tertiary);
}

.approval-target code {
  background: var(--warp-bg-base);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-family: var(--warp-font-mono);
}

.approval-description {
  font-size: 13px;
  color: var(--warp-text-secondary);
  line-height: 1.4;
  margin-bottom: 10px;
}

.approval-meta {
  display: flex;
  gap: 16px;
  font-size: 11px;
  color: var(--warp-text-tertiary);
  margin-bottom: 12px;
}

.expires {
  color: #f59e0b;
}

.approval-actions {
  display: flex;
  gap: 8px;
}

.reject-btn,
.approve-btn {
  flex: 1;
  padding: 8px 12px;
  border: none;
  border-radius: 6px;
  font-weight: 600;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.2s;
}

.reject-btn {
  background: var(--warp-bg-base);
  color: var(--warp-text-secondary);
}

.reject-btn:hover {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}

.approve-btn {
  background: var(--warp-accent-primary);
  color: white;
}

.approve-btn:hover {
  opacity: 0.9;
}

.approve-btn.high {
  background: #f59e0b;
}

.approve-btn.critical {
  background: #ef4444;
}

/* Quick Actions */
.quick-actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--warp-border-subtle);
}

.quick-btn {
  flex: 1;
  padding: 10px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  font-size: 12px;
  cursor: pointer;
}

.quick-btn.reject-all {
  background: var(--warp-bg-elevated);
  color: var(--warp-text-secondary);
}

.quick-btn.reject-all:hover {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
}

.quick-btn.approve-low {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}

.quick-btn.approve-low:hover {
  background: rgba(34, 197, 94, 0.25);
}
</style>
