<template>
  <div class="workflow-card" @click="$emit('execute', workflow)">
    <div class="card-header">
      <span class="workflow-icon">{{ workflow.icon || getDefaultIcon() }}</span>
      <div class="workflow-info">
        <h4>{{ workflow.name }}</h4>
        <p>{{ workflow.description }}</p>
      </div>
      <div class="card-actions" @click.stop>
        <button
          @click="$emit('toggle-favorite', workflow.id)"
          :class="['action-btn', { active: workflow.isFavorite }]"
          title="Toggle favorite"
        >
          {{ workflow.isFavorite ? '⭐' : '☆' }}
        </button>
        <button
          v-if="!workflow.isBuiltin"
          @click="$emit('edit', workflow)"
          class="action-btn"
          title="Edit"
        >
          ✏️
        </button>
        <button
          v-if="!workflow.isBuiltin"
          @click="$emit('delete', workflow)"
          class="action-btn danger"
          title="Delete"
        >
          🗑️
        </button>
      </div>
    </div>
    <div class="card-body">
      <code class="command-preview">{{ truncateCommand(workflow.command) }}</code>
    </div>
    <div class="card-footer">
      <div class="tags">
        <span v-for="tag in workflow.tags.slice(0, 3)" :key="tag" class="tag">
          {{ tag }}
        </span>
      </div>
      <span v-if="workflow.usageCount > 0" class="usage-count">
        {{ workflow.usageCount }} uses
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Workflow } from '../composables/useWorkflows'

const props = defineProps<{
  workflow: Workflow
}>()

defineEmits<{
  execute: [workflow: Workflow]
  'toggle-favorite': [id: string]
  edit: [workflow: Workflow]
  delete: [workflow: Workflow]
}>()

function getDefaultIcon(): string {
  switch (props.workflow.category) {
    case 'git': return ''
    case 'docker': return '🐳'
    case 'npm': return '📦'
    case 'system': return '💻'
    case 'network': return '🌐'
    default: return '⚡'
  }
}

function truncateCommand(cmd: string): string {
  const maxLen = 60
  return cmd.length > maxLen ? cmd.slice(0, maxLen) + '...' : cmd
}
</script>

<style scoped>
.workflow-card {
  background: #2a2a4a;
  border: 1px solid #3a3a5a;
  border-radius: 10px;
  padding: 14px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.workflow-card:hover {
  border-color: #6366f1;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
}

.card-header {
  display: flex;
  gap: 12px;
  margin-bottom: 12px;
}

.workflow-icon {
  font-size: 24px;
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #1a1a3a;
  border-radius: 8px;
  flex-shrink: 0;
}

.workflow-info {
  flex: 1;
  min-width: 0;
}

.workflow-info h4 {
  margin: 0 0 4px;
  font-size: 14px;
  font-weight: 600;
  color: #e0e0e0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.workflow-info p {
  margin: 0;
  font-size: 12px;
  color: #8080a0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.card-actions {
  display: flex;
  gap: 4px;
  opacity: 0;
  transition: opacity 0.2s;
}

.workflow-card:hover .card-actions {
  opacity: 1;
}

.action-btn {
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  cursor: pointer;
  border-radius: 4px;
  font-size: 14px;
  opacity: 0.6;
  transition: all 0.2s;
}

.action-btn:hover {
  background: #3a3a5a;
  opacity: 1;
}

.action-btn.active {
  opacity: 1;
}

.action-btn.danger:hover {
  background: rgba(239, 68, 68, 0.2);
}

.card-body {
  margin-bottom: 12px;
}

.command-preview {
  display: block;
  padding: 8px 10px;
  background: #1a1a3a;
  border-radius: 6px;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 11px;
  color: #a0a0c0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.card-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.tags {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.tag {
  padding: 2px 8px;
  background: #3a3a5a;
  border-radius: 12px;
  font-size: 10px;
  color: #a0a0c0;
}

.usage-count {
  font-size: 10px;
  color: #6060a0;
}
</style>
