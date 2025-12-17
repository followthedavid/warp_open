<template>
  <Teleport to="body">
    <div class="toast-container" v-if="toasts.length > 0">
      <TransitionGroup name="toast">
        <div
          v-for="toast in toasts"
          :key="toast.id"
          :class="['toast', `toast-${toast.type}`]"
          @click="dismissToast(toast.id)"
        >
          <div class="toast-icon">
            <span v-if="toast.type === 'success'">&#10003;</span>
            <span v-else-if="toast.type === 'error'">&#10007;</span>
            <span v-else-if="toast.type === 'warning'">&#9888;</span>
            <span v-else>&#8505;</span>
          </div>
          <div class="toast-content">
            <div v-if="toast.title" class="toast-title">{{ toast.title }}</div>
            <div class="toast-message">{{ toast.message }}</div>
          </div>
          <button class="toast-dismiss" @click.stop="dismissToast(toast.id)" title="Dismiss">
            &times;
          </button>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { useToast } from '../composables/useToast'

const { toasts, dismissToast } = useToast()
</script>

<style scoped>
.toast-container {
  position: fixed;
  bottom: 20px;
  right: 20px;
  z-index: 10000;
  display: flex;
  flex-direction: column-reverse;
  gap: 10px;
  max-width: 400px;
  pointer-events: none;
}

.toast {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 8px;
  background: var(--bg-secondary, #2a2a3e);
  border: 1px solid var(--border-color, #3a3a4e);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  cursor: pointer;
  pointer-events: auto;
  min-width: 280px;
  max-width: 400px;
}

.toast:hover {
  filter: brightness(1.1);
}

.toast-icon {
  font-size: 18px;
  line-height: 1;
  flex-shrink: 0;
  width: 24px;
  text-align: center;
}

.toast-success {
  border-left: 4px solid #4caf50;
}

.toast-success .toast-icon {
  color: #4caf50;
}

.toast-error {
  border-left: 4px solid #f44336;
}

.toast-error .toast-icon {
  color: #f44336;
}

.toast-warning {
  border-left: 4px solid #ff9800;
}

.toast-warning .toast-icon {
  color: #ff9800;
}

.toast-info {
  border-left: 4px solid #2196f3;
}

.toast-info .toast-icon {
  color: #2196f3;
}

.toast-content {
  flex: 1;
  min-width: 0;
}

.toast-title {
  font-weight: 600;
  font-size: 14px;
  color: var(--text-primary, #fff);
  margin-bottom: 4px;
}

.toast-message {
  font-size: 13px;
  color: var(--text-secondary, #aaa);
  line-height: 1.4;
  word-wrap: break-word;
}

.toast-dismiss {
  background: none;
  border: none;
  color: var(--text-secondary, #888);
  font-size: 20px;
  cursor: pointer;
  padding: 0;
  line-height: 1;
  opacity: 0.6;
  transition: opacity 0.2s;
}

.toast-dismiss:hover {
  opacity: 1;
  color: var(--text-primary, #fff);
}

/* Transition animations */
.toast-enter-active,
.toast-leave-active {
  transition: all 0.3s ease;
}

.toast-enter-from {
  opacity: 0;
  transform: translateX(100%);
}

.toast-leave-to {
  opacity: 0;
  transform: translateX(100%);
}

.toast-move {
  transition: transform 0.3s ease;
}
</style>
