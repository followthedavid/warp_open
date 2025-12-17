/**
 * Toast Notification Composable
 *
 * Provides non-blocking toast notifications for user feedback.
 * Replaces console.error/warn with user-visible notifications.
 */

import { ref, computed } from 'vue'

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface Toast {
  id: string
  type: ToastType
  message: string
  title?: string
  duration: number
  timestamp: number
}

interface ToastOptions {
  title?: string
  duration?: number // ms, 0 = persistent
}

const DEFAULT_DURATION = 4000 // 4 seconds
const MAX_TOASTS = 5

// Global toast state
const toasts = ref<Toast[]>([])
let toastIdCounter = 0

export function useToast() {
  // Generate unique ID
  function generateId(): string {
    return `toast-${Date.now()}-${++toastIdCounter}`
  }

  // Add a toast notification
  function addToast(
    type: ToastType,
    message: string,
    options: ToastOptions = {}
  ): string {
    const id = generateId()
    const toast: Toast = {
      id,
      type,
      message,
      title: options.title,
      duration: options.duration ?? DEFAULT_DURATION,
      timestamp: Date.now()
    }

    // Add to beginning (newest first in display)
    toasts.value.unshift(toast)

    // Limit number of toasts
    if (toasts.value.length > MAX_TOASTS) {
      toasts.value = toasts.value.slice(0, MAX_TOASTS)
    }

    // Auto-dismiss if duration > 0
    if (toast.duration > 0) {
      setTimeout(() => {
        dismissToast(id)
      }, toast.duration)
    }

    return id
  }

  // Dismiss a toast by ID
  function dismissToast(id: string): void {
    const index = toasts.value.findIndex(t => t.id === id)
    if (index !== -1) {
      toasts.value.splice(index, 1)
    }
  }

  // Clear all toasts
  function clearAll(): void {
    toasts.value = []
  }

  // Convenience methods
  function success(message: string, options?: ToastOptions): string {
    return addToast('success', message, options)
  }

  function error(message: string, options?: ToastOptions): string {
    // Errors stay longer by default
    return addToast('error', message, { duration: 6000, ...options })
  }

  function warning(message: string, options?: ToastOptions): string {
    return addToast('warning', message, { duration: 5000, ...options })
  }

  function info(message: string, options?: ToastOptions): string {
    return addToast('info', message, options)
  }

  // Computed for active toasts (reversed for display order)
  const activeToasts = computed(() => toasts.value)

  return {
    toasts: activeToasts,
    addToast,
    dismissToast,
    clearAll,
    success,
    error,
    warning,
    info
  }
}
