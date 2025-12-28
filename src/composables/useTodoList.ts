/**
 * useTodoList - Claude Code-style task list management
 *
 * Provides reactive todo list for tracking AI agent progress
 */

import { ref, computed, watch } from 'vue'

export interface TodoItem {
  content: string
  status: 'pending' | 'in_progress' | 'completed'
  activeForm: string
}

// Shared state across components
const todos = ref<TodoItem[]>([])
const STORAGE_KEY = 'warp-open-todos'

// Load from localStorage on init
const savedTodos = localStorage.getItem(STORAGE_KEY)
if (savedTodos) {
  try {
    todos.value = JSON.parse(savedTodos)
  } catch {}
}

// Persist on change
watch(todos, (newTodos) => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(newTodos))
}, { deep: true })

export function useTodoList() {
  // Computed
  const completedCount = computed(() =>
    todos.value.filter(t => t.status === 'completed').length
  )

  const pendingCount = computed(() =>
    todos.value.filter(t => t.status === 'pending').length
  )

  const inProgressCount = computed(() =>
    todos.value.filter(t => t.status === 'in_progress').length
  )

  const progressPercent = computed(() => {
    if (!todos.value.length) return 0
    return Math.round((completedCount.value / todos.value.length) * 100)
  })

  const currentTask = computed(() => {
    const inProgress = todos.value.find(t => t.status === 'in_progress')
    return inProgress?.activeForm || null
  })

  // Actions
  function setTodos(newTodos: TodoItem[]) {
    todos.value = newTodos
  }

  function addTodo(todo: TodoItem) {
    todos.value.push(todo)
  }

  function addTodos(newTodos: TodoItem[]) {
    todos.value.push(...newTodos)
  }

  function updateTodo(index: number, updates: Partial<TodoItem>) {
    if (todos.value[index]) {
      todos.value[index] = { ...todos.value[index], ...updates }
    }
  }

  function updateTodoByContent(content: string, updates: Partial<TodoItem>) {
    const index = todos.value.findIndex(t => t.content === content)
    if (index >= 0) {
      updateTodo(index, updates)
    }
  }

  function removeTodo(index: number) {
    todos.value.splice(index, 1)
  }

  function clearTodos() {
    todos.value = []
  }

  function clearCompleted() {
    todos.value = todos.value.filter(t => t.status !== 'completed')
  }

  // Mark first pending as in_progress
  function startNextTask(): TodoItem | null {
    const pending = todos.value.find(t => t.status === 'pending')
    if (pending) {
      pending.status = 'in_progress'
      return pending
    }
    return null
  }

  // Mark current in_progress as completed
  function completeCurrentTask(): TodoItem | null {
    const inProgress = todos.value.find(t => t.status === 'in_progress')
    if (inProgress) {
      inProgress.status = 'completed'
      return inProgress
    }
    return null
  }

  // Tool interface for AI - matches Claude Code's TodoWrite tool
  function todoWrite(newTodos: TodoItem[]): { success: boolean; message: string } {
    setTodos(newTodos)
    return {
      success: true,
      message: `Updated todo list with ${newTodos.length} items`
    }
  }

  return {
    // State
    todos,
    completedCount,
    pendingCount,
    inProgressCount,
    progressPercent,
    currentTask,

    // Actions
    setTodos,
    addTodo,
    addTodos,
    updateTodo,
    updateTodoByContent,
    removeTodo,
    clearTodos,
    clearCompleted,
    startNextTask,
    completeCurrentTask,

    // Tool interface
    todoWrite
  }
}

export default useTodoList
