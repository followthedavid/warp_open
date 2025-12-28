<template>
  <div class="todo-panel" :class="{ collapsed: isCollapsed }">
    <div class="todo-header" @click="toggleCollapsed">
      <div class="header-left">
        <span class="icon">{{ isCollapsed ? '▶' : '▼' }}</span>
        <span class="title">Tasks</span>
        <span class="count" v-if="todos.length">{{ completedCount }}/{{ todos.length }}</span>
      </div>
      <div class="header-right">
        <div class="progress-bar" v-if="todos.length">
          <div class="progress-fill" :style="{ width: progressPercent + '%' }"></div>
        </div>
      </div>
    </div>

    <div class="todo-list" v-if="!isCollapsed && todos.length">
      <div
        v-for="(todo, index) in todos"
        :key="index"
        class="todo-item"
        :class="[todo.status, { active: todo.status === 'in_progress' }]"
      >
        <span class="status-icon">
          <span v-if="todo.status === 'completed'" class="check">✓</span>
          <span v-else-if="todo.status === 'in_progress'" class="spinner">⟳</span>
          <span v-else class="pending">○</span>
        </span>
        <span class="todo-text">
          {{ todo.status === 'in_progress' ? todo.activeForm : todo.content }}
        </span>
      </div>
    </div>

    <div class="todo-empty" v-if="!isCollapsed && !todos.length">
      No active tasks
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'

export interface TodoItem {
  content: string
  status: 'pending' | 'in_progress' | 'completed'
  activeForm: string
}

// Reactive todo list - shared state
const todos = ref<TodoItem[]>([])
const isCollapsed = ref(false)

// Computed properties
const completedCount = computed(() =>
  todos.value.filter(t => t.status === 'completed').length
)

const progressPercent = computed(() => {
  if (!todos.value.length) return 0
  return Math.round((completedCount.value / todos.value.length) * 100)
})

// Methods
function toggleCollapsed() {
  isCollapsed.value = !isCollapsed.value
}

// Expose methods for external control
function setTodos(newTodos: TodoItem[]) {
  todos.value = newTodos
}

function addTodo(todo: TodoItem) {
  todos.value.push(todo)
}

function updateTodo(index: number, updates: Partial<TodoItem>) {
  if (todos.value[index]) {
    todos.value[index] = { ...todos.value[index], ...updates }
  }
}

function clearTodos() {
  todos.value = []
}

// Load from localStorage on mount
onMounted(() => {
  const saved = localStorage.getItem('warp-todos')
  if (saved) {
    try {
      todos.value = JSON.parse(saved)
    } catch {}
  }
})

// Save to localStorage on change
watch(todos, (newTodos) => {
  localStorage.setItem('warp-todos', JSON.stringify(newTodos))
}, { deep: true })

// Expose for parent components
defineExpose({
  todos,
  setTodos,
  addTodo,
  updateTodo,
  clearTodos,
  completedCount,
  progressPercent
})
</script>

<style scoped>
.todo-panel {
  background: var(--bg-secondary, #1a1a2e);
  border: 1px solid var(--border-color, #333);
  border-radius: 8px;
  margin: 8px;
  overflow: hidden;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 13px;
}

.todo-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  background: var(--bg-tertiary, #252540);
  cursor: pointer;
  user-select: none;
}

.todo-header:hover {
  background: var(--bg-hover, #2a2a4a);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.icon {
  font-size: 10px;
  color: var(--text-muted, #888);
}

.title {
  font-weight: 600;
  color: var(--text-primary, #fff);
}

.count {
  color: var(--text-muted, #888);
  font-size: 12px;
}

.header-right {
  flex: 1;
  max-width: 100px;
  margin-left: 16px;
}

.progress-bar {
  height: 4px;
  background: var(--bg-primary, #0d0d1a);
  border-radius: 2px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--accent-color, #4ade80);
  transition: width 0.3s ease;
}

.todo-list {
  padding: 8px 0;
}

.todo-item {
  display: flex;
  align-items: flex-start;
  padding: 6px 12px;
  gap: 8px;
  transition: background 0.15s;
}

.todo-item:hover {
  background: var(--bg-hover, rgba(255,255,255,0.03));
}

.todo-item.in_progress {
  background: var(--bg-active, rgba(74, 222, 128, 0.1));
}

.todo-item.completed {
  opacity: 0.6;
}

.status-icon {
  flex-shrink: 0;
  width: 16px;
  text-align: center;
}

.check {
  color: var(--success-color, #4ade80);
}

.spinner {
  color: var(--accent-color, #60a5fa);
  animation: spin 1s linear infinite;
  display: inline-block;
}

.pending {
  color: var(--text-muted, #666);
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.todo-text {
  color: var(--text-primary, #ddd);
  line-height: 1.4;
}

.todo-item.completed .todo-text {
  text-decoration: line-through;
  color: var(--text-muted, #888);
}

.todo-item.in_progress .todo-text {
  color: var(--accent-color, #4ade80);
}

.todo-empty {
  padding: 16px;
  text-align: center;
  color: var(--text-muted, #666);
  font-style: italic;
}

.collapsed .todo-list,
.collapsed .todo-empty {
  display: none;
}
</style>
