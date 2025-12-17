<template>
  <div class="input-area">
    <textarea
      ref="inputRef"
      v-model="input"
      @keydown="handleKeyDown"
      :placeholder="placeholder"
      rows="1"
      autofocus
    ></textarea>
    <button @click="sendMessage" :disabled="!input.trim()" class="send-btn">
      <span v-if="!sending">Send</span>
      <span v-else>...</span>
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, nextTick } from 'vue'

const emit = defineEmits<{
  (e: 'send', message: string): void
}>()

const input = ref('')
const inputRef = ref<HTMLTextAreaElement | null>(null)
const sending = ref(false)

const placeholder = computed(() => {
  return 'Type a message or /shell <command> to execute terminal commands...'
})

function handleKeyDown(e: KeyboardEvent) {
  // Enter without shift sends message
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault()
    sendMessage()
  }
  
  // Auto-resize textarea
  nextTick(() => {
    if (inputRef.value) {
      inputRef.value.style.height = 'auto'
      inputRef.value.style.height = inputRef.value.scrollHeight + 'px'
    }
  })
}

async function sendMessage() {
  if (!input.value.trim() || sending.value) return
  
  const message = input.value.trim()
  input.value = ''
  
  // Reset textarea height
  if (inputRef.value) {
    inputRef.value.style.height = 'auto'
  }
  
  sending.value = true
  emit('send', message)
  
  // Reset sending state after a short delay
  setTimeout(() => {
    sending.value = false
  }, 500)
}

// Focus input on mount
nextTick(() => {
  inputRef.value?.focus()
})
</script>

<style scoped>
.input-area {
  display: flex;
  align-items: flex-end;
  gap: 8px;
  padding: 12px;
  background-color: #1e1e1e;
  border-top: 1px solid #404040;
}

textarea {
  flex: 1;
  min-height: 40px;
  max-height: 200px;
  padding: 10px 12px;
  background-color: #2d2d2d;
  color: #e0e0e0;
  border: 1px solid #404040;
  border-radius: 8px;
  font-size: 14px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
  line-height: 1.4;
  resize: none;
  outline: none;
  transition: border-color 0.2s;
}

textarea:focus {
  border-color: #0084ff;
}

textarea::placeholder {
  color: #666;
}

.send-btn {
  padding: 10px 20px;
  background-color: #0084ff;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: background-color 0.2s, opacity 0.2s;
  white-space: nowrap;
}

.send-btn:hover:not(:disabled) {
  background-color: #0073e6;
}

.send-btn:active:not(:disabled) {
  background-color: #0062cc;
}

.send-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
