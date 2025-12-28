<template>
  <div class="inline-suggestion" v-if="visible && suggestion">
    <span class="suggestion-text">{{ suggestion }}</span>
    <span class="suggestion-hint">Tab to accept</span>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

const props = defineProps<{
  input: string
  visible: boolean
}>()

const emit = defineEmits<{
  (e: 'accept', suggestion: string): void
}>()

const suggestion = ref('')
const isGenerating = ref(false)
let debounceTimer: number | null = null
let abortController: AbortController | null = null

// Common command patterns for quick suggestions
const QUICK_PATTERNS: Record<string, string> = {
  'git s': 'git status',
  'git a': 'git add .',
  'git c': 'git commit -m ""',
  'git p': 'git push',
  'git l': 'git log --oneline -10',
  'git d': 'git diff',
  'git b': 'git branch',
  'npm i': 'npm install',
  'npm r': 'npm run',
  'npm t': 'npm test',
  'npm s': 'npm start',
  'cd ..': 'cd ..',
  'ls -': 'ls -la',
  'mkdir': 'mkdir -p',
  'rm -': 'rm -rf',
  'cat ': 'cat',
  'grep': 'grep -rn',
  'find': 'find . -name',
}

// Generate suggestion using local LLM
async function generateSuggestion(input: string) {
  if (!input || input.length < 2) {
    suggestion.value = ''
    return
  }

  // Check quick patterns first
  for (const [pattern, complete] of Object.entries(QUICK_PATTERNS)) {
    if (complete.startsWith(input) && complete !== input) {
      suggestion.value = complete.slice(input.length)
      return
    }
  }

  // Skip if already complete-looking
  if (input.endsWith(' ') || input.endsWith('\n')) {
    suggestion.value = ''
    return
  }

  isGenerating.value = true
  abortController = new AbortController()

  try {
    // Use Ollama for suggestion
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: `curl -s http://localhost:11434/api/generate -d '${JSON.stringify({
        model: 'qwen2.5-coder:1.5b',
        prompt: `Complete this shell command (respond with ONLY the completion, no explanation):\n${input}`,
        stream: false,
        options: { num_predict: 50, temperature: 0.3 }
      })}'`,
      cwd: undefined
    })

    if (result.stdout) {
      try {
        const response = JSON.parse(result.stdout)
        if (response.response) {
          // Extract just the completion part
          let completion = response.response.trim()

          // Remove the input if it's echoed back
          if (completion.toLowerCase().startsWith(input.toLowerCase())) {
            completion = completion.slice(input.length)
          }

          // Clean up
          completion = completion.split('\n')[0].trim()

          // Only show if it makes sense
          if (completion && completion.length < 100 && !completion.includes('```')) {
            suggestion.value = completion
          } else {
            suggestion.value = ''
          }
        }
      } catch {
        suggestion.value = ''
      }
    }
  } catch {
    suggestion.value = ''
  } finally {
    isGenerating.value = false
  }
}

// Watch input changes with debounce
watch(() => props.input, (newInput) => {
  if (debounceTimer) {
    clearTimeout(debounceTimer)
  }

  if (abortController) {
    abortController.abort()
  }

  suggestion.value = ''

  if (newInput && props.visible) {
    debounceTimer = window.setTimeout(() => {
      generateSuggestion(newInput)
    }, 300) // 300ms debounce
  }
})

// Handle Tab key to accept
function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Tab' && suggestion.value && props.visible) {
    e.preventDefault()
    emit('accept', props.input + suggestion.value)
    suggestion.value = ''
  }
}

onMounted(() => {
  document.addEventListener('keydown', handleKeydown)
})

onUnmounted(() => {
  document.removeEventListener('keydown', handleKeydown)
  if (debounceTimer) {
    clearTimeout(debounceTimer)
  }
})
</script>

<style scoped>
.inline-suggestion {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  color: var(--text-muted, #666);
  font-family: 'SF Mono', 'Fira Code', monospace;
  pointer-events: none;
}

.suggestion-text {
  opacity: 0.5;
  color: var(--text-muted, #888);
}

.suggestion-hint {
  font-size: 10px;
  padding: 2px 6px;
  background: var(--bg-tertiary, rgba(255,255,255,0.1));
  border-radius: 4px;
  color: var(--text-muted, #666);
}
</style>
