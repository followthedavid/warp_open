<template>
  <div class="ask-question-modal" v-if="visible" @click.self="handleCancel">
    <div class="modal-content">
      <div class="modal-header">
        <span class="header-icon">❓</span>
        <span class="header-title">Question from AI</span>
      </div>

      <div class="questions-container">
        <div v-for="(q, qIndex) in questions" :key="qIndex" class="question-block">
          <div class="question-header" v-if="q.header">
            <span class="header-chip">{{ q.header }}</span>
          </div>
          <div class="question-text">{{ q.question }}</div>

          <div class="options-list" :class="{ 'multi-select': q.multiSelect }">
            <button
              v-for="(opt, oIndex) in q.options"
              :key="oIndex"
              class="option-btn"
              :class="{ selected: isSelected(qIndex, oIndex) }"
              @click="toggleOption(qIndex, oIndex, q.multiSelect)"
            >
              <span class="option-check" v-if="q.multiSelect">
                {{ isSelected(qIndex, oIndex) ? '☑' : '☐' }}
              </span>
              <span class="option-radio" v-else>
                {{ isSelected(qIndex, oIndex) ? '●' : '○' }}
              </span>
              <div class="option-content">
                <span class="option-label">{{ opt.label }}</span>
                <span class="option-desc" v-if="opt.description">{{ opt.description }}</span>
              </div>
            </button>

            <!-- Other option -->
            <button
              class="option-btn other"
              :class="{ selected: otherSelected[qIndex] }"
              @click="toggleOther(qIndex)"
            >
              <span class="option-radio">{{ otherSelected[qIndex] ? '●' : '○' }}</span>
              <div class="option-content">
                <span class="option-label">Other</span>
                <span class="option-desc">Provide custom input</span>
              </div>
            </button>

            <div class="other-input-container" v-if="otherSelected[qIndex]">
              <input
                type="text"
                class="other-input"
                v-model="otherText[qIndex]"
                placeholder="Enter your response..."
                @keyup.enter="handleSubmit"
              />
            </div>
          </div>
        </div>
      </div>

      <div class="modal-footer">
        <button class="btn cancel" @click="handleCancel">Cancel</button>
        <button class="btn submit" @click="handleSubmit" :disabled="!canSubmit">
          Submit
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'

export interface QuestionOption {
  label: string
  description?: string
}

export interface Question {
  question: string
  header?: string
  options: QuestionOption[]
  multiSelect?: boolean
}

const props = defineProps<{
  visible: boolean
  questions: Question[]
}>()

const emit = defineEmits<{
  (e: 'submit', answers: Record<string, string | string[]>): void
  (e: 'cancel'): void
}>()

// Selection state - maps question index to selected option indices
const selections = ref<Map<number, Set<number>>>(new Map())
const otherSelected = ref<Record<number, boolean>>({})
const otherText = ref<Record<number, string>>({})

// Reset when questions change
watch(() => props.questions, () => {
  selections.value = new Map()
  otherSelected.value = {}
  otherText.value = {}
}, { immediate: true })

function isSelected(qIndex: number, oIndex: number): boolean {
  return selections.value.get(qIndex)?.has(oIndex) ?? false
}

function toggleOption(qIndex: number, oIndex: number, multiSelect?: boolean) {
  if (!selections.value.has(qIndex)) {
    selections.value.set(qIndex, new Set())
  }

  const selected = selections.value.get(qIndex)!

  if (multiSelect) {
    // Toggle for multi-select
    if (selected.has(oIndex)) {
      selected.delete(oIndex)
    } else {
      selected.add(oIndex)
    }
  } else {
    // Single select - clear others
    selected.clear()
    selected.add(oIndex)
    otherSelected.value[qIndex] = false
  }

  selections.value = new Map(selections.value) // Trigger reactivity
}

function toggleOther(qIndex: number) {
  if (!props.questions[qIndex].multiSelect) {
    // Single select - clear other options
    selections.value.set(qIndex, new Set())
  }
  otherSelected.value[qIndex] = !otherSelected.value[qIndex]
}

const canSubmit = computed(() => {
  // Every question must have at least one selection or other text
  return props.questions.every((q, qIndex) => {
    const hasSelection = (selections.value.get(qIndex)?.size ?? 0) > 0
    const hasOther = otherSelected.value[qIndex] && otherText.value[qIndex]?.trim()
    return hasSelection || hasOther
  })
})

function handleSubmit() {
  if (!canSubmit.value) return

  const answers: Record<string, string | string[]> = {}

  props.questions.forEach((q, qIndex) => {
    const key = q.header || `question_${qIndex}`
    const selectedIndices = Array.from(selections.value.get(qIndex) || [])
    const selectedLabels = selectedIndices.map(i => q.options[i]?.label || '')

    if (otherSelected.value[qIndex] && otherText.value[qIndex]?.trim()) {
      selectedLabels.push(otherText.value[qIndex].trim())
    }

    if (q.multiSelect) {
      answers[key] = selectedLabels
    } else {
      answers[key] = selectedLabels[0] || ''
    }
  })

  emit('submit', answers)
}

function handleCancel() {
  emit('cancel')
}
</script>

<style scoped>
.ask-question-modal {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(4px);
}

.modal-content {
  background: var(--bg-primary, #1a1a2e);
  border: 1px solid var(--border-color, #333);
  border-radius: 12px;
  width: 90%;
  max-width: 500px;
  max-height: 80vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 20px;
  background: var(--bg-secondary, #252540);
  border-bottom: 1px solid var(--border-color, #333);
}

.header-icon {
  font-size: 18px;
}

.header-title {
  font-weight: 600;
  color: var(--text-primary, #fff);
  font-size: 16px;
}

.questions-container {
  padding: 20px;
  overflow-y: auto;
  flex: 1;
}

.question-block {
  margin-bottom: 24px;
}

.question-block:last-child {
  margin-bottom: 0;
}

.question-header {
  margin-bottom: 8px;
}

.header-chip {
  display: inline-block;
  padding: 4px 10px;
  background: var(--accent-color, #60a5fa);
  color: #000;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.question-text {
  color: var(--text-primary, #fff);
  font-size: 15px;
  margin-bottom: 16px;
  line-height: 1.5;
}

.options-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.option-btn {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 16px;
  background: var(--bg-secondary, #252540);
  border: 1px solid var(--border-color, #333);
  border-radius: 8px;
  cursor: pointer;
  text-align: left;
  transition: all 0.15s;
  color: var(--text-primary, #ddd);
}

.option-btn:hover {
  background: var(--bg-hover, #2a2a4a);
  border-color: var(--accent-color, #60a5fa);
}

.option-btn.selected {
  background: var(--bg-active, rgba(96, 165, 250, 0.15));
  border-color: var(--accent-color, #60a5fa);
}

.option-radio,
.option-check {
  font-size: 14px;
  color: var(--accent-color, #60a5fa);
  margin-top: 2px;
}

.option-content {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.option-label {
  font-weight: 500;
  color: var(--text-primary, #fff);
}

.option-desc {
  font-size: 12px;
  color: var(--text-muted, #888);
  line-height: 1.4;
}

.option-btn.other {
  border-style: dashed;
}

.other-input-container {
  margin-top: 8px;
  margin-left: 26px;
}

.other-input {
  width: 100%;
  padding: 10px 12px;
  background: var(--bg-primary, #1a1a2e);
  border: 1px solid var(--border-color, #333);
  border-radius: 6px;
  color: var(--text-primary, #fff);
  font-size: 14px;
}

.other-input:focus {
  outline: none;
  border-color: var(--accent-color, #60a5fa);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding: 16px 20px;
  background: var(--bg-secondary, #252540);
  border-top: 1px solid var(--border-color, #333);
}

.btn {
  padding: 10px 20px;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  border: none;
}

.btn.cancel {
  background: transparent;
  color: var(--text-muted, #888);
  border: 1px solid var(--border-color, #333);
}

.btn.cancel:hover {
  background: var(--bg-hover, #2a2a4a);
  color: var(--text-primary, #fff);
}

.btn.submit {
  background: var(--accent-color, #60a5fa);
  color: #000;
}

.btn.submit:hover {
  filter: brightness(1.1);
}

.btn.submit:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
