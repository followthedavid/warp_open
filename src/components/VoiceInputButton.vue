<template>
  <button
    class="voice-btn"
    :class="{ listening: isListening, processing: voice.isProcessing.value }"
    @click="handleClick"
    :title="getTitle()"
    :disabled="voice.isProcessing.value"
  >
    <span class="voice-icon">
      <template v-if="voice.isProcessing.value">
        <span class="spinner"></span>
      </template>
      <template v-else-if="isListening">
        <span class="listening-icon">
          <span class="pulse"></span>
          <span class="mic">🎙️</span>
        </span>
      </template>
      <template v-else>
        🎤
      </template>
    </span>
    <span v-if="isListening && voice.audioLevel.value > 0" class="audio-level">
      <span
        class="level-bar"
        :style="{ height: `${voice.audioLevel.value * 100}%` }"
      ></span>
    </span>
  </button>

  <!-- Transcript Preview -->
  <Transition name="fade">
    <div v-if="isListening && voice.lastTranscript.value" class="transcript-preview">
      <div class="transcript-text">
        {{ voice.lastTranscript.value.text }}
        <span v-if="!voice.lastTranscript.value.isFinal" class="typing-indicator">...</span>
      </div>
      <div class="transcript-actions">
        <button class="send-btn" @click="sendTranscript" :disabled="!voice.lastTranscript.value.isFinal">
          Send
        </button>
        <button class="cancel-btn" @click="cancelTranscript">
          Cancel
        </button>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { watch } from 'vue'
import { useVoiceInterface } from '../composables/useVoiceInterface'

const props = defineProps<{
  isListening: boolean
}>()

const emit = defineEmits<{
  (e: 'toggle'): void
  (e: 'transcript', text: string): void
}>()

const voice = useVoiceInterface()

function handleClick() {
  if (props.isListening) {
    voice.stopListening()
    // Check if we have a final transcript to send
    if (voice.lastTranscript.value?.isFinal) {
      emit('transcript', voice.lastTranscript.value.text)
    }
  } else {
    voice.startListening()
  }
  emit('toggle')
}

function sendTranscript() {
  if (voice.lastTranscript.value?.text) {
    emit('transcript', voice.lastTranscript.value.text)
    voice.stopListening()
    emit('toggle')
  }
}

function cancelTranscript() {
  voice.stopListening()
  emit('toggle')
}

function getTitle(): string {
  if (voice.isProcessing.value) return 'Processing...'
  if (props.isListening) return 'Stop listening (click to send)'
  return 'Start voice input'
}

// Watch for final transcripts when in continuous mode
watch(() => voice.lastTranscript.value, (transcript) => {
  if (transcript?.isFinal && props.isListening) {
    // Auto-send after a short delay
    setTimeout(() => {
      if (voice.lastTranscript.value?.isFinal) {
        // User can send manually or we could auto-send
      }
    }, 1000)
  }
})
</script>

<style scoped>
.voice-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  padding: 0;
  background: transparent;
  border: 1px solid var(--warp-border);
  border-radius: var(--warp-radius-full);
  color: var(--warp-text-secondary);
  cursor: pointer;
  transition: all 0.2s ease;
  position: relative;
}

.voice-btn:hover:not(:disabled) {
  background: var(--warp-bg-hover);
  border-color: var(--warp-accent-primary);
  color: var(--warp-text-primary);
}

.voice-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.voice-btn.listening {
  background: rgba(239, 68, 68, 0.15);
  border-color: #ef4444;
  color: #ef4444;
  animation: pulse-border 1.5s ease-in-out infinite;
}

.voice-btn.processing {
  background: var(--warp-bg-elevated);
}

@keyframes pulse-border {
  0%, 100% {
    box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4);
  }
  50% {
    box-shadow: 0 0 0 6px rgba(239, 68, 68, 0);
  }
}

.voice-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
}

.listening-icon {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.pulse {
  position: absolute;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: rgba(239, 68, 68, 0.3);
  animation: pulse-ring 1s ease-out infinite;
}

@keyframes pulse-ring {
  0% {
    transform: scale(0.8);
    opacity: 1;
  }
  100% {
    transform: scale(1.5);
    opacity: 0;
  }
}

.mic {
  position: relative;
  z-index: 1;
  font-size: 14px;
}

.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid var(--warp-border);
  border-top-color: var(--warp-accent-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.audio-level {
  position: absolute;
  right: -6px;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 16px;
  background: var(--warp-bg-elevated);
  border-radius: 2px;
  overflow: hidden;
}

.level-bar {
  position: absolute;
  bottom: 0;
  left: 0;
  width: 100%;
  background: #22c55e;
  border-radius: 2px;
  transition: height 0.05s ease;
}

/* Transcript Preview */
.transcript-preview {
  position: fixed;
  bottom: 60px;
  right: 16px;
  width: 320px;
  background: var(--warp-bg-surface);
  border: 1px solid var(--warp-border);
  border-radius: var(--warp-radius-lg);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  padding: 12px;
  z-index: 150;
}

.transcript-text {
  font-size: 14px;
  line-height: 1.5;
  margin-bottom: 12px;
  color: var(--warp-text-primary);
  min-height: 40px;
}

.typing-indicator {
  opacity: 0.5;
  animation: blink 1s step-end infinite;
}

@keyframes blink {
  0%, 100% { opacity: 0.5; }
  50% { opacity: 0; }
}

.transcript-actions {
  display: flex;
  gap: 8px;
}

.send-btn,
.cancel-btn {
  flex: 1;
  padding: 8px 12px;
  border: none;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.send-btn {
  background: var(--warp-accent-primary);
  color: white;
}

.send-btn:hover:not(:disabled) {
  opacity: 0.9;
}

.send-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.cancel-btn {
  background: var(--warp-bg-elevated);
  color: var(--warp-text-secondary);
}

.cancel-btn:hover {
  background: var(--warp-bg-hover);
}

/* Transitions */
.fade-enter-active,
.fade-leave-active {
  transition: all 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(10px);
}
</style>
