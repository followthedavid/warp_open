<template>
  <div class="analyzer-panel">
    <div class="panel-header">
      <span class="panel-title">Screen Analyzer</span>
      <button class="close-btn" @click="$emit('close')">×</button>
    </div>

    <div class="panel-content">
      <!-- Capture Controls -->
      <div class="capture-section">
        <div class="section-title">Capture Screen</div>
        <div class="capture-buttons">
          <button
            class="capture-btn"
            @click="captureFullscreen"
            :disabled="visual.isCapturing.value || visual.isAnalyzing.value"
          >
            <span class="btn-icon">🖥️</span>
            Full Screen
          </button>
          <button
            class="capture-btn"
            @click="captureWindow"
            :disabled="visual.isCapturing.value || visual.isAnalyzing.value"
          >
            <span class="btn-icon">📱</span>
            Active Window
          </button>
          <button
            class="capture-btn"
            @click="captureSelection"
            :disabled="visual.isCapturing.value || visual.isAnalyzing.value"
          >
            <span class="btn-icon">✂️</span>
            Selection
          </button>
        </div>
      </div>

      <!-- Status -->
      <div v-if="visual.isCapturing.value || visual.isAnalyzing.value" class="status-section">
        <div class="spinner"></div>
        <span>{{ visual.isCapturing.value ? 'Capturing...' : 'Analyzing...' }}</span>
      </div>

      <!-- Current Analysis -->
      <div v-if="visual.currentCapture.value" class="analysis-section">
        <div class="section-title">Analysis Result</div>

        <div class="analysis-card">
          <!-- Image Preview -->
          <div class="image-preview">
            <img :src="getImageUrl(visual.currentCapture.value.imagePath)" alt="Capture" />
          </div>

          <!-- Description -->
          <div class="description">
            <div class="description-label">Description:</div>
            <div class="description-text">{{ visual.currentCapture.value.description }}</div>
          </div>

          <!-- Extracted Text -->
          <div v-if="visual.currentCapture.value.text.length > 0" class="extracted-text">
            <div class="text-label">
              Extracted Text ({{ visual.currentCapture.value.text.length }} lines):
            </div>
            <div class="text-content">
              <div
                v-for="(line, i) in visual.currentCapture.value.text.slice(0, 10)"
                :key="i"
                class="text-line"
              >
                {{ line }}
              </div>
              <div v-if="visual.currentCapture.value.text.length > 10" class="text-more">
                ... and {{ visual.currentCapture.value.text.length - 10 }} more lines
              </div>
            </div>
          </div>

          <!-- Actions -->
          <div class="analysis-actions">
            <button class="action-btn primary" @click="sendToAI">
              Send to AI
            </button>
            <button class="action-btn" @click="copyText">
              Copy Text
            </button>
          </div>
        </div>
      </div>

      <!-- History -->
      <div v-if="visual.history.value.length > 0" class="history-section">
        <div class="section-header">
          <span class="section-title">Recent Captures</span>
          <button class="clear-btn" @click="visual.clearHistory()">Clear</button>
        </div>

        <div class="history-grid">
          <div
            v-for="capture in visual.history.value.slice(-6).reverse()"
            :key="capture.id"
            class="history-item"
            @click="selectCapture(capture)"
          >
            <img :src="getImageUrl(capture.imagePath)" alt="Capture" />
            <div class="history-meta">
              <span class="history-time">{{ formatTime(capture.timestamp) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Capabilities -->
      <div v-if="!capabilities" class="capabilities-loading">
        Checking capabilities...
      </div>
      <div v-else-if="!capabilities.visionModel" class="capabilities-warning">
        <div class="warning-icon">⚠️</div>
        <div class="warning-text">
          <strong>No vision model detected</strong>
          <p>Install llava for full image analysis:</p>
          <code>ollama pull llava</code>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useVisualUnderstanding, type AnalysisResult } from '../composables/useVisualUnderstanding'

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'analyzed', result: { screenshot: string; description: string }): void
}>()

const visual = useVisualUnderstanding()
const capabilities = ref<{
  screenCapture: boolean
  visionModel: boolean
  ocr: boolean
} | null>(null)

onMounted(async () => {
  capabilities.value = await visual.checkCapabilities()
})

async function captureFullscreen() {
  const result = await visual.captureAndAnalyze({ type: 'fullscreen' })
  if (result) {
    emitResult(result)
  }
}

async function captureWindow() {
  const imagePath = await visual.captureActiveWindow()
  if (imagePath) {
    const result = await visual.analyzeImage(imagePath)
    if (result) {
      emitResult(result)
    }
  }
}

async function captureSelection() {
  const result = await visual.captureAndAnalyze({ type: 'selection' })
  if (result) {
    emitResult(result)
  }
}

function selectCapture(capture: AnalysisResult) {
  // Make this the current capture for viewing
  emitResult(capture)
}

function emitResult(result: AnalysisResult) {
  emit('analyzed', {
    screenshot: result.imagePath,
    description: result.description + (result.text.length > 0 ? '\n\nExtracted text:\n' + result.text.join('\n') : '')
  })
}

function sendToAI() {
  if (visual.currentCapture.value) {
    emitResult(visual.currentCapture.value)
  }
}

async function copyText() {
  if (visual.currentCapture.value?.text.length) {
    const text = visual.currentCapture.value.text.join('\n')
    await navigator.clipboard.writeText(text)
  }
}

function getImageUrl(path: string): string {
  // Convert file path to file:// URL for display
  const expandedPath = path.replace('~', '/Users/' + (import.meta.env.VITE_USER || 'user'))
  return `file://${expandedPath}`
}

function formatTime(date: Date): string {
  const d = new Date(date)
  const now = new Date()
  const diff = now.getTime() - d.getTime()

  if (diff < 60000) return 'Just now'
  if (diff < 3600000) return `${Math.round(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.round(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}
</script>

<style scoped>
.analyzer-panel {
  position: fixed;
  right: 16px;
  top: 60px;
  width: 400px;
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

.panel-title {
  font-weight: 600;
  font-size: 14px;
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
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.section-title {
  font-size: 11px;
  text-transform: uppercase;
  color: var(--warp-text-tertiary);
  letter-spacing: 0.5px;
  font-weight: 600;
  margin-bottom: 10px;
}

/* Capture Section */
.capture-buttons {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}

.capture-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 12px 8px;
  background: var(--warp-bg-elevated);
  border: 1px solid var(--warp-border);
  border-radius: 8px;
  color: var(--warp-text-secondary);
  font-size: 11px;
  cursor: pointer;
  transition: all 0.2s;
}

.capture-btn:hover:not(:disabled) {
  background: var(--warp-bg-hover);
  border-color: var(--warp-accent-primary);
  color: var(--warp-text-primary);
}

.capture-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-icon {
  font-size: 20px;
}

/* Status */
.status-section {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 20px;
  color: var(--warp-text-tertiary);
  font-size: 13px;
}

.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid var(--warp-border);
  border-top-color: var(--warp-accent-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Analysis Card */
.analysis-card {
  background: var(--warp-bg-elevated);
  border-radius: 10px;
  overflow: hidden;
}

.image-preview {
  width: 100%;
  max-height: 200px;
  overflow: hidden;
  background: var(--warp-bg-base);
}

.image-preview img {
  width: 100%;
  height: auto;
  object-fit: cover;
}

.description {
  padding: 12px;
  border-bottom: 1px solid var(--warp-border-subtle);
}

.description-label {
  font-size: 10px;
  text-transform: uppercase;
  color: var(--warp-text-tertiary);
  margin-bottom: 6px;
}

.description-text {
  font-size: 13px;
  line-height: 1.5;
  color: var(--warp-text-secondary);
}

.extracted-text {
  padding: 12px;
  border-bottom: 1px solid var(--warp-border-subtle);
}

.text-label {
  font-size: 10px;
  text-transform: uppercase;
  color: var(--warp-text-tertiary);
  margin-bottom: 8px;
}

.text-content {
  font-family: var(--warp-font-mono);
  font-size: 11px;
  background: var(--warp-bg-base);
  padding: 8px;
  border-radius: 6px;
  max-height: 120px;
  overflow-y: auto;
}

.text-line {
  padding: 2px 0;
  color: var(--warp-text-secondary);
}

.text-more {
  color: var(--warp-text-tertiary);
  font-style: italic;
  margin-top: 4px;
}

.analysis-actions {
  display: flex;
  gap: 8px;
  padding: 12px;
}

.action-btn {
  flex: 1;
  padding: 8px 12px;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  background: var(--warp-bg-base);
  color: var(--warp-text-secondary);
}

.action-btn:hover {
  background: var(--warp-bg-hover);
}

.action-btn.primary {
  background: var(--warp-accent-primary);
  color: white;
}

.action-btn.primary:hover {
  opacity: 0.9;
}

/* History */
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.clear-btn {
  background: transparent;
  border: none;
  color: var(--warp-text-tertiary);
  font-size: 11px;
  cursor: pointer;
}

.clear-btn:hover {
  color: #ef4444;
}

.history-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}

.history-item {
  position: relative;
  aspect-ratio: 16/9;
  border-radius: 6px;
  overflow: hidden;
  cursor: pointer;
  border: 1px solid var(--warp-border);
  transition: all 0.2s;
}

.history-item:hover {
  border-color: var(--warp-accent-primary);
  transform: scale(1.02);
}

.history-item img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.history-meta {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  padding: 4px;
  background: linear-gradient(transparent, rgba(0, 0, 0, 0.7));
}

.history-time {
  font-size: 9px;
  color: white;
}

/* Capabilities Warning */
.capabilities-loading {
  text-align: center;
  padding: 20px;
  color: var(--warp-text-tertiary);
  font-size: 12px;
}

.capabilities-warning {
  display: flex;
  gap: 12px;
  padding: 12px;
  background: rgba(245, 158, 11, 0.1);
  border-radius: 8px;
  border: 1px solid rgba(245, 158, 11, 0.3);
}

.warning-icon {
  font-size: 20px;
}

.warning-text {
  font-size: 12px;
}

.warning-text strong {
  display: block;
  margin-bottom: 4px;
}

.warning-text p {
  margin: 4px 0;
  color: var(--warp-text-secondary);
}

.warning-text code {
  display: inline-block;
  margin-top: 4px;
  padding: 4px 8px;
  background: var(--warp-bg-base);
  border-radius: 4px;
  font-family: var(--warp-font-mono);
  font-size: 11px;
}
</style>
