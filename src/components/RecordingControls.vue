<template>
  <div class="recording-controls" v-if="visible">
    <!-- Recording Mode -->
    <div v-if="!isReplayMode" class="control-group">
      <button
        v-if="!isRecordingActive"
        class="control-btn record"
        @click="startRec"
        title="Start Recording"
      >
        <span class="icon">⏺</span>
        <span class="label">Record</span>
      </button>

      <template v-else>
        <button
          class="control-btn stop"
          @click="stopRec"
          title="Stop Recording"
        >
          <span class="icon">⏹</span>
          <span class="label">Stop</span>
        </button>

        <span class="recording-indicator">
          <span class="dot"></span>
          REC {{ formatElapsed }}
        </span>
      </template>

      <button
        v-if="recordings.length > 0"
        class="control-btn replay"
        @click="showRecordingsList = !showRecordingsList"
        title="View Recordings"
      >
        <span class="icon">▶</span>
        <span class="label">Replay ({{ recordings.length }})</span>
      </button>
    </div>

    <!-- Replay Mode -->
    <div v-else class="control-group replay-mode">
      <button
        class="control-btn"
        @click="exitReplay"
        title="Exit Replay"
      >
        <span class="icon">✕</span>
      </button>

      <button
        class="control-btn"
        @click="skipBack"
        title="Skip Back 5s"
      >
        <span class="icon">⏪</span>
      </button>

      <button
        v-if="!replayState?.isPlaying || replayState?.isPaused"
        class="control-btn play"
        @click="playReplay"
        title="Play"
      >
        <span class="icon">▶</span>
      </button>
      <button
        v-else
        class="control-btn pause"
        @click="pauseReplay"
        title="Pause"
      >
        <span class="icon">⏸</span>
      </button>

      <button
        class="control-btn"
        @click="skipForward"
        title="Skip Forward 5s"
      >
        <span class="icon">⏩</span>
      </button>

      <div class="progress-bar" @click="seekTo">
        <div class="progress-fill" :style="{ width: `${progress}%` }"></div>
        <div class="progress-thumb" :style="{ left: `${progress}%` }"></div>
      </div>

      <span class="time-display">
        {{ formatCurrentTime }} / {{ formatDurationDisplay }}
      </span>

      <select
        class="speed-select"
        :value="replayState?.speed || 1"
        @change="setPlaybackSpeed"
      >
        <option value="0.5">0.5x</option>
        <option value="1">1x</option>
        <option value="2">2x</option>
        <option value="4">4x</option>
      </select>
    </div>

    <!-- Recordings List Modal -->
    <div v-if="showRecordingsList" class="recordings-modal">
      <div class="modal-header">
        <h3>Recordings</h3>
        <button class="close-btn" @click="showRecordingsList = false">✕</button>
      </div>
      <div class="recordings-list">
        <div
          v-for="rec in recordings"
          :key="rec.id"
          class="recording-item"
        >
          <div class="recording-info">
            <span class="recording-name">{{ rec.name }}</span>
            <span class="recording-meta">
              {{ formatDate(rec.startTime) }} · {{ formatDurationShort(rec.duration || 0) }} · {{ rec.eventCount }} events
            </span>
          </div>
          <div class="recording-actions">
            <button @click="loadAndPlay(rec)" title="Play">▶</button>
            <button @click="exportRec(rec)" title="Export">📥</button>
            <button @click="deleteRec(rec)" title="Delete">🗑</button>
          </div>
        </div>
        <div v-if="recordings.length === 0" class="no-recordings">
          No recordings yet. Click Record to start.
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRecording, type Recording } from '../composables/useRecording'
import { useReplay } from '../composables/useReplay'

const props = defineProps<{
  paneId: string
  ptyId: number
  tabId: string
  visible?: boolean
  cwd?: string
  cols?: number
  rows?: number
}>()

const emit = defineEmits<{
  (e: 'replay-output', data: string): void
  (e: 'replay-started'): void
  (e: 'replay-ended'): void
}>()

// Composables
const {
  recordings: allRecordings,
  startRecording,
  stopRecording,
  isRecording,
  recordOutput,
  recordInput,
  deleteRecording,
  exportRecording,
  formatDuration,
  getRecordingsForPane,
} = useRecording()

const {
  state: replayState,
  progress,
  loadRecording,
  setOutputCallback,
  play: playReplayFn,
  pause: pauseReplayFn,
  stop: stopReplayFn,
  seek,
  setSpeed,
  skipForward: skipForwardFn,
  skipBackward: skipBackwardFn,
  formatTime,
} = useReplay(props.paneId)

// Local state
const showRecordingsList = ref(false)
const isReplayMode = ref(false)
const recordingStartTime = ref<number | null>(null)
const elapsedTimer = ref<number | null>(null)
const elapsed = ref(0)

// Computed
const isRecordingActive = computed(() => isRecording(props.paneId))

const recordings = computed(() => {
  // Get recordings for this pane, most recent first
  return allRecordings.value
    .filter(r => r.paneId === props.paneId)
    .slice(0, 20)
})

const formatElapsed = computed(() => {
  const mins = Math.floor(elapsed.value / 60)
  const secs = elapsed.value % 60
  return `${mins}:${secs.toString().padStart(2, '0')}`
})

const formatCurrentTime = computed(() => {
  if (!replayState.value) return '0:00'
  return formatTime(replayState.value.currentTime)
})

const formatDurationDisplay = computed(() => {
  if (!replayState.value) return '0:00'
  return formatTime(replayState.value.duration)
})

// Methods
function startRec() {
  startRecording(props.paneId, props.ptyId, props.tabId, {
    name: `Recording ${new Date().toLocaleTimeString()}`,
    initialCwd: props.cwd,
    initialCols: props.cols,
    initialRows: props.rows,
  })

  recordingStartTime.value = Date.now()
  elapsed.value = 0

  // Update elapsed time every second
  elapsedTimer.value = window.setInterval(() => {
    if (recordingStartTime.value) {
      elapsed.value = Math.floor((Date.now() - recordingStartTime.value) / 1000)
    }
  }, 1000)
}

function stopRec() {
  stopRecording(props.paneId)

  if (elapsedTimer.value) {
    clearInterval(elapsedTimer.value)
    elapsedTimer.value = null
  }
  recordingStartTime.value = null
  elapsed.value = 0
}

function loadAndPlay(rec: Recording) {
  showRecordingsList.value = false
  isReplayMode.value = true

  // Set up output callback to emit to terminal
  setOutputCallback((data: string) => {
    emit('replay-output', data)
  })

  loadRecording(rec)
  emit('replay-started')
  playReplayFn()
}

function playReplay() {
  playReplayFn()
}

function pauseReplay() {
  pauseReplayFn()
}

function exitReplay() {
  stopReplayFn()
  isReplayMode.value = false
  emit('replay-ended')
}

function skipForward() {
  skipForwardFn(5000)
}

function skipBack() {
  skipBackwardFn(5000)
}

function seekTo(event: MouseEvent) {
  const target = event.currentTarget as HTMLElement
  const rect = target.getBoundingClientRect()
  const percent = (event.clientX - rect.left) / rect.width
  const time = percent * (replayState.value?.duration || 0)
  seek(time)
}

function setPlaybackSpeed(event: Event) {
  const select = event.target as HTMLSelectElement
  setSpeed(parseFloat(select.value))
}

function deleteRec(rec: Recording) {
  if (confirm(`Delete recording "${rec.name}"?`)) {
    deleteRecording(rec.id)
  }
}

function exportRec(rec: Recording) {
  const json = exportRecording(rec.id)
  if (json) {
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${rec.name.replace(/[^a-z0-9]/gi, '_')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }
}

function formatDate(timestamp: number): string {
  return new Date(timestamp).toLocaleDateString()
}

function formatDurationShort(ms: number): string {
  const secs = Math.floor(ms / 1000)
  if (secs < 60) return `${secs}s`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ${secs % 60}s`
  const hours = Math.floor(mins / 60)
  return `${hours}h ${mins % 60}m`
}

// Expose methods for parent component to call
defineExpose({
  recordOutput: (data: string) => recordOutput(props.paneId, props.ptyId, data),
  recordInput: (data: string) => recordInput(props.paneId, props.ptyId, data),
  isRecording: () => isRecordingActive.value,
  isReplayMode: () => isReplayMode.value,
})

// Cleanup
onUnmounted(() => {
  if (elapsedTimer.value) {
    clearInterval(elapsedTimer.value)
  }
})
</script>

<style scoped>
.recording-controls {
  display: flex;
  align-items: center;
  padding: 4px 8px;
  background: var(--bg-secondary, #1a1a2e);
  border-bottom: 1px solid var(--border-color, #333);
  font-size: 12px;
  position: relative;
}

.control-group {
  display: flex;
  align-items: center;
  gap: 8px;
}

.control-btn {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 4px 8px;
  border: none;
  border-radius: 4px;
  background: var(--bg-tertiary, #252540);
  color: var(--text-color, #fff);
  cursor: pointer;
  font-size: 11px;
  transition: background 0.2s;
}

.control-btn:hover {
  background: var(--bg-hover, #353555);
}

.control-btn.record:hover {
  background: #ff4444;
}

.control-btn.stop {
  background: #ff4444;
}

.control-btn.play {
  background: #44aa44;
}

.control-btn .icon {
  font-size: 10px;
}

.recording-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
  color: #ff4444;
  font-weight: 500;
}

.recording-indicator .dot {
  width: 8px;
  height: 8px;
  background: #ff4444;
  border-radius: 50%;
  animation: pulse 1s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

/* Replay Mode */
.replay-mode {
  width: 100%;
}

.progress-bar {
  flex: 1;
  height: 6px;
  background: var(--bg-tertiary, #252540);
  border-radius: 3px;
  cursor: pointer;
  position: relative;
  margin: 0 8px;
}

.progress-fill {
  height: 100%;
  background: var(--accent-color, #6366f1);
  border-radius: 3px;
}

.progress-thumb {
  position: absolute;
  top: 50%;
  width: 12px;
  height: 12px;
  background: var(--accent-color, #6366f1);
  border-radius: 50%;
  transform: translate(-50%, -50%);
}

.time-display {
  font-family: monospace;
  font-size: 11px;
  color: var(--text-secondary, #888);
  min-width: 80px;
}

.speed-select {
  padding: 2px 4px;
  border: 1px solid var(--border-color, #333);
  border-radius: 3px;
  background: var(--bg-tertiary, #252540);
  color: var(--text-color, #fff);
  font-size: 11px;
}

/* Recordings Modal */
.recordings-modal {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  background: var(--bg-secondary, #1a1a2e);
  border: 1px solid var(--border-color, #333);
  border-radius: 4px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  z-index: 100;
  max-height: 300px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border-color, #333);
}

.modal-header h3 {
  margin: 0;
  font-size: 13px;
  font-weight: 500;
}

.close-btn {
  background: none;
  border: none;
  color: var(--text-secondary, #888);
  cursor: pointer;
  font-size: 14px;
}

.close-btn:hover {
  color: var(--text-color, #fff);
}

.recordings-list {
  overflow-y: auto;
  padding: 8px;
}

.recording-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px;
  border-radius: 4px;
  margin-bottom: 4px;
}

.recording-item:hover {
  background: var(--bg-tertiary, #252540);
}

.recording-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.recording-name {
  font-weight: 500;
  font-size: 12px;
}

.recording-meta {
  font-size: 10px;
  color: var(--text-secondary, #888);
}

.recording-actions {
  display: flex;
  gap: 4px;
}

.recording-actions button {
  background: none;
  border: none;
  padding: 4px;
  cursor: pointer;
  opacity: 0.7;
  font-size: 12px;
}

.recording-actions button:hover {
  opacity: 1;
}

.no-recordings {
  text-align: center;
  padding: 20px;
  color: var(--text-secondary, #888);
  font-size: 12px;
}
</style>
