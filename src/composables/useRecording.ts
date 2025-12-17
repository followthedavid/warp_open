import { ref, computed } from 'vue'

// Types
export interface RecordedEvent {
  type: 'output' | 'input' | 'resize' | 'cwd_change' | 'command'
  timestamp: number
  relativeTime: number  // ms from recording start
  paneId: string
  ptyId: number
  data: string
  cols?: number
  rows?: number
  // Command-specific metadata
  commandIndex?: number
}

export interface RecordingMetadata {
  os?: string
  shell?: string
  termType?: string
  appVersion?: string
  recordedAt: string  // ISO date
  sizeChanges: Array<{ time: number; cols: number; rows: number }>
  commandBoundaries: number[]  // relativeTime values where commands start
}

export interface Recording {
  id: string
  name: string
  description?: string
  paneId: string
  ptyId: number
  tabId: string
  startTime: number
  endTime?: number
  duration?: number
  initialCwd?: string
  initialCols?: number
  initialRows?: number
  events: RecordedEvent[]
  eventCount: number
  tags?: string[]
  // Enhanced metadata
  metadata?: RecordingMetadata
  // Trim markers
  trimStart?: number  // relativeTime to start from
  trimEnd?: number    // relativeTime to end at
}

// Gist-compatible export format
export interface GistRecording {
  version: 1
  title: string
  description: string
  duration: number
  commands: string[]
  cast: Array<[number, string, string]>  // [time, type, data]
  env: {
    shell?: string
    term?: string
    os?: string
  }
}

export interface RecordingState {
  isRecording: boolean
  isPaused: boolean
  currentRecordingId: string | null
  startTime: number | null
}

// Storage key
const RECORDINGS_STORAGE_KEY = 'warp_recordings'
const MAX_RECORDINGS = 50
const MAX_EVENTS_PER_RECORDING = 50000

// Shared state
const recordings = ref<Recording[]>([])
const activeRecordings = ref<Map<string, RecordingState>>(new Map())

// Load from localStorage
function loadRecordings(): Recording[] {
  try {
    const stored = localStorage.getItem(RECORDINGS_STORAGE_KEY)
    if (stored) {
      const parsed = JSON.parse(stored)
      if (Array.isArray(parsed)) {
        return parsed
      }
    }
  } catch (e) {
    console.error('[useRecording] Failed to load recordings:', e)
  }
  return []
}

// Save to localStorage
function saveRecordings() {
  try {
    // Only save metadata and limited events (for replay, full events stored separately)
    const toSave = recordings.value.map(r => ({
      ...r,
      events: r.events.slice(0, 1000),  // Limit stored events
      eventCount: r.events.length,
    }))
    localStorage.setItem(RECORDINGS_STORAGE_KEY, JSON.stringify(toSave))
  } catch (e) {
    console.error('[useRecording] Failed to save recordings:', e)
  }
}

// Initialize
recordings.value = loadRecordings()

export function useRecording() {
  // Generate unique ID
  function generateId(): string {
    return `rec-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`
  }

  // Start recording for a pane
  function startRecording(
    paneId: string,
    ptyId: number,
    tabId: string,
    options: {
      name?: string
      initialCwd?: string
      initialCols?: number
      initialRows?: number
      shell?: string
    } = {}
  ): string {
    const id = generateId()
    const now = Date.now()

    // Detect OS
    const os = typeof navigator !== 'undefined' ? navigator.platform : 'unknown'

    const recording: Recording = {
      id,
      name: options.name || `Recording ${new Date(now).toLocaleString()}`,
      paneId,
      ptyId,
      tabId,
      startTime: now,
      initialCwd: options.initialCwd,
      initialCols: options.initialCols,
      initialRows: options.initialRows,
      events: [],
      eventCount: 0,
      metadata: {
        os,
        shell: options.shell || process.env.SHELL || 'unknown',
        termType: 'xterm-256color',
        appVersion: '0.1.0',
        recordedAt: new Date(now).toISOString(),
        sizeChanges: [],
        commandBoundaries: []
      }
    }

    recordings.value.unshift(recording)

    // Limit total recordings
    while (recordings.value.length > MAX_RECORDINGS) {
      recordings.value.pop()
    }

    // Set active state
    activeRecordings.value.set(paneId, {
      isRecording: true,
      isPaused: false,
      currentRecordingId: id,
      startTime: now,
    })

    saveRecordings()
    console.log(`[useRecording] Started recording ${id} for pane ${paneId}`)

    return id
  }

  // Stop recording for a pane
  function stopRecording(paneId: string): Recording | null {
    const state = activeRecordings.value.get(paneId)
    if (!state || !state.currentRecordingId) {
      return null
    }

    const recording = recordings.value.find(r => r.id === state.currentRecordingId)
    if (recording) {
      recording.endTime = Date.now()
      recording.duration = recording.endTime - recording.startTime
      recording.eventCount = recording.events.length
    }

    activeRecordings.value.delete(paneId)
    saveRecordings()

    console.log(`[useRecording] Stopped recording for pane ${paneId}`)
    return recording || null
  }

  // Pause/resume recording
  function pauseRecording(paneId: string): boolean {
    const state = activeRecordings.value.get(paneId)
    if (state) {
      state.isPaused = true
      return true
    }
    return false
  }

  function resumeRecording(paneId: string): boolean {
    const state = activeRecordings.value.get(paneId)
    if (state) {
      state.isPaused = false
      return true
    }
    return false
  }

  // Record an event
  function recordEvent(
    paneId: string,
    event: Omit<RecordedEvent, 'relativeTime'>
  ): boolean {
    const state = activeRecordings.value.get(paneId)
    if (!state || !state.isRecording || state.isPaused) {
      return false
    }

    const recording = recordings.value.find(r => r.id === state.currentRecordingId)
    if (!recording) {
      return false
    }

    // Check event limit
    if (recording.events.length >= MAX_EVENTS_PER_RECORDING) {
      console.warn('[useRecording] Max events reached, stopping recording')
      stopRecording(paneId)
      return false
    }

    const fullEvent: RecordedEvent = {
      ...event,
      relativeTime: event.timestamp - recording.startTime,
    }

    recording.events.push(fullEvent)
    recording.eventCount = recording.events.length

    // Periodic save (every 100 events)
    if (recording.events.length % 100 === 0) {
      saveRecordings()
    }

    return true
  }

  // Record output event
  function recordOutput(paneId: string, ptyId: number, data: string): boolean {
    return recordEvent(paneId, {
      type: 'output',
      timestamp: Date.now(),
      paneId,
      ptyId,
      data,
    })
  }

  // Record input event
  function recordInput(paneId: string, ptyId: number, data: string): boolean {
    return recordEvent(paneId, {
      type: 'input',
      timestamp: Date.now(),
      paneId,
      ptyId,
      data,
    })
  }

  // Record resize event
  function recordResize(paneId: string, ptyId: number, cols: number, rows: number): boolean {
    return recordEvent(paneId, {
      type: 'resize',
      timestamp: Date.now(),
      paneId,
      ptyId,
      data: '',
      cols,
      rows,
    })
  }

  // Check if pane is recording
  function isRecording(paneId: string): boolean {
    const state = activeRecordings.value.get(paneId)
    return state?.isRecording || false
  }

  function isPaused(paneId: string): boolean {
    const state = activeRecordings.value.get(paneId)
    return state?.isPaused || false
  }

  // Get recording by ID
  function getRecording(id: string): Recording | undefined {
    return recordings.value.find(r => r.id === id)
  }

  // Delete recording
  function deleteRecording(id: string): boolean {
    const index = recordings.value.findIndex(r => r.id === id)
    if (index !== -1) {
      recordings.value.splice(index, 1)
      saveRecordings()
      return true
    }
    return false
  }

  // Rename recording
  function renameRecording(id: string, name: string): boolean {
    const recording = recordings.value.find(r => r.id === id)
    if (recording) {
      recording.name = name
      saveRecordings()
      return true
    }
    return false
  }

  // Export recording as JSON
  function exportRecording(id: string): string | null {
    const recording = recordings.value.find(r => r.id === id)
    if (!recording) return null

    return JSON.stringify(recording, null, 2)
  }

  // Export all recordings
  function exportAllRecordings(): string {
    return JSON.stringify(recordings.value, null, 2)
  }

  // Import recording
  function importRecording(json: string): Recording | null {
    try {
      const recording = JSON.parse(json) as Recording
      if (recording.id && recording.events) {
        // Generate new ID to avoid conflicts
        recording.id = generateId()
        recordings.value.unshift(recording)
        saveRecordings()
        return recording
      }
    } catch (e) {
      console.error('[useRecording] Failed to import:', e)
    }
    return null
  }

  // Format duration for display
  function formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`
    } else {
      return `${seconds}s`
    }
  }

  // Get recordings for a specific pane
  const getRecordingsForPane = (paneId: string) => {
    return recordings.value.filter(r => r.paneId === paneId)
  }

  // Clear all recordings
  function clearAllRecordings() {
    recordings.value = []
    activeRecordings.value.clear()
    saveRecordings()
  }

  // Mark a command boundary (called when Enter is pressed)
  function markCommandBoundary(paneId: string, command: string): void {
    const state = activeRecordings.value.get(paneId)
    if (!state || !state.isRecording) return

    const recording = recordings.value.find(r => r.id === state.currentRecordingId)
    if (!recording || !recording.metadata) return

    const relativeTime = Date.now() - recording.startTime
    recording.metadata.commandBoundaries.push(relativeTime)

    // Also record as a command event
    recordEvent(paneId, {
      type: 'command',
      timestamp: Date.now(),
      paneId,
      ptyId: recording.ptyId,
      data: command,
      commandIndex: recording.metadata.commandBoundaries.length - 1
    })
  }

  // Set trim markers for a recording
  function setTrimMarkers(id: string, trimStart?: number, trimEnd?: number): boolean {
    const recording = recordings.value.find(r => r.id === id)
    if (!recording) return false

    recording.trimStart = trimStart
    recording.trimEnd = trimEnd
    saveRecordings()
    return true
  }

  // Get command boundaries for seeking
  function getCommandBoundaries(id: string): number[] {
    const recording = recordings.value.find(r => r.id === id)
    return recording?.metadata?.commandBoundaries || []
  }

  // Jump to next command boundary
  function getNextCommandBoundary(id: string, currentTime: number): number | null {
    const boundaries = getCommandBoundaries(id)
    for (const boundary of boundaries) {
      if (boundary > currentTime) return boundary
    }
    return null
  }

  // Jump to previous command boundary
  function getPreviousCommandBoundary(id: string, currentTime: number): number | null {
    const boundaries = getCommandBoundaries(id)
    for (let i = boundaries.length - 1; i >= 0; i--) {
      if (boundaries[i] < currentTime) return boundaries[i]
    }
    return 0
  }

  // Export as gist-compatible format
  function exportAsGist(id: string): GistRecording | null {
    const recording = recordings.value.find(r => r.id === id)
    if (!recording) return null

    // Extract commands from command events
    const commands = recording.events
      .filter(e => e.type === 'command')
      .map(e => e.data)

    // Apply trim markers
    const trimStart = recording.trimStart || 0
    const trimEnd = recording.trimEnd || (recording.duration || 0)

    // Convert events to cast format [time_in_seconds, type, data]
    const cast: Array<[number, string, string]> = recording.events
      .filter(e => e.relativeTime >= trimStart && e.relativeTime <= trimEnd)
      .filter(e => e.type === 'output')
      .map(e => [
        (e.relativeTime - trimStart) / 1000,  // Convert to seconds
        'o',  // output
        e.data
      ])

    return {
      version: 1,
      title: recording.name,
      description: recording.description || '',
      duration: (trimEnd - trimStart) / 1000,
      commands,
      cast,
      env: {
        shell: recording.metadata?.shell,
        term: recording.metadata?.termType,
        os: recording.metadata?.os
      }
    }
  }

  // Export gist as downloadable JSON
  function downloadGistExport(id: string): boolean {
    const gist = exportAsGist(id)
    if (!gist) return false

    const recording = recordings.value.find(r => r.id === id)
    const filename = `${(recording?.name || 'recording').replace(/[^a-z0-9]/gi, '_')}.json`

    const blob = new Blob([JSON.stringify(gist, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    return true
  }

  // Get trimmed events for replay
  function getTrimmedEvents(id: string): RecordedEvent[] {
    const recording = recordings.value.find(r => r.id === id)
    if (!recording) return []

    const trimStart = recording.trimStart || 0
    const trimEnd = recording.trimEnd || Infinity

    return recording.events
      .filter(e => e.relativeTime >= trimStart && e.relativeTime <= trimEnd)
      .map(e => ({
        ...e,
        relativeTime: e.relativeTime - trimStart  // Normalize timing
      }))
  }

  return {
    // State
    recordings: computed(() => recordings.value),
    activeRecordings: computed(() => activeRecordings.value),

    // Recording control
    startRecording,
    stopRecording,
    pauseRecording,
    resumeRecording,

    // Event recording
    recordOutput,
    recordInput,
    recordResize,
    recordEvent,

    // Status checks
    isRecording,
    isPaused,

    // CRUD
    getRecording,
    deleteRecording,
    renameRecording,
    getRecordingsForPane,
    clearAllRecordings,

    // Import/Export
    exportRecording,
    exportAllRecordings,
    importRecording,
    exportAsGist,
    downloadGistExport,

    // Trim & Navigation
    setTrimMarkers,
    getTrimmedEvents,
    getCommandBoundaries,
    getNextCommandBoundary,
    getPreviousCommandBoundary,
    markCommandBoundary,

    // Utils
    formatDuration,
  }
}
