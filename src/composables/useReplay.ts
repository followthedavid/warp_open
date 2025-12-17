import { ref, computed, watch, onUnmounted } from 'vue'
import type { Recording, RecordedEvent } from './useRecording'

export interface ReplayState {
  isPlaying: boolean
  isPaused: boolean
  currentTime: number      // Current playback position in ms
  duration: number         // Total duration
  speed: number            // Playback speed multiplier (0.5, 1, 2, 4)
  currentEventIndex: number
  recording: Recording | null
}

export interface ReplayControls {
  play: () => void
  pause: () => void
  stop: () => void
  seek: (timeMs: number) => void
  setSpeed: (speed: number) => void
  skipForward: (ms?: number) => void
  skipBackward: (ms?: number) => void
}

// Shared replay state per pane
const replayStates = ref<Map<string, ReplayState>>(new Map())

export function useReplay(paneId: string) {
  // Initialize state for this pane if needed
  if (!replayStates.value.has(paneId)) {
    replayStates.value.set(paneId, {
      isPlaying: false,
      isPaused: false,
      currentTime: 0,
      duration: 0,
      speed: 1,
      currentEventIndex: 0,
      recording: null,
    })
  }

  const state = computed(() => replayStates.value.get(paneId)!)

  // Animation frame ID for cleanup
  let animationFrameId: number | null = null
  let lastFrameTime: number | null = null

  // Output callback (set by TerminalPane)
  let outputCallback: ((data: string) => void) | null = null
  let resizeCallback: ((cols: number, rows: number) => void) | null = null

  // Set callbacks for receiving replay data
  function setOutputCallback(cb: (data: string) => void) {
    outputCallback = cb
  }

  function setResizeCallback(cb: (cols: number, rows: number) => void) {
    resizeCallback = cb
  }

  // Load a recording for replay
  function loadRecording(recording: Recording): boolean {
    const s = replayStates.value.get(paneId)
    if (!s) return false

    // Stop any existing replay
    stop()

    s.recording = recording
    s.duration = recording.duration ||
      (recording.events.length > 0
        ? recording.events[recording.events.length - 1].relativeTime
        : 0)
    s.currentTime = 0
    s.currentEventIndex = 0
    s.isPlaying = false
    s.isPaused = false

    console.log(`[useReplay] Loaded recording ${recording.id} with ${recording.events.length} events`)
    return true
  }

  // Process events up to current time
  function processEventsToTime(targetTime: number) {
    const s = replayStates.value.get(paneId)
    if (!s || !s.recording) return

    const events = s.recording.events

    // Find events to process
    while (s.currentEventIndex < events.length) {
      const event = events[s.currentEventIndex]

      if (event.relativeTime > targetTime) {
        break
      }

      // Process the event
      processEvent(event)
      s.currentEventIndex++
    }
  }

  // Process a single event
  function processEvent(event: RecordedEvent) {
    switch (event.type) {
      case 'output':
        if (outputCallback && event.data) {
          outputCallback(event.data)
        }
        break

      case 'input':
        // Show input in a different style or skip
        // For now, we'll show it as output (what the user typed)
        if (outputCallback && event.data) {
          // Optionally style input differently
          outputCallback(event.data)
        }
        break

      case 'resize':
        if (resizeCallback && event.cols && event.rows) {
          resizeCallback(event.cols, event.rows)
        }
        break

      case 'cwd_change':
        // Could emit an event for UI updates
        break
    }
  }

  // Animation loop for playback
  function playbackLoop(timestamp: number) {
    const s = replayStates.value.get(paneId)
    if (!s || !s.isPlaying || s.isPaused) {
      lastFrameTime = null
      return
    }

    if (lastFrameTime === null) {
      lastFrameTime = timestamp
    }

    // Calculate elapsed time since last frame, adjusted for speed
    const deltaMs = (timestamp - lastFrameTime) * s.speed
    lastFrameTime = timestamp

    // Update current time
    s.currentTime = Math.min(s.currentTime + deltaMs, s.duration)

    // Process events up to current time
    processEventsToTime(s.currentTime)

    // Check if we've reached the end
    if (s.currentTime >= s.duration) {
      s.isPlaying = false
      s.currentTime = s.duration
      console.log('[useReplay] Playback complete')
      return
    }

    // Continue loop
    animationFrameId = requestAnimationFrame(playbackLoop)
  }

  // Playback controls
  function play() {
    const s = replayStates.value.get(paneId)
    if (!s || !s.recording) return

    if (s.currentTime >= s.duration) {
      // Restart from beginning
      s.currentTime = 0
      s.currentEventIndex = 0
    }

    s.isPlaying = true
    s.isPaused = false
    lastFrameTime = null

    animationFrameId = requestAnimationFrame(playbackLoop)
    console.log('[useReplay] Playing')
  }

  function pause() {
    const s = replayStates.value.get(paneId)
    if (!s) return

    s.isPaused = true
    if (animationFrameId !== null) {
      cancelAnimationFrame(animationFrameId)
      animationFrameId = null
    }
    console.log('[useReplay] Paused')
  }

  function stop() {
    const s = replayStates.value.get(paneId)
    if (!s) return

    s.isPlaying = false
    s.isPaused = false
    s.currentTime = 0
    s.currentEventIndex = 0

    if (animationFrameId !== null) {
      cancelAnimationFrame(animationFrameId)
      animationFrameId = null
    }
    lastFrameTime = null

    console.log('[useReplay] Stopped')
  }

  function seek(timeMs: number) {
    const s = replayStates.value.get(paneId)
    if (!s || !s.recording) return

    const wasPlaying = s.isPlaying && !s.isPaused

    // Pause during seek
    if (wasPlaying) {
      pause()
    }

    // Clamp time
    const targetTime = Math.max(0, Math.min(timeMs, s.duration))

    // If seeking backwards, reset and replay from start
    if (targetTime < s.currentTime) {
      s.currentTime = 0
      s.currentEventIndex = 0

      // Clear terminal if callback available
      if (outputCallback) {
        outputCallback('\x1b[2J\x1b[H')  // Clear screen and home cursor
      }
    }

    // Process events up to target time
    processEventsToTime(targetTime)
    s.currentTime = targetTime

    // Resume if was playing
    if (wasPlaying) {
      play()
    }

    console.log(`[useReplay] Seeked to ${timeMs}ms`)
  }

  function setSpeed(speed: number) {
    const s = replayStates.value.get(paneId)
    if (!s) return

    s.speed = Math.max(0.25, Math.min(speed, 8))
    console.log(`[useReplay] Speed set to ${s.speed}x`)
  }

  function skipForward(ms: number = 5000) {
    const s = replayStates.value.get(paneId)
    if (!s) return

    seek(s.currentTime + ms)
  }

  function skipBackward(ms: number = 5000) {
    const s = replayStates.value.get(paneId)
    if (!s) return

    seek(s.currentTime - ms)
  }

  // Format time for display
  function formatTime(ms: number): string {
    const totalSeconds = Math.floor(ms / 1000)
    const minutes = Math.floor(totalSeconds / 60)
    const seconds = totalSeconds % 60

    return `${minutes}:${seconds.toString().padStart(2, '0')}`
  }

  // Progress percentage
  const progress = computed(() => {
    const s = state.value
    if (!s || s.duration === 0) return 0
    return (s.currentTime / s.duration) * 100
  })

  // Cleanup on unmount
  onUnmounted(() => {
    if (animationFrameId !== null) {
      cancelAnimationFrame(animationFrameId)
    }
  })

  return {
    // State
    state,
    progress,

    // Loading
    loadRecording,

    // Callbacks
    setOutputCallback,
    setResizeCallback,

    // Controls
    play,
    pause,
    stop,
    seek,
    setSpeed,
    skipForward,
    skipBackward,

    // Utils
    formatTime,
  }
}
