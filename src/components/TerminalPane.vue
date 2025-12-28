<template>
  <div class="terminal-pane" :class="{ active: isActive }">
    <RecordingControls
      ref="recordingControlsRef"
      :paneId="paneId"
      :ptyId="ptyId"
      :tabId="tabId"
      :visible="showRecordingControls"
      :cwd="currentCwd"
      :cols="terminalCols"
      :rows="terminalRows"
      @replay-output="handleReplayOutput"
      @replay-started="handleReplayStarted"
      @replay-ended="handleReplayEnded"
    />
    <!-- Warp-style command blocks -->
    <div class="blocks-view" v-if="(blocks.length > 0 || activeBlock) && showBlocks">
      <div class="blocks-toolbar">
        <span class="block-count">{{ blocks.length + (activeBlock ? 1 : 0) }} command{{ (blocks.length + (activeBlock ? 1 : 0)) !== 1 ? 's' : '' }}</span>
        <button class="toggle-blocks-btn" @click="showBlocks = false" title="Hide blocks">
          ▼ Hide
        </button>
      </div>
      <!-- Completed blocks -->
      <CommandBlock
        v-for="block in blocks"
        :key="block.id"
        :block="block"
        @toggle="blocksStore.toggleBlock"
        @rerun="blocksStore.rerunBlock"
        @copy="blocksStore.copyBlock"
      />
      <!-- Currently running block -->
      <CommandBlock
        v-if="activeBlock"
        :key="activeBlock.id"
        :block="activeBlock"
        @toggle="blocksStore.toggleBlock"
        @rerun="blocksStore.rerunBlock"
        @copy="blocksStore.copyBlock"
      />
    </div>
    <button
      v-else-if="(blocks.length > 0 || activeBlock) && !showBlocks"
      class="show-blocks-btn"
      @click="showBlocks = true"
    >
      ▶ Show {{ blocks.length + (activeBlock ? 1 : 0) }} command{{ (blocks.length + (activeBlock ? 1 : 0)) !== 1 ? 's' : '' }}
    </button>
    <div class="terminal-window" ref="terminalContainer" @click="focusTerminal"></div>
    <AIOverlay
      :isVisible="showAIOverlay"
      :cwd="currentCwd"
      :recentOutput="recentOutput"
      :paneId="paneId"
      @close="showAIOverlay = false"
    />
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { Terminal } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { WebLinksAddon } from 'xterm-addon-web-links'
import { WebglAddon } from 'xterm-addon-webgl'
import { invoke } from '@tauri-apps/api/tauri'
import { listen } from '@tauri-apps/api/event'
import { useTheme } from '../composables/useTheme'
import { usePreferences } from '../composables/usePreferences'
import { useSecuritySettings } from '../composables/useSecuritySettings'
import { useTerminalBuffer } from '../composables/useTerminalBuffer'
import { useBlocks } from '../composables/useBlocks'
import AIOverlay from './AIOverlay.vue'
import RecordingControls from './RecordingControls.vue'
import CommandBlock from './CommandBlock.vue'
import 'xterm/css/xterm.css'

const props = defineProps({
  paneId: {
    type: String,
    required: true
  },
  ptyId: {
    type: Number,
    required: true
  },
  tabId: {
    type: String,
    default: ''
  },
  isActive: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['cwd-change', 'title-change', 'output-change', 'command-executed', 'blocks-updated'])

const terminalContainer = ref(null)
let terminal = null
let fitAddon = null
let webglAddon = null
let outputUnlisten = null
let resizeDebounceTimer = null

// Performance: Output batching for high-throughput scenarios
let pendingWrites = []
let batchWriteTimer = null
let lastWriteTime = 0
const { getTheme } = useTheme()
const { preferences } = usePreferences()
const { isAIEnabled, isClipboardWriteAllowed } = useSecuritySettings()
const currentTheme = getTheme()

// Performance: Batched write to terminal
// Reduces DOM updates for high-throughput scenarios
function batchedWrite(data) {
  if (!terminal) return

  const now = Date.now()
  const throttleInterval = preferences.value.performance?.throttleInterval || 16

  // If we're under the throttle interval, batch the write
  if (now - lastWriteTime < throttleInterval) {
    pendingWrites.push(data)

    // Schedule a flush if not already scheduled
    if (!batchWriteTimer) {
      batchWriteTimer = setTimeout(() => {
        flushWrites()
      }, throttleInterval)
    }
    return
  }

  // Otherwise write immediately
  terminal.write(data)
  lastWriteTime = now
}

function flushWrites() {
  if (!terminal || pendingWrites.length === 0) {
    batchWriteTimer = null
    return
  }

  // Combine all pending writes
  const combined = pendingWrites.join('')
  pendingWrites = []
  batchWriteTimer = null

  terminal.write(combined)
  lastWriteTime = Date.now()
}

// AI overlay state
const showAIOverlay = ref(false)
const currentCwd = ref(undefined)
const recentOutput = ref('')
const MAX_OUTPUT_LINES = 50

// Terminal buffer for large scrollback support
const terminalBuffer = useTerminalBuffer(props.paneId, {
  maxLines: preferences.value.performance?.maxOutputBuffer || 100000,
  overscan: 50,
  batchSize: 1000,
  searchTimeout: 100
})

// Blocks for command grouping (Warp-style)
const blocksStore = useBlocks(props.ptyId)
const blocks = blocksStore.blocks // Expose computed ref for template
const activeBlock = blocksStore.activeBlock // Currently running block

// Recording state
const showRecordingControls = ref(true)

// Blocks visibility state
const showBlocks = ref(true)

// AI Ghost Text Autocomplete state
const ghostSuggestion = ref('')
const isShowingGhost = ref(false)
let ghostDebounceTimer = null
let ghostDecoration = null

// Command tracking for analytics
let inputBuffer = ''
const recordingControlsRef = ref(null)
const terminalCols = ref(80)
const terminalRows = ref(24)
const isInReplayMode = ref(false)

// ============================================================================
// AI Ghost Text Autocomplete Functions
// ============================================================================

/**
 * Fetch AI completion suggestion for partial command
 */
async function fetchGhostSuggestion(partial) {
  if (partial.length < 2) {
    clearGhostText()
    return
  }

  try {
    const suggestion = await invoke('get_ai_completion', {
      partialCommand: partial,
      cwd: currentCwd.value || '~'
    })

    if (suggestion && suggestion.trim()) {
      ghostSuggestion.value = suggestion.trim()
      showGhostText(suggestion.trim())
    } else {
      clearGhostText()
    }
  } catch (error) {
    console.log('[TerminalPane] Ghost suggestion unavailable:', error.message || error)
    clearGhostText()
  }
}

/**
 * Show ghost text suggestion after cursor using xterm decoration
 */
function showGhostText(suggestion) {
  if (!terminal || !suggestion) return

  // Clear existing decoration
  clearGhostText()

  // Get cursor position
  const cursorX = terminal.buffer.active.cursorX
  const cursorY = terminal.buffer.active.cursorY

  // Create a marker at current position
  const marker = terminal.registerMarker(0)
  if (!marker) return

  // Create decoration with ghost text
  const decoration = terminal.registerDecoration({
    marker,
    x: cursorX,
    width: suggestion.length,
    backgroundColor: 'transparent'
  })

  if (decoration) {
    decoration.onRender((element) => {
      element.style.color = '#666'
      element.style.fontStyle = 'italic'
      element.style.pointerEvents = 'none'
      element.textContent = suggestion
    })
    ghostDecoration = { decoration, marker }
    isShowingGhost.value = true
  }
}

/**
 * Clear ghost text decoration
 */
function clearGhostText() {
  if (ghostDecoration) {
    if (ghostDecoration.decoration) {
      ghostDecoration.decoration.dispose()
    }
    if (ghostDecoration.marker) {
      ghostDecoration.marker.dispose()
    }
    ghostDecoration = null
  }
  ghostSuggestion.value = ''
  isShowingGhost.value = false
}

/**
 * Accept ghost text suggestion - insert it
 */
async function acceptGhostSuggestion() {
  if (!isShowingGhost.value || !ghostSuggestion.value) return false

  const suggestion = ghostSuggestion.value
  clearGhostText()

  // Send suggestion to PTY
  try {
    await invoke('send_input', { id: props.ptyId, input: suggestion })
    inputBuffer += suggestion
    return true
  } catch (error) {
    console.error('[TerminalPane] Failed to accept suggestion:', error)
    return false
  }
}

/**
 * Debounced ghost suggestion fetch
 */
function debouncedFetchGhost(partial) {
  if (ghostDebounceTimer) {
    clearTimeout(ghostDebounceTimer)
  }
  ghostDebounceTimer = setTimeout(() => {
    fetchGhostSuggestion(partial)
  }, 300) // 300ms debounce
}

onMounted(async () => {
  console.log('[TerminalPane] Mounted for pane:', props.paneId, 'PTY:', props.ptyId)

  terminal = new Terminal({
    cursorBlink: preferences.value.terminal.cursorBlink,
    cursorStyle: preferences.value.terminal.cursorStyle,
    fontSize: preferences.value.terminal.fontSize,
    fontFamily: preferences.value.terminal.fontFamily,
    lineHeight: preferences.value.terminal.lineHeight,
    scrollback: preferences.value.terminal.scrollback,
    allowProposedApi: true,
    theme: currentTheme.terminal
  })

  fitAddon = new FitAddon()
  terminal.loadAddon(fitAddon)

  // WebLinksAddon with click handler to open links in browser
  const webLinksAddon = new WebLinksAddon((event, uri) => {
    // Open link using Tauri's shell API
    import('@tauri-apps/api/shell').then(({ open }) => {
      // Validate URL before opening
      try {
        const url = new URL(uri)
        // Only allow http, https protocols
        if (url.protocol === 'http:' || url.protocol === 'https:') {
          open(uri)
        } else {
          console.warn('[TerminalPane] Blocked non-http link:', uri)
        }
      } catch {
        console.warn('[TerminalPane] Invalid URL:', uri)
      }
    }).catch(err => {
      console.error('[TerminalPane] Failed to open link:', err)
    })
  })
  terminal.loadAddon(webLinksAddon)

  terminal.open(terminalContainer.value)

  // WebGL addon for GPU-accelerated rendering (performance optimization)
  if (preferences.value.performance?.enableGPUAcceleration !== false) {
    try {
      webglAddon = new WebglAddon()
      webglAddon.onContextLoss(() => {
        console.warn('[TerminalPane] WebGL context lost, falling back to canvas')
        webglAddon?.dispose()
        webglAddon = null
      })
      terminal.loadAddon(webglAddon)
      console.log('[TerminalPane] WebGL renderer enabled')
    } catch (e) {
      console.warn('[TerminalPane] WebGL not supported, using canvas renderer:', e.message)
    }
  }

  fitAddon.fit()

  const dims = terminal
  console.log('[TerminalPane] Dimensions:', dims.cols, 'x', dims.rows)

  try {
    await invoke('resize_pty', { id: props.ptyId, cols: dims.cols, rows: dims.rows })
  } catch (error) {
    console.error('[TerminalPane] Failed to resize PTY:', error)
  }

  if (props.isActive) {
    terminal.focus()
  }

  // OSC 7: Working directory notification
  terminal.parser.registerOscHandler(7, (data) => {
    try {
      const match = data.match(/file:\/\/[^/]*(.*)/)
      if (match) {
        const cwd = decodeURIComponent(match[1])
        console.log('[TerminalPane] OSC 7 cwd:', cwd)
        currentCwd.value = cwd  // Track locally for AI context
        emit('cwd-change', { paneId: props.paneId, cwd })
        // Update blocks store with new CWD
        blocksStore.processOutput('', cwd) // Empty string just to update CWD
      }
    } catch (e) {
      console.error('[TerminalPane] Failed to parse OSC 7:', e)
    }
    return true
  })

  // OSC 0/2: Window title
  terminal.parser.registerOscHandler(0, (data) => {
    emit('title-change', { paneId: props.paneId, title: data })
    return true
  })
  terminal.parser.registerOscHandler(2, (data) => {
    emit('title-change', { paneId: props.paneId, title: data })
    return true
  })

  // OSC 8: Hyperlinks
  // Format: OSC 8 ; params ; uri ST ... text ... OSC 8 ; ; ST
  // xterm.js handles rendering, but we can add custom link handling
  // The WebLinksAddon already handles basic URL detection
  // OSC 8 is registered natively by xterm.js when allowProposedApi is true

  // OSC 52: Clipboard operations
  // Format: OSC 52 ; target ; base64-data ST
  // target: c = clipboard, p = primary selection
  // Security: Only allow clipboard write, not read (prevents data exfiltration)
  // Respects security settings for clipboard permissions
  terminal.parser.registerOscHandler(52, (data) => {
    try {
      const parts = data.split(';')
      if (parts.length >= 2) {
        const target = parts[0]
        const b64Data = parts.slice(1).join(';')

        // Only handle 'c' (clipboard) or 'p' (primary) targets
        if (target === 'c' || target === 'p' || target === '') {
          // If b64Data is '?', it's a read request - ALWAYS ignore for security
          if (b64Data === '?') {
            console.log('[TerminalPane] OSC 52 clipboard read request BLOCKED (security)')
            return true
          }

          // Check security settings before allowing clipboard write
          if (!isClipboardWriteAllowed()) {
            console.log('[TerminalPane] OSC 52 clipboard write BLOCKED (disabled in settings)')
            return true
          }

          // Decode base64 and write to clipboard
          try {
            const decoded = atob(b64Data)
            navigator.clipboard.writeText(decoded).then(() => {
              console.log('[TerminalPane] OSC 52 clipboard write:', decoded.length, 'chars')
            }).catch(err => {
              console.error('[TerminalPane] OSC 52 clipboard write failed:', err)
            })
          } catch (decodeErr) {
            console.error('[TerminalPane] OSC 52 base64 decode failed:', decodeErr)
          }
        }
      }
    } catch (e) {
      console.error('[TerminalPane] Failed to parse OSC 52:', e)
    }
    return true
  })

  // Clipboard handling
  terminal.onSelectionChange(() => {
    const selection = terminal.getSelection()
    if (selection) {
      navigator.clipboard.writeText(selection).catch(err => {
        console.error('[TerminalPane] Failed to copy:', err)
      })
    }
  })

  terminal.attachCustomKeyEventHandler((event) => {
    // Tab: Accept ghost text suggestion if showing
    if (event.key === 'Tab' && event.type === 'keydown' && isShowingGhost.value) {
      acceptGhostSuggestion()
      return false // Prevent default tab behavior
    }

    // Escape: Clear ghost text or close AI overlay
    if (event.key === 'Escape' && event.type === 'keydown') {
      if (isShowingGhost.value) {
        clearGhostText()
        return false
      }
      if (showAIOverlay.value) {
        showAIOverlay.value = false
        return false
      }
    }

    // Cmd/Ctrl + Shift + A: Toggle AI overlay (only if AI is enabled)
    if ((event.metaKey || event.ctrlKey) && event.shiftKey && event.key === 'a' && event.type === 'keydown') {
      if (isAIEnabled()) {
        showAIOverlay.value = !showAIOverlay.value
      } else {
        console.log('[TerminalPane] AI is disabled (air-gapped mode)')
      }
      return false
    }

    // Cmd/Ctrl + V: Paste
    if ((event.metaKey || event.ctrlKey) && event.key === 'v' && event.type === 'keydown') {
      navigator.clipboard.readText().then(text => {
        if (text) {
          const lines = text.split('\n')
          if (lines.length > 1) {
            invoke('send_input', { id: props.ptyId, input: '\x1b[200~' + text + '\x1b[201~' })
          } else {
            invoke('send_input', { id: props.ptyId, input: text })
          }
        }
      }).catch(err => {
        console.error('[TerminalPane] Failed to paste:', err)
      })
      return false
    }
    return true
  })

  // Input handling
  terminal.onData(async (data) => {
    try {
      // Clear ghost text on any input (will re-fetch after debounce)
      clearGhostText()

      // Track command input for analytics
      if (data === '\r' || data === '\n') {
        // Enter pressed - emit command if we have input
        if (inputBuffer.trim()) {
          emit('command-executed', {
            paneId: props.paneId,
            tabId: props.tabId,
            command: inputBuffer.trim()
          })
          // Notify blocks store of command submission
          blocksStore.onCommandSubmit(inputBuffer.trim(), currentCwd.value || '~')
        }
        inputBuffer = ''
      } else if (data === '\x7f' || data === '\b') {
        // Backspace - remove last char
        inputBuffer = inputBuffer.slice(0, -1)
        // Fetch new suggestion for shorter input
        if (inputBuffer.length >= 2 && isAIEnabled()) {
          debouncedFetchGhost(inputBuffer)
        }
      } else if (data === '\x03') {
        // Ctrl+C - clear buffer
        inputBuffer = ''
      } else if (data.length === 1 && data.charCodeAt(0) >= 32) {
        // Printable character
        inputBuffer += data
        // Fetch AI suggestion if AI enabled
        if (isAIEnabled()) {
          debouncedFetchGhost(inputBuffer)
        }
      } else if (data.length > 1 && !data.startsWith('\x1b')) {
        // Pasted text (not escape sequence)
        inputBuffer += data
        // Fetch AI suggestion for pasted text
        if (isAIEnabled()) {
          debouncedFetchGhost(inputBuffer)
        }
      }

      // Record input if recording is active
      recordInputIfActive(data)
      await invoke('send_input', { id: props.ptyId, input: data })
    } catch (error) {
      console.error('[TerminalPane] Failed to send input:', error)
    }
  })

  // Resize handling
  terminal.onResize(async ({ cols, rows }) => {
    try {
      // Track dimensions for recording
      terminalCols.value = cols
      terminalRows.value = rows
      await invoke('resize_pty', { id: props.ptyId, cols, rows })
    } catch (error) {
      console.error('[TerminalPane] Failed to resize PTY:', error)
    }
  })

  // Start event-driven output streaming (replaces polling)
  await startOutputStream()

  // Handle window resize with debouncing
  window.addEventListener('resize', handleResizeDebounced)
  handleResize()
})

onUnmounted(() => {
  // Flush any pending writes before cleanup
  if (batchWriteTimer) {
    clearTimeout(batchWriteTimer)
    flushWrites()
  }

  // Clean up ghost text
  if (ghostDebounceTimer) {
    clearTimeout(ghostDebounceTimer)
  }
  clearGhostText()

  stopOutputStream()
  window.removeEventListener('resize', handleResizeDebounced)
  if (resizeDebounceTimer) {
    clearTimeout(resizeDebounceTimer)
  }

  // Dispose WebGL addon before terminal
  if (webglAddon) {
    webglAddon.dispose()
    webglAddon = null
  }

  if (terminal) {
    terminal.dispose()
  }
})

// Watch for active state changes to focus
watch(() => props.isActive, (newVal) => {
  if (newVal && terminal) {
    terminal.focus()
    handleResize()
  }
})

function handleResize() {
  if (fitAddon) {
    fitAddon.fit()
  }
}

// Debounced resize handler to reduce resize calls during rapid window changes
function handleResizeDebounced() {
  if (resizeDebounceTimer) {
    clearTimeout(resizeDebounceTimer)
  }
  resizeDebounceTimer = setTimeout(() => {
    handleResize()
  }, 16) // ~60fps debounce
}

// Event-driven output streaming (replaces polling)
async function startOutputStream() {
  try {
    // Start the output stream on the Rust side
    await invoke('start_pty_output_stream', { id: props.ptyId })

    // Listen for PTY output events
    outputUnlisten = await listen('pty_output', (event) => {
      const { id, data } = event.payload
      // Only process output for this PTY
      if (id === props.ptyId && data && terminal) {
        // Use batched write for better performance with high throughput
        batchedWrite(data)

        // Record output if recording is active
        recordOutputIfActive(data)

        // Store in terminal buffer for search/recording/export
        terminalBuffer.appendOutput(data)

        // Process output through blocks for command grouping
        blocksStore.processOutput(data, currentCwd.value || '~')

        // Emit blocks update for UI
        emit('blocks-updated', {
          paneId: props.paneId,
          blocks: blocksStore.blocks.value,
          activeBlock: blocksStore.activeBlock.value
        })

        // Track recent output for AI context (last N lines)
        const allLines = terminalBuffer.getAllLines()
        const recentLines = allLines.slice(-MAX_OUTPUT_LINES)
        recentOutput.value = recentLines.map(l => l.content).join('\n')

        // Emit output change for global search (with full buffer access)
        emit('output-change', {
          paneId: props.paneId,
          output: recentOutput.value,
          buffer: terminalBuffer  // Pass buffer reference for full search
        })
      }
    })

    console.log('[TerminalPane] Started event-driven output stream for PTY:', props.ptyId)
  } catch (error) {
    console.error('[TerminalPane] Failed to start output stream:', error)
    // Fallback to polling if event stream fails
    startOutputPollingFallback()
  }
}

function stopOutputStream() {
  if (outputUnlisten) {
    outputUnlisten()
    outputUnlisten = null
  }
  // Also stop fallback polling if it was started
  stopOutputPollingFallback()
}

// Fallback polling in case event streaming fails
let outputInterval = null
function startOutputPollingFallback() {
  console.warn('[TerminalPane] Using fallback polling mode')
  outputInterval = setInterval(async () => {
    try {
      const output = await invoke('read_pty', { id: props.ptyId })
      if (output && output.length > 0 && terminal) {
        batchedWrite(output)

        // Record output if recording is active
        recordOutputIfActive(output)

        // Store in terminal buffer
        terminalBuffer.appendOutput(output)

        // Track recent output for AI context
        const allLines = terminalBuffer.getAllLines()
        const recentLines = allLines.slice(-MAX_OUTPUT_LINES)
        recentOutput.value = recentLines.map(l => l.content).join('\n')

        emit('output-change', {
          paneId: props.paneId,
          output: recentOutput.value,
          buffer: terminalBuffer
        })
      }
    } catch (error) {
      if (!error.toString().includes('not found')) {
        console.error('[TerminalPane] Fallback polling error:', error)
      }
    }
  }, 50)
}

function stopOutputPollingFallback() {
  if (outputInterval) {
    clearInterval(outputInterval)
    outputInterval = null
  }
}

function focusTerminal() {
  if (terminal) {
    terminal.focus()
  }
}

// Recording handlers
function handleReplayOutput(data) {
  if (terminal) {
    terminal.write(data)
  }
}

function handleReplayStarted() {
  isInReplayMode.value = true
  // Clear terminal for replay
  if (terminal) {
    terminal.clear()
  }
}

function handleReplayEnded() {
  isInReplayMode.value = false
}

// Record output when recording is active
function recordOutputIfActive(data) {
  if (recordingControlsRef.value?.isRecording?.()) {
    recordingControlsRef.value.recordOutput(data)
  }
}

// Record input when recording is active
function recordInputIfActive(data) {
  if (recordingControlsRef.value?.isRecording?.()) {
    recordingControlsRef.value.recordInput(data)
  }
}

// Toggle recording controls visibility with keyboard shortcut
function toggleRecordingControls() {
  showRecordingControls.value = !showRecordingControls.value
}

// Expose buffer and blocks for external access (search, recording, UI)
defineExpose({
  // Get the full terminal buffer for search
  getBuffer: () => terminalBuffer,
  // Search the buffer directly
  searchBuffer: (pattern, options) => terminalBuffer.search(pattern, options),
  // Get all output for recording/export
  getAllOutput: () => terminalBuffer.getRawContent(),
  // Get buffer stats
  getBufferStats: () => terminalBuffer.stats.value,
  // Blocks API for command grouping UI
  getBlocks: () => blocksStore.blocks.value,
  getActiveBlock: () => blocksStore.activeBlock.value,
  toggleBlock: (id) => blocksStore.toggleBlock(id),
  rerunBlock: (id) => blocksStore.rerunBlock(id),
  copyBlock: (id) => blocksStore.copyBlock(id),
  copyCommand: (id) => blocksStore.copyCommand(id),
  collapseAllBlocks: () => blocksStore.collapseAll(),
  expandAllBlocks: () => blocksStore.expandAll(),
  clearBlocks: () => blocksStore.clearBlocks(),
  exportBlocks: () => blocksStore.exportAllBlocks(),
  exportAsScript: () => blocksStore.exportAsScript(),
  hasShellIntegration: () => blocksStore.hasShellIntegration.value
})
</script>

<style scoped>
.terminal-pane {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  background-color: var(--bg-color);
}

.terminal-pane.active {
  /* Active pane styling handled by parent */
}

/* Warp-style command blocks */
.blocks-view {
  flex: 0 0 auto;
  max-height: 35%;
  overflow-y: auto;
  padding: 8px;
  background: linear-gradient(to bottom, #1a1a1a 0%, #0d0d0d 100%);
  border-bottom: 1px solid #3a3a3a;
}

.blocks-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid #333;
}

.block-count {
  color: #888;
  font-size: 11px;
  font-weight: 500;
}

.toggle-blocks-btn {
  background: transparent;
  border: 1px solid #444;
  color: #aaa;
  padding: 2px 8px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 10px;
  transition: all 0.15s ease;
}

.toggle-blocks-btn:hover {
  background: #333;
  color: #fff;
  border-color: #555;
}

.show-blocks-btn {
  background: linear-gradient(to right, #1e253a 0%, #0f172a 100%);
  border: none;
  border-bottom: 1px solid #3a3a3a;
  color: #64748b;
  padding: 6px 12px;
  cursor: pointer;
  font-size: 11px;
  width: 100%;
  text-align: left;
  transition: all 0.15s ease;
}

.show-blocks-btn:hover {
  background: linear-gradient(to right, #2d3a52 0%, #1e253a 100%);
  color: #94a3b8;
}

.blocks-view::-webkit-scrollbar {
  width: 8px;
}

.blocks-view::-webkit-scrollbar-track {
  background: #1a1a1a;
}

.blocks-view::-webkit-scrollbar-thumb {
  background: #404040;
  border-radius: 4px;
}

.blocks-view::-webkit-scrollbar-thumb:hover {
  background: #505050;
}

.terminal-window {
  flex: 1;
  min-height: 0;
  padding: 4px;
  background-color: var(--bg-color);
}

:deep(.xterm) {
  height: 100%;
}

:deep(.xterm-viewport) {
  background-color: var(--bg-color) !important;
}
</style>
