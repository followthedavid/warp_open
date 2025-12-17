<template>
  <div class="terminal-container">
    <div class="blocks-view" v-if="blocks.length > 0">
      <CommandBlock
        v-for="block in blocks"
        :key="block.id"
        :block="block"
        @toggle="toggleBlock"
        @rerun="rerunBlock"
        @copy="copyBlock"
      />
    </div>
    <div class="terminal-window" ref="terminalContainer" @click="focusTerminal" tabindex="0"></div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { Terminal } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { WebLinksAddon } from 'xterm-addon-web-links'
import { invoke } from '@tauri-apps/api/tauri'
import { useTheme } from '../composables/useTheme'
import { usePreferences } from '../composables/usePreferences'
import { useBlocks } from '../composables/useBlocks'
import CommandBlock from './CommandBlock.vue'
import 'xterm/css/xterm.css'

const props = defineProps({
  ptyId: {
    type: Number,
    required: true
  },
  tabId: {
    type: String,
    required: true
  }
})

const emit = defineEmits(['cwd-change', 'title-change'])

const terminalContainer = ref(null)
let terminal = null
let fitAddon = null
let outputInterval = null
const { getTheme } = useTheme()
const { preferences } = usePreferences()
const currentTheme = getTheme()

// Initialize blocks tracking
const { 
  blocks, 
  processOutput, 
  toggleBlock: toggleBlockFn, 
  rerunBlock: rerunBlockFn, 
  copyBlock: copyBlockFn 
} = useBlocks(props.ptyId)

function toggleBlock(blockId) {
  toggleBlockFn(blockId)
}

function rerunBlock(blockId) {
  rerunBlockFn(blockId)
}

function copyBlock(blockId) {
  copyBlockFn(blockId)
}

onMounted(async () => {
  console.log('TerminalWindow mounted for PTY:', props.ptyId, 'Tab:', props.tabId)
  // Initialize xterm.js with current theme and preferences
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

  // Add addons
  fitAddon = new FitAddon()
  terminal.loadAddon(fitAddon)

  // WebLinksAddon with click handler to open links in browser
  const webLinksAddon = new WebLinksAddon((event, uri) => {
    import('@tauri-apps/api/shell').then(({ open }) => {
      try {
        const url = new URL(uri)
        if (url.protocol === 'http:' || url.protocol === 'https:') {
          open(uri)
        } else {
          console.warn('[Terminal] Blocked non-http link:', uri)
        }
      } catch {
        console.warn('[Terminal] Invalid URL:', uri)
      }
    }).catch(err => {
      console.error('[Terminal] Failed to open link:', err)
    })
  })
  terminal.loadAddon(webLinksAddon)

  // Open terminal
  console.log('Opening xterm terminal...')
  terminal.open(terminalContainer.value)
  fitAddon.fit()
  
  // Get the actual terminal dimensions after fit
  const dims = terminal;
  console.log('Terminal dimensions:', dims.cols, 'x', dims.rows)
  
  // Resize the PTY to match the terminal
  try {
    await invoke('resize_pty', { id: props.ptyId, cols: dims.cols, rows: dims.rows })
    console.log('PTY resized to', dims.cols, 'x', dims.rows)
  } catch (error) {
    console.error('Failed to resize PTY:', error)
  }
  
  // Focus the terminal immediately
  terminal.focus()
  console.log('Terminal opened and focused')

  // Enable mouse selection and clipboard
  terminal.options.cursorBlink = true
  terminal.options.rightClickSelectsWord = true

  // Register OSC handlers for cwd and title updates
  // OSC 7: Working directory notification (file://host/path)
  terminal.parser.registerOscHandler(7, (data) => {
    // data is typically: file://hostname/path/to/dir
    try {
      const match = data.match(/file:\/\/[^/]*(.*)/)
      if (match) {
        const cwd = decodeURIComponent(match[1])
        console.log('[Terminal] OSC 7 cwd:', cwd)
        emit('cwd-change', { tabId: props.tabId, cwd })
      }
    } catch (e) {
      console.error('[Terminal] Failed to parse OSC 7:', e)
    }
    return true
  })

  // OSC 0/2: Window/icon title
  terminal.parser.registerOscHandler(0, (data) => {
    console.log('[Terminal] OSC 0 title:', data)
    emit('title-change', { tabId: props.tabId, title: data })
    return true
  })
  terminal.parser.registerOscHandler(2, (data) => {
    console.log('[Terminal] OSC 2 title:', data)
    emit('title-change', { tabId: props.tabId, title: data })
    return true
  })

  // OSC 52: Clipboard operations
  // Format: OSC 52 ; target ; base64-data ST
  // Security: Only allow clipboard write, not read (prevents data exfiltration)
  terminal.parser.registerOscHandler(52, (data) => {
    try {
      const parts = data.split(';')
      if (parts.length >= 2) {
        const target = parts[0]
        const b64Data = parts.slice(1).join(';')

        // Only handle 'c' (clipboard) or 'p' (primary) targets
        if (target === 'c' || target === 'p' || target === '') {
          // If b64Data is '?', it's a read request - ignore for security
          if (b64Data === '?') {
            console.log('[Terminal] OSC 52 clipboard read request ignored (security)')
            return true
          }

          // Decode base64 and write to clipboard
          try {
            const decoded = atob(b64Data)
            navigator.clipboard.writeText(decoded).then(() => {
              console.log('[Terminal] OSC 52 clipboard write:', decoded.length, 'chars')
            }).catch(err => {
              console.error('[Terminal] OSC 52 clipboard write failed:', err)
            })
          } catch (decodeErr) {
            console.error('[Terminal] OSC 52 base64 decode failed:', decodeErr)
          }
        }
      }
    } catch (e) {
      console.error('[Terminal] Failed to parse OSC 52:', e)
    }
    return true
  })

  // Handle selection for copy
  terminal.onSelectionChange(() => {
    const selection = terminal.getSelection()
    if (selection) {
      // Copy to clipboard automatically on selection
      navigator.clipboard.writeText(selection).catch(err => {
        console.error('Failed to copy to clipboard:', err)
      })
    }
  })

  // Handle paste from clipboard (Cmd/Ctrl+V)
  terminal.attachCustomKeyEventHandler((event) => {
    // Check for Cmd+V (Mac) or Ctrl+V (Windows/Linux)
    if ((event.metaKey || event.ctrlKey) && event.key === 'v' && event.type === 'keydown') {
      navigator.clipboard.readText().then(text => {
        if (text) {
          // Use bracketed paste mode for multi-line content
          const lines = text.split('\n')
          if (lines.length > 1) {
            // Bracketed paste: wrap in ESC[200~ ... ESC[201~
            invoke('send_input', { id: props.ptyId, input: '\x1b[200~' + text + '\x1b[201~' })
          } else {
            // Single line: just send as-is
            invoke('send_input', { id: props.ptyId, input: text })
          }
        }
      }).catch(err => {
        console.error('Failed to read from clipboard:', err)
      })
      return false // Prevent default paste behavior
    }
    return true // Allow other key events
  })

  // Handle terminal input
  terminal.onData(async (data) => {
    console.log('Terminal input:', data.length, 'bytes')
    try {
      await invoke('send_input', { id: props.ptyId, input: data })
    } catch (error) {
      console.error('Failed to send input:', error)
    }
  })

  // Handle terminal resize
  terminal.onResize(async ({ cols, rows }) => {
    try {
      await invoke('resize_pty', { id: props.ptyId, cols, rows })
    } catch (error) {
      console.error('Failed to resize PTY:', error)
    }
  })

  // Start polling for output
  startOutputPolling()
  
  // Immediately try to read any initial output
  setTimeout(async () => {
    try {
      const output = await invoke('read_pty', { id: props.ptyId })
      console.log('Initial output check:', output ? output.length : 0, 'bytes')
      if (output && output.length > 0) {
        console.log('Writing initial output to terminal:', output.substring(0, 100))
        terminal.write(output)
      }
    } catch (error) {
      console.error('Failed to read initial output:', error)
    }
  }, 100)

  // Handle window resize
  window.addEventListener('resize', handleResize)
  handleResize()
})

onUnmounted(() => {
  stopOutputPolling()
  window.removeEventListener('resize', handleResize)
  if (terminal) {
    terminal.dispose()
  }
})

function handleResize() {
  if (fitAddon) {
    setTimeout(() => {
      fitAddon.fit()
    }, 0)
  }
}

function startOutputPolling() {
  console.log('Starting output polling for PTY:', props.ptyId)
  // Poll for PTY output every 50ms
  outputInterval = setInterval(async () => {
    try {
      const output = await invoke('read_pty', { id: props.ptyId })
      if (output && output.length > 0) {
        console.log('Received output:', output.substring(0, 50), '...')
        // Process output for block boundaries
        processOutput(output)
        // Write to terminal
        terminal.write(output)
      }
    } catch (error) {
      // PTY might be closed or not ready
      if (!error.toString().includes('not found')) {
        console.error('Failed to read PTY output:', error)
      }
    }
  }, 50)
}

function stopOutputPolling() {
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
</script>

<style scoped>
.terminal-container {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background-color: var(--bg-color);
}

.blocks-view {
  flex: 0 0 auto;
  max-height: 40%;
  overflow-y: auto;
  padding: 8px;
  background: #1a1a1a;
  border-bottom: 1px solid #3a3a3a;
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
  padding: 8px;
  background-color: var(--bg-color);
}

:deep(.xterm) {
  height: 100%;
}

:deep(.xterm-viewport) {
  background-color: var(--bg-color) !important;
}
</style>
