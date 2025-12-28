/**
 * useEditorKeybindings - Vim/Emacs keybindings for Monaco editor
 *
 * Enables optional Vim or Emacs keybindings in the Monaco editor
 */

import { ref, watch } from 'vue'
import type * as Monaco from 'monaco-editor'

export type KeybindingMode = 'standard' | 'vim' | 'emacs'

const STORAGE_KEY = 'warp-editor-keybindings'

// Current mode
const currentMode = ref<KeybindingMode>(
  (localStorage.getItem(STORAGE_KEY) as KeybindingMode) || 'standard'
)

// Save on change
watch(currentMode, (mode) => {
  localStorage.setItem(STORAGE_KEY, mode)
})

// Vim state
interface VimState {
  mode: 'normal' | 'insert' | 'visual' | 'command'
  register: string
  count: string
  lastCommand: string
}

const vimState = ref<VimState>({
  mode: 'normal',
  register: '"',
  count: '',
  lastCommand: ''
})

export function useEditorKeybindings() {
  let editor: Monaco.editor.IStandaloneCodeEditor | null = null
  let disposables: Monaco.IDisposable[] = []

  /**
   * Initialize keybindings for an editor
   */
  function initEditor(monacoEditor: Monaco.editor.IStandaloneCodeEditor) {
    editor = monacoEditor
    applyMode(currentMode.value)
  }

  /**
   * Set keybinding mode
   */
  function setMode(mode: KeybindingMode) {
    currentMode.value = mode
    if (editor) {
      applyMode(mode)
    }
  }

  /**
   * Apply keybinding mode to editor
   */
  function applyMode(mode: KeybindingMode) {
    if (!editor) return

    // Clear previous bindings
    disposables.forEach(d => d.dispose())
    disposables = []

    if (mode === 'vim') {
      applyVimBindings()
    } else if (mode === 'emacs') {
      applyEmacsBindings()
    }
    // 'standard' mode uses default Monaco bindings
  }

  /**
   * Apply Vim keybindings
   */
  function applyVimBindings() {
    if (!editor) return

    const monaco = (window as any).monaco as typeof Monaco
    if (!monaco) return

    vimState.value.mode = 'normal'

    // Add status bar indicator
    updateVimStatusBar()

    // Key handler for normal mode
    disposables.push(
      editor.onKeyDown((e) => {
        if (vimState.value.mode !== 'normal') return

        const key = e.browserEvent.key

        // Movement keys
        if (key === 'h') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorLeft', {})
        } else if (key === 'j') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorDown', {})
        } else if (key === 'k') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorUp', {})
        } else if (key === 'l') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorRight', {})
        } else if (key === 'w') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorWordStartRight', {})
        } else if (key === 'b') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorWordStartLeft', {})
        } else if (key === '0') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorHome', {})
        } else if (key === '$') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorEnd', {})
        } else if (key === 'g' && e.browserEvent.shiftKey) {
          e.preventDefault()
          editor!.trigger('vim', 'cursorBottom', {})
        } else if (key === 'g') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorTop', {})
        }
        // Mode switches
        else if (key === 'i') {
          e.preventDefault()
          vimState.value.mode = 'insert'
          updateVimStatusBar()
        } else if (key === 'a') {
          e.preventDefault()
          editor!.trigger('vim', 'cursorRight', {})
          vimState.value.mode = 'insert'
          updateVimStatusBar()
        } else if (key === 'o') {
          e.preventDefault()
          editor!.trigger('vim', 'editor.action.insertLineAfter', {})
          vimState.value.mode = 'insert'
          updateVimStatusBar()
        } else if (key === 'O') {
          e.preventDefault()
          editor!.trigger('vim', 'editor.action.insertLineBefore', {})
          vimState.value.mode = 'insert'
          updateVimStatusBar()
        }
        // Editing
        else if (key === 'd' && e.browserEvent.shiftKey) {
          e.preventDefault()
          editor!.trigger('vim', 'deleteAllRight', {})
        } else if (key === 'x') {
          e.preventDefault()
          editor!.trigger('vim', 'deleteRight', {})
        } else if (key === 'u') {
          e.preventDefault()
          editor!.trigger('vim', 'undo', {})
        } else if (key === 'r' && e.ctrlKey) {
          e.preventDefault()
          editor!.trigger('vim', 'redo', {})
        }
        // Search
        else if (key === '/') {
          e.preventDefault()
          editor!.trigger('vim', 'actions.find', {})
        } else if (key === 'n') {
          e.preventDefault()
          editor!.trigger('vim', 'editor.action.nextMatchFindAction', {})
        } else if (key === 'N') {
          e.preventDefault()
          editor!.trigger('vim', 'editor.action.previousMatchFindAction', {})
        }
      })
    )

    // Escape to return to normal mode
    disposables.push(
      editor.onKeyDown((e) => {
        if (e.browserEvent.key === 'Escape') {
          e.preventDefault()
          vimState.value.mode = 'normal'
          updateVimStatusBar()
        }
      })
    )
  }

  /**
   * Apply Emacs keybindings
   */
  function applyEmacsBindings() {
    if (!editor) return

    const monaco = (window as any).monaco as typeof Monaco
    if (!monaco) return

    // Emacs keybindings
    const bindings = [
      // Movement
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyF, command: 'cursorRight' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyB, command: 'cursorLeft' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyN, command: 'cursorDown' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyP, command: 'cursorUp' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyA, command: 'cursorHome' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyE, command: 'cursorEnd' },
      { key: monaco.KeyMod.Alt | monaco.KeyCode.KeyF, command: 'cursorWordEndRight' },
      { key: monaco.KeyMod.Alt | monaco.KeyCode.KeyB, command: 'cursorWordStartLeft' },

      // Editing
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyD, command: 'deleteRight' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyH, command: 'deleteLeft' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, command: 'deleteAllRight' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyY, command: 'editor.action.clipboardPasteAction' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyW, command: 'editor.action.clipboardCutAction' },
      { key: monaco.KeyMod.Alt | monaco.KeyCode.KeyW, command: 'editor.action.clipboardCopyAction' },

      // Undo
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.Slash, command: 'undo' },

      // Search
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, command: 'actions.find' },
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyR, command: 'editor.action.startFindReplaceAction' },

      // Buffer/Window
      { key: monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyG, command: 'cancelSelection' },
    ]

    for (const binding of bindings) {
      disposables.push(
        editor.addCommand(binding.key, () => {
          editor!.trigger('emacs', binding.command, {})
        })
      )
    }
  }

  /**
   * Update Vim status bar
   */
  function updateVimStatusBar() {
    // Dispatch event for status bar to pick up
    window.dispatchEvent(new CustomEvent('vim-mode-change', {
      detail: { mode: vimState.value.mode }
    }))
  }

  /**
   * Cleanup
   */
  function dispose() {
    disposables.forEach(d => d.dispose())
    disposables = []
    editor = null
  }

  return {
    currentMode,
    vimState,
    initEditor,
    setMode,
    dispose
  }
}

export default useEditorKeybindings
