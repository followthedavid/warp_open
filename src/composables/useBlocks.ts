/**
 * useBlocks - Warp-style command grouping with collapsible output
 *
 * Supports two modes:
 * 1. OSC 133 shell integration (preferred, accurate)
 * 2. Prompt heuristic detection (fallback, works with any shell)
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

export interface CommandBlock {
  id: string
  command: string
  output: string
  outputLines: string[]
  exitCode: number | null
  startTime: number
  endTime: number | null
  duration: number | null
  cwd: string
  collapsed: boolean
  ptyId: number
  isRunning: boolean
  outputType: 'plain' | 'error' | 'json' | 'table' | 'diff'
}

interface BlockState {
  blocks: Map<number, CommandBlock[]> // ptyId -> blocks
  activeBlock: Map<number, CommandBlock | null> // ptyId -> current block
  useOSC133: Map<number, boolean> // ptyId -> whether OSC 133 detected
}

const state = ref<BlockState>({
  blocks: new Map(),
  activeBlock: new Map(),
  useOSC133: new Map()
})

// Prompt detection patterns for fallback mode
const PROMPT_PATTERNS = [
  // Bash/Zsh standard prompts
  /^[\w\-\.]+@[\w\-\.]+:[~\/][\w\/\-\.]*[$#%]\s*/,
  // Simple $ or # or % prompt
  /^[$#%]\s+/,
  // User@host format (including macOS style with %)
  /^[\w\-]+@[\w\-\.]+\s*[$#%>]\s*/,
  // Path-based prompts (zsh)
  /^[~\/][\w\/\-\.]*\s*[$#%>]\s*/,
  // macOS default zsh prompt: user@hostname ~ %
  /^[\w\-]+@[\w\-\.]+ [~\/][\w\/\-\.]* %\s*/,
  // Fish shell
  /^[\w\-]+@[\w\-]+\s+[~\/][\w\/\-\.]*>\s*/,
  // Starship and modern prompts
  /^[❯➜→▶]\s*/,
  // Oh-my-zsh themes
  /^➜\s+[\w\-\.]+\s+/,
  // Simple % prompt (common in zsh)
  /^%\s*/,
]

// Error output patterns for output type detection
const ERROR_PATTERNS = [
  /^error:/i,
  /^Error:/,
  /^ERROR/,
  /^fatal:/i,
  /^FATAL/,
  /^failed/i,
  /^exception/i,
  /^\s*at\s+[\w\.$]+\s*\(/,
  /^Traceback \(most recent call last\)/,
  /^panic:/,
]

export function useBlocks(ptyId: number) {
  // Get blocks for this PTY
  const blocks = computed(() => state.value.blocks.get(ptyId) || [])
  const activeBlock = computed(() => state.value.activeBlock.get(ptyId) || null)

  // Parse OSC 133 sequences from PTY output
  function parseOSC133(data: string): { type: string; exitCode?: number } | null {
    // OSC 133 format: ESC ] 133 ; <type> [; <data>] ST
    // Where ST is BEL (0x07) or ESC \ (0x1b 0x5c)
    
    // Match: \x1b]133;A\x07 (PromptStart)
    if (data.includes('\x1b]133;A\x07')) {
      return { type: 'prompt_start' }
    }
    // Match: \x1b]133;B\x07 (CommandStart)
    if (data.includes('\x1b]133;B\x07')) {
      return { type: 'command_start' }
    }
    // Match: \x1b]133;C\x07 (CommandEnd)
    if (data.includes('\x1b]133;C\x07')) {
      return { type: 'command_end' }
    }
    // Match: \x1b]133;D;0\x07 (CommandFinished with exit code)
    const finishedMatch = data.match(/\x1b\]133;D;(\d+)\x07/)
    if (finishedMatch) {
      return { type: 'command_finished', exitCode: parseInt(finishedMatch[1]) }
    }
    // Match: \x1b]133;D\x07 (CommandFinished without exit code)
    if (data.includes('\x1b]133;D\x07')) {
      return { type: 'command_finished' }
    }

    return null
  }

  // Process PTY output for block boundaries
  function processOutput(data: string, cwd: string = process.env.HOME || '/') {
    const osc = parseOSC133(data)

    // Track if OSC 133 is available for this PTY
    if (osc && !state.value.useOSC133.get(ptyId)) {
      state.value.useOSC133.set(ptyId, true)
      console.log('[useBlocks] OSC 133 shell integration detected for PTY', ptyId)
    }

    if (osc?.type === 'command_start') {
      // Start new block
      startBlock(cwd)
    } else if (osc?.type === 'command_finished') {
      // End current block
      endBlock(osc.exitCode || 0)
    } else if (activeBlock.value) {
      // Accumulate output to active block
      appendOutput(data)
    } else if (!state.value.useOSC133.get(ptyId)) {
      // Fallback: use prompt detection for shells without OSC 133
      processOutputWithPromptDetection(data, cwd)
    }
  }

  // Fallback mode: detect blocks by prompt patterns
  function processOutputWithPromptDetection(data: string, cwd: string) {
    const lines = data.split(/\r?\n/)

    for (const line of lines) {
      if (isPromptLine(line)) {
        // This is a prompt line - extract any command after it
        const command = extractCommandFromPrompt(line)

        // If there's a running block, finish it
        const current = state.value.activeBlock.get(ptyId)
        if (current?.isRunning) {
          endBlock(0) // Assume success in fallback mode
        }

        // If there's a command, start a new block
        if (command) {
          startBlock(cwd, command)
        }
      } else if (line.trim()) {
        // Non-prompt, non-empty line - accumulate as output
        const current = state.value.activeBlock.get(ptyId)
        if (current) {
          appendOutput(line + '\n')
        }
      }
    }
  }

  // Handle explicit command submission (from input tracking)
  function onCommandSubmit(command: string, cwd: string) {
    // If using prompt detection, create a block immediately
    if (!state.value.useOSC133.get(ptyId)) {
      startBlock(cwd, command)
    }
  }

  // Detect if a line looks like a shell prompt
  function isPromptLine(line: string): boolean {
    return PROMPT_PATTERNS.some(pattern => pattern.test(line))
  }

  // Extract command from a prompt line
  function extractCommandFromPrompt(line: string): string {
    for (const pattern of PROMPT_PATTERNS) {
      const match = line.match(pattern)
      if (match) {
        return line.slice(match[0].length).trim()
      }
    }
    return line.trim()
  }

  // Detect output type for rich rendering
  function detectOutputType(output: string): CommandBlock['outputType'] {
    // Check for errors
    if (ERROR_PATTERNS.some(p => p.test(output))) {
      return 'error'
    }

    // Check for JSON
    try {
      const trimmed = output.trim()
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
          (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        JSON.parse(trimmed)
        return 'json'
      }
    } catch {}

    // Check for diff output
    if (/^(diff|---|\+\+\+|@@)/m.test(output)) {
      return 'diff'
    }

    // Check for table-like output
    const lines = output.split('\n').filter(l => l.trim())
    if (lines.length > 2 && lines.every(l => l.includes('  ') || l.includes('\t'))) {
      return 'table'
    }

    return 'plain'
  }

  // Start a new command block
  function startBlock(cwd: string, command?: string) {
    // Finish any running block first
    const currentActive = state.value.activeBlock.get(ptyId)
    if (currentActive && currentActive.isRunning) {
      endBlock(0) // Assume success if we're starting a new block
    }

    const block: CommandBlock = {
      id: `block-${ptyId}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      command: command || '',
      output: '',
      outputLines: [],
      exitCode: null,
      startTime: Date.now(),
      endTime: null,
      duration: null,
      cwd,
      collapsed: false,
      ptyId,
      isRunning: true,
      outputType: 'plain'
    }

    // Set as active block
    state.value.activeBlock.set(ptyId, block)

    console.log('[useBlocks] Started block:', block.id, command ? `cmd: ${command}` : '')
  }

  // Append output to active block
  function appendOutput(data: string) {
    const block = state.value.activeBlock.get(ptyId)
    if (!block) return

    // Strip OSC sequences from display output
    const cleanData = data
      .replace(/\x1b\]133;[ABCD];?\d*\x07/g, '')
      .replace(/\x1b\]133;[ABCD];?\d*\x1b\\/g, '')

    block.output += cleanData

    // Also track by lines for rich rendering
    const lines = cleanData.split(/\r?\n/)
    block.outputLines.push(...lines.filter(l => l.length > 0))
  }

  // Extract command from first line of output
  function extractCommand(output: string): string {
    const lines = output.split('\n')
    for (const line of lines) {
      const trimmed = line.trim()
      // Skip empty lines and prompts
      if (trimmed && !trimmed.endsWith('$') && !trimmed.endsWith('#') && !trimmed.endsWith('>')) {
        return trimmed
      }
    }
    return output.substring(0, 50).trim()
  }

  // End current block
  function endBlock(exitCode: number) {
    const block = state.value.activeBlock.get(ptyId)
    if (!block) return

    block.exitCode = exitCode
    block.endTime = Date.now()
    block.duration = block.endTime - block.startTime
    block.isRunning = false

    // Extract command if not set
    if (!block.command) {
      block.command = extractCommand(block.output)
    }

    // Detect output type for rich rendering
    block.outputType = detectOutputType(block.output)

    // Add to blocks list
    const blocksList = state.value.blocks.get(ptyId) || []
    blocksList.push(block)
    state.value.blocks.set(ptyId, blocksList)

    // Clear active block
    state.value.activeBlock.set(ptyId, null)

    console.log('[useBlocks] Ended block:', block.id, 'exit:', exitCode, 'duration:', block.duration + 'ms', 'type:', block.outputType)
  }

  // Toggle block collapse state
  function toggleBlock(blockId: string) {
    const blocksList = state.value.blocks.get(ptyId)
    if (!blocksList) return

    const block = blocksList.find(b => b.id === blockId)
    if (block) {
      block.collapsed = !block.collapsed
    }
  }

  // Rerun a block's command
  async function rerunBlock(blockId: string) {
    const blocksList = state.value.blocks.get(ptyId)
    if (!blocksList) return

    const block = blocksList.find(b => b.id === blockId)
    if (!block) return

    try {
      await invoke('send_input', { 
        id: ptyId, 
        input: block.command + '\n' 
      })
      console.log('[useBlocks] Reran command:', block.command)
    } catch (error) {
      console.error('[useBlocks] Failed to rerun command:', error)
    }
  }

  // Copy block output to clipboard
  async function copyBlock(blockId: string) {
    const blocksList = state.value.blocks.get(ptyId)
    if (!blocksList) return

    const block = blocksList.find(b => b.id === blockId)
    if (!block) return

    try {
      await navigator.clipboard.writeText(block.output)
      console.log('[useBlocks] Copied block output to clipboard')
    } catch (error) {
      console.error('[useBlocks] Failed to copy to clipboard:', error)
    }
  }

  // Export block as JSON
  function exportBlock(blockId: string): string | null {
    const blocksList = state.value.blocks.get(ptyId)
    if (!blocksList) return null

    const block = blocksList.find(b => b.id === blockId)
    if (!block) return null

    return JSON.stringify(block, null, 2)
  }

  // Clear all blocks for this PTY
  function clearBlocks() {
    state.value.blocks.set(ptyId, [])
    state.value.activeBlock.set(ptyId, null)
  }

  // Navigate blocks (for keyboard shortcuts)
  function navigateBlocks(direction: 'up' | 'down') {
    const blocksList = blocks.value
    if (blocksList.length === 0) return null

    // Find currently focused block (for now, just return first/last)
    if (direction === 'up') {
      return blocksList[blocksList.length - 1]
    } else {
      return blocksList[0]
    }
  }

  // Copy command only
  async function copyCommand(blockId: string): Promise<boolean> {
    const blocksList = state.value.blocks.get(ptyId)
    if (!blocksList) return false

    const block = blocksList.find(b => b.id === blockId)
    if (!block) return false

    try {
      await navigator.clipboard.writeText(block.command)
      return true
    } catch {
      return false
    }
  }

  // Collapse all blocks
  function collapseAll() {
    const blocksList = state.value.blocks.get(ptyId)
    if (blocksList) {
      blocksList.forEach(b => { b.collapsed = true })
    }
  }

  // Expand all blocks
  function expandAll() {
    const blocksList = state.value.blocks.get(ptyId)
    if (blocksList) {
      blocksList.forEach(b => { b.collapsed = false })
    }
  }

  // Export all blocks as JSON
  function exportAllBlocks(): string {
    const blocksList = state.value.blocks.get(ptyId) || []
    return JSON.stringify(blocksList.map(b => ({
      command: b.command,
      output: b.output,
      exitCode: b.exitCode,
      cwd: b.cwd,
      startTime: new Date(b.startTime).toISOString(),
      endTime: b.endTime ? new Date(b.endTime).toISOString() : null,
      duration: b.duration,
      outputType: b.outputType
    })), null, 2)
  }

  // Export as shell script
  function exportAsScript(): string {
    const blocksList = state.value.blocks.get(ptyId) || []
    const lines = ['#!/bin/bash', '', '# Exported from Warp_Open terminal', '']

    for (const block of blocksList) {
      if (block.command.trim()) {
        lines.push(`# CWD: ${block.cwd}`)
        if (block.exitCode !== null && block.exitCode !== 0) {
          lines.push(`# Exit code: ${block.exitCode}`)
        }
        lines.push(block.command)
        lines.push('')
      }
    }

    return lines.join('\n')
  }

  // Get running block
  const runningBlock = computed(() => {
    const current = state.value.activeBlock.get(ptyId)
    return current?.isRunning ? current : null
  })

  // Get failed blocks count
  const failedBlocksCount = computed(() => {
    const blocksList = state.value.blocks.get(ptyId) || []
    return blocksList.filter(b => b.exitCode !== null && b.exitCode !== 0).length
  })

  // Check if OSC 133 is being used
  const hasShellIntegration = computed(() => state.value.useOSC133.get(ptyId) || false)

  return {
    // State
    blocks,
    activeBlock,
    runningBlock,
    failedBlocksCount,
    hasShellIntegration,

    // Output processing
    processOutput,
    onCommandSubmit,

    // Block lifecycle
    startBlock,
    endBlock,

    // UI actions
    toggleBlock,
    collapseAll,
    expandAll,

    // Clipboard & sharing
    rerunBlock,
    copyBlock,
    copyCommand,
    exportBlock,
    exportAllBlocks,
    exportAsScript,

    // Utilities
    clearBlocks,
    navigateBlocks,
    isPromptLine,
    detectOutputType
  }
}

export type UseBlocksReturn = ReturnType<typeof useBlocks>
