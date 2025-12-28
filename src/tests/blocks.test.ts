/**
 * Command Blocks Tests
 *
 * Verifies Warp-style command grouping works correctly.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

// Mock Tauri invoke - must be hoisted, so use factory pattern
vi.mock('@tauri-apps/api/tauri', () => ({
  invoke: vi.fn()
}))

// Import after mocking
import { invoke } from '@tauri-apps/api/tauri'
import { useBlocks } from '../composables/useBlocks'

// Get the mocked function for assertions
const mockInvoke = vi.mocked(invoke)

describe('useBlocks', () => {
  let blocksStore: ReturnType<typeof useBlocks>
  const TEST_PTY_ID = 1

  beforeEach(() => {
    vi.clearAllMocks()
    blocksStore = useBlocks(TEST_PTY_ID)
    blocksStore.clearBlocks()
  })

  describe('Block Creation', () => {
    test('onCommandSubmit creates an active block', () => {
      expect(blocksStore.blocks.value.length).toBe(0)
      expect(blocksStore.activeBlock.value).toBeNull()

      blocksStore.onCommandSubmit('echo hello', '/home/user')

      expect(blocksStore.activeBlock.value).not.toBeNull()
      expect(blocksStore.activeBlock.value?.command).toBe('echo hello')
      expect(blocksStore.activeBlock.value?.cwd).toBe('/home/user')
      expect(blocksStore.activeBlock.value?.isRunning).toBe(true)
      expect(blocksStore.activeBlock.value?.exitCode).toBeNull()
    })

    test('active block is not in completed blocks list', () => {
      blocksStore.onCommandSubmit('echo hello', '~')

      expect(blocksStore.activeBlock.value).not.toBeNull()
      expect(blocksStore.blocks.value.length).toBe(0) // Not in completed list yet
    })

    test('endBlock finalizes active block and adds to list', () => {
      blocksStore.onCommandSubmit('echo hello', '~')
      blocksStore.endBlock(0)

      expect(blocksStore.activeBlock.value).toBeNull()
      expect(blocksStore.blocks.value.length).toBe(1)
      expect(blocksStore.blocks.value[0].exitCode).toBe(0)
      expect(blocksStore.blocks.value[0].isRunning).toBe(false)
      expect(blocksStore.blocks.value[0].duration).not.toBeNull()
    })

    test('block has correct exit code on failure', () => {
      blocksStore.onCommandSubmit('false', '~')
      blocksStore.endBlock(1)

      expect(blocksStore.blocks.value[0].exitCode).toBe(1)
    })
  })

  describe('Output Accumulation', () => {
    test('processOutput accumulates to active block', () => {
      blocksStore.onCommandSubmit('ls', '~')
      blocksStore.processOutput('file1.txt\n', '~')
      blocksStore.processOutput('file2.txt\n', '~')

      expect(blocksStore.activeBlock.value?.output).toContain('file1.txt')
      expect(blocksStore.activeBlock.value?.output).toContain('file2.txt')
    })
  })

  describe('Prompt Detection', () => {
    test('detects zsh % prompt', () => {
      expect(blocksStore.isPromptLine('user@host ~ % ')).toBe(true)
      expect(blocksStore.isPromptLine('% ')).toBe(true)
    })

    test('detects bash $ prompt', () => {
      expect(blocksStore.isPromptLine('user@host:~$ ')).toBe(true)
      expect(blocksStore.isPromptLine('$ ')).toBe(true)
    })

    test('detects starship/modern prompts', () => {
      expect(blocksStore.isPromptLine('❯ ')).toBe(true)
      expect(blocksStore.isPromptLine('➜  project ')).toBe(true)
    })

    test('does not detect regular output as prompt', () => {
      expect(blocksStore.isPromptLine('hello world')).toBe(false)
      expect(blocksStore.isPromptLine('total 100')).toBe(false)
      expect(blocksStore.isPromptLine('drwxr-xr-x 5 user staff')).toBe(false)
    })
  })

  describe('Output Type Detection', () => {
    test('detects error output', () => {
      expect(blocksStore.detectOutputType('Error: file not found')).toBe('error')
      expect(blocksStore.detectOutputType('fatal: not a git repository')).toBe('error')
      expect(blocksStore.detectOutputType('panic: runtime error')).toBe('error')
    })

    test('detects JSON output', () => {
      expect(blocksStore.detectOutputType('{"key": "value"}')).toBe('json')
      expect(blocksStore.detectOutputType('[1, 2, 3]')).toBe('json')
    })

    test('detects diff output', () => {
      expect(blocksStore.detectOutputType('diff --git a/file b/file\n--- a/file')).toBe('diff')
    })

    test('defaults to plain', () => {
      expect(blocksStore.detectOutputType('hello world')).toBe('plain')
    })
  })

  describe('Block Actions', () => {
    test('toggleBlock collapses/expands', () => {
      blocksStore.onCommandSubmit('echo hello', '~')
      blocksStore.endBlock(0)

      const blockId = blocksStore.blocks.value[0].id
      expect(blocksStore.blocks.value[0].collapsed).toBe(false)

      blocksStore.toggleBlock(blockId)
      expect(blocksStore.blocks.value[0].collapsed).toBe(true)

      blocksStore.toggleBlock(blockId)
      expect(blocksStore.blocks.value[0].collapsed).toBe(false)
    })

    test('collapseAll collapses all blocks', () => {
      blocksStore.onCommandSubmit('echo 1', '~')
      blocksStore.endBlock(0)
      blocksStore.onCommandSubmit('echo 2', '~')
      blocksStore.endBlock(0)

      blocksStore.collapseAll()

      expect(blocksStore.blocks.value.every(b => b.collapsed)).toBe(true)
    })

    test('expandAll expands all blocks', () => {
      blocksStore.onCommandSubmit('echo 1', '~')
      blocksStore.endBlock(0)
      blocksStore.onCommandSubmit('echo 2', '~')
      blocksStore.endBlock(0)

      blocksStore.collapseAll()
      blocksStore.expandAll()

      expect(blocksStore.blocks.value.every(b => !b.collapsed)).toBe(true)
    })

    test('clearBlocks removes all blocks', () => {
      blocksStore.onCommandSubmit('echo 1', '~')
      blocksStore.endBlock(0)
      blocksStore.onCommandSubmit('echo 2', '~')
      blocksStore.endBlock(0)

      blocksStore.clearBlocks()

      expect(blocksStore.blocks.value.length).toBe(0)
    })

    test('rerunBlock sends command to PTY', async () => {
      mockInvoke.mockResolvedValue(undefined)

      blocksStore.onCommandSubmit('echo hello', '~')
      blocksStore.endBlock(0)

      const blockId = blocksStore.blocks.value[0].id
      await blocksStore.rerunBlock(blockId)

      expect(mockInvoke).toHaveBeenCalledWith('send_input', {
        id: TEST_PTY_ID,
        input: 'echo hello\n'
      })
    })
  })

  describe('Export Functions', () => {
    test('exportAllBlocks returns valid JSON', () => {
      blocksStore.onCommandSubmit('echo 1', '~')
      blocksStore.endBlock(0)
      blocksStore.onCommandSubmit('echo 2', '~')
      blocksStore.endBlock(0)

      const exported = blocksStore.exportAllBlocks()
      const parsed = JSON.parse(exported)

      expect(parsed.length).toBe(2)
      expect(parsed[0].command).toBe('echo 1')
      expect(parsed[1].command).toBe('echo 2')
    })

    test('exportAsScript returns bash script', () => {
      blocksStore.onCommandSubmit('echo hello', '/home/user')
      blocksStore.endBlock(0)

      const script = blocksStore.exportAsScript()

      expect(script).toContain('#!/bin/bash')
      expect(script).toContain('echo hello')
      expect(script).toContain('# CWD: /home/user')
    })
  })

  describe('Running Block State', () => {
    test('runningBlock computed shows active running block', () => {
      expect(blocksStore.runningBlock.value).toBeNull()

      blocksStore.onCommandSubmit('echo hello', '~')
      expect(blocksStore.runningBlock.value).not.toBeNull()
      expect(blocksStore.runningBlock.value?.isRunning).toBe(true)

      blocksStore.endBlock(0)
      expect(blocksStore.runningBlock.value).toBeNull()
    })

    test('failedBlocksCount tracks failures', () => {
      expect(blocksStore.failedBlocksCount.value).toBe(0)

      blocksStore.onCommandSubmit('success', '~')
      blocksStore.endBlock(0)
      expect(blocksStore.failedBlocksCount.value).toBe(0)

      blocksStore.onCommandSubmit('fail', '~')
      blocksStore.endBlock(1)
      expect(blocksStore.failedBlocksCount.value).toBe(1)

      blocksStore.onCommandSubmit('fail2', '~')
      blocksStore.endBlock(127)
      expect(blocksStore.failedBlocksCount.value).toBe(2)
    })
  })
})
